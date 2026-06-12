import http from "node:http";
import https from "node:https";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  throw error;
}

function normalizeBaseUrl(url) {
  if (typeof url !== "string" || !url.trim()) {
    fail(400, "3x-ui panel URL is required");
  }
  const trimmed = url.trim().replace(/\/+$/, "");
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      fail(400, "3x-ui panel URL must be http or https");
    }
  } catch {
    fail(400, "3x-ui panel URL must be valid");
  }
  return trimmed;
}

function allowInsecureTls(panel) {
  return panel?.allowInsecureTls === true || panel?.insecureTls === true;
}

function normalizeLoginBaseUrl(url) {
  const base = normalizeBaseUrl(url);
  return base.replace(/\/panel$/i, "") || base;
}

function uniqueStrings(values) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    if (typeof value !== "string" || !value.trim()) continue;
    const normalized = value.trim().replace(/\/+$/, "");
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

function firstString(...values) {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function parseFiniteNumber(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function normalizeSubscriptionPath(value) {
  const trimmed = typeof value === "string" ? value.trim() : "";
  return trimmed ? trimmed.replace(/^\/+|\/+$/g, "") || "sub" : "sub";
}

function normalizeSubscriptionPrefix(panel) {
  const url = firstString(panel?.subscriptionUrl);
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return parsed.toString().replace(/\/+$/, "");
  } catch {
    return null;
  }
}

function isPublicHttpUrl(value) {
  if (typeof value !== "string" || !value.trim()) return false;
  try {
    const parsed = new URL(value.trim());
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function readPath(payload, path) {
  let node = payload;
  for (const key of path) {
    if (!node || typeof node !== "object") return null;
    node = node[key];
  }
  return node;
}

function readResponseText(response) {
  if (!response || typeof response.text !== "function") return Promise.resolve("");
  return response.text();
}

async function readJsonPayload(response) {
  const text = await readResponseText(response);
  if (!text || !text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function responseError(response, message) {
  fail(response?.status || 502, `${message} with HTTP ${response?.status}`);
}

function requestFailureMessage(error) {
  const code = error?.cause?.code || error?.code || "";
  const message = String(error?.message || "").toLowerCase();
  if (
    code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    code === "ERR_TLS_CERT_ALTNAME_INVALID" ||
    code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
    code === "CERT_HAS_EXPIRED" ||
    message.includes("certificate") ||
    message.includes("self signed")
  ) {
    return "TLS/certificate issue";
  }
  if (code === "ECONNRESET" || message.includes("connection reset")) {
    return "connection reset";
  }
  if (code === "ECONNREFUSED" || code === "EHOSTUNREACH" || code === "ENETUNREACH" || code === "EAI_AGAIN" || code === "ENOTFOUND" || code === "ETIMEDOUT") {
    return "unreachable panel";
  }
  if (code === "HPE_INVALID_CONSTANT" || code === "ERR_INVALID_PROTOCOL" || message.includes("invalid http version") || message.includes("invalid protocol")) {
    return "invalid protocol response";
  }
  return "request failed";
}

function authHeaders(auth) {
  const headers = {
    accept: "application/json",
    "x-requested-with": "XMLHttpRequest"
  };
  if (auth?.authorization) headers.authorization = auth.authorization;
  if (auth?.cookie) headers.cookie = auth.cookie;
  if (auth?.csrfToken) headers["x-csrf-token"] = auth.csrfToken;
  return headers;
}

function extractSessionCookie(response) {
  const direct =
    response?.headers?.getSetCookie?.() ??
    response?.headers?.raw?.()?.["set-cookie"] ??
    response?.headers?.get?.("set-cookie") ??
    response?.headers?.get?.("Set-Cookie") ??
    response?.headers?.["set-cookie"] ??
    response?.headers?.["Set-Cookie"];
  if (!direct) return "";
  const values = Array.isArray(direct) ? direct : [direct];
  return values
    .flatMap((value) => String(value).split(/,(?=[^;]+=[^;]+)/))
    .map((part) => part.split(";")[0].trim())
    .filter(Boolean)
    .join("; ");
}

function extractExplicitSubscriptionUrl(payload) {
  const candidates = [
    payload?.subscriptionUrl,
    payload?.subscription_url,
    payload?.subUrl,
    payload?.sub_url,
    payload?.data?.subscriptionUrl,
    payload?.data?.subscription_url,
    payload?.data?.subUrl,
    payload?.data?.sub_url,
    payload?.obj?.subscriptionUrl,
    payload?.obj?.subscription_url,
    payload?.obj?.subUrl,
    payload?.obj?.sub_url,
    payload?.obj?.client?.subscriptionUrl,
    payload?.obj?.client?.subscription_url,
    payload?.obj?.client?.subUrl,
    payload?.obj?.client?.sub_url
  ];
  for (const candidate of candidates) {
    if (isPublicHttpUrl(candidate)) return candidate.trim();
  }
  return null;
}

function extractSubscriptionIdentifier(payload, user) {
  return firstString(
    payload?.subId,
    payload?.subscriptionId,
    payload?.data?.subId,
    payload?.data?.subscriptionId,
    payload?.obj?.subId,
    payload?.obj?.subscriptionId,
    payload?.obj?.client?.subId,
    payload?.obj?.client?.subscriptionId,
    user?.subscriptionId,
    user?.subId,
    user?.username,
    user?.email,
    payload?.username,
    payload?.email,
    payload?.obj?.client?.email
  );
}

function buildSubscriptionFallback(panel, identifier) {
  const prefix = normalizeSubscriptionPrefix(panel);
  if (!prefix) return null;
  const token = firstString(identifier);
  if (!token) return null;
  const path = normalizeSubscriptionPath(panel?.subscriptionPath);
  return `${prefix}/${path}/${encodeURIComponent(token)}`;
}

function normalizeHeaderMap(headers) {
  const map = {};
  for (const [key, value] of Object.entries(headers || {})) {
    map[String(key).toLowerCase()] = value;
  }
  return map;
}

function buildNodeResponse(status, headers, chunks) {
  const buffer = Buffer.concat(chunks);
  const headerMap = normalizeHeaderMap(headers);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get(name) {
        const key = String(name || "").toLowerCase();
        const value = headerMap[key];
        if (Array.isArray(value)) return value.join(", ");
        return firstString(value);
      }
    },
    async text() {
      return buffer.toString("utf8");
    }
  };
}

function buildFetchLikeResponse(status, headers, text) {
  const bodyText = typeof text === "string" ? text : "";
  const headerMap = normalizeHeaderMap(headers);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get(name) {
        const key = String(name || "").toLowerCase();
        const value = headerMap[key];
        if (Array.isArray(value)) return value.join(", ");
        return firstString(value);
      }
    },
    async text() {
      return bodyText;
    }
  };
}

function requestWithNode(url, { method = "GET", headers = {}, body, insecureTls = false } = {}) {
  const target = new URL(url);
  const transport = target.protocol === "https:" ? https : http;
  const requestBody = body instanceof URLSearchParams ? body.toString() : body;
  const requestOptions = {
    method,
    headers,
    ...(target.protocol === "https:" && insecureTls ? { agent: new https.Agent({ rejectUnauthorized: false }) } : {})
  };
  return new Promise((resolve, reject) => {
    const req = transport.request(target, requestOptions, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      response.on("end", () => {
        resolve(buildNodeResponse(response.statusCode || 0, response.headers || {}, chunks));
      });
    });
    req.on("error", reject);
    if (requestBody !== undefined) req.write(requestBody);
    req.end();
  });
}

function requestWithPowerShell(url, { method = "GET", headers = {}, body } = {}) {
  const payload = {
    url,
    method,
    headers,
    body: body === undefined ? null : body
  };
  const script = String.raw`
$ErrorActionPreference = 'Stop'
$payload = $env:AEGIS_3XUI_REQUEST | ConvertFrom-Json -Depth 32
$headers = @{}
if ($null -ne $payload.headers) {
  foreach ($prop in $payload.headers.PSObject.Properties) {
    if ($prop.Name -ieq 'content-type') {
      continue
    }
    $headers[$prop.Name] = [string]$prop.Value
  }
}
$invokeParams = @{
  Uri = [string]$payload.url
  Method = [string]$payload.method
  SkipCertificateCheck = $true
  Headers = $headers
  ErrorAction = 'Stop'
  SkipHttpErrorCheck = $true
}
if ($null -ne $payload.body -and [string]$payload.body -ne '') {
  $invokeParams.Body = [string]$payload.body
}
if ($null -ne $payload.headers -and $payload.headers.PSObject.Properties.Name -contains 'content-type') {
  $invokeParams.ContentType = [string]$payload.headers.'content-type'
}
$resp = Invoke-WebRequest @invokeParams
$result = [ordered]@{
  status = [int]$resp.StatusCode
  headers = @{}
  body = $resp.Content
}
foreach ($name in $resp.Headers.Keys) {
  $result.headers[$name] = [string]$resp.Headers[$name]
}
$result | ConvertTo-Json -Depth 10 -Compress
`;
  return new Promise((resolve, reject) => {
    const child = spawn("pwsh", ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], {
      windowsHide: true,
      env: {
        ...process.env,
        AEGIS_3XUI_REQUEST: JSON.stringify(payload)
      }
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr.trim() || `powershell exited with code ${code}`));
        return;
      }
      try {
        const parsed = stdout.trim() ? JSON.parse(stdout) : {};
        resolve(buildFetchLikeResponse(parsed.status || 0, parsed.headers || {}, parsed.body || ""));
      } catch (error) {
        reject(error);
      }
    });
  });
}

async function performRequest(client, url, { method = "GET", body, headers = {} } = {}) {
  const requestBody = toRequestBody(body);
  try {
    const preferPowerShell =
      client.allowInsecureTls &&
      process.platform === "win32" &&
      process.env.AEGIS_3XUI_POWERSHELL_TRANSPORT !== "0";
    if (preferPowerShell) {
      try {
        return await requestWithPowerShell(url, {
          method,
          headers,
          body: requestBody
        });
      } catch (error) {
        try {
          return await requestWithNode(url, {
            method,
            headers,
            body: requestBody,
            insecureTls: true
          });
        } catch {
          fail(502, `3x-ui request failed: ${requestFailureMessage(error)}`);
        }
      }
    }
    if (client.allowInsecureTls) {
      return await requestWithNode(url, {
        method,
        headers,
        body: requestBody,
        insecureTls: true
      });
    }
    return await fetch(url, {
      method,
      headers,
      body: requestBody
    });
  } catch (error) {
    if (client.allowInsecureTls && process.platform === "win32") {
      try {
        return await requestWithPowerShell(url, {
          method,
          headers,
          body: requestBody
        });
      } catch {
        // Fall through to the original Node/fetch error below.
      }
    }
    fail(502, `3x-ui request failed: ${requestFailureMessage(error)}`);
  }
}

function buildAuthRoots(panel) {
  return uniqueStrings([normalizeLoginBaseUrl(panel?.url), normalizeBaseUrl(panel?.url)]);
}

async function requestSessionToken(client, root) {
  const response = await performRequest(client, `${root}/csrf-token`, {
    method: "GET",
    headers: {
      accept: "application/json",
      "x-requested-with": "XMLHttpRequest"
    }
  });
  const payload = await readJsonPayload(response);
  if (!response.ok) {
    responseError(response, "3x-ui csrf token request failed");
  }
  const token = firstString(payload?.obj, payload?.data?.obj, payload?.token, payload?.data?.token);
  if (!token) {
    fail(502, "3x-ui csrf token response missing token");
  }
  const cookie = extractSessionCookie(response);
  if (!cookie) {
    fail(502, "3x-ui csrf token response missing session cookie");
  }
  return { token, cookie };
}

async function authenticateWithSession(client, root) {
  let token;
  let cookie;
  try {
    ({ token, cookie } = await requestSessionToken(client, root));
  } catch (error) {
    error.stage = "csrf";
    throw error;
  }
  const response = await performRequest(client, `${root}/login`, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
      "x-requested-with": "XMLHttpRequest",
      "x-csrf-token": token,
      cookie
    },
    body: new URLSearchParams({
      username: client.username,
      password: client.password
    })
  });
  const payload = await readJsonPayload(response);
  if (!response.ok) {
    if (response.status === 401) {
      const error = new Error(firstString(payload?.msg, "3x-ui login failed"));
      error.status = 401;
      error.stage = "login";
      throw error;
    }
    responseError(response, "3x-ui login failed");
  }
  if (payload && typeof payload === "object" && payload.success === false) {
    const error = new Error(firstString(payload?.msg, "3x-ui login failed"));
    error.status = 401;
    error.stage = "login";
    throw error;
  }
  const tokenFromResponse = firstString(payload?.access_token, payload?.token, payload?.data?.access_token, payload?.data?.token);
  if (tokenFromResponse) {
    return { authorization: `Bearer ${tokenFromResponse}` };
  }
  const sessionCookie = extractSessionCookie(response) || cookie;
  if (!sessionCookie) {
    fail(502, "3x-ui login response missing session cookie");
  }
  return { cookie: sessionCookie, csrfToken: token };
}

function extractTrafficBytes(payload) {
  const candidates = [
    payload?.used_traffic,
    payload?.usedTraffic,
    payload?.data_used,
    payload?.used,
    payload?.usedGB,
    payload?.obj?.used_traffic,
    payload?.obj?.usedTraffic,
    payload?.obj?.data_used,
    payload?.obj?.used,
    payload?.obj?.usedGB,
    payload?.obj?.client?.used_traffic,
    payload?.obj?.client?.usedTraffic,
    payload?.obj?.client?.data_used,
    payload?.obj?.client?.used,
    payload?.obj?.client?.usedGB
  ];
  for (const candidate of candidates) {
    const value = parseFiniteNumber(candidate);
    if (value !== null && value >= 0) return value;
  }
  const up = parseFiniteNumber(payload?.up ?? payload?.obj?.up ?? payload?.obj?.client?.up);
  const down = parseFiniteNumber(payload?.down ?? payload?.obj?.down ?? payload?.obj?.client?.down);
  if (up !== null && down !== null) return Math.max(0, up + down);
  return null;
}

function extractClient(payload) {
  if (payload && typeof payload === "object") {
    if (payload.client && typeof payload.client === "object") return payload.client;
    if (payload.obj && typeof payload.obj === "object" && payload.obj.client && typeof payload.obj.client === "object") {
      return payload.obj.client;
    }
    if ("email" in payload || "subId" in payload || "uuid" in payload) return payload;
    if (payload.obj && typeof payload.obj === "object" && ("email" in payload.obj || "subId" in payload.obj || "uuid" in payload.obj)) {
      return payload.obj;
    }
  }
  return null;
}

function collectInboundRows(payload) {
  const candidates = [
    payload,
    payload?.obj,
    payload?.data,
    payload?.obj?.inbounds,
    payload?.obj?.items,
    payload?.obj?.rows,
    payload?.data?.inbounds,
    payload?.data?.items,
    payload?.data?.rows
  ];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) return candidate;
  }
  if (payload && typeof payload === "object") {
    return Object.values(payload).flatMap((value) => (Array.isArray(value) ? value : []));
  }
  return [];
}

function normalizeInboundId(inbound) {
  const id = inbound?.id ?? inbound?.Id ?? inbound?.ID;
  if (id !== undefined && id !== null && `${id}`.trim()) return String(id).trim();
  const protocol = firstString(inbound?.protocol, inbound?.Protocol);
  const label = firstString(inbound?.remark, inbound?.tag, inbound?.label, inbound?.name);
  const port = inbound?.port ?? inbound?.Port;
  return [protocol, label, port].filter((item) => item !== "" && item !== null && item !== undefined).join(":");
}

function normalizeInbound(inbound) {
  const streamSettings = inbound?.streamSettings && typeof inbound.streamSettings === "object" ? inbound.streamSettings : {};
  return {
    id: normalizeInboundId(inbound),
    label: firstString(inbound?.remark, inbound?.tag, inbound?.label, inbound?.name, inbound?.protocol, inbound?.id),
    protocol: firstString(inbound?.protocol, inbound?.Protocol),
    network: firstString(inbound?.network, streamSettings.network),
    tls: firstString(inbound?.tls, streamSettings.security),
    port: parseFiniteNumber(inbound?.port ?? inbound?.Port),
    enabled: inbound?.enable !== false && inbound?.enabled !== false
  };
}

function normalizeInboundIds(value) {
  const raw = Array.isArray(value)
    ? value
    : value !== undefined && value !== null
      ? [value]
      : [];
  const ids = [];
  const seen = new Set();
  for (const item of raw) {
    const parsed = parseFiniteNumber(item);
    if (parsed === null || !Number.isInteger(parsed) || parsed <= 0 || seen.has(parsed)) continue;
    seen.add(parsed);
    ids.push(parsed);
  }
  return ids;
}

function buildClientPayload(user) {
  const email = firstString(user?.username, user?.email);
  if (!email) fail(400, "3x-ui email is required");
  const inboundIds = normalizeInboundIds(user?.inboundIds ?? user?.inboundId);
  if (inboundIds.length === 0) fail(400, "At least one inbound must be selected for 3x-ui");
  const limitBytes = parseFiniteNumber(user?.limitBytes);
  const expiresAt = user?.expiresAt ? new Date(user.expiresAt).getTime() : 0;
  const generatedSubId = randomUUID().replace(/-/g, "").slice(0, 16);
  return {
    email,
    uuid: firstString(user?.uuid) || randomUUID(),
    subId: firstString(user?.subscriptionId, user?.subId) || generatedSubId,
    totalGB: limitBytes !== null && limitBytes > 0 ? limitBytes : 0,
    expiryTime: Number.isFinite(expiresAt) && expiresAt > 0 ? expiresAt : 0,
    enable: user?.active !== false,
    flow: firstString(user?.flow),
    security: firstString(user?.security) || "auto",
    limitIp: parseFiniteNumber(user?.limitIp) ?? 0,
    tgId: parseFiniteNumber(user?.tgId) ?? 0,
    group: firstString(user?.group),
    comment: firstString(user?.note, user?.comment),
    reset: parseFiniteNumber(user?.reset) ?? 0,
    inboundIds
  };
}

function buildCreatePayload(user) {
  const client = buildClientPayload(user);
  return {
    client: {
      email: client.email,
      uuid: client.uuid,
      subId: client.subId,
      totalGB: client.totalGB,
      expiryTime: client.expiryTime,
      tgId: client.tgId,
      limitIp: client.limitIp,
      enable: client.enable,
      flow: client.flow,
      security: client.security,
      comment: client.comment,
      group: client.group,
      reset: client.reset
    },
    inboundIds: client.inboundIds
  };
}

function buildUpdatePayload(user, current = {}) {
  const merged = {
    ...current,
    ...user,
    limitBytes: Object.prototype.hasOwnProperty.call(user, "limitBytes") ? user.limitBytes : current.limitBytes,
    expiresAt: Object.prototype.hasOwnProperty.call(user, "expiresAt") ? user.expiresAt : current.expiresAt,
    active: Object.prototype.hasOwnProperty.call(user, "active") ? user.active : current.active,
    note: Object.prototype.hasOwnProperty.call(user, "note") ? user.note : current.note,
    flow: Object.prototype.hasOwnProperty.call(user, "flow") ? user.flow : current.flow,
    security: Object.prototype.hasOwnProperty.call(user, "security") ? user.security : current.security,
    tgId: Object.prototype.hasOwnProperty.call(user, "tgId") ? user.tgId : current.tgId,
    limitIp: Object.prototype.hasOwnProperty.call(user, "limitIp") ? user.limitIp : current.limitIp,
    group: Object.prototype.hasOwnProperty.call(user, "group") ? user.group : current.group,
    reset: Object.prototype.hasOwnProperty.call(user, "reset") ? user.reset : current.reset,
    uuid: Object.prototype.hasOwnProperty.call(user, "uuid") ? user.uuid : current.uuid,
    subscriptionId: Object.prototype.hasOwnProperty.call(user, "subscriptionId") ? user.subscriptionId : current.subscriptionId,
    subId: Object.prototype.hasOwnProperty.call(user, "subId") ? user.subId : current.subId
  };
  const client = buildClientPayload(merged);
  return {
    email: client.email,
    uuid: client.uuid,
    subId: client.subId,
    totalGB: client.totalGB,
    expiryTime: client.expiryTime,
    tgId: client.tgId,
    limitIp: client.limitIp,
    enable: client.enable,
    flow: client.flow,
    security: client.security,
    comment: client.comment,
    group: client.group,
    reset: client.reset
  };
}

function buildSubscriptionUrlFromPayload(panel, payload, user) {
  const explicit = extractExplicitSubscriptionUrl(payload) || extractExplicitSubscriptionUrl(user);
  if (explicit) return explicit;
  const identifier = extractSubscriptionIdentifier(payload, user);
  return buildSubscriptionFallback(panel, identifier);
}

function toRequestBody(body) {
  if (body === undefined || body === null) return undefined;
  if (body instanceof URLSearchParams) return body.toString();
  if (typeof body === "string") return body;
  return JSON.stringify(body);
}

async function requestPanel(client, auth, path, { method = "GET", body, headers: extraHeaders = {}, errorLabel = "request" } = {}) {
  const headers = { ...authHeaders(auth), ...extraHeaders };
  const requestBody = toRequestBody(body);
  if (requestBody !== undefined && !headers["content-type"]) {
    headers["content-type"] = "application/json";
  }
  const response = await performRequest(client, `${client.apiBase}${path}`, { method, headers, body: requestBody });
  const payload = await readJsonPayload(response);
  if (!response.ok && response.status !== 204) {
    responseError(response, `3x-ui ${errorLabel} failed`);
  }
  return payload;
}

export function buildClient(panel) {
  const baseUrl = normalizeBaseUrl(panel?.url);
  const loginUrl = `${normalizeLoginBaseUrl(panel?.url)}/login`;
  const apiKey = firstString(panel?.apiKey, panel?.token);
  const username = firstString(panel?.username);
  const password = firstString(panel?.password, panel?.secret);
  const insecureTls = allowInsecureTls(panel);
  if (!apiKey && (!username || !password)) {
    fail(400, "3x-ui apiKey or username and password are required");
  }
  return {
    baseUrl,
    apiBase: `${baseUrl}/api`,
    loginUrl,
    authRoots: buildAuthRoots(panel),
    apiKey,
    username,
    password,
    allowInsecureTls: insecureTls
  };
}

export async function authenticate(client) {
  if (client.apiKey) {
    return { authorization: `Bearer ${client.apiKey}` };
  }
  let lastError = null;
  const roots = Array.isArray(client.authRoots) && client.authRoots.length > 0
    ? client.authRoots
    : [normalizeLoginBaseUrl(client.baseUrl || client.loginUrl || "")];
  for (const root of roots) {
    try {
      return await authenticateWithSession(client, root);
    } catch (error) {
      lastError = error;
      if (error?.stage === "login" && error?.status === 401) {
        throw error;
      }
      continue;
    }
  }
  throw lastError || new Error("3x-ui login failed");
}

export async function listInbounds(panel) {
  const client = buildClient(panel);
  const auth = await authenticate(client);
  const payload = await requestPanel(client, auth, "/inbounds/list", { errorLabel: "list inbounds" });
  return collectInboundRows(payload).map((inbound) => normalizeInbound(inbound));
}

export async function createUser(panel, user) {
  const client = buildClient(panel);
  const auth = await authenticate(client);
  const body = buildCreatePayload(user);
  const payload = await requestPanel(client, auth, "/clients/add", {
    method: "POST",
    body,
    errorLabel: "create client"
  });
  const clientPayload = extractClient(payload) || {};
  const subscriptionId = extractSubscriptionIdentifier(clientPayload, { ...user, subscriptionId: body.client?.subId });
  return {
    id: clientPayload.id ?? clientPayload.email ?? user?.id ?? body.client?.email,
    username: firstString(clientPayload.email, user?.username, body.client?.email),
    status: clientPayload.enable === false ? "disabled" : "active",
    active: clientPayload.enable !== false,
    subscriptionId,
    subscriptionUrl: buildSubscriptionUrl(panel, clientPayload, { ...user, subscriptionId: body.client?.subId })
  };
}

export async function updateUser(panel, user, changes = {}) {
  const client = buildClient(panel);
  const auth = await authenticate(client);
  const username = firstString(user?.username, user?.email);
  if (!username) fail(400, "3x-ui email is required");
  const currentInbounds = normalizeInboundIds(user?.inboundIds);
  const desiredInbounds = normalizeInboundIds(
    Object.prototype.hasOwnProperty.call(changes, "inboundIds") ? changes.inboundIds : currentInbounds
  );
  const body = buildUpdatePayload({ ...user, ...changes }, user);
  const payload = await requestPanel(client, auth, `/clients/update/${encodeURIComponent(username)}`, {
    method: "POST",
    body,
    errorLabel: "update client"
  });
  const clientPayload = extractClient(payload) || {};
  const remoteUsername = firstString(clientPayload.email, username);
  const desiredSet = new Set(desiredInbounds);
  const currentSet = new Set(currentInbounds);
  const addIds = desiredInbounds.filter((id) => !currentSet.has(id));
  const removeIds = currentInbounds.filter((id) => !desiredSet.has(id));
  if (addIds.length > 0) {
    await requestPanel(client, auth, `/clients/${encodeURIComponent(remoteUsername)}/attach`, {
      method: "POST",
      body: { inboundIds: addIds },
      errorLabel: "attach client inbounds"
    });
  }
  if (removeIds.length > 0) {
    await requestPanel(client, auth, `/clients/${encodeURIComponent(remoteUsername)}/detach`, {
      method: "POST",
      body: { inboundIds: removeIds },
      errorLabel: "detach client inbounds"
    });
  }
  return {
    id: clientPayload.id ?? clientPayload.email ?? user?.id ?? username,
    username: firstString(clientPayload.email, username),
    status: clientPayload.enable === false ? "disabled" : "active",
    active: clientPayload.enable !== false,
    subscriptionId: extractSubscriptionIdentifier(clientPayload, { ...user, ...changes, subscriptionId: body.subId }),
    subscriptionUrl: buildSubscriptionUrl(panel, clientPayload, { ...user, ...changes, subscriptionId: body.subId })
  };
}

export async function deleteUser(panel, user) {
  const client = buildClient(panel);
  const auth = await authenticate(client);
  const username = firstString(user?.username, user?.email);
  if (!username) fail(400, "3x-ui email is required");
  const response = await fetch(`${client.apiBase}/clients/del/${encodeURIComponent(username)}`, {
    method: "POST",
    headers: authHeaders(auth)
  });
  if (response.status === 404) {
    return { ok: true, username, status: "missing" };
  }
  if (!response.ok && response.status !== 204) {
    responseError(response, "3x-ui delete client failed");
  }
  return { ok: true, username, status: "deleted" };
}

export async function getUser(panel, user) {
  const client = buildClient(panel);
  const auth = await authenticate(client);
  const username = firstString(user?.username, user?.email);
  if (!username) fail(400, "3x-ui email is required");
  const clientPayload = await requestPanel(client, auth, `/clients/get/${encodeURIComponent(username)}`, {
    errorLabel: "get client"
  });
  let trafficPayload = null;
  try {
    trafficPayload = await requestPanel(client, auth, `/clients/traffic/${encodeURIComponent(username)}`, {
      errorLabel: "get client traffic"
    });
  } catch {
    trafficPayload = null;
  }
  const clientInfo = extractClient(clientPayload) || {};
  const subscriptionId = extractSubscriptionIdentifier(clientInfo, { ...user, username });
  const subscriptionUrl = buildSubscriptionUrl(panel, clientPayload, { ...user, subscriptionId, username });
  const usedBytes =
    extractTrafficBytes(trafficPayload) ??
    extractTrafficBytes(clientPayload) ??
    (typeof user?.usedBytes === "number" && Number.isFinite(user.usedBytes) ? user.usedBytes : 0);
  return {
    id: clientInfo.id ?? user?.id ?? username,
    username: firstString(clientInfo.email, username),
    active: clientInfo.enable !== false,
    status: clientInfo.enable === false ? "disabled" : "active",
    limitBytes: (() => {
      const value = parseFiniteNumber(clientInfo.totalGB);
      return value !== null && value >= 0 ? value : typeof user?.limitBytes === "number" && Number.isFinite(user.limitBytes) ? user.limitBytes : 0;
    })(),
    expiresAt: (() => {
      const value = parseFiniteNumber(clientInfo.expiryTime);
      return value !== null && value > 0 ? new Date(value).toISOString() : null;
    })(),
    usedBytes,
    subscriptionId,
    subscriptionUrl,
    inboundIds: normalizeInboundIds(readPath(clientPayload, ["obj", "inboundIds"]) ?? clientPayload?.inboundIds ?? clientInfo?.inboundIds)
  };
}

export async function syncUserTraffic(panel, user) {
  return getUser(panel, user);
}

export async function testConnection(panel) {
  const inbounds = await listInbounds(panel);
  return {
    ok: true,
    panelId: panel?.id ?? null,
    type: "three-x-ui",
    message: `Connection OK: ${inbounds.length} inbounds`,
    inboundCount: inbounds.length,
    checkedAt: new Date().toISOString()
  };
}

export function buildSubscriptionUrl(panel, remoteUser, localUser = remoteUser) {
  return buildSubscriptionUrlFromPayload(panel, remoteUser, localUser);
}

export const threeXUiAdapter = {
  type: "three-x-ui",
  label: "3x-ui / Sanaei",
  capabilities: {
    canTestConnection: true,
    canListInbounds: true,
    canCreateUser: true,
    canUpdateUser: true,
    canDeleteUser: true,
    canSyncTraffic: true,
    canBuildSubscriptionUrl: true,
    canGetUser: true
  },
  async health() {
    fail(501, "three-x-ui health is not implemented yet");
  },
  async testConnection(panel) {
    return testConnection(panel);
  },
  async buildClient(panel) {
    return buildClient(panel);
  },
  async authenticate(client) {
    return authenticate(client);
  },
  async listInbounds(panel) {
    return listInbounds(panel);
  },
  async listUsers() {
    fail(501, "three-x-ui listUsers is not implemented yet");
  },
  async createUser(panel, user) {
    return createUser(panel, user);
  },
  async updateUser(panel, user, changes) {
    return updateUser(panel, user, changes);
  },
  async deleteUser(panel, user) {
    return deleteUser(panel, user);
  },
  async getUser(panel, user) {
    return getUser(panel, user);
  },
  async syncUserTraffic(panel, user) {
    return syncUserTraffic(panel, user);
  },
  async buildSubscriptionUrl(panel, remoteUser, localUser) {
    return buildSubscriptionUrl(panel, remoteUser, localUser);
  },
  async sync() {
    fail(501, "three-x-ui sync is not implemented yet");
  }
};
