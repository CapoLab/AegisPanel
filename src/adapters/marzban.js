function notImplemented(method) {
  const error = new Error(`Marzban ${method} is not implemented yet`);
  error.status = 501;
  return error;
}

function reject(method) {
  throw notImplemented(method);
}

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  throw error;
}

function normalizeBaseUrl(url) {
  if (typeof url !== "string" || !url.trim()) fail(400, "Marzban base URL is required");
  return url.trim().replace(/\/+$/, "");
}

function readCredential(panel, keys) {
  for (const key of keys) {
    const value = panel?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function stableInboundId(inbound, fallbackProtocol = "") {
  if (inbound?.id !== undefined && inbound?.id !== null && `${inbound.id}`.trim()) return String(inbound.id);
  const protocol = String(inbound?.protocol ?? fallbackProtocol ?? "").trim();
  const label = String(inbound?.tag ?? inbound?.label ?? inbound?.remark ?? inbound?.name ?? "").trim();
  const port = inbound?.port !== undefined && inbound?.port !== null ? String(inbound.port).trim() : "";
  return [protocol, label, port].filter(Boolean).join(":");
}

export function buildClient(panel) {
  const baseUrl = normalizeBaseUrl(panel?.url);
  const username = readCredential(panel, ["username"]);
  const password = readCredential(panel, ["password", "secret"]);
  if (!username || !password) fail(400, "Marzban username and password are required");
  return {
    baseUrl,
    username,
    password,
    authUrl: `${baseUrl}/api/admin/token`,
    inboundsUrl: `${baseUrl}/api/inbounds`
  };
}

export async function authenticate(client) {
  const body = new URLSearchParams({
    username: client.username,
    password: client.password
  });
  const response = await fetch(client.authUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body
  });
  if (!response.ok) fail(response.status || 502, `Marzban token request failed with HTTP ${response.status}`);
  const payload = await response.json();
  const accessToken = payload?.access_token;
  if (typeof accessToken !== "string" || !accessToken.trim()) {
    fail(502, "Marzban token response missing access_token");
  }
  return accessToken.trim();
}

function normalizeInbound(inbound) {
  return {
    id: stableInboundId(inbound),
    label: String(inbound?.tag ?? inbound?.label ?? inbound?.remark ?? inbound?.name ?? inbound?.id ?? ""),
    protocol: String(inbound?.protocol ?? ""),
    network: String(inbound?.network ?? inbound?.streamSettings?.network ?? ""),
    tls: String(inbound?.tls ?? inbound?.streamSettings?.security ?? ""),
    port: inbound?.port ?? null,
    enabled: inbound?.enabled !== false
  };
}

function flattenInboundPayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === "object") {
    if (Array.isArray(payload.obj)) return payload.obj;
    if (Array.isArray(payload.data)) return payload.data;
    return Object.values(payload).flatMap((group) => (Array.isArray(group) ? group : []));
  }
  return [];
}

export async function listInbounds(panel) {
  const client = buildClient(panel);
  const accessToken = await authenticate(client);
  const response = await fetch(client.inboundsUrl, {
    headers: { authorization: `Bearer ${accessToken}` }
  });
  if (!response.ok) fail(response.status || 502, `Marzban inbounds request failed with HTTP ${response.status}`);
  const payload = await response.json();
  return flattenInboundPayload(payload).map((inbound) => normalizeInbound(inbound));
}

export const marzbanAdapter = {
  type: "marzban",
  label: "Marzban",
  capabilities: ["password-auth", "multi-inbound", "data-limit", "status-sync"],
  async health() {
    reject("health");
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
    reject("listUsers");
  },
  async createUser() {
    reject("createUser");
  },
  async deleteUser() {
    reject("deleteUser");
  },
  async syncUserTraffic() {
    reject("syncUserTraffic");
  },
  async sync() {
    reject("sync");
  }
};
