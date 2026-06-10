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

function parseNonNegativeFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function extractUsedBytes(payload) {
  const candidates = [
    payload?.used_traffic,
    payload?.usedTraffic,
    payload?.data_used,
    payload?.used,
    payload?.data?.used_traffic,
    payload?.data?.usedTraffic,
    payload?.data?.data_used,
    payload?.data?.used
  ];
  for (const candidate of candidates) {
    const value = parseNonNegativeFiniteNumber(candidate);
    if (value !== null) return value;
  }
  return null;
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

function parseSelectedInbounds(user) {
  const raw = Array.isArray(user?.inboundIds)
    ? user.inboundIds
    : typeof user?.inboundId === "string" && user.inboundId.trim()
      ? [user.inboundId.trim()]
      : [];
  const grouped = {};
  for (const item of raw) {
    const value = String(item || "").trim();
    if (!value) continue;
    const lastColon = value.lastIndexOf(":");
    const firstColon = value.indexOf(":");
    if (firstColon <= 0 || lastColon <= firstColon) continue;
    const protocol = value.slice(0, firstColon).trim();
    const tag = value.slice(firstColon + 1, lastColon).trim();
    if (!protocol || !tag) continue;
    (grouped[protocol] ||= new Set()).add(tag);
  }
  return grouped;
}

function buildUserPayload(user, { status = "active", note = "" } = {}) {
  const inboundGroups = parseSelectedInbounds(user);
  const protocols = Object.keys(inboundGroups);
  if (!protocols.length) fail(400, "At least one inbound must be selected for Marzban");
  const inbounds = {};
  const proxies = {};
  for (const protocol of protocols) {
    inbounds[protocol] = [...inboundGroups[protocol]];
    proxies[protocol] = {};
  }
  const expire = user?.expiresAt ? Math.max(0, Math.floor(new Date(user.expiresAt).getTime() / 1000)) : 0;
  const dataLimit = typeof user?.limitBytes === "number" && Number.isFinite(user.limitBytes) ? user.limitBytes : 0;
  const username = String(user?.username ?? user?.email ?? "").trim();
  if (!username) fail(400, "Marzban username is required");
  return {
    username,
    status,
    expire,
    data_limit: dataLimit > 0 ? dataLimit : 0,
    data_limit_reset_strategy: "no_reset",
    inbounds,
    proxies,
    note,
    on_hold_expire_duration: 0,
    on_hold_timeout: null,
    next_plan: {
      data_limit: 0,
      expire: 0,
      add_remaining_traffic: false,
      fire_on_either: true
    }
  };
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

export async function createUser(panel, user) {
  const client = buildClient(panel);
  const body = buildUserPayload(user);
  const accessToken = await authenticate(client);
  const response = await fetch(`${client.baseUrl}/api/user`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(body)
  });
  if (!response.ok && response.status !== 201) {
    fail(response.status || 502, `Marzban create user failed with HTTP ${response.status}`);
  }
  const payload = await response.json();
  return {
    id: payload?.id ?? payload?.data?.id ?? payload?.username ?? user?.username ?? null,
    username: payload?.username ?? payload?.data?.username ?? user?.username ?? null,
    status: payload?.status ?? payload?.data?.status ?? "active"
  };
}

export async function updateUser(panel, user, changes = {}) {
  const client = buildClient(panel);
  const merged = {
    ...user,
    ...changes,
    inboundIds: Array.isArray(changes.inboundIds) ? changes.inboundIds : user?.inboundIds,
    expiresAt: Object.prototype.hasOwnProperty.call(changes, "expiresAt") ? changes.expiresAt : user?.expiresAt,
    flow: Object.prototype.hasOwnProperty.call(changes, "flow") ? changes.flow : user?.flow,
    active: Object.prototype.hasOwnProperty.call(changes, "active") ? changes.active : user?.active
  };
  const body = buildUserPayload(merged, {
    status: merged.active === false ? "disabled" : "active",
    note: String(merged.flow ?? "")
  });
  const username = String(user?.username ?? "").trim();
  if (!username) fail(400, "Marzban username is required");
  const accessToken = await authenticate(client);
  const response = await fetch(`${client.baseUrl}/api/user/${encodeURIComponent(username)}`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(body)
  });
  if (!response.ok && response.status !== 200 && response.status !== 204) {
    fail(response.status || 502, `Marzban update user failed with HTTP ${response.status}`);
  }
  if (response.status === 204) {
    return {
      id: user?.id ?? username,
      username,
      status: body.status
    };
  }
  const payload = await response.json();
  return {
    id: payload?.id ?? payload?.data?.id ?? payload?.username ?? username,
    username: payload?.username ?? payload?.data?.username ?? username,
    status: payload?.status ?? payload?.data?.status ?? body.status
  };
}

export async function deleteUser(panel, user) {
  const client = buildClient(panel);
  const username = String(user?.username ?? "").trim();
  if (!username) fail(400, "Marzban username is required");
  const accessToken = await authenticate(client);
  const response = await fetch(`${client.baseUrl}/api/user/${encodeURIComponent(username)}`, {
    method: "DELETE",
    headers: { authorization: `Bearer ${accessToken}` }
  });
  if (response.status === 404) {
    return { ok: true, username, status: "missing" };
  }
  if (!response.ok && response.status !== 204) {
    fail(response.status || 502, `Marzban delete user failed with HTTP ${response.status}`);
  }
  return { ok: true, username, status: "deleted" };
}

export async function getUser(panel, user) {
  const client = buildClient(panel);
  const username = String(user?.username ?? "").trim();
  if (!username) fail(400, "Marzban username is required");
  const accessToken = await authenticate(client);
  const response = await fetch(`${client.baseUrl}/api/user/${encodeURIComponent(username)}`, {
    headers: { authorization: `Bearer ${accessToken}` }
  });
  if (!response.ok) {
    fail(response.status || 502, `Marzban user lookup failed with HTTP ${response.status}`);
  }
  const payload = await response.json();
  const usedBytes = extractUsedBytes(payload);
  return {
    username,
    usedBytes: usedBytes ?? (typeof user?.usedBytes === "number" && Number.isFinite(user.usedBytes) ? user.usedBytes : 0)
  };
}

export async function syncUserTraffic(panel, user) {
  return getUser(panel, user);
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
  async sync() {
    reject("sync");
  }
};
