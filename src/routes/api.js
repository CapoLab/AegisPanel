import { cpus, freemem, loadavg, totalmem, uptime } from "node:os";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { config } from "../config.js";
import { store } from "../storage/store.js";
import { adapterFor, supportedPanels } from "../adapters/registry.js";
import { hashPassword, signSession, verifyPassword, verifySession } from "../utils/security.js";
import { readJson, sendJson } from "../utils/http.js";

const loginAttempts = new Map();
const LOGIN_LIMIT = 5;
const LOGIN_WINDOW_MS = 10 * 60 * 1000;

function publicAdmin(admin) {
  const { passwordHash, ...safe } = admin;
  if (safe.validUntil == null && safe.expiresAt != null) {
    safe.validUntil = safe.expiresAt;
  }
  return safe;
}

function publicPanel(panel) {
  const { username, secret, apiKey, token, credentials, password, ...safe } = panel;
  return safe;
}

function editablePanel(panel) {
  const { secret, apiKey, token, credentials, password, ...safe } = panel;
  return safe;
}

function normalizeInboundSearchText(value) {
  if (value == null) return "";
  const normalized = String(value);
  return (typeof normalized.normalize === "function" ? normalized.normalize("NFKC") : normalized).toLowerCase();
}

function normalizePanelSubscriptionPath(value, fallback = "sub") {
  const trimmed = typeof value === "string" ? value.trim() : "";
  const normalized = trimmed.replace(/^\/+|\/+$/g, "");
  return normalized || fallback;
}

function validateHttpUrl(value, key, { allowEmpty = false } = {}) {
  if (value == null || value === "") {
    if (allowEmpty) return "";
    const error = new Error(`Missing required field: ${key}`);
    error.status = 400;
    throw error;
  }
  if (typeof value !== "string") {
    const error = new Error(`Invalid ${key}`);
    error.status = 400;
    throw error;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    if (allowEmpty) return "";
    const error = new Error(`Invalid ${key}`);
    error.status = 400;
    throw error;
  }
  try {
    const url = new URL(trimmed);
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Invalid protocol");
    return trimmed;
  } catch {
    const error = new Error(`Invalid ${key}`);
    error.status = 400;
    throw error;
  }
}

function parseOptionalNonNegativeNumber(value, key, fallback) {
  if (value == null || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    const error = new Error(`Invalid ${key}`);
    error.status = 400;
    throw error;
  }
  return parsed;
}

function isPublicSubscriptionUrl(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!trimmed) return false;
  try {
    const url = new URL(trimmed);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function buildPublicSubscriptionUrl(panel, user) {
  if (!isPublicSubscriptionUrl(panel?.subscriptionUrl)) return null;
  const prefix = panel.subscriptionUrl.trim().replace(/\/+$/, "");
  const path = typeof panel?.subscriptionPath === "string" && panel.subscriptionPath.trim()
    ? panel.subscriptionPath.trim().replace(/^\/+|\/+$/g, "")
    : "sub";
  const identifier = typeof user?.subscriptionId === "string" && user.subscriptionId.trim()
    ? user.subscriptionId.trim()
    : typeof user?.username === "string" && user.username.trim()
      ? user.username.trim()
      : "";
  if (!identifier) return null;
  return `${prefix}/${path}/${encodeURIComponent(identifier)}`;
}

function publicUser(user) {
  const safe = { ...user };
  safe.inboundMode = normalizeInboundMode(safe.inboundMode);
  if (Array.isArray(safe.inboundIds) && safe.inboundIds.length > 0) {
    safe.inboundId = preferredInboundId(safe.inboundIds, safe.inboundId);
  } else if (safe.inboundId) {
    safe.inboundId = preferredInboundId([safe.inboundId], safe.inboundId);
  }
  if (!isPublicSubscriptionUrl(safe.subscriptionUrl)) {
    safe.subscriptionUrl = null;
  }
  return safe;
}

async function hydrateSubscriptionUrlForUser(actor, user) {
  if (!user || isPublicSubscriptionUrl(user.subscriptionUrl)) {
    return user;
  }
  const panel = store.find("panels", user.panelId);
  if (!panel || panel.type !== "marzban") {
    return user;
  }
  const adapter = adapterFor(panel.type);
  if (!adapter || typeof adapter.getUser !== "function") {
    return user;
  }
  try {
    const remoteUser = await adapter.getUser(panel, user);
    const subscriptionUrl = isPublicSubscriptionUrl(remoteUser?.subscriptionUrl)
      ? remoteUser.subscriptionUrl.trim()
      : buildPublicSubscriptionUrl(panel, remoteUser ?? user);
    if (!subscriptionUrl) return user;
    const patch = { subscriptionUrl };
    const subscriptionId = typeof remoteUser?.subscriptionId === "string" ? remoteUser.subscriptionId.trim() : "";
    if (subscriptionId && !user.subscriptionId) patch.subscriptionId = subscriptionId;
    return store.update("users", user.id, patch) || { ...user, ...patch };
  } catch {
    const subscriptionUrl = buildPublicSubscriptionUrl(panel, user);
    if (!subscriptionUrl) return user;
    const patch = { subscriptionUrl };
    return store.update("users", user.id, patch) || { ...user, ...patch };
  }
}

function normalizeInboundMode(value) {
  return value === "all" ? "all" : "custom";
}

function requiredString(body, key) {
  const value = body?.[key];
  if (typeof value !== "string" || !value.trim()) {
    const error = new Error(`Missing required field: ${key}`);
    error.status = 400;
    throw error;
  }
  return value.trim();
}

function loginRateKey(req) {
  return req.socket?.remoteAddress || req.connection?.remoteAddress || "unknown";
}

function getLoginPenalty(req) {
  const key = loginRateKey(req);
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (!entry || now - entry.firstAttemptAt >= LOGIN_WINDOW_MS) {
    const fresh = { count: 0, firstAttemptAt: now };
    loginAttempts.set(key, fresh);
    return fresh;
  }
  return entry;
}

function recordFailedLogin(req) {
  const entry = getLoginPenalty(req);
  entry.count += 1;
  if (entry.count > LOGIN_LIMIT) {
    const error = new Error("Too many failed login attempts. Please try again later.");
    error.status = 429;
    throw error;
  }
}

function clearLoginPenalty(req) {
  loginAttempts.delete(loginRateKey(req));
}

function canDeleteAdmin(actor, targetAdmin, superadminCount) {
  if (!targetAdmin) {
    return { status: 404, error: "Admin not found" };
  }
  if (targetAdmin.id === actor.id) {
    return { status: 400, error: "You cannot delete your own account" };
  }
  if (targetAdmin.role === "superadmin" && superadminCount <= 1) {
    return { status: 409, error: "At least one superadmin must remain" };
  }
  return null;
}

function requireAuth(req, role) {
  const session = req.headers["x-aegis-session"] || "";
  const payload = verifySession(session, config.sessionSecret);
  if (!payload) {
    const error = new Error("Authentication required");
    error.status = 401;
    throw error;
  }
  const admin = store.list("admins").find((item) => item.id === payload.sub && item.active);
  if (!admin) {
    const error = new Error("Account is disabled or missing");
    error.status = 401;
    throw error;
  }
  if (role && admin.role !== role && admin.role !== "superadmin") {
    const error = new Error("Insufficient permissions");
    error.status = 403;
    throw error;
  }
  return admin;
}

function scopedUsers(actor) {
  if (actor.role === "superadmin") return store.list("users");
  return store.list("users").filter((user) => user.ownerAdminId === actor.id);
}

function scopedPanels(actor) {
  if (actor.role === "superadmin") return store.list("panels");
  return store.list("panels").filter((panel) => panel.id === actor.panelId);
}

function finiteQuotaBytes(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function finiteDateMs(value) {
  if (!value) return null;
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? time : null;
}

function parseNonNegativeFiniteBytes(value, key, { allowMissing = false, defaultValue = 0 } = {}) {
  if (value === undefined) {
    if (allowMissing) return defaultValue;
    const error = new Error(`Missing required field: ${key}`);
    error.status = 400;
    throw error;
  }
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    const error = new Error(`Invalid ${key}`);
    error.status = 400;
    throw error;
  }
  return value;
}

function isDummyOrMetricsInboundId(value) {
  return /dummy|metrics/i.test(normalizeInboundSearchText(value));
}

function preferredInboundId(inboundIds, fallbackInboundId = "") {
  const selected = Array.isArray(inboundIds) ? inboundIds.filter((value) => typeof value === "string" && value.trim()) : [];
  const real = selected.find((value) => !isDummyOrMetricsInboundId(value));
  return real || selected[0] || (typeof fallbackInboundId === "string" && fallbackInboundId.trim()) || "default";
}

function selectedInboundIdsFromBody(body, fallback = []) {
  if (Array.isArray(body?.inboundIds)) {
    const selected = body.inboundIds.filter((value) => typeof value === "string" && value.trim());
    if (selected.length > 0) return selected;
  }
  if (typeof body?.inboundId === "string" && body.inboundId.trim()) {
    return [body.inboundId.trim()];
  }
  return Array.isArray(fallback) ? fallback.filter((value) => typeof value === "string" && value.trim()) : [];
}

function normalizeIsoDateOrNull(value, key, { allowPast = false } = {}) {
  if (value == null || value === "") return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    const error = new Error(`Invalid ${key}`);
    error.status = 400;
    throw error;
  }
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const expiryDay = new Date(date);
  expiryDay.setHours(0, 0, 0, 0);
  if (!allowPast && expiryDay < today) {
    const error = new Error("Expiry date cannot be in the past.");
    error.status = 400;
    throw error;
  }
  return date.toISOString();
}

function enforceResellerValidity(actor, expiresAt) {
  if (actor.role !== "admin") return;
  const validUntilMs = finiteDateMs(actor.validUntil ?? actor.expiresAt);
  if (validUntilMs === null) return;
  if (Date.now() > validUntilMs) {
    const error = new Error("Reseller validity has expired.");
    error.status = 400;
    throw error;
  }
  if (expiresAt == null || expiresAt === "") {
    const error = new Error("VPN account expiry is required for resellers with a validity limit.");
    error.status = 400;
    throw error;
  }
  const expiresAtMs = finiteDateMs(expiresAt);
  if (expiresAtMs === null || expiresAtMs > validUntilMs) {
    const error = new Error("VPN account expiry cannot exceed reseller validity.");
    error.status = 400;
    throw error;
  }
}

function dashboard(actor) {
  const panels = scopedPanels(actor);
  const users = scopedUsers(actor);
  const admins = actor.role === "superadmin" ? store.list("admins") : [actor];
  const usedBytes = users.reduce((sum, user) => sum + Number(user.usedBytes || 0), 0);
  const limitBytes = users.reduce((sum, user) => sum + Number(user.limitBytes || 0), 0);
  return {
    actor: publicAdmin(actor),
    totals: {
      admins: admins.length,
      panels: panels.length,
      users: users.length,
      activeUsers: users.filter((user) => user.active).length,
      usedBytes,
      limitBytes
    },
    panels: panels.map(publicPanel),
    recentEvents: store.list("trafficEvents").slice(0, 25),
    news: store.list("news").slice(0, 5),
    distribution: store.state.distribution
  };
}

function match(pathname, pattern) {
  const pathParts = pathname.split("/").filter(Boolean);
  const patternParts = pattern.split("/").filter(Boolean);
  if (pathParts.length !== patternParts.length) return null;
  const params = {};
  for (let i = 0; i < patternParts.length; i += 1) {
    if (patternParts[i].startsWith(":")) params[patternParts[i].slice(1)] = decodeURIComponent(pathParts[i]);
    else if (patternParts[i] !== pathParts[i]) return null;
  }
  return params;
}

export { canDeleteAdmin };

export async function handleApi(req, res, route) {
  const { method, pathname } = route;

  if (method === "GET" && pathname === "/api/health") {
    return sendJson(res, 200, { ok: true, product: "AegisPanel", uptime: process.uptime() });
  }

  if (method === "GET" && pathname === "/api/meta") {
    return sendJson(res, 200, {
      ok: true,
      product: "AegisPanel",
      panelTypes: supportedPanels(),
      publicUrl: config.publicUrl
    });
  }

  if (method === "GET" && pathname === "/api/community") {
    return sendJson(res, 200, { ok: true, data: store.state.distribution });
  }

  if (method === "POST" && pathname === "/api/auth/login") {
    const body = await readJson(req);
    const username = requiredString(body, "username");
    const password = requiredString(body, "password");
    const admin = store.list("admins").find((item) => item.username === username);
    if (!admin || !admin.active || !verifyPassword(password, admin.passwordHash)) {
      recordFailedLogin(req);
      return sendJson(res, 401, { ok: false, error: "Invalid credentials" });
    }
    clearLoginPenalty(req);
    const session = signSession({ sub: admin.id, username: admin.username, role: admin.role }, config.sessionSecret);
    store.audit(admin, "auth.login", admin.id);
    return sendJson(res, 200, { ok: true, session, admin: publicAdmin(admin) });
  }

  const actor = requireAuth(req);

  if (method === "GET" && pathname === "/api/dashboard") {
    return sendJson(res, 200, { ok: true, data: dashboard(actor) });
  }

  if (method === "GET" && pathname === "/api/superadmin/admins") {
    requireAuth(req, "superadmin");
    return sendJson(res, 200, { ok: true, data: store.list("admins").map(publicAdmin) });
  }

  if (method === "POST" && pathname === "/api/superadmin/admins") {
    const superadmin = requireAuth(req, "superadmin");
    const body = await readJson(req);
    const username = requiredString(body, "username");
    const password = requiredString(body, "password");
    const validity = normalizeIsoDateOrNull(body.validUntil ?? body.expiresAt, "validUntil", { allowPast: true });
    if (store.list("admins").some((admin) => admin.username === username)) {
      return sendJson(res, 409, { ok: false, error: "Username already exists" });
    }
    const admin = store.insert("admins", {
      username,
      passwordHash: hashPassword(password),
      role: body.role || "admin",
      active: body.active !== false,
      panelId: body.panelId || null,
      inboundIds: body.inboundIds || [],
      trafficLimitBytes: body.trafficLimitBytes ?? null,
      trafficRemainingBytes: body.trafficLimitBytes ?? null,
      updateReturnTraffic: body.updateReturnTraffic !== false,
      deleteReturnTraffic: body.deleteReturnTraffic !== false,
      validUntil: validity,
      expiresAt: validity
    });
    store.audit(superadmin, "admin.create", admin.id, { username: admin.username });
    return sendJson(res, 201, { ok: true, data: publicAdmin(admin) });
  }

  const adminId = match(pathname, "/api/superadmin/admins/:id");
  if (adminId && method === "PUT") {
    const superadmin = requireAuth(req, "superadmin");
    const body = await readJson(req);
    const patch = { ...body };
    if (body.password) patch.passwordHash = hashPassword(body.password);
    delete patch.password;
    const admin = store.update("admins", adminId.id, patch);
    if (!admin) return sendJson(res, 404, { ok: false, error: "Admin not found" });
    store.audit(superadmin, "admin.update", admin.id);
    return sendJson(res, 200, { ok: true, data: publicAdmin(admin) });
  }

  if (adminId && method === "DELETE") {
    const superadmin = requireAuth(req, "superadmin");
    const targetAdmin = store.find("admins", adminId.id);
    const superadminCount = store.list("admins").filter((admin) => admin.role === "superadmin" && admin.active).length;
    const blocked = canDeleteAdmin(superadmin, targetAdmin, superadminCount);
    if (blocked) return sendJson(res, blocked.status, { ok: false, error: blocked.error });
    const removed = store.remove("admins", adminId.id);
    store.audit(superadmin, "admin.delete", adminId.id);
    return sendJson(res, removed ? 200 : 404, { ok: removed });
  }

  if (method === "GET" && pathname === "/api/superadmin/panels") {
    requireAuth(req, "superadmin");
    return sendJson(res, 200, { ok: true, data: store.list("panels").map(publicPanel) });
  }

  if (method === "POST" && pathname === "/api/superadmin/panels") {
    const superadmin = requireAuth(req, "superadmin");
    const body = await readJson(req);
    const name = requiredString(body, "name");
    const type = requiredString(body, "type");
    const url = validateHttpUrl(requiredString(body, "url"), "url");
    if (!adapterFor(type)) return sendJson(res, 400, { ok: false, error: "Unsupported panel type" });
    const panel = store.insert("panels", {
      name,
      type,
      url,
      subscriptionUrl: validateHttpUrl(body.subscriptionUrl ?? "", "subscriptionUrl", { allowEmpty: true }),
      subscriptionPath: normalizePanelSubscriptionPath(body.subscriptionPath),
      username: body.username || "",
      secret: body.secret || "",
      apiKey: body.apiKey || "",
      active: body.active !== false,
      syncIntervalSeconds: parseOptionalNonNegativeNumber(body.syncIntervalSeconds, "syncIntervalSeconds", 300),
      lastSyncAt: null
    });
    store.audit(superadmin, "panel.create", panel.id, { name: panel.name, type: panel.type });
    return sendJson(res, 201, { ok: true, data: publicPanel(panel) });
  }

  const panelId = match(pathname, "/api/superadmin/panels/:id");
  if (panelId && method === "GET") {
    requireAuth(req, "superadmin");
    const panel = store.find("panels", panelId.id);
    if (!panel) return sendJson(res, 404, { ok: false, error: "Panel not found" });
    return sendJson(res, 200, { ok: true, data: editablePanel(panel) });
  }
  if (panelId && method === "PUT") {
    const superadmin = requireAuth(req, "superadmin");
    const body = await readJson(req);
    const panel = store.find("panels", panelId.id);
    if (!panel) return sendJson(res, 404, { ok: false, error: "Panel not found" });
    if (Object.prototype.hasOwnProperty.call(body, "type") && body.type !== panel.type) {
      return sendJson(res, 400, { ok: false, error: "Panel type cannot be changed" });
    }
    const patch = {};
    if (Object.prototype.hasOwnProperty.call(body, "name")) patch.name = requiredString(body, "name");
    if (Object.prototype.hasOwnProperty.call(body, "url")) patch.url = validateHttpUrl(body.url, "url");
    if (Object.prototype.hasOwnProperty.call(body, "subscriptionUrl")) {
      patch.subscriptionUrl = validateHttpUrl(body.subscriptionUrl, "subscriptionUrl", { allowEmpty: true });
    }
    if (Object.prototype.hasOwnProperty.call(body, "subscriptionPath")) {
      patch.subscriptionPath = normalizePanelSubscriptionPath(body.subscriptionPath);
    }
    if (Object.prototype.hasOwnProperty.call(body, "username")) patch.username = requiredString(body, "username");
    const credentialValue = [body.secret, body.password, body.apiKey].find((value) => typeof value === "string" && value.trim());
    if (credentialValue) patch.secret = credentialValue.trim();
    if (Object.prototype.hasOwnProperty.call(body, "active")) patch.active = body.active !== false;
    if (Object.prototype.hasOwnProperty.call(body, "syncIntervalSeconds")) {
      patch.syncIntervalSeconds = parseOptionalNonNegativeNumber(body.syncIntervalSeconds, "syncIntervalSeconds", panel.syncIntervalSeconds ?? 300);
    }
    const updated = store.update("panels", panelId.id, patch);
    if (!updated) return sendJson(res, 404, { ok: false, error: "Panel not found" });
    store.audit(superadmin, "panel.update", panel.id);
    return sendJson(res, 200, { ok: true, data: publicPanel(updated) });
  }

  if (panelId && method === "DELETE") {
    const superadmin = requireAuth(req, "superadmin");
    const removed = store.remove("panels", panelId.id);
    store.audit(superadmin, "panel.delete", panelId.id);
    return sendJson(res, removed ? 200 : 404, { ok: removed });
  }

  const inbounds = match(pathname, "/api/superadmin/panels/:id/inbounds");
  if (inbounds && method === "GET") {
    requireAuth(req, "superadmin");
    const panel = store.find("panels", inbounds.id);
    if (!panel) return sendJson(res, 404, { ok: false, error: "Panel not found" });
    if (panel.type !== "marzban") {
      return sendJson(res, 501, { ok: false, error: "Real inbounds are only implemented for Marzban panels" });
    }
    const adapter = adapterFor(panel.type);
    if (!adapter || typeof adapter.listInbounds !== "function") {
      return sendJson(res, 501, { ok: false, error: "Real inbounds are not available for this panel type yet" });
    }
    return sendJson(res, 200, { ok: true, data: await adapter.listInbounds(panel) });
  }

  const scopedInbounds = match(pathname, "/api/admin/panels/:id/inbounds");
  if (scopedInbounds && method === "GET") {
    requireAuth(req, "superadmin");
    const panel = store.find("panels", scopedInbounds.id);
    if (!panel) return sendJson(res, 404, { ok: false, error: "Panel not found" });
    if (panel.type !== "marzban") {
      return sendJson(res, 501, { ok: false, error: "Real inbounds are only implemented for Marzban panels" });
    }
    const adapter = adapterFor(panel.type);
    if (!adapter || typeof adapter.listInbounds !== "function") {
      return sendJson(res, 501, { ok: false, error: "Real inbounds are not available for this panel type yet" });
    }
    return sendJson(res, 200, { ok: true, data: await adapter.listInbounds(panel) });
  }

  const syncPanel = match(pathname, "/api/panels/:id/sync");
  if (syncPanel && method === "POST") {
    const panel = scopedPanels(actor).find((item) => item.id === syncPanel.id);
    if (!panel) return sendJson(res, 404, { ok: false, error: "Panel not found" });
    const adapter = adapterFor(panel.type);
    const result = await adapter.sync(panel, store.list("users"));
    store.update("panels", panel.id, { lastSyncAt: new Date().toISOString() });
    store.audit(actor, "panel.sync", panel.id, result);
    return sendJson(res, 200, { ok: true, data: result });
  }

  if (method === "GET" && pathname === "/api/admin/users") {
    const users = [];
    for (const user of scopedUsers(actor)) {
      users.push(await hydrateSubscriptionUrlForUser(actor, user));
    }
    return sendJson(res, 200, { ok: true, data: users.map(publicUser) });
  }

  if (method === "POST" && pathname === "/api/admin/users") {
    const body = await readJson(req);
    const username = requiredString(body, "username");
    const effectivePanelId = actor.role === "superadmin" ? requiredString(body, "panelId") : actor.panelId;
    if (actor.role !== "superadmin" && !effectivePanelId) {
      return sendJson(res, 400, { ok: false, error: "No panel assigned to this reseller." });
    }
    if (actor.role === "admin" && Object.prototype.hasOwnProperty.call(body, "panelId")) {
      return sendJson(res, 400, { ok: false, error: "Cannot set panelId" });
    }
    const panel = store.find("panels", effectivePanelId);
    if (!panel) return sendJson(res, 400, { ok: false, error: "Valid panelId is required" });
    const expiresAt = Object.prototype.hasOwnProperty.call(body, "expiresAt") ? normalizeIsoDateOrNull(body.expiresAt, "expiresAt") : null;
    enforceResellerValidity(actor, expiresAt);
    const requestedLimitBytes = Object.prototype.hasOwnProperty.call(body, "limitBytes")
      ? parseNonNegativeFiniteBytes(body.limitBytes, "limitBytes")
      : 0;
    const requestedUsedBytes = Object.prototype.hasOwnProperty.call(body, "usedBytes")
      ? parseNonNegativeFiniteBytes(body.usedBytes, "usedBytes")
      : 0;
    const owner = store.find("admins", actor.role === "superadmin" ? body.ownerAdminId || actor.id : actor.id);
    if (!owner) return sendJson(res, 400, { ok: false, error: "Valid ownerAdminId is required" });
    const adapter = adapterFor(panel.type);
    const resellerMarzbanInbounds = actor.role === "admin" && panel.type === "marzban";
    let resolvedInboundIds = selectedInboundIdsFromBody(body);
    if (resellerMarzbanInbounds) {
      if (!adapter || typeof adapter.listInbounds !== "function") {
        return sendJson(res, 501, { ok: false, error: "Real inbound defaults are not available for this panel type yet" });
      }
      const rows = await adapter.listInbounds(panel);
      resolvedInboundIds = rows.map((row) => row.id).filter((value) => typeof value === "string" && value.trim());
    }
    if (resellerMarzbanInbounds && resolvedInboundIds.length === 0) {
      return sendJson(res, 400, { ok: false, error: "No Marzban inbounds available for this panel" });
    }
    const ownerRemainingBytes = finiteQuotaBytes(owner?.trafficRemainingBytes);
    if (requestedLimitBytes > 0 && ownerRemainingBytes !== null) {
      if (ownerRemainingBytes < requestedLimitBytes) {
        return sendJson(res, 409, { ok: false, error: "Insufficient traffic quota" });
      }
      store.update("admins", owner.id, {
        trafficRemainingBytes: ownerRemainingBytes - requestedLimitBytes
      });
    }
    const primaryInboundId = preferredInboundId(resolvedInboundIds, body.inboundId);
    const userRecord = {
      ownerAdminId: owner.id,
      panelId: panel.id,
      username,
      uuid: body.uuid || null,
      subscriptionId: body.subscriptionId || null,
      subscriptionUrl: null,
      inboundId: primaryInboundId,
      inboundMode: resellerMarzbanInbounds ? "all" : normalizeInboundMode(body.inboundMode),
      flow: actor.role === "superadmin" ? body.flow || "" : "",
      note: body.note || "",
      active: body.active !== false,
      limitBytes: requestedLimitBytes,
      usedBytes: requestedUsedBytes,
      reservedBytes: requestedLimitBytes,
      expiresAt
    };
    if (resellerMarzbanInbounds) {
      userRecord.inboundIds = resolvedInboundIds;
    } else if (resolvedInboundIds.length > 0) {
      userRecord.inboundIds = resolvedInboundIds;
    }
    const user = store.insert("users", {
      ...userRecord
    });
    let createdUser = user;
    if (panel.type === "marzban") {
      if (!adapter || typeof adapter.createUser !== "function") {
        if (requestedLimitBytes > 0 && ownerRemainingBytes !== null) {
          store.update("admins", owner.id, {
            trafficRemainingBytes: ownerRemainingBytes
          });
        }
        store.remove("users", user.id);
        return sendJson(res, 501, { ok: false, error: "Real user creation is not available for this panel type yet" });
      }
      try {
        const remoteUser = await adapter.createUser(panel, {
          ...user,
          inboundIds: userRecord.inboundIds || [],
          expiresAt
        });
        let subscriptionUrl = typeof remoteUser?.subscriptionUrl === "string" ? remoteUser.subscriptionUrl.trim() : "";
        if (!subscriptionUrl && typeof adapter.getUser === "function") {
          try {
            const refreshedUser = await adapter.getUser(panel, {
              username: remoteUser?.username ?? user.username,
              usedBytes: user.usedBytes,
              subscriptionId: remoteUser?.subscriptionId ?? user.subscriptionId
            });
            subscriptionUrl = typeof refreshedUser?.subscriptionUrl === "string" ? refreshedUser.subscriptionUrl.trim() : "";
          } catch {
            subscriptionUrl = "";
          }
        }
        const patch = {};
        const remoteSubscriptionId = typeof remoteUser?.subscriptionId === "string" ? remoteUser.subscriptionId.trim() : "";
        if (remoteSubscriptionId && !user.subscriptionId) patch.subscriptionId = remoteSubscriptionId;
        if (subscriptionUrl) {
          patch.subscriptionUrl = subscriptionUrl;
        }
        if (Object.keys(patch).length) {
          createdUser = store.update("users", user.id, patch) || { ...user, ...patch };
        }
      } catch (error) {
        if (requestedLimitBytes > 0 && ownerRemainingBytes !== null) {
          store.update("admins", owner.id, {
            trafficRemainingBytes: ownerRemainingBytes
          });
        }
        store.remove("users", user.id);
        return sendJson(res, error.status || 502, {
          ok: false,
          error: error.message || "Marzban user creation failed"
        });
      }
    }
    store.audit(actor, "user.create", user.id, { username: user.username });
    return sendJson(res, 201, { ok: true, data: publicUser(createdUser) });
  }

  const userId = match(pathname, "/api/admin/users/:id");
  if (userId && method === "PUT") {
    const user = scopedUsers(actor).find((item) => item.id === userId.id);
    if (!user) return sendJson(res, 404, { ok: false, error: "User not found" });
    const body = await readJson(req);
    const blockedField = (actor.role === "admin"
      ? ["username", "panelId", "ownerAdminId", "usedBytes", "reservedBytes", "inboundId", "inboundIds", "inboundMode", "flow", "uuid", "subscriptionId"]
      : ["username", "panelId", "ownerAdminId", "usedBytes", "reservedBytes"]
    ).find((field) => Object.prototype.hasOwnProperty.call(body, field));
    if (blockedField) {
      return sendJson(res, 400, { ok: false, error: `Cannot update ${blockedField}` });
    }
    const panel = store.find("panels", user.panelId);
    const inboundIds = selectedInboundIdsFromBody(body, user.inboundIds || [user.inboundId]);
    const primaryInboundId = preferredInboundId(inboundIds, body.inboundId ?? user.inboundId);
    const oldReservedBytes = Math.max(0, finiteQuotaBytes(user.reservedBytes) ?? finiteQuotaBytes(user.limitBytes) ?? 0);
    const oldLimitBytes = Math.max(0, finiteQuotaBytes(user.limitBytes) ?? 0);
    const usedBytes = Math.max(0, finiteQuotaBytes(user.usedBytes) ?? 0);
    const limitBytesChanged = Object.prototype.hasOwnProperty.call(body, "limitBytes");
    const requestedLimitBytes = limitBytesChanged ? parseNonNegativeFiniteBytes(body.limitBytes, "limitBytes") : oldLimitBytes;
    if (limitBytesChanged && requestedLimitBytes < usedBytes) {
      return sendJson(res, 400, { ok: false, error: "Traffic limit cannot be lower than used traffic." });
    }
    const limitDelta = limitBytesChanged ? requestedLimitBytes - oldReservedBytes : 0;
    const owner = store.find("admins", user.ownerAdminId);
    const ownerRemainingBytes = finiteQuotaBytes(owner?.trafficRemainingBytes);
    if (limitDelta > 0 && ownerRemainingBytes !== null && ownerRemainingBytes < limitDelta) {
      return sendJson(res, 409, { ok: false, error: "Insufficient traffic quota" });
    }
    const updatePatch = actor.role === "admin"
      ? {
          ...(limitBytesChanged ? { limitBytes: requestedLimitBytes, reservedBytes: requestedLimitBytes } : {}),
          expiresAt: Object.prototype.hasOwnProperty.call(body, "expiresAt") ? normalizeIsoDateOrNull(body.expiresAt, "expiresAt") : user.expiresAt || null,
          note: Object.prototype.hasOwnProperty.call(body, "note") ? body.note || "" : user.note || "",
          active: Object.prototype.hasOwnProperty.call(body, "active") ? body.active !== false : user.active !== false
        }
      : {
          ...body,
          inboundId: primaryInboundId,
          inboundMode: normalizeInboundMode(body.inboundMode ?? user.inboundMode),
          ...(limitBytesChanged ? { limitBytes: requestedLimitBytes, reservedBytes: requestedLimitBytes } : {}),
          expiresAt: Object.prototype.hasOwnProperty.call(body, "expiresAt") ? normalizeIsoDateOrNull(body.expiresAt, "expiresAt") : user.expiresAt || null,
          flow: Object.prototype.hasOwnProperty.call(body, "flow") ? body.flow || "" : user.flow || "",
          note: Object.prototype.hasOwnProperty.call(body, "note") ? body.note || "" : user.note || "",
          active: Object.prototype.hasOwnProperty.call(body, "active") ? body.active !== false : user.active !== false
        };
    if (actor.role !== "admin") {
      if (inboundIds.length > 0) {
        updatePatch.inboundIds = inboundIds;
      } else {
        delete updatePatch.inboundIds;
      }
      delete updatePatch.username;
      delete updatePatch.panelId;
      delete updatePatch.ownerAdminId;
      delete updatePatch.usedBytes;
    }
    if (panel?.type === "marzban") {
      const adapter = adapterFor(panel.type);
      if (!adapter || typeof adapter.updateUser !== "function") {
        return sendJson(res, 501, { ok: false, error: "Real user update is not available for this panel type yet" });
      }
      try {
        await adapter.updateUser(panel, user, updatePatch);
      } catch (error) {
        return sendJson(res, error.status || 502, {
          ok: false,
          error: error.message || "Marzban user update failed"
        });
      }
    }
    if (limitBytesChanged && limitDelta !== 0 && ownerRemainingBytes !== null) {
      const nextRemaining = ownerRemainingBytes + (limitDelta < 0 ? Math.abs(limitDelta) : -limitDelta);
      store.update("admins", owner.id, {
        trafficRemainingBytes: nextRemaining
      });
    }
    const updated = store.update("users", user.id, updatePatch);
    store.audit(actor, "user.update", user.id);
    return sendJson(res, 200, { ok: true, data: publicUser(updated) });
  }

  const userTrafficSyncId = match(pathname, "/api/admin/users/:id/sync-traffic");
  if (userTrafficSyncId && method === "POST") {
    const user = scopedUsers(actor).find((item) => item.id === userTrafficSyncId.id);
    if (!user) return sendJson(res, 404, { ok: false, error: "User not found" });
    const panel = store.find("panels", user.panelId);
    if (!panel) return sendJson(res, 404, { ok: false, error: "Panel not found" });
    if (panel.type !== "marzban") {
      return sendJson(res, 501, { ok: false, error: "Traffic sync is only implemented for Marzban panels" });
    }
    const adapter = adapterFor(panel.type);
    if (!adapter || typeof adapter.syncUserTraffic !== "function") {
      return sendJson(res, 501, { ok: false, error: "Single-user traffic sync is not available for this panel type yet" });
    }
    try {
      const result = await adapter.syncUserTraffic(panel, user);
      const usedBytes = finiteQuotaBytes(result?.usedBytes);
      const patch = {};
      if (usedBytes !== null) patch.usedBytes = usedBytes;
      const subscriptionUrl = typeof result?.subscriptionUrl === "string" ? result.subscriptionUrl.trim() : "";
      if (subscriptionUrl) {
        patch.subscriptionUrl = subscriptionUrl;
      }
      const subscriptionId = typeof result?.subscriptionId === "string" ? result.subscriptionId.trim() : "";
      if (subscriptionId && !user.subscriptionId) {
        patch.subscriptionId = subscriptionId;
      }
      const updated = Object.keys(patch).length ? store.update("users", user.id, patch) : user;
      store.audit(actor, "user.syncTraffic", user.id, { username: user.username, usedBytes: updated.usedBytes });
      return sendJson(res, 200, { ok: true, data: publicUser(updated) });
    } catch (error) {
      return sendJson(res, error.status || 502, {
        ok: false,
        error: error.message || "Marzban traffic sync failed"
      });
    }
  }

  if (userId && method === "DELETE") {
    const user = scopedUsers(actor).find((item) => item.id === userId.id);
    if (!user) return sendJson(res, 404, { ok: false, error: "User not found" });
    const panel = store.find("panels", user.panelId);
    let usedBytesForReturn = finiteQuotaBytes(user.usedBytes) ?? 0;
    if (panel?.type === "marzban") {
      const adapter = adapterFor(panel.type);
      if (!adapter || typeof adapter.deleteUser !== "function" || typeof adapter.getUser !== "function") {
        return sendJson(res, 501, { ok: false, error: "Real user deletion is not available for this panel type yet" });
      }
      try {
        const remoteUser = await adapter.getUser(panel, user);
        usedBytesForReturn = finiteQuotaBytes(remoteUser?.usedBytes) ?? usedBytesForReturn;
      } catch (error) {
        return sendJson(res, error.status || 502, {
          ok: false,
          error: error.message || "Marzban user lookup failed"
        });
      }
      try {
        await adapter.deleteUser(panel, user);
      } catch (error) {
        return sendJson(res, error.status || 502, {
          ok: false,
          error: error.message || "Marzban user deletion failed"
        });
      }
    }
    const owner = store.find("admins", user.ownerAdminId);
    const ownerRemainingBytes = finiteQuotaBytes(owner?.trafficRemainingBytes);
    const limitBytes = finiteQuotaBytes(user.limitBytes) ?? 0;
    const usedBytes = usedBytesForReturn;
    const reservedBytes = finiteQuotaBytes(user.reservedBytes) ?? limitBytes;
    const returned = Math.min(Math.max(limitBytes - usedBytes, 0), reservedBytes);
    if (owner?.deleteReturnTraffic && ownerRemainingBytes !== null && returned > 0) {
      store.update("admins", owner.id, {
        trafficRemainingBytes: ownerRemainingBytes + returned
      });
      store.state.trafficEvents.unshift({
        id: `evt_${Date.now()}`,
        userId: user.id,
        adminId: owner.id,
        type: "return-on-delete",
        bytes: returned,
        createdAt: new Date().toISOString()
      });
    }
    const removed = store.remove("users", user.id);
    store.audit(actor, "user.delete", user.id);
    return sendJson(res, 200, { ok: removed });
  }

  if (method === "GET" && pathname === "/api/superadmin/backup") {
    requireAuth(req, "superadmin");
    return sendJson(res, 200, {
      ok: true,
      data: {
        ...store.state,
        panels: store.list("panels").map(publicPanel)
      }
    });
  }

  if (method === "GET" && pathname === "/api/superadmin/logs") {
    requireAuth(req, "superadmin");
    return sendJson(res, 200, { ok: true, data: store.list("auditLogs") });
  }

  if (method === "GET" && pathname === "/api/superadmin/system") {
    requireAuth(req, "superadmin");
    return sendJson(res, 200, {
      ok: true,
      data: {
        uptimeSeconds: uptime(),
        appUptimeSeconds: process.uptime(),
        loadAverage: loadavg(),
        cpuCount: cpus().length,
        memory: { free: freemem(), total: totalmem() }
      }
    });
  }

  if (method === "GET" && pathname === "/api/superadmin/news") {
    requireAuth(req, "superadmin");
    return sendJson(res, 200, { ok: true, data: store.list("news") });
  }

  if (method === "POST" && pathname === "/api/superadmin/news") {
    const superadmin = requireAuth(req, "superadmin");
    const news = store.insert("news", await readJson(req));
    store.audit(superadmin, "news.create", news.id);
    return sendJson(res, 201, { ok: true, data: news });
  }

  if (method === "GET" && pathname === "/api/version") {
    const pkg = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8"));
    return sendJson(res, 200, { ok: true, data: { version: pkg.version, name: pkg.name } });
  }

  return false;
}
