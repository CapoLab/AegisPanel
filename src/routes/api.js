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
  return safe;
}

function publicPanel(panel) {
  const { username, secret, apiKey, token, credentials, password, ...safe } = panel;
  return safe;
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
      expiresAt: body.expiresAt || null
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
    const url = requiredString(body, "url");
    if (!adapterFor(type)) return sendJson(res, 400, { ok: false, error: "Unsupported panel type" });
    const panel = store.insert("panels", {
      name,
      type,
      url,
      subscriptionUrl: body.subscriptionUrl || "",
      username: body.username || "",
      secret: body.secret || "",
      apiKey: body.apiKey || "",
      active: body.active !== false,
      syncIntervalSeconds: Number(body.syncIntervalSeconds || 300),
      lastSyncAt: null
    });
    store.audit(superadmin, "panel.create", panel.id, { name: panel.name, type: panel.type });
    return sendJson(res, 201, { ok: true, data: publicPanel(panel) });
  }

  const panelId = match(pathname, "/api/superadmin/panels/:id");
  if (panelId && method === "PUT") {
    const superadmin = requireAuth(req, "superadmin");
    const panel = store.update("panels", panelId.id, await readJson(req));
    if (!panel) return sendJson(res, 404, { ok: false, error: "Panel not found" });
    store.audit(superadmin, "panel.update", panel.id);
    return sendJson(res, 200, { ok: true, data: publicPanel(panel) });
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
    const adapter = adapterFor(panel.type);
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
    return sendJson(res, 200, { ok: true, data: scopedUsers(actor) });
  }

  if (method === "POST" && pathname === "/api/admin/users") {
    const body = await readJson(req);
    const username = requiredString(body, "username");
    const panelIdRaw = requiredString(body, "panelId");
    const panelIdValue = actor.role === "superadmin" ? panelIdRaw : actor.panelId;
    const panel = store.find("panels", panelIdValue);
    if (!panel) return sendJson(res, 400, { ok: false, error: "Valid panelId is required" });
    const requestedLimitBytes = Object.prototype.hasOwnProperty.call(body, "limitBytes")
      ? parseNonNegativeFiniteBytes(body.limitBytes, "limitBytes")
      : 0;
    const requestedUsedBytes = Object.prototype.hasOwnProperty.call(body, "usedBytes")
      ? parseNonNegativeFiniteBytes(body.usedBytes, "usedBytes")
      : 0;
    const owner = store.find("admins", actor.role === "superadmin" ? body.ownerAdminId || actor.id : actor.id);
    if (!owner) return sendJson(res, 400, { ok: false, error: "Valid ownerAdminId is required" });
    const ownerRemainingBytes = finiteQuotaBytes(owner?.trafficRemainingBytes);
    if (requestedLimitBytes > 0 && ownerRemainingBytes !== null) {
      if (ownerRemainingBytes < requestedLimitBytes) {
        return sendJson(res, 409, { ok: false, error: "Insufficient traffic quota" });
      }
      store.update("admins", owner.id, {
        trafficRemainingBytes: ownerRemainingBytes - requestedLimitBytes
      });
    }
    const user = store.insert("users", {
      ownerAdminId: owner.id,
      panelId: panel.id,
      username,
      uuid: body.uuid || null,
      subscriptionId: body.subscriptionId || null,
      inboundId: body.inboundId || "default",
      flow: body.flow || "",
      active: body.active !== false,
      limitBytes: requestedLimitBytes,
      usedBytes: requestedUsedBytes,
      reservedBytes: requestedLimitBytes,
      expiresAt: body.expiresAt || null
    });
    store.audit(actor, "user.create", user.id, { username: user.username });
    return sendJson(res, 201, { ok: true, data: user });
  }

  const userId = match(pathname, "/api/admin/users/:id");
  if (userId && method === "PUT") {
    const user = scopedUsers(actor).find((item) => item.id === userId.id);
    if (!user) return sendJson(res, 404, { ok: false, error: "User not found" });
    const body = await readJson(req);
    const blockedField = ["ownerAdminId", "limitBytes", "usedBytes", "reservedBytes"].find((field) =>
      Object.prototype.hasOwnProperty.call(body, field)
    );
    if (blockedField) {
      return sendJson(res, 400, { ok: false, error: `Cannot update ${blockedField}` });
    }
    const updated = store.update("users", user.id, body);
    store.audit(actor, "user.update", user.id);
    return sendJson(res, 200, { ok: true, data: updated });
  }

  if (userId && method === "DELETE") {
    const user = scopedUsers(actor).find((item) => item.id === userId.id);
    if (!user) return sendJson(res, 404, { ok: false, error: "User not found" });
    const owner = store.find("admins", user.ownerAdminId);
    const ownerRemainingBytes = finiteQuotaBytes(owner?.trafficRemainingBytes);
    const limitBytes = finiteQuotaBytes(user.limitBytes) ?? 0;
    const usedBytes = finiteQuotaBytes(user.usedBytes) ?? 0;
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
