const state = {
  session: localStorage.getItem("aegis.session"),
  admin: JSON.parse(localStorage.getItem("aegis.admin") || "null"),
  view: localStorage.getItem("aegis.view") || "dashboard",
  theme: localStorage.getItem("aegis.theme") || "dark",
  data: null,
  meta: null,
  admins: [],
  users: [],
  logs: [],
  news: [],
  system: null,
  syncingUserId: null,
  createUserPanelId: "",
  createUserInbounds: [],
  createUserInboundsLoading: false,
  createUserInboundsError: "",
  createUserInboundId: "",
  createUserInboundIds: [],
  createUserExpiryDate: "",
  error: "",
  notice: ""
};

const app = document.querySelector("#app");
document.documentElement.dataset.theme = state.theme;

async function api(path, options = {}) {
  const headers = { "content-type": "application/json", ...(options.headers || {}) };
  if (state.session) headers["x-aegis-session"] = state.session;
  const response = await fetch(path, {
    ...options,
    headers,
    body: options.body && typeof options.body !== "string" ? JSON.stringify(options.body) : options.body
  });
  const payload = await response.json();
  if (!response.ok || payload.ok === false) throw new Error(payload.error || "Request failed");
  return payload.data ?? payload;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#039;"
  })[char]);
}

function bytes(value) {
  const n = Number(value || 0);
  if (n >= 1024 ** 4) return `${(n / 1024 ** 4).toFixed(2)} TB`;
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(2)} GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(2)} MB`;
  return `${n} B`;
}

function gbToBytes(value) {
  return Math.max(0, Number(value || 0)) * 1024 ** 3;
}

function dateShort(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

async function login(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  try {
    const result = await api("/api/auth/login", {
      method: "POST",
      body: {
        username: form.get("username"),
        password: form.get("password")
      }
    });
    state.session = result.session;
    state.admin = result.admin;
    localStorage.setItem("aegis.session", state.session);
    localStorage.setItem("aegis.admin", JSON.stringify(state.admin));
    await load();
  } catch (error) {
    state.error = error.message;
    renderLogin();
  }
}

function logout() {
  localStorage.removeItem("aegis.session");
  localStorage.removeItem("aegis.admin");
  state.session = null;
  state.admin = null;
  renderLogin();
}

async function load() {
  try {
    state.meta = await api("/api/meta");
    state.data = await api("/api/dashboard");
    if (state.admin?.role === "superadmin") {
      state.admins = await api("/api/superadmin/admins");
      state.logs = await api("/api/superadmin/logs");
      state.news = await api("/api/superadmin/news");
      state.system = await api("/api/superadmin/system");
    }
    state.users = await api("/api/admin/users");
    state.error = "";
    renderApp();
  } catch (error) {
    state.error = error.message;
    if (String(error.message).includes("Authentication")) logout();
    else renderApp();
  }
}

function renderLogin() {
  app.innerHTML = `
    <section class="login-page">
      <div class="login-art">
        <div class="orb"></div>
        <p class="eyebrow">Community Edition</p>
        <h1>AegisPanel</h1>
        <p>Free public control surface for operators, resellers, traffic accounting, backups, and multi-panel workflows.</p>
      </div>
      <form class="login-card form" onsubmit="window.Aegis.login(event)">
        <div class="brand compact">
          <div class="mark">A</div>
          <div>
            <strong>AegisPanel</strong>
            <span>No paid gate</span>
          </div>
        </div>
        <label>Username<input name="username" autocomplete="username" required /></label>
        <label>Password<input name="password" type="password" autocomplete="current-password" required /></label>
        ${state.error ? `<p class="alert danger">${esc(state.error)}</p>` : ""}
        <button class="primary" type="submit">Sign in</button>
        <p class="muted">Use the credentials from the environment file. Change defaults before putting this on a server.</p>
      </form>
    </section>
  `;
}

function nav() {
  const items = [
    ["dashboard", "Dashboard", "Overview and live totals"],
    ["panels", "Panels", "Panel registry and sync"],
    ["admins", "Resellers", "SuperAdmin and reseller accounts"],
    ["users", "VPN Accounts", "Customers and traffic"],
    ["operations", "Operations", "Backup, logs, system"]
  ];
  return items.map(([key, label, hint]) => `
    <button class="${state.view === key ? "active" : ""}" onclick="window.Aegis.view('${key}')">
      <span>${label}</span><small>${hint}</small>
    </button>
  `).join("");
}

function shell(content) {
  app.innerHTML = `
    <section class="shell">
      <aside class="sidebar">
        <div class="brand">
          <div class="mark">A</div>
          <div>
            <strong>AegisPanel</strong>
            <span>${esc(state.admin?.username)} / ${esc(roleLabel(state.admin?.role))}</span>
          </div>
        </div>
        <nav class="nav">${nav()}</nav>
        <div class="side-footer">
          <div class="pill">Community Free</div>
          <button class="ghost" onclick="window.Aegis.toggleTheme()">Theme</button>
          <button class="ghost" onclick="window.Aegis.logout()">Logout</button>
        </div>
      </aside>
      <main class="content">
        ${state.notice ? `<p class="alert ok">${esc(state.notice)}</p>` : ""}
        ${state.error ? `<p class="alert danger">${esc(state.error)}</p>` : ""}
        ${content}
      </main>
    </section>
  `;
}

function pageTitle(title, subtitle, action = "") {
  return `
    <header class="topbar">
      <div>
        <p class="eyebrow">AegisPanel</p>
        <h2>${title}</h2>
        <p class="muted">${subtitle}</p>
      </div>
      <div class="actions">
        <button class="ghost" onclick="window.Aegis.load()">Refresh</button>
        ${action}
      </div>
    </header>
  `;
}

function metric(label, value, hint = "") {
  return `<article class="metric-card"><span>${label}</span><strong>${value ?? 0}</strong><small>${hint}</small></article>`;
}

function roleLabel(role) {
  if (role === "admin") return "Reseller";
  if (role === "superadmin") return "SuperAdmin";
  return role || "-";
}

function dashboard() {
  const totals = state.data?.totals || {};
  const distribution = state.data?.distribution || {};
  return `
    ${pageTitle("Unified Dashboard", "A clean control room for panels, resellers, VPN accounts, traffic, and operations.")}
    <section class="metrics">
      ${metric("Resellers", totals.admins, "superadmin + resellers")}
      ${metric("Panels", totals.panels, "registered upstreams")}
      ${metric("VPN Accounts", totals.users, `${totals.activeUsers || 0} active`)}
      ${metric("Traffic Used", bytes(totals.usedBytes), `${bytes(totals.limitBytes)} allocated`)}
    </section>
    <section class="split">
      <article class="card">
        <div class="card-head"><h3>Panel adapters</h3><span class="pill">${state.meta?.panelTypes?.length || 0} supported</span></div>
        <div class="adapter-grid">
          ${(state.meta?.panelTypes || []).map((p) => `
            <div class="adapter">
              <strong>${esc(p.label)}</strong>
              <small>${esc(p.type)}</small>
              <p>${p.capabilities.map(esc).join(" · ")}</p>
            </div>
          `).join("")}
        </div>
      </article>
      <article class="card">
        <div class="card-head"><h3>Release mode</h3><span class="pill green">${esc(distribution.status || "free")}</span></div>
        <table class="table compact-table">
          <tbody>
            <tr><td>Edition</td><td>${esc(distribution.edition || "community")}</td></tr>
            <tr><td>Paid checks</td><td>${esc(distribution.monetization || "disabled")}</td></tr>
            <tr><td>Seat target</td><td>${esc(distribution.seats || 3)}</td></tr>
          </tbody>
        </table>
      </article>
    </section>
    <section class="card section">
      <div class="card-head"><h3>Recent activity</h3><span class="muted">last audit events</span></div>
      ${logsTable(state.logs.slice(0, 6))}
    </section>
  `;
}

function panels() {
  const rows = state.data?.panels || [];
  return `
    ${pageTitle("Panels", "Create upstream panels, check adapter capability, and trigger sync jobs.", `<button class="primary" onclick="window.Aegis.showPanelForm()">New panel</button>`)}
    <section class="card">
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Name</th><th>Type</th><th>URL</th><th>Sub URL</th><th>Status</th><th>Last Sync</th><th></th></tr></thead>
          <tbody>
            ${rows.map((p) => `
              <tr>
                <td><strong>${esc(p.name)}</strong></td>
                <td><span class="badge">${esc(panelLabel(p.type))}</span></td>
                <td class="mono">${esc(p.url)}</td>
                <td class="mono">${esc(p.subscriptionUrl || "-")}</td>
                <td><span class="badge ${p.active ? "green" : "red"}">${p.active ? "Active" : "Off"}</span></td>
                <td>${dateShort(p.lastSyncAt)}</td>
                <td class="row-actions">
                  <button class="ghost" onclick="window.Aegis.loadPanelInbounds('${p.id}')">View inbounds</button>
                  ${p.type === "marzban"
                    ? `<button class="ghost" disabled title="Marzban sync is not ready yet">Sync not ready</button>`
                    : `<button class="ghost" onclick="window.Aegis.syncPanel('${p.id}')">Sync</button>`}
                  <button class="danger-btn" onclick="window.Aegis.deletePanel('${p.id}')">Delete</button>
                </td>
              </tr>
            `).join("") || emptyRow(7, "No panels configured yet.")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function admins() {
  return `
    ${pageTitle("Resellers", "Manage super admins and reseller accounts with traffic quota and validity windows.", `<button class="primary" onclick="window.Aegis.showAdminForm()">New reseller</button>`)}
    <section class="card">
      <p class="muted section-note">Resellers receive quota and validity from SuperAdmin. Future reseller limits should stay within the assigned validity window.</p>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Username</th><th>Role</th><th>Panel</th><th>Traffic</th><th>Return</th><th>Status</th><th></th></tr></thead>
          <tbody>
            ${state.admins.map((a) => `
              <tr>
                <td><strong>${esc(a.username)}</strong></td>
                <td><span class="badge">${esc(roleLabel(a.role))}</span></td>
                <td>${esc(panelName(a.panelId))}</td>
                <td>${a.trafficLimitBytes ? bytes(a.trafficLimitBytes) : "Unlimited"}</td>
                <td>${a.deleteReturnTraffic ? "Delete" : "-"} ${a.updateReturnTraffic ? "Update" : ""}</td>
                <td><span class="badge ${a.active ? "green" : "red"}">${a.active ? "Active" : "Off"}</span></td>
                <td class="row-actions">${a.role === "superadmin" ? "" : `<button class="danger-btn" onclick="window.Aegis.deleteAdmin('${a.id}')">Delete</button>`}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function users() {
  return `
    ${pageTitle("VPN Accounts", "Create reseller-scoped VPN accounts, assign panel/inbound, and control quota, expiry, flow, and deletion return.", `<button class="primary" onclick="window.Aegis.showUserForm()">Create VPN account</button>`)}
    <section class="card">
      <p class="muted section-note">VPN accounts are created for reseller customers and should stay within the reseller's assigned traffic quota and validity period.</p>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>VPN Account</th><th>Panel</th><th>Inbound</th><th>Used</th><th>Limit</th><th>Expiry</th><th>Status</th><th></th></tr></thead>
          <tbody>
            ${state.users.map((u) => `
              <tr>
                <td><strong>${esc(u.username)}</strong><small class="block mono">${esc(u.uuid || u.subscriptionId || "")}</small></td>
                <td>${esc(panelName(u.panelId))}</td>
                <td>${esc(u.inboundId || "default")}</td>
                <td>${bytes(u.usedBytes)}</td>
                <td>${bytes(u.limitBytes)}</td>
                <td>${dateShort(u.expiresAt)}</td>
                <td><span class="badge ${u.active ? "green" : "red"}">${u.active ? "Active" : "Off"}</span></td>
                <td class="row-actions">
                  <button class="ghost" ${state.syncingUserId === u.id ? "disabled" : `onclick="window.Aegis.syncUserTraffic('${u.id}')"`}>
                    ${state.syncingUserId === u.id ? "Syncing..." : "Sync traffic"}
                  </button>
                  <button class="danger-btn" onclick="window.Aegis.deleteUser('${u.id}')">Delete</button>
                </td>
              </tr>
            `).join("") || emptyRow(8, "No VPN accounts yet.")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function operations() {
  return `
    ${pageTitle("Operations", "Backups, audit trail, news, and local system telemetry.", `<button class="primary" onclick="window.Aegis.downloadBackup()">Backup JSON</button>`)}
    <section class="metrics">
      ${metric("CPU Cores", state.system?.cpuCount || "-", "host")}
      ${metric("Free Memory", bytes(state.system?.memory?.free), "available")}
      ${metric("App Uptime", `${Math.floor((state.system?.appUptimeSeconds || 0) / 60)}m`, "runtime")}
      ${metric("Logs", state.logs.length, "audit records")}
    </section>
    <section class="split">
      <article class="card">
        <div class="card-head"><h3>News</h3><button class="ghost" onclick="window.Aegis.showNewsForm()">Add news</button></div>
        ${state.news.map((n) => `<div class="notice-item"><strong>${esc(n.title || "Update")}</strong><p>${esc(n.message || "")}</p></div>`).join("") || `<p class="muted">No news yet.</p>`}
      </article>
      <article class="card">
        <div class="card-head"><h3>System</h3><span class="pill">local node</span></div>
        <table class="table compact-table">
          <tbody>
            <tr><td>Host uptime</td><td>${Math.floor((state.system?.uptimeSeconds || 0) / 3600)}h</td></tr>
            <tr><td>Load average</td><td>${(state.system?.loadAverage || []).map((n) => Number(n).toFixed(2)).join(" / ")}</td></tr>
            <tr><td>Total memory</td><td>${bytes(state.system?.memory?.total)}</td></tr>
          </tbody>
        </table>
      </article>
    </section>
    <section class="card section">
      <div class="card-head"><h3>Audit logs</h3><span class="muted">security-sensitive actions</span></div>
      ${logsTable(state.logs)}
    </section>
  `;
}

function logsTable(rows) {
  return `
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th></tr></thead>
        <tbody>
          ${rows.map((log) => `<tr><td>${dateShort(log.createdAt)}</td><td>${esc(log.actor)}</td><td>${esc(log.action)}</td><td class="mono">${esc(log.target)}</td></tr>`).join("") || emptyRow(4, "No audit logs yet.")}
        </tbody>
      </table>
    </div>
  `;
}

function emptyRow(cols, text) {
  return `<tr><td colspan="${cols}" class="muted empty">${text}</td></tr>`;
}

function panelLabel(type) {
  return state.meta?.panelTypes?.find((panel) => panel.type === type)?.label || type || "-";
}

function panelName(id) {
  return state.data?.panels?.find((panel) => panel.id === id)?.name || "-";
}

function renderApp() {
  if (!state.session) return renderLogin();
  const views = { dashboard, panels, admins, users, operations };
  shell((views[state.view] || dashboard)());
}

function modal(title, body) {
  document.querySelector(".modal-root")?.remove();
  const root = document.createElement("div");
  root.className = "modal-root";
  root.innerHTML = `<div class="modal-backdrop" onclick="window.Aegis.closeModal()"></div>${modalPanel(title, body)}`;
  document.body.append(root);
}

function modalPanel(title, body) {
  const wide = String(title).toLowerCase().includes("inbounds") ? " wide-modal" : "";
  return `<section class="modal card${wide}"><div class="card-head"><h3>${esc(title)}</h3><button class="ghost" onclick="window.Aegis.closeModal()">Close</button></div>${body}</section>`;
}

function setModal(title, body) {
  const root = document.querySelector(".modal-root");
  if (!root) return modal(title, body);
  root.querySelector(".modal")?.replaceWith(htmlToElement(modalPanel(title, body)));
}

function closeModal() {
  document.querySelector(".modal-root")?.remove();
}

function htmlToElement(html) {
  const template = document.createElement("template");
  template.innerHTML = html.trim();
  return template.content.firstElementChild;
}

function showPanelForm() {
  modal("New panel", `
    <form class="form" onsubmit="window.Aegis.createPanel(event)">
      <label>Name<input name="name" required placeholder="Edge Tehran 01" /></label>
      <label>Type<select name="type">${(state.meta?.panelTypes || []).map((p) => `<option value="${p.type}">${p.label}</option>`).join("")}</select></label>
      <label>Panel URL<input name="url" required placeholder="https://panel.example.com" /></label>
      <label>Subscription URL<input name="subscriptionUrl" placeholder="https://panel.example.com/sub" /></label>
      <label>Username<input name="username" placeholder="panel admin, if needed" /></label>
      <label>Secret / API key<input name="secret" placeholder="stored locally for connector use" /></label>
      <button class="primary" type="submit">Create panel</button>
    </form>
  `);
}

function showAdminForm() {
  modal("New reseller", `
    <form class="form" onsubmit="window.Aegis.createAdmin(event)">
      <label>Username<input name="username" required placeholder="reseller-01" /></label>
      <label>Password<input name="password" required type="password" placeholder="Strong password" /></label>
      <label>Role<select name="role"><option value="admin">Reseller</option><option value="superadmin">SuperAdmin</option></select></label>
      <label>Panel<select name="panelId"><option value="">No fixed panel</option>${(state.data?.panels || []).map((p) => `<option value="${p.id}">${esc(p.name)}</option>`).join("")}</select></label>
      <label>Traffic limit (GB)<input name="trafficGb" type="number" min="0" step="1" placeholder="100" /></label>
      <div class="check-row"><label><input name="deleteReturnTraffic" type="checkbox" checked /> Return traffic on delete</label><label><input name="updateReturnTraffic" type="checkbox" checked /> Return traffic on update</label></div>
      <button class="primary" type="submit">Create reseller</button>
    </form>
  `);
}

function showUserForm() {
  state.createUserPanelId = state.data?.panels?.[0]?.id || "";
  state.createUserInbounds = [];
  state.createUserInboundsLoading = false;
  state.createUserInboundsError = "";
  state.createUserInboundId = "";
  state.createUserInboundIds = [];
  state.createUserExpiryDate = "";
  modal("Create VPN account", createUserModalBody());
  if (state.createUserPanelId) {
    void loadUserInbounds(state.createUserPanelId, { silent: true });
  }
}

function createUserModalBody() {
  return `
    <form class="form create-user-form" onsubmit="window.Aegis.createUser(event)">
      <label>Username<input name="username" required placeholder="client-name" /></label>
      <label>Panel<select name="panelId" required onchange="window.Aegis.loadUserInbounds(this.value)">${(state.data?.panels || []).map((p) => `<option value="${p.id}"${p.id === state.createUserPanelId ? " selected" : ""}>${esc(p.name)}</option>`).join("")}</select></label>
      <div id="user-inbound-field">${createUserInboundField()}</div>
      <label>Flow<input name="flow" placeholder="xtls-rprx-vision, optional" /></label>
      <label>Traffic limit (GB)<input name="limitGb" type="number" min="0" step="1" value="25" /></label>
      <div id="user-expiry-field">${createUserExpiryField()}</div>
      <button class="primary" type="submit">Create VPN account</button>
    </form>
  `;
}

function createUserInboundField() {
  const panel = state.data?.panels?.find((item) => item.id === state.createUserPanelId);
  const isMarzban = panel?.type === "marzban";
  if (!isMarzban) {
    return `<label>Inbound<input name="inboundId" placeholder="default" value="${esc(state.createUserInboundId || "")}" /></label>`;
  }
  if (state.createUserInboundsLoading) {
    return `<p class="muted">Loading Marzban inbounds...</p>`;
  }
  if (state.createUserInboundsError) {
    return `<p class="alert danger">${esc(state.createUserInboundsError)}</p>`;
  }
  if (!state.createUserInbounds.length) {
    return `<p class="alert danger">This Marzban panel has no inbounds yet. Load inbounds before creating a VPN account.</p>`;
  }
  const grouped = groupMarzbanInbounds(state.createUserInbounds);
  return `
    <div class="inbound-picker">
      <div class="card-head compact-head">
        <h4>Inbounds</h4>
        <div class="actions">
          <button type="button" class="ghost" onclick="window.Aegis.selectAllMarzbanInbounds()">Select all</button>
          <button type="button" class="ghost" onclick="window.Aegis.clearMarzbanInbounds()">Clear</button>
        </div>
      </div>
      ${Object.entries(grouped).map(([protocol, inbounds]) => `
        <div class="inbound-group">
          <div class="inbound-group-title">${esc(protocol.toUpperCase())}</div>
          <div class="inbound-checklist">
            ${inbounds.map((inbound) => `
              <label class="inbound-option ${state.createUserInboundIds.includes(inbound.id) ? "selected" : ""}">
                <input
                  type="checkbox"
                  name="marzbanInbound"
                  value="${esc(inbound.id)}"
                  ${state.createUserInboundIds.includes(inbound.id) ? "checked" : ""}
                  onchange="window.Aegis.toggleMarzbanInboundSelection(this.value, this.checked)"
                />
                <span>
                  <strong>${esc(inbound.label || inbound.id)}</strong>
                  <small>${esc(formatInboundDetails(inbound))}</small>
                </span>
              </label>
            `).join("")}
          </div>
        </div>
      `).join("")}
    </div>
  `;
}

function refreshUserInboundField() {
  const field = document.querySelector("#user-inbound-field");
  if (!field) {
    setModal("Create VPN account", createUserModalBody());
    return;
  }
  field.innerHTML = createUserInboundField();
}

function refreshUserExpiryField() {
  const field = document.querySelector("#user-expiry-field");
  if (!field) {
    setModal("Create VPN account", createUserModalBody());
    return;
  }
  field.innerHTML = createUserExpiryField();
}

function formatInboundOption(inbound) {
  const details = [inbound.protocol, inbound.network, inbound.tls, inbound.port].filter((part) => part !== "" && part !== null && part !== undefined).join("/");
  return `${inbound.label || inbound.id} — ${details || inbound.id}`;
}

function formatInboundDetails(inbound) {
  return [inbound.protocol, inbound.network, inbound.tls, inbound.port].filter((part) => part !== "" && part !== null && part !== undefined).join("/");
}

function groupMarzbanInbounds(inbounds) {
  const order = [];
  const grouped = {};
  for (const inbound of inbounds) {
    const protocol = inbound.protocol || "other";
    const key = protocol.toLowerCase();
    if (!grouped[key]) {
      grouped[key] = [];
      order.push({ key, label: protocol });
    }
    grouped[key].push({ ...inbound });
  }
  return order.reduce((acc, item) => {
    acc[item.label] = grouped[item.key];
    return acc;
  }, {});
}

function normalMarzbanInboundIds(inbounds) {
  return inbounds.filter((inbound) => !/dummy|metrics/i.test(`${inbound.label || ""} ${inbound.id || ""}`)).map((inbound) => inbound.id);
}

function createUserExpiryField() {
  const value = state.createUserExpiryDate || "";
  return `
    <div class="expiry-picker">
      <label>Expiry Date</label>
      <div class="expiry-shell${value ? " has-value" : ""}">
        <button type="button" class="expiry-display" onclick="window.Aegis.openCreateUserExpiryPicker(event)" aria-label="Select expiry date">
          <span class="expiry-display-value">${esc(value)}</span>
          <span class="expiry-display-icon" aria-hidden="true">${calendarIcon()}</span>
        </button>
        <input class="expiry-native" name="expiresAtDate" type="date" value="${esc(value)}" onchange="window.Aegis.setCreateUserExpiryDate(this.value)" />
        ${value ? `<button type="button" class="expiry-clear" onclick="window.Aegis.clearCreateUserExpiry(event)" aria-label="Clear expiry date">×</button>` : ""}
      </div>
    </div>
  `;
}

function calendarIcon() {
  return `
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d="M7 2a1 1 0 0 1 1 1v1h8V3a1 1 0 1 1 2 0v1h1.5A2.5 2.5 0 0 1 22 6.5v12A2.5 2.5 0 0 1 19.5 21h-15A2.5 2.5 0 0 1 2 18.5v-12A2.5 2.5 0 0 1 4.5 4H6V3a1 1 0 0 1 1-1Zm12 8H5v8.5c0 .28.22.5.5.5h13a.5.5 0 0 0 .5-.5V10Zm0-4.5a.5.5 0 0 0-.5-.5H17v1a1 1 0 1 1-2 0V5H9v1a1 1 0 1 1-2 0V5H4.5a.5.5 0 0 0-.5.5V8h15V5.5Z"/>
    </svg>
  `;
}

function pad2(value) {
  return String(value).padStart(2, "0");
}

function toggleMarzbanInboundSelection(id, checked) {
  const selected = new Set(state.createUserInboundIds);
  if (checked) selected.add(id);
  else selected.delete(id);
  state.createUserInboundIds = [...selected];
  refreshUserInboundField();
}

function selectAllMarzbanInbounds() {
  state.createUserInboundIds = normalMarzbanInboundIds(state.createUserInbounds);
  refreshUserInboundField();
}

function clearMarzbanInbounds() {
  state.createUserInboundIds = [];
  refreshUserInboundField();
}

function setCreateUserExpiryDate(value) {
  state.createUserExpiryDate = value;
  refreshUserExpiryField();
}

function clearCreateUserExpiry(event) {
  event?.preventDefault();
  event?.stopPropagation();
  state.createUserExpiryDate = "";
  refreshUserExpiryField();
}

function openCreateUserExpiryPicker(event) {
  if (event?.target?.closest?.(".expiry-clear")) return;
  const input = document.querySelector(".expiry-native");
  if (!input) return;
  if (typeof input.showPicker === "function") {
    input.showPicker();
    return;
  }
  input.focus();
  input.click?.();
}

async function loadUserInbounds(panelId, { silent = false } = {}) {
  state.createUserPanelId = panelId;
  const panel = state.data?.panels?.find((item) => item.id === panelId);
  if (!panel) {
    state.createUserInbounds = [];
    state.createUserInboundsError = "Select a panel to load inbounds.";
    state.createUserInboundsLoading = false;
    state.createUserInboundId = "";
    state.createUserInboundIds = [];
    refreshUserInboundField();
    return;
  }
  if (panel.type !== "marzban") {
    state.createUserInbounds = [];
    state.createUserInboundsError = "";
    state.createUserInboundsLoading = false;
    state.createUserInboundId = "";
    state.createUserInboundIds = [];
    refreshUserInboundField();
    return;
  }
  state.createUserInboundsLoading = true;
  state.createUserInboundsError = "";
  state.createUserInbounds = [];
  state.createUserInboundId = "";
  refreshUserInboundField();
  try {
    const rows = await api(`/api/superadmin/panels/${panelId}/inbounds`);
    state.createUserInbounds = rows;
    state.createUserInboundIds = normalMarzbanInboundIds(rows);
    state.createUserInboundId = state.createUserInboundIds[0] || "";
    state.createUserInboundsError = "";
  } catch (error) {
    state.createUserInbounds = [];
    state.createUserInboundId = "";
    state.createUserInboundIds = [];
    state.createUserInboundsError = error.message || "Failed to load Marzban inbounds";
  } finally {
    state.createUserInboundsLoading = false;
    refreshUserInboundField();
  }
}

function showNewsForm() {
  modal("Add news", `
    <form class="form" onsubmit="window.Aegis.createNews(event)">
      <label>Title<input name="title" required placeholder="Maintenance" /></label>
      <label>Message<textarea name="message" required rows="4" placeholder="Write a short operator note"></textarea></label>
      <button class="primary" type="submit">Publish</button>
    </form>
  `);
}

async function createPanel(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  await runAction(async () => {
    await api("/api/superadmin/panels", {
      method: "POST",
      body: Object.fromEntries(form.entries())
    });
  }, "Panel created");
}

async function createAdmin(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  await runAction(async () => {
    await api("/api/superadmin/admins", {
      method: "POST",
      body: {
        username: form.get("username"),
        password: form.get("password"),
        role: form.get("role"),
        panelId: form.get("panelId") || null,
        trafficLimitBytes: form.get("trafficGb") ? gbToBytes(form.get("trafficGb")) : null,
        deleteReturnTraffic: form.has("deleteReturnTraffic"),
        updateReturnTraffic: form.has("updateReturnTraffic")
      }
    });
  }, "Reseller created");
}

async function createUser(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const panelId = form.get("panelId");
  const panel = state.data?.panels?.find((item) => item.id === panelId);
  await runAction(async () => {
    if (panel?.type === "marzban") {
      if (state.createUserInboundsLoading) {
        throw new Error("Please wait for Marzban inbounds to load.");
      }
      if (!state.createUserInboundIds.length) {
        throw new Error(state.createUserInboundsError || "Select a Marzban inbound before creating the VPN account.");
      }
      const inboundId = state.createUserInboundIds[0];
      const expiresAt = resolveCreateUserExpiry(form);
      const body = {
        username: form.get("username"),
        panelId,
        flow: form.get("flow") || "",
        limitBytes: gbToBytes(form.get("limitGb")),
        expiresAt,
        inboundId,
        inboundIds: state.createUserInboundIds
      };
      await api("/api/admin/users", {
        method: "POST",
        body
      });
      return;
    }
    const body = {
      username: form.get("username"),
      panelId,
      flow: form.get("flow") || "",
      limitBytes: gbToBytes(form.get("limitGb")),
      expiresAt: resolveCreateUserExpiry(form),
      inboundId: form.get("inboundId") || "default"
    };
    await api("/api/admin/users", {
      method: "POST",
      body
    });
  }, "VPN account created");
}

function resolveCreateUserExpiry(form) {
  const value = state.createUserExpiryDate || form.get("expiresAtDate") || "";
  if (!value) return null;
  const date = new Date(`${value}T23:59:59`);
  if (Number.isNaN(date.getTime())) {
    throw new Error("Please select a valid expiry date.");
  }
  return date.toISOString();
}

async function createNews(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  await runAction(async () => {
    await api("/api/superadmin/news", {
      method: "POST",
      body: Object.fromEntries(form.entries())
    });
  }, "News published");
}

async function syncPanel(id) {
  await runAction(async () => {
    const result = await api(`/api/panels/${id}/sync`, { method: "POST" });
    state.notice = `Sync complete: pulled ${result.pulled}, pushed ${result.pushed}`;
  }, state.notice || "Panel synced");
}

async function loadPanelInbounds(id) {
  modal("Panel inbounds", `<p class="muted">Loading inbounds...</p>`);
  try {
    const rows = await api(`/api/superadmin/panels/${id}/inbounds`);
    setModal("Panel inbounds", `
      <div class="table-wrap">
        <table class="table compact-table inbounds-table">
          <thead>
            <tr><th>Label</th><th>Protocol</th><th>Network</th><th>TLS</th><th>Port</th><th>Status</th></tr>
          </thead>
          <tbody>
            ${rows.map((inbound) => `
              <tr>
                <td class="inbound-label"><strong>${esc(inbound.label || "-")}</strong><small class="block mono">${esc(inbound.id || "")}</small></td>
                <td>${esc(inbound.protocol || "-")}</td>
                <td>${esc(inbound.network || "-")}</td>
                <td>${esc(inbound.tls || "-")}</td>
                <td>${inbound.port ?? "-"}</td>
                <td><span class="badge inbound-status ${inbound.enabled ? "green" : "red"}">${inbound.enabled ? "Enabled" : "Disabled"}</span></td>
              </tr>
            `).join("") || emptyRow(6, "No inbounds returned by this panel.")}
          </tbody>
        </table>
      </div>
    `);
  } catch (error) {
    setModal("Panel inbounds", `<p class="alert danger">${esc(error.message)}</p>`);
  }
}

async function syncUserTraffic(id) {
  const previous = state.syncingUserId;
  state.syncingUserId = id;
  state.error = "";
  renderApp();
  try {
    const updated = await api(`/api/admin/users/${id}/sync-traffic`, { method: "POST" });
    state.users = state.users.map((user) => (user.id === id ? { ...user, usedBytes: updated.usedBytes } : user));
    if (state.data?.users) {
      state.data = {
        ...state.data,
        users: state.users
      };
    }
    state.notice = "VPN account traffic synced";
    state.error = "";
  } catch (error) {
    state.error = error.message || "Traffic sync failed";
  } finally {
    state.syncingUserId = previous;
    renderApp();
  }
}

async function deletePanel(id) {
  if (!confirm("Delete this panel?")) return;
  await runAction(() => api(`/api/superadmin/panels/${id}`, { method: "DELETE" }), "Panel deleted");
}

async function deleteAdmin(id) {
  if (!confirm("Delete this reseller?")) return;
  await runAction(() => api(`/api/superadmin/admins/${id}`, { method: "DELETE" }), "Reseller deleted");
}

async function deleteUser(id) {
  if (!confirm("Delete this VPN account? Remaining traffic will return when enabled.")) return;
  await runAction(() => api(`/api/admin/users/${id}`, { method: "DELETE" }), "VPN account deleted");
}

async function runAction(action, message) {
  try {
    state.error = "";
    state.notice = "";
    await action();
    closeModal();
    state.notice = message;
    await load();
  } catch (error) {
    state.error = error.message;
    renderApp();
  }
}

async function downloadBackup() {
  const backup = await api("/api/superadmin/backup");
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `aegis-backup-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

window.Aegis = {
  login,
  logout,
  load,
  closeModal,
  showPanelForm,
  showAdminForm,
  showUserForm,
  showNewsForm,
  createPanel,
  createAdmin,
  createUser,
  loadUserInbounds,
  toggleMarzbanInboundSelection,
  selectAllMarzbanInbounds,
  clearMarzbanInbounds,
  setCreateUserExpiryDate,
  clearCreateUserExpiry,
  openCreateUserExpiryPicker,
  createNews,
  syncPanel,
  syncUserTraffic,
  loadPanelInbounds,
  deletePanel,
  deleteAdmin,
  deleteUser,
  downloadBackup,
  toggleTheme() {
    state.theme = state.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = state.theme;
    localStorage.setItem("aegis.theme", state.theme);
  },
  view(next) {
    state.view = next;
    localStorage.setItem("aegis.view", next);
    renderApp();
  }
};

if (state.session) load();
else renderLogin();
