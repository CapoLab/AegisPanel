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
  createUserError: "",
  editUserId: "",
  editUserUsername: "",
  editUserPanelId: "",
  editUserInbounds: [],
  editUserInboundsLoading: false,
  editUserInboundsError: "",
  editUserInboundId: "",
  editUserInboundIds: [],
  editUserExpiryDate: "",
  editUserFlow: "",
  editUserActive: true,
  editUserError: "",
  error: "",
  notice: ""
};

const app = document.querySelector("#app");
document.documentElement.dataset.theme = state.theme;

function isSuperadmin() {
  return state.admin?.role === "superadmin";
}

function isReseller() {
  return state.admin?.role === "admin";
}

function roleScopedViews() {
  return isReseller() ? ["dashboard", "users"] : ["dashboard", "panels", "admins", "users", "operations"];
}

function requireSuperadminUi() {
  if (isSuperadmin()) return true;
  state.error = "Insufficient permissions";
  renderApp();
  return false;
}

function resetRoleScopedState() {
  state.admins = [];
  state.logs = [];
  state.news = [];
  state.system = null;
}

function normalizeViewForRole() {
  if (isReseller() && !roleScopedViews().includes(state.view)) {
    state.view = "dashboard";
    localStorage.setItem("aegis.view", state.view);
  }
}

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
  resetRoleScopedState();
  state.users = [];
  state.data = null;
  state.meta = null;
  state.createUserPanelId = "";
  state.createUserInbounds = [];
  state.createUserInboundsLoading = false;
  state.createUserInboundsError = "";
  state.createUserInboundId = "";
  state.createUserInboundIds = [];
  state.createUserExpiryDate = "";
  state.notice = "";
  state.error = "";
  state.createUserError = "";
  state.editUserId = "";
  state.editUserUsername = "";
  state.editUserPanelId = "";
  state.editUserInbounds = [];
  state.editUserInboundsLoading = false;
  state.editUserInboundsError = "";
  state.editUserInboundId = "";
  state.editUserInboundIds = [];
  state.editUserExpiryDate = "";
  state.editUserFlow = "";
  state.editUserActive = true;
  state.editUserError = "";
  closeModal();
  renderLogin();
}

async function load() {
  try {
    state.meta = await api("/api/meta");
    state.data = await api("/api/dashboard");
    if (state.data?.actor) {
      state.admin = state.data.actor;
      localStorage.setItem("aegis.admin", JSON.stringify(state.admin));
    }
    if (isSuperadmin()) {
      state.admins = await api("/api/superadmin/admins");
      state.logs = await api("/api/superadmin/logs");
      state.news = await api("/api/superadmin/news");
      state.system = await api("/api/superadmin/system");
    } else {
      resetRoleScopedState();
    }
    state.users = await api("/api/admin/users");
    state.error = "";
    normalizeViewForRole();
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
  const items = isReseller()
    ? [
        ["dashboard", "Dashboard", "Your quota and validity"],
        ["users", "VPN Accounts", "Customers and traffic"]
      ]
    : [
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
            <span>${esc(state.admin?.username)} / ${esc(roleLabel(state.admin?.role))}${state.admin?.validUntil ? ` · ${esc(dateShort(state.admin.validUntil))}` : ""}</span>
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
  if (isReseller()) {
    const assignedPanel = panelName(state.admin?.panelId);
    const quotaLimit = Number(state.admin?.trafficLimitBytes || 0);
    const quotaRemaining = Number(state.admin?.trafficRemainingBytes ?? state.admin?.trafficLimitBytes ?? 0);
    const quotaUsed = Math.max(0, quotaLimit - quotaRemaining);
    const users = state.users || [];
    return `
      ${pageTitle("Dashboard", "Your reseller workspace for quota, validity, and VPN account creation.", `<button class="primary" onclick="window.Aegis.showUserForm()">Create VPN account</button>`)}
      <section class="card section">
        <p class="muted section-note">You can create VPN accounts within your assigned quota and validity.</p>
        <div class="metrics">
          ${metric("Assigned Panel", assignedPanel, "scoped panel")}
          ${metric("Traffic Limit", state.admin?.trafficLimitBytes == null ? "Unlimited" : bytes(state.admin.trafficLimitBytes), "assigned quota")}
          ${metric("Traffic Remaining", state.admin?.trafficRemainingBytes == null ? "Unlimited" : bytes(state.admin.trafficRemainingBytes), "available")}
          ${metric("Used Traffic", bytes(quotaUsed), "consumed")}
          ${metric("Active VPN Accounts", users.filter((user) => user.active).length, "currently active")}
          ${metric("Total VPN Accounts", users.length, "all scoped accounts")}
        </div>
        <div class="reseller-summary">
          <table class="table compact-table">
            <tbody>
              <tr><td>Valid until</td><td>${esc(state.admin?.validUntil ? dateShort(state.admin.validUntil) : "Unlimited")}</td></tr>
              <tr><td>Panel</td><td>${esc(assignedPanel)}</td></tr>
              <tr><td>Notes</td><td>VPN account expiry must stay within your reseller validity window.</td></tr>
            </tbody>
          </table>
        </div>
      </section>
      <section class="card section">
        <div class="card-head"><h3>VPN Accounts</h3><button class="primary" onclick="window.Aegis.showUserForm()">Create VPN account</button></div>
        ${users.length ? `
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>VPN Account</th><th>Panel</th><th>Inbound</th><th>Used</th><th>Limit</th><th>Expiry</th><th>Status</th><th></th></tr></thead>
              <tbody>
                ${users.map((u) => `
                  <tr>
                    <td><strong>${esc(u.username)}</strong><small class="block mono">${esc(u.uuid || u.subscriptionId || "")}</small></td>
                    <td>${esc(panelName(u.panelId))}</td>
                    <td>${esc(vpnAccountInboundSummary(u))}</td>
                    <td>${bytes(u.usedBytes)}</td>
                    <td>${bytes(u.limitBytes)}</td>
                    <td>${dateShort(u.expiresAt)}</td>
                    <td><span class="badge ${u.active ? "green" : "red"}">${u.active ? "Active" : "Off"}</span></td>
                    <td class="row-actions">
                      <button class="ghost" onclick="window.Aegis.showEditUserForm('${u.id}')">Edit</button>
                      <button class="ghost" ${state.syncingUserId === u.id ? "disabled" : `onclick="window.Aegis.syncUserTraffic('${u.id}')"`}>
                        ${state.syncingUserId === u.id ? "Syncing..." : "Sync traffic"}
                      </button>
                      <button class="danger-btn" onclick="window.Aegis.deleteUser('${u.id}')">Delete</button>
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        ` : `<p class="muted">No VPN accounts yet.</p>`}
      </section>
    `;
  }
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
          <thead><tr><th>Username</th><th>Role</th><th>Valid until</th><th>Panel</th><th>Traffic</th><th>Return</th><th>Status</th><th></th></tr></thead>
          <tbody>
            ${state.admins.map((a) => `
              <tr>
                <td><strong>${esc(a.username)}</strong></td>
                <td><span class="badge">${esc(roleLabel(a.role))}</span></td>
                <td>${esc(a.validUntil ? dateShort(a.validUntil) : "Unlimited")}</td>
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
                <td>${esc(vpnAccountInboundSummary(u))}</td>
                <td>${bytes(u.usedBytes)}</td>
                <td>${bytes(u.limitBytes)}</td>
                <td>${dateShort(u.expiresAt)}</td>
                <td><span class="badge ${u.active ? "green" : "red"}">${u.active ? "Active" : "Off"}</span></td>
                <td class="row-actions">
                  <button class="ghost" onclick="window.Aegis.showEditUserForm('${u.id}')">Edit</button>
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
  normalizeViewForRole();
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
  const compact = String(title).toLowerCase().includes("edit vpn account") ? " edit-modal" : "";
  return `<section class="modal card${wide}${compact}"><div class="card-head"><h3>${esc(title)}</h3><button class="ghost" onclick="window.Aegis.closeModal()">Close</button></div>${body}</section>`;
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
  if (!requireSuperadminUi()) return;
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
  if (!requireSuperadminUi()) return;
  modal("New reseller", `
    <form class="form" onsubmit="window.Aegis.createAdmin(event)">
      <label>Username<input name="username" required placeholder="reseller-01" /></label>
      <label>Password<input name="password" required type="password" placeholder="Strong password" /></label>
      <label>Role<select name="role"><option value="admin">Reseller</option><option value="superadmin">SuperAdmin</option></select></label>
      <label>Panel<select name="panelId"><option value="">No fixed panel</option>${(state.data?.panels || []).map((p) => `<option value="${p.id}">${esc(p.name)}</option>`).join("")}</select></label>
      <label>Traffic limit (GB)<input name="trafficGb" type="number" min="0" step="1" placeholder="100" /></label>
      <label>Valid until<input name="validUntilDate" type="date" /></label>
      <div class="check-row"><label><input name="deleteReturnTraffic" type="checkbox" checked /> Return traffic on delete</label><label><input name="updateReturnTraffic" type="checkbox" checked /> Return traffic on update</label></div>
      <button class="primary" type="submit">Create reseller</button>
    </form>
  `);
}

function showUserForm() {
  state.error = "";
  state.createUserError = "";
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
      <div id="user-create-error">${state.createUserError ? `<p class="alert danger">${esc(state.createUserError)}</p>` : ""}</div>
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
  return renderMarzbanInboundPicker({
    title: "Inbounds",
    inbounds: state.createUserInbounds,
    selectedIds: state.createUserInboundIds,
    loading: state.createUserInboundsLoading,
    error: state.createUserInboundsError,
    emptyMessage: "This Marzban panel has no inbounds yet. Load inbounds before creating a VPN account.",
    toggleAction: "toggleMarzbanInboundSelection",
    selectAllAction: "selectAllMarzbanInbounds",
    clearAction: "clearMarzbanInbounds"
  });
}

function refreshUserInboundField() {
  const field = document.querySelector("#user-inbound-field");
  if (!field) {
    setModal("Create VPN account", createUserModalBody());
    return;
  }
  field.innerHTML = createUserInboundField();
}

function refreshCreateUserError() {
  const field = document.querySelector("#user-create-error");
  if (!field) {
    setModal("Create VPN account", createUserModalBody());
    return;
  }
  field.innerHTML = state.createUserError ? `<p class="alert danger">${esc(state.createUserError)}</p>` : "";
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

function normalizeInboundSearchText(value) {
  if (value == null) return "";
  const normalized = String(value);
  return (typeof normalized.normalize === "function" ? normalized.normalize("NFKC") : normalized).toLowerCase();
}

function isDummyOrMetricsInbound(inbound) {
  return /dummy|metrics/i.test(normalizeInboundSearchText(`${inbound?.label || ""} ${inbound?.id || ""}`));
}

function vpnAccountInboundMode(user) {
  return user?.inboundMode === "all" ? "All" : "Custom";
}

function vpnAccountInboundCount(user) {
  if (Array.isArray(user?.inboundIds) && user.inboundIds.length > 0) return user.inboundIds.length;
  return user?.inboundId ? 1 : 0;
}

function vpnAccountInboundSummary(user) {
  const mode = vpnAccountInboundMode(user);
  const count = vpnAccountInboundCount(user);
  return count > 0 ? `${mode} · ${count} inbounds` : mode;
}

function inboundModeFromSelection(selectedIds, allIds) {
  const selected = Array.isArray(selectedIds) ? selectedIds.filter((id) => typeof id === "string" && id.trim()) : [];
  const all = Array.isArray(allIds) ? allIds.filter((id) => typeof id === "string" && id.trim()) : [];
  if (all.length > 0 && selected.length === all.length && all.every((id) => selected.includes(id))) {
    return "all";
  }
  return "custom";
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
  return inbounds.map((inbound) => inbound.id);
}

function preferredMarzbanInboundId(inboundIds, fallbackId = "") {
  const real = inboundIds.find((id) => !isDummyOrMetricsInbound({ id }));
  return real || inboundIds[0] || fallbackId || "default";
}

function displayInboundId(user) {
  const inboundIds = Array.isArray(user?.inboundIds) && user.inboundIds.length ? user.inboundIds : [user?.inboundId].filter(Boolean);
  return preferredMarzbanInboundId(inboundIds, user?.inboundId);
}

function normalizeDateInputValue(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const year = date.getFullYear();
  const month = pad2(date.getMonth() + 1);
  const day = pad2(date.getDate());
  return `${year}-${month}-${day}`;
}

function renderMarzbanInboundPicker({ title, inbounds, selectedIds, loading, error, emptyMessage, toggleAction, selectAllAction, clearAction }) {
  if (loading) {
    return `<p class="muted">Loading Marzban inbounds...</p>`;
  }
  if (error) {
    return `<p class="alert danger">${esc(error)}</p>`;
  }
  if (!inbounds.length) {
    return `<p class="alert danger">${esc(emptyMessage)}</p>`;
  }
  const grouped = groupMarzbanInbounds(inbounds);
  return `
    <div class="inbound-picker">
      <div class="card-head compact-head">
        <h4>${esc(title)}</h4>
        <div class="actions">
          <button type="button" class="ghost" onclick="window.Aegis.${selectAllAction}()">Select all</button>
          <button type="button" class="ghost" onclick="window.Aegis.${clearAction}()">Clear</button>
        </div>
      </div>
      ${Object.entries(grouped).map(([protocol, protocolInbounds]) => `
        <div class="inbound-group">
          <div class="inbound-group-title">${esc(protocol.toUpperCase())}</div>
          <div class="inbound-checklist">
            ${protocolInbounds.map((inbound) => `
              <label class="inbound-option ${selectedIds.includes(inbound.id) ? "selected" : ""}">
                <input
                  type="checkbox"
                  name="marzbanInbound"
                  value="${esc(inbound.id)}"
                  ${selectedIds.includes(inbound.id) ? "checked" : ""}
                  onchange="window.Aegis.${toggleAction}(this.value, this.checked)"
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

function createUserExpiryField() {
  return renderExpiryField({
    value: state.createUserExpiryDate,
    openAction: "openCreateUserExpiryPicker",
    changeAction: "setCreateUserExpiryDate",
    clearAction: "clearCreateUserExpiry",
    valueName: "expiresAtDate"
  });
}

function editUserExpiryField() {
  return renderExpiryField({
    value: state.editUserExpiryDate,
    openAction: "openEditUserExpiryPicker",
    changeAction: "setEditUserExpiryDate",
    clearAction: "clearEditUserExpiry",
    valueName: "editExpiresAtDate"
  });
}

function renderExpiryField({ value, openAction, changeAction, clearAction, valueName }) {
  const currentValue = value || "";
  return `
    <div class="expiry-picker">
      <label>Expiry Date</label>
      <div class="expiry-shell${currentValue ? " has-value" : ""}">
        <button type="button" class="expiry-display" onclick="window.Aegis.${openAction}(event)" aria-label="Select expiry date">
          <span class="expiry-display-value">${esc(currentValue)}</span>
          <span class="expiry-display-icon" aria-hidden="true">${calendarIcon()}</span>
        </button>
        <input class="expiry-native" name="${esc(valueName)}" type="date" value="${esc(currentValue)}" onchange="window.Aegis.${changeAction}(this.value)" />
        ${currentValue ? `<button type="button" class="expiry-clear" onclick="window.Aegis.${clearAction}(event)" aria-label="Clear expiry date">×</button>` : ""}
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
  state.createUserError = "";
  refreshUserInboundField();
  refreshCreateUserError();
}

function selectAllMarzbanInbounds() {
  state.createUserInboundIds = normalMarzbanInboundIds(state.createUserInbounds);
  state.createUserError = "";
  refreshUserInboundField();
  refreshCreateUserError();
}

function clearMarzbanInbounds() {
  state.createUserInboundIds = [];
  state.createUserError = "";
  refreshUserInboundField();
  refreshCreateUserError();
}

function setCreateUserExpiryDate(value) {
  state.createUserExpiryDate = value;
  state.createUserError = "";
  refreshUserExpiryField();
  refreshCreateUserError();
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
  state.createUserError = "";
  const panel = state.data?.panels?.find((item) => item.id === panelId);
  if (!panel) {
    state.createUserInbounds = [];
    state.createUserInboundsError = "Select a panel to load inbounds.";
    state.createUserInboundsLoading = false;
    state.createUserInboundId = "";
    state.createUserInboundIds = [];
    refreshUserInboundField();
    refreshCreateUserError();
    return;
  }
  if (panel.type !== "marzban") {
    state.createUserInbounds = [];
    state.createUserInboundsError = "";
    state.createUserInboundsLoading = false;
    state.createUserInboundId = "";
    state.createUserInboundIds = [];
    refreshUserInboundField();
    refreshCreateUserError();
    return;
  }
  state.createUserInboundsLoading = true;
  state.createUserInboundsError = "";
  state.createUserInbounds = [];
  state.createUserInboundId = "";
  refreshUserInboundField();
  refreshCreateUserError();
  try {
    const rows = await api(`/api/admin/panels/${panelId}/inbounds`);
    state.createUserInbounds = rows;
    state.createUserInboundIds = normalMarzbanInboundIds(rows);
    state.createUserInboundId = preferredMarzbanInboundId(state.createUserInboundIds);
    state.createUserInboundsError = "";
  } catch (error) {
    state.createUserInbounds = [];
    state.createUserInboundId = "";
    state.createUserInboundIds = [];
    state.createUserInboundsError = error.message || "Failed to load Marzban inbounds";
  } finally {
    state.createUserInboundsLoading = false;
    refreshUserInboundField();
    refreshCreateUserError();
  }
}

function showNewsForm() {
  if (!requireSuperadminUi()) return;
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
        validUntil: resolveLocalDateEndOfDay(form.get("validUntilDate")),
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
  state.error = "";
  state.createUserError = "";
  refreshCreateUserError();
  try {
    if (panel?.type === "marzban") {
      if (state.createUserInboundsLoading) {
        throw new Error("Please wait for Marzban inbounds to load.");
      }
      const selectedInbounds = state.createUserInbounds.filter((inbound) => state.createUserInboundIds.includes(inbound.id));
      if (!selectedInbounds.length) {
        throw new Error("Select a Marzban inbound before creating the VPN account.");
      }
      const expiresAt = resolveCreateUserExpiry(form);
      const inboundIds = selectedInbounds.map((inbound) => inbound.id);
      await api("/api/admin/users", {
        method: "POST",
        body: {
          username: form.get("username"),
          panelId,
          flow: form.get("flow") || "",
          limitBytes: gbToBytes(form.get("limitGb")),
          expiresAt,
          inboundId: preferredMarzbanInboundId(inboundIds),
          inboundIds,
          inboundMode: inboundModeFromSelection(inboundIds, state.createUserInbounds.map((inbound) => inbound.id))
        }
      });
    } else {
      await api("/api/admin/users", {
        method: "POST",
        body: {
          username: form.get("username"),
          panelId,
          flow: form.get("flow") || "",
          limitBytes: gbToBytes(form.get("limitGb")),
          expiresAt: resolveCreateUserExpiry(form),
          inboundId: form.get("inboundId") || "default"
        }
      });
    }
    closeModal();
    state.notice = "VPN account created";
    await load();
  } catch (error) {
    state.createUserError = error.message;
    refreshCreateUserError();
  }
}

function showEditUserForm(id) {
  const user = state.users?.find((item) => item.id === id);
  if (!user) {
    state.error = "User not found";
    renderApp();
    return;
  }
  state.editUserId = user.id;
  state.editUserUsername = user.username || "";
  state.editUserPanelId = user.panelId || "";
  state.editUserInbounds = [];
  const panel = state.data?.panels?.find((item) => item.id === user.panelId);
  state.editUserInboundsLoading = panel?.type === "marzban";
  state.editUserInboundsError = "";
  state.editUserInboundIds = Array.isArray(user.inboundIds) && user.inboundIds.length
    ? user.inboundIds.filter((value) => typeof value === "string" && value.trim())
    : [user.inboundId].filter(Boolean);
  state.editUserInboundId = preferredMarzbanInboundId(state.editUserInboundIds, user.inboundId);
  state.editUserExpiryDate = normalizeDateInputValue(user.expiresAt);
  state.editUserFlow = user.flow || "";
  state.editUserActive = user.active !== false;
  state.editUserError = "";
  modal("Edit VPN account", editUserModalBody());
  if (panel?.type === "marzban") {
    void loadEditUserInbounds(user.id, user.panelId, { silent: true });
  } else {
    state.editUserInboundsLoading = false;
  }
}

function editUserModalBody() {
  const panel = state.data?.panels?.find((item) => item.id === state.editUserPanelId);
  const isMarzban = panel?.type === "marzban";
  return `
    <form class="form edit-user-form" onsubmit="window.Aegis.saveEditUser(event)">
      <label>Username<input name="username" readonly value="${esc(state.editUserUsername)}" /></label>
      <label>Panel<input readonly value="${esc(panelName(state.editUserPanelId))}" /></label>
      <div id="edit-user-inbound-field">${isMarzban ? editUserInboundField() : `<label>Inbound<input name="inboundId" value="${esc(state.editUserInboundId || "")}" /></label>`}</div>
      <label>Flow<input name="flow" value="${esc(state.editUserFlow)}" placeholder="xtls-rprx-vision, optional" /></label>
      <label class="inline-check">Active<input name="active" type="checkbox"${state.editUserActive ? " checked" : ""} /></label>
      <div id="edit-user-expiry-field">${editUserExpiryField()}</div>
      <div id="edit-user-error">${state.editUserError ? `<p class="alert danger">${esc(state.editUserError)}</p>` : ""}</div>
      <button class="primary" type="submit">Save VPN account</button>
    </form>
  `;
}

function editUserInboundField() {
  const panel = state.data?.panels?.find((item) => item.id === state.editUserPanelId);
  if (panel?.type !== "marzban") {
    return `<label>Inbound<input name="inboundId" value="${esc(state.editUserInboundId || "")}" /></label>`;
  }
  return renderMarzbanInboundPicker({
    title: "Inbounds",
    inbounds: state.editUserInbounds,
    selectedIds: state.editUserInboundIds,
    loading: state.editUserInboundsLoading,
    error: state.editUserInboundsError,
    emptyMessage: "This Marzban panel has no inbounds yet. Load inbounds before saving the VPN account.",
    toggleAction: "toggleEditMarzbanInboundSelection",
    selectAllAction: "selectAllEditMarzbanInbounds",
    clearAction: "clearEditMarzbanInbounds"
  });
}

function refreshEditUserInboundField() {
  const field = document.querySelector("#edit-user-inbound-field");
  if (!field) {
    setModal("Edit VPN account", editUserModalBody());
    return;
  }
  field.innerHTML = editUserInboundField();
}

function refreshEditUserError() {
  const field = document.querySelector("#edit-user-error");
  if (!field) {
    setModal("Edit VPN account", editUserModalBody());
    return;
  }
  field.innerHTML = state.editUserError ? `<p class="alert danger">${esc(state.editUserError)}</p>` : "";
}

function refreshEditUserExpiryField() {
  const field = document.querySelector("#edit-user-expiry-field");
  if (!field) {
    setModal("Edit VPN account", editUserModalBody());
    return;
  }
  field.innerHTML = editUserExpiryField();
}

function toggleEditMarzbanInboundSelection(id, checked) {
  const selected = new Set(state.editUserInboundIds);
  if (checked) selected.add(id);
  else selected.delete(id);
  state.editUserInboundIds = [...selected];
  state.editUserError = "";
  refreshEditUserInboundField();
  refreshEditUserError();
}

function selectAllEditMarzbanInbounds() {
  state.editUserInboundIds = state.editUserInbounds.map((inbound) => inbound.id);
  state.editUserError = "";
  refreshEditUserInboundField();
  refreshEditUserError();
}

function clearEditMarzbanInbounds() {
  state.editUserInboundIds = [];
  state.editUserError = "";
  refreshEditUserInboundField();
  refreshEditUserError();
}

function setEditUserExpiryDate(value) {
  state.editUserExpiryDate = value;
  state.editUserError = "";
  refreshEditUserExpiryField();
  refreshEditUserError();
}

function clearEditUserExpiry(event) {
  event?.preventDefault();
  event?.stopPropagation();
  state.editUserExpiryDate = "";
  refreshEditUserExpiryField();
}

function openEditUserExpiryPicker(event) {
  if (event?.target?.closest?.(".expiry-clear")) return;
  const input = document.querySelector("#edit-user-expiry-field .expiry-native");
  if (!input) return;
  if (typeof input.showPicker === "function") {
    input.showPicker();
    return;
  }
  input.focus();
  input.click?.();
}

async function loadEditUserInbounds(userId, panelId, { silent = false } = {}) {
  const panel = state.data?.panels?.find((item) => item.id === panelId);
  if (!panel) {
    state.editUserInbounds = [];
    state.editUserInboundsError = "Select a panel to load inbounds.";
    state.editUserInboundsLoading = false;
    state.editUserInboundIds = [];
    state.editUserInboundId = "";
    refreshEditUserInboundField();
    refreshEditUserError();
    return;
  }
  if (panel.type !== "marzban") {
    const user = state.users?.find((item) => item.id === userId);
    state.editUserInbounds = [];
    state.editUserInboundsError = "";
    state.editUserInboundsLoading = false;
    state.editUserInboundId = user?.inboundId || state.editUserInboundId || "";
    state.editUserInboundIds = [state.editUserInboundId].filter(Boolean);
    refreshEditUserInboundField();
    refreshEditUserError();
    return;
  }
  state.editUserInboundsLoading = true;
  state.editUserInboundsError = "";
  state.editUserInbounds = [];
  refreshEditUserInboundField();
  refreshEditUserError();
  try {
    const rows = await api(`/api/admin/panels/${panelId}/inbounds`);
    state.editUserInbounds = rows;
    const existing = state.editUserInboundIds.length ? state.editUserInboundIds : [state.editUserInboundId].filter(Boolean);
    const selected = existing.filter((id) => rows.some((row) => row.id === id));
    state.editUserInboundIds = selected.length ? selected : rows.map((row) => row.id);
    state.editUserInboundId = preferredMarzbanInboundId(state.editUserInboundIds, state.editUserInboundId);
    state.editUserInboundsError = "";
  } catch (error) {
    state.editUserInbounds = [];
    state.editUserInboundIds = [];
    state.editUserInboundId = "";
    state.editUserInboundsError = error.message || "Failed to load Marzban inbounds";
  } finally {
    state.editUserInboundsLoading = false;
    refreshEditUserInboundField();
    refreshEditUserError();
  }
}

async function saveEditUser(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const user = state.users?.find((item) => item.id === state.editUserId);
  const panel = state.data?.panels?.find((item) => item.id === state.editUserPanelId);
  state.error = "";
  state.editUserError = "";
  refreshEditUserError();
  try {
    if (!user) throw new Error("User not found");
    if (panel?.type === "marzban") {
      if (state.editUserInboundsLoading) {
        throw new Error("Please wait for Marzban inbounds to load.");
      }
      const selectedInbounds = state.editUserInbounds.filter((inbound) => state.editUserInboundIds.includes(inbound.id));
      if (!selectedInbounds.length) {
        throw new Error("Select a Marzban inbound before saving the VPN account.");
      }
      const inboundIds = selectedInbounds.map((inbound) => inbound.id);
      const expiresAt = resolveEditUserExpiry(form);
      await api(`/api/admin/users/${user.id}`, {
        method: "PUT",
        body: {
          inboundIds,
          inboundId: preferredMarzbanInboundId(inboundIds),
          inboundMode: inboundModeFromSelection(inboundIds, state.editUserInbounds.map((inbound) => inbound.id)),
          expiresAt,
          flow: form.get("flow") || "",
          active: form.has("active")
        }
      });
    } else {
      await api(`/api/admin/users/${user.id}`, {
        method: "PUT",
        body: {
          inboundId: form.get("inboundId") || user.inboundId || "default",
          expiresAt: resolveEditUserExpiry(form),
          flow: form.get("flow") || "",
          active: form.has("active")
        }
      });
    }
    closeModal();
    state.notice = "VPN account updated";
    await load();
  } catch (error) {
    state.editUserError = error.message;
    refreshEditUserError();
  }
}

function resolveEditUserExpiry(form) {
  const value = state.editUserExpiryDate || form.get("expiresAtDate") || "";
  if (!value) return null;
  return resolveLocalDateEndOfDay(value, "Please select a valid expiry date.");
}

function resolveCreateUserExpiry(form) {
  const value = state.createUserExpiryDate || form.get("expiresAtDate") || "";
  if (!value) return null;
  return resolveLocalDateEndOfDay(value, "Please select a valid expiry date.");
}

function resolveLocalDateEndOfDay(value, errorMessage = "Please select a valid date.") {
  if (!value) return null;
  const date = new Date(`${value}T23:59:59`);
  if (Number.isNaN(date.getTime())) {
    throw new Error(errorMessage);
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
  if (!requireSuperadminUi()) return;
  await runAction(async () => {
    const result = await api(`/api/panels/${id}/sync`, { method: "POST" });
    state.notice = `Sync complete: pulled ${result.pulled}, pushed ${result.pushed}`;
  }, state.notice || "Panel synced");
}

async function loadPanelInbounds(id) {
  if (!requireSuperadminUi()) return;
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
  if (!requireSuperadminUi()) return;
  if (!confirm("Delete this panel?")) return;
  await runAction(() => api(`/api/superadmin/panels/${id}`, { method: "DELETE" }), "Panel deleted");
}

async function deleteAdmin(id) {
  if (!requireSuperadminUi()) return;
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
  if (!requireSuperadminUi()) return;
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
  showEditUserForm,
  showNewsForm,
  createPanel,
  createAdmin,
  createUser,
  saveEditUser,
  loadUserInbounds,
  loadEditUserInbounds,
  toggleMarzbanInboundSelection,
  selectAllMarzbanInbounds,
  clearMarzbanInbounds,
  setCreateUserExpiryDate,
  clearCreateUserExpiry,
  openCreateUserExpiryPicker,
  toggleEditMarzbanInboundSelection,
  selectAllEditMarzbanInbounds,
  clearEditMarzbanInbounds,
  setEditUserExpiryDate,
  clearEditUserExpiry,
  openEditUserExpiryPicker,
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
