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
  testingPanelId: null,
  restoreBackupError: "",
  editPanelId: "",
  editPanel: null,
  editPanelLoading: false,
  editPanelError: "",
  editAdminId: "",
  editAdminUsername: "",
  editAdminPanelId: "",
  createAdminInbounds: [],
  createAdminInboundsLoading: false,
  createAdminInboundsError: "",
  createAdminInboundIds: [],
  editAdminInbounds: [],
  editAdminInboundsLoading: false,
  editAdminInboundsError: "",
  editAdminInboundIds: [],
  editAdminLimitGb: "",
  editAdminRemainingGb: "",
  editAdminValidUntilDate: "",
  editAdminActive: true,
  editAdminDeleteReturnTraffic: true,
  editAdminUpdateReturnTraffic: true,
  editAdminError: "",
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
  editUserLimitGb: "0",
  editUserExpiryDate: "",
  editUserNote: "",
  editUserFlow: "",
  editUserActive: true,
  editUserProtocolOpen: "",
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
  return isReseller() ? ["dashboard", "users"] : ["dashboard", "panels", "admins", "operations"];
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
  } else if (isSuperadmin() && state.view === "users") {
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

function trafficDisplay(value) {
  if (value == null) return "Unlimited traffic";
  return bytes(value);
}

function gbToBytes(value) {
  return Math.max(0, Number(value || 0)) * 1024 ** 3;
}

function bytesToGbInputValue(value) {
  const bytesValue = Number(value);
  if (!Number.isFinite(bytesValue) || bytesValue < 0) return "0";
  return String(Math.round((bytesValue / 1024 ** 3) * 1000) / 1000);
}

function todayDateInputValue() {
  const now = new Date();
  const year = now.getFullYear();
  const month = pad2(now.getMonth() + 1);
  const day = pad2(now.getDate());
  return `${year}-${month}-${day}`;
}

function dateOnlyValue(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const year = date.getFullYear();
  const month = pad2(date.getMonth() + 1);
  const day = pad2(date.getDate());
  return `${year}-${month}-${day}`;
}

function daysBetweenDates(value) {
  if (!value) return null;
  const selected = new Date(`${value}T00:00:00`);
  if (Number.isNaN(selected.getTime())) return null;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  selected.setHours(0, 0, 0, 0);
  return Math.round((selected.getTime() - today.getTime()) / 86400000);
}

function relativeExpiryText(value) {
  const diff = daysBetweenDates(value);
  if (diff === null) return "";
  if (diff === 0) return "Expires today";
  if (diff > 0) return `Expires in ${diff} day${diff === 1 ? "" : "s"}`;
  const abs = Math.abs(diff);
  return `Expired ${abs} day${abs === 1 ? "" : "s"} ago`;
}

function dateShort(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

function formatValidityDaysLeft(validUntil) {
  if (!validUntil) return "Unlimited validity";
  const date = new Date(validUntil);
  if (Number.isNaN(date.getTime())) return "Unlimited validity";
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const expiry = new Date(date);
  expiry.setHours(0, 0, 0, 0);
  const diff = Math.round((expiry.getTime() - today.getTime()) / 86400000);
  if (diff < 0) return "Expired";
  if (diff === 0) return "Expires today";
  return `${diff} day${diff === 1 ? "" : "s"} left`;
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
  state.editPanelId = "";
  state.editPanel = null;
  state.editPanelLoading = false;
  state.editPanelError = "";
  state.editAdminId = "";
  state.editAdminUsername = "";
  state.editAdminPanelId = "";
  state.createAdminInbounds = [];
  state.createAdminInboundsLoading = false;
  state.createAdminInboundsError = "";
  state.createAdminInboundIds = [];
  state.editAdminInbounds = [];
  state.editAdminInboundsLoading = false;
  state.editAdminInboundsError = "";
  state.editAdminInboundIds = [];
  state.editAdminLimitGb = "";
  state.editAdminRemainingGb = "";
  state.editAdminValidUntilDate = "";
  state.editAdminActive = true;
  state.editAdminDeleteReturnTraffic = true;
  state.editAdminUpdateReturnTraffic = true;
  state.editAdminError = "";
  state.editUserId = "";
  state.editUserUsername = "";
  state.editUserPanelId = "";
  state.editUserInbounds = [];
  state.editUserInboundsLoading = false;
  state.editUserInboundsError = "";
  state.editUserInboundId = "";
  state.editUserInboundIds = [];
  state.editUserLimitGb = "0";
  state.editUserExpiryDate = "";
  state.editUserNote = "";
  state.editUserFlow = "";
  state.editUserActive = true;
  state.editUserProtocolOpen = "";
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
        ["dashboard", "Dashboard", "Quota and validity"],
        ["users", "Users", "Customers and traffic"]
      ]
    : [
        ["dashboard", "Dashboard", "Overview and live totals"],
        ["panels", "Panels", "Panel registry and sync"],
        ["admins", "Resellers", "SuperAdmin and reseller accounts"],
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

function pageTitle(title, subtitle, action = "", options = {}) {
  const showRefresh = options.showRefresh !== false;
  return `
    <header class="topbar">
      <div>
        <p class="eyebrow">AegisPanel</p>
        <h2>${title}</h2>
        <p class="muted">${subtitle}</p>
      </div>
      <div class="actions">
        ${showRefresh ? `<button class="ghost" onclick="window.Aegis.load()">Refresh</button>` : ""}
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

function createUserLabel() {
  return isReseller() ? "Create User" : "Create VPN account";
}

function editUserLabel() {
  return isReseller() ? "Edit User" : "Edit VPN account";
}

function saveUserLabel() {
  return isReseller() ? "Save User" : "Save VPN account";
}

function singleUserLabel() {
  return isReseller() ? "User" : "VPN account";
}

function iconActionButton(icon, title, onclick, { disabled = false, className = "" } = {}) {
  const disabledAttr = disabled ? " disabled" : "";
  const clickAttr = disabled ? "" : ` onclick="${onclick}"`;
  const label = esc(title);
  return `<button class="ghost icon-action ${className}" title="${label}" aria-label="${label}"${disabledAttr}${clickAttr}><span aria-hidden="true">${icon}</span></button>`;
}

function renderExpirySummary(value) {
  if (!value) {
    return `<div class="expiry-summary"><strong>Unlimited</strong></div>`;
  }
  const short = dateShort(value);
  const helper = relativeExpiryText(value);
  return `<div class="expiry-summary"><strong>${esc(short)}</strong>${helper ? `<small class="muted block">${esc(helper)}</small>` : ""}</div>`;
}

function renderSubscriptionLinkAction(user) {
  if (!isValidSubscriptionUrl(user?.subscriptionUrl)) {
    return iconActionButton("🔗", "No subscription link", "", { disabled: true, className: "link-action" });
  }
  return iconActionButton("🔗", "Copy subscription link", `window.Aegis.copySubscriptionLink('${esc(user.id)}')`, { className: "link-action" });
}

function renderUserRowActions(user, { compact = false } = {}) {
  const editLabel = compact ? "Edit" : "Edit User";
  const deleteLabel = compact ? "Delete" : "Delete User";
  const syncLabel = state.syncingUserId === user.id ? "Syncing..." : "Sync traffic";
  return `
    ${iconActionButton("✎", editLabel, `window.Aegis.showEditUserForm('${esc(user.id)}')`, { className: "edit-action" })}
    ${renderSubscriptionLinkAction(user)}
    ${iconActionButton("↻", syncLabel, `window.Aegis.syncUserTraffic('${esc(user.id)}')`, {
      disabled: state.syncingUserId === user.id,
      className: "sync-action"
    })}
    ${iconActionButton("🗑", deleteLabel, `window.Aegis.deleteUser('${esc(user.id)}')`, { className: "delete-action" })}
  `;
}

function isValidSubscriptionUrl(value) {
  if (typeof value !== "string" || !value.trim()) return false;
  try {
    const url = new URL(value.trim());
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function dashboard() {
  const totals = state.data?.totals || {};
  if (isReseller()) {
    const assignedPanel = panelName(state.admin?.panelId);
    const quotaLimit = Number(state.admin?.trafficLimitBytes || 0);
    const quotaRemaining = Number(state.admin?.trafficRemainingBytes ?? state.admin?.trafficLimitBytes ?? 0);
    const quotaAllocated = state.admin?.trafficRemainingBytes == null ? null : Math.max(0, quotaLimit - quotaRemaining);
    const users = state.users || [];
    return `
      ${pageTitle("Dashboard", "Manage your users, traffic, and remaining validity.", `<button class="primary" onclick="window.Aegis.showUserForm()">Create User</button>`)}
      <section class="card section">
        <p class="muted section-note">You can create users within your assigned quota and validity.</p>
        <div class="metrics">
          ${metric("Assigned Panel", assignedPanel, "scoped panel")}
          ${metric("Remaining Traffic", trafficDisplay(state.admin?.trafficRemainingBytes), "available")}
          ${metric("Validity Left", formatValidityDaysLeft(state.admin?.validUntil), "calendar days")}
          ${metric("Allocated Traffic", quotaAllocated == null ? "Unlimited traffic" : bytes(quotaAllocated), "assigned to users")}
          ${metric("Active Users", users.filter((user) => user.active).length, "currently active")}
          ${metric("Total Users", users.length, "all scoped users")}
        </div>
        <div class="reseller-summary">
          <table class="table compact-table">
            <tbody>
              <tr><td>Assigned Panel</td><td>${esc(assignedPanel)}</td></tr>
              <tr><td>Validity</td><td>${esc(formatValidityDaysLeft(state.admin?.validUntil))}</td></tr>
              <tr><td>Notes</td><td>User expiry must stay within your reseller validity window.</td></tr>
            </tbody>
          </table>
        </div>
      </section>
      <section class="card section">
        <div class="card-head"><h3>Users</h3><button class="primary" onclick="window.Aegis.showUserForm()">Create User</button></div>
        ${users.length ? `
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>User</th><th>Used</th><th>Limit</th><th>Expiry</th><th>Status</th><th>Actions</th></tr></thead>
              <tbody>
                ${users.map((u) => `
                  <tr>
                    <td><strong>${esc(u.username)}</strong><small class="block mono">${esc(u.uuid || u.subscriptionId || "")}</small></td>
                    <td>${bytes(u.usedBytes)}</td>
                    <td>${bytes(u.limitBytes)}</td>
                    <td>${dateShort(u.expiresAt)}</td>
                    <td><span class="badge ${u.active ? "green" : "red"}">${u.active ? "Active" : "Off"}</span></td>
                    <td class="row-actions">
                      <button class="ghost" onclick="window.Aegis.showEditUserForm('${u.id}')">Edit User</button>
                      ${renderSubscriptionLinkAction(u)}
                      <button class="ghost" ${state.syncingUserId === u.id ? "disabled" : `onclick="window.Aegis.syncUserTraffic('${u.id}')"`}>
                        ${state.syncingUserId === u.id ? "Syncing..." : "Sync traffic"}
                      </button>
                      <button class="danger-btn" onclick="window.Aegis.deleteUser('${u.id}')">Delete User</button>
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        ` : `<p class="muted">No users yet.</p>`}
      </section>
    `;
  }
  return `
    ${pageTitle("Dashboard", "Overview of panels, resellers, users, and traffic.")}
    <section class="metrics">
      ${metric("Resellers", totals.resellers, "reseller accounts")}
      ${metric("Panels", totals.panels, "registered upstreams")}
      ${metric("Users", totals.users, `${totals.activeUsers || 0} active users`)}
      ${metric("Traffic Used", bytes(totals.usedBytes), `${bytes(totals.limitBytes)} allocated to users`)}
    </section>
  `;
}

function panels() {
  const rows = state.data?.panels || [];
  return `
    ${pageTitle("Panels", "Create upstream panels, check adapter capability, and trigger sync jobs.", `<button class="primary" onclick="window.Aegis.showPanelForm()">New panel</button>`, { showRefresh: false })}
    <section class="card">
      <div class="table-wrap">
        <table class="table panels-table">
          <thead><tr><th>Name</th><th>Type</th><th>URL</th><th>Sub URL</th><th>Status</th><th>Last Sync</th><th></th></tr></thead>
          <tbody>
            ${rows.map((p) => `
              <tr>
                <td><strong>${esc(p.name)}</strong></td>
                <td><span class="badge">${esc(panelLabel(p.type))}</span></td>
                <td class="mono ellipsis-cell" title="${esc(p.url)}">${esc(p.url)}</td>
                <td class="mono ellipsis-cell" title="${esc(p.subscriptionUrl || "-")}">${esc(p.subscriptionUrl || "-")}</td>
                <td><span class="badge ${p.active ? "green" : "red"}">${p.active ? "Active" : "Off"}</span></td>
                <td>${dateShort(p.lastSyncAt)}</td>
                <td class="row-actions icon-actions">
                  ${iconActionButton("✎", "Edit panel", `window.Aegis.showEditPanelForm('${esc(p.id)}')`, { className: "edit-action" })}
                  ${iconActionButton("≡", "View inbounds", `window.Aegis.loadPanelInbounds('${esc(p.id)}')`, { className: "inbounds-action" })}
                  ${state.testingPanelId === p.id
                    ? iconActionButton("✓", "Testing connection", "", { disabled: true, className: "test-action" })
                    : iconActionButton("✓", "Test connection", `window.Aegis.testPanelConnection('${esc(p.id)}')`, { className: "test-action" })}
                  ${p.type === "marzban"
                    ? iconActionButton("↻", "Sync not ready", "", { disabled: true, className: "sync-action" })
                    : iconActionButton("↻", "Sync panel", `window.Aegis.syncPanel('${esc(p.id)}')`, { className: "sync-action" })}
                  ${iconActionButton("🗑", "Delete panel", `window.Aegis.deletePanel('${esc(p.id)}')`, { className: "delete-action" })}
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
  const rows = (state.admins || []).filter((admin) => admin.role === "admin");
  return `
    ${pageTitle("Resellers", "Manage reseller accounts with traffic quota and validity windows.", `<button class="primary" onclick="window.Aegis.showAdminForm()">New reseller</button>`, { showRefresh: false })}
    <section class="card">
      <p class="muted section-note">Resellers receive quota and validity from SuperAdmin. Future reseller limits should stay within the assigned validity window.</p>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Username</th><th>Panel</th><th>Users</th><th>Allocated</th><th>Used</th><th>Remaining</th><th>Limit</th><th>Valid until</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>
            ${rows.map((a) => `
              <tr>
                <td><strong>${esc(a.username)}</strong></td>
                <td>${esc(panelName(a.panelId))}</td>
                <td>${a.userCount ?? 0}</td>
                <td>${bytes(a.allocatedTrafficBytes ?? 0)}</td>
                <td>${bytes(a.usedTrafficBytes ?? 0)}</td>
                <td>${trafficDisplay(a.remainingTrafficBytes)}</td>
                <td>${trafficDisplay(a.trafficLimitBytes)}</td>
                <td>${esc(formatValidityDaysLeft(a.validUntil))}</td>
                <td><span class="badge ${a.active ? "green" : "red"}">${a.active ? "Active" : "Off"}</span></td>
                <td class="row-actions">${iconActionButton("✎", "Edit reseller", `window.Aegis.showEditAdminForm('${esc(a.id)}')`, { className: "edit-action" })}${iconActionButton("🗑", "Delete reseller", `window.Aegis.deleteAdmin('${esc(a.id)}')`, { className: "delete-action" })}</td>
              </tr>
            `).join("") || emptyRow(10, "No resellers yet.")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function users() {
  if (isReseller()) {
    const rows = state.users || [];
    return `
      ${pageTitle("Users", "Create and manage customer users within your assigned traffic and validity.", `<button class="primary" onclick="window.Aegis.showUserForm()">Create User</button>`, { showRefresh: false })}
      <section class="card">
        <p class="muted section-note">Create and manage customer users within your assigned quota and validity window.</p>
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th>User</th><th>Used</th><th>Limit</th><th>Expiry</th><th>Status</th><th>Actions</th></tr></thead>
              <tbody>
                ${rows.map((u) => `
                  <tr>
                    <td><strong>${esc(u.username)}</strong><small class="block mono">${esc(u.uuid || u.subscriptionId || "")}</small></td>
                    <td>${bytes(u.usedBytes)}</td>
                    <td>${bytes(u.limitBytes)}</td>
                    <td>${renderExpirySummary(u.expiresAt)}</td>
                    <td><span class="badge ${u.active ? "green" : "red"}">${u.active ? "Active" : "Off"}</span></td>
                    <td class="row-actions icon-actions">${renderUserRowActions(u, { compact: true })}</td>
                  </tr>
                `).join("") || emptyRow(6, "No users yet.")}
              </tbody>
            </table>
        </div>
      </section>
    `;
  }
  return `
    ${pageTitle("Users", "Customer users and owner visibility across assigned quota and validity.", "", { showRefresh: false })}
    <section class="card">
      <p class="muted section-note">Customer users are created for reseller customers and should stay within the reseller's assigned traffic quota and validity period.</p>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>User</th><th>Owner / Reseller</th><th>Panel</th><th>Inbound</th><th>Used</th><th>Limit</th><th>Expiry</th><th>Status</th><th></th></tr></thead>
              <tbody>
                ${state.users.map((u) => `
                  <tr>
                    <td><strong>${esc(u.username)}</strong><small class="block mono">${esc(u.uuid || u.subscriptionId || "")}</small></td>
                    <td>${esc(u.ownerUsername || "Orphaned")}</td>
                    <td>${esc(panelName(u.panelId))}</td>
                    <td>${esc(vpnAccountInboundSummary(u))}</td>
                    <td>${bytes(u.usedBytes)}</td>
                    <td>${bytes(u.limitBytes)}</td>
                    <td>${renderExpirySummary(u.expiresAt)}</td>
                    <td><span class="badge ${u.active ? "green" : "red"}">${u.active ? "Active" : "Off"}</span></td>
                    <td class="row-actions icon-actions">${renderUserRowActions(u)}</td>
                  </tr>
                `).join("") || emptyRow(9, "No users yet.")}
              </tbody>
            </table>
      </div>
    </section>
  `;
}

function operations() {
  return `
    ${pageTitle("Operations", "Backup and restore JSON, audit logs, news, and system maintenance.")}
    <section class="metrics">
      ${metric("CPU Cores", state.system?.cpuCount || "-", "host")}
      ${metric("Free Memory", bytes(state.system?.memory?.free), "available")}
      ${metric("App Uptime", `${Math.floor((state.system?.appUptimeSeconds || 0) / 60)}m`, "runtime")}
      ${metric("Logs", state.logs.length, "audit records")}
    </section>
    <section class="ops-grid">
      <article class="card ops-card">
        <div class="card-head"><h3>Backup JSON</h3><span class="muted">Download a local snapshot.</span></div>
        <p class="muted ops-copy">Backup may include stored panel credentials. Keep this file private.</p>
        <button class="primary" onclick="window.Aegis.downloadBackup()">Backup JSON</button>
      </article>
      <article class="card ops-card">
        <div class="card-head"><h3>Restore JSON</h3><span class="muted">Upload a backup and confirm.</span></div>
        <p class="muted ops-copy">Restore replaces the local store after RESTORE confirmation.</p>
        <button class="ghost" onclick="window.Aegis.showRestoreBackupForm()">Restore JSON</button>
      </article>
      <article class="card ops-card">
        <div class="card-head"><h3>Audit Logs</h3><span class="muted">Latest system and admin events.</span></div>
        <p class="muted ops-copy">View the newest audit entries in a compact modal.</p>
        <button class="ghost" onclick="window.Aegis.showAuditLogs()">Show Logs</button>
      </article>
      <article class="card ops-card">
        <div class="card-head"><h3>News</h3><span class="muted">Operator announcements and notices.</span></div>
        <p class="muted ops-copy">View recent news or create a new notice.</p>
        <div class="actions">
          <button class="ghost" onclick="window.Aegis.showNewsList()">Show News</button>
          <button class="ghost" onclick="window.Aegis.showNewsForm()">Create News</button>
        </div>
      </article>
      <article class="card ops-card ops-span-2">
        <div class="card-head"><h3>System</h3><span class="pill">local node</span></div>
        <table class="table compact-table ops-system-table">
          <tbody>
            <tr><td>Host uptime</td><td>${Math.floor((state.system?.uptimeSeconds || 0) / 3600)}h</td></tr>
            <tr><td>Load average</td><td>${(state.system?.loadAverage || []).map((n) => Number(n).toFixed(2)).join(" / ")}</td></tr>
            <tr><td>Total memory</td><td>${bytes(state.system?.memory?.total)}</td></tr>
          </tbody>
        </table>
      </article>
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

function restoreBackupModalBody() {
  return `
    <form class="form" onsubmit="window.Aegis.restoreBackup(event)">
      <label>Backup file<input name="backupFile" type="file" accept=".json,application/json" required onchange="window.Aegis.clearRestoreBackupError()" /></label>
      <label>Confirmation<input name="confirmation" autocomplete="off" placeholder="RESTORE" required oninput="window.Aegis.clearRestoreBackupError()" /></label>
      <p class="muted">Type RESTORE before restoring the local store.</p>
      <div id="restore-backup-error">${state.restoreBackupError ? `<p class="alert danger">${esc(state.restoreBackupError)}</p>` : ""}</div>
      <button class="primary" type="submit">Restore JSON</button>
    </form>
  `;
}

function showRestoreBackupForm() {
  if (!requireSuperadminUi()) return;
  modal("Restore JSON", restoreBackupModalBody());
}

function showAuditLogs() {
  if (!requireSuperadminUi()) return;
  modal("Audit Logs", `
    <p class="muted">Latest system and admin events.</p>
    ${logsTable(state.logs.slice(0, 10))}
  `);
}

function showNewsList() {
  if (!requireSuperadminUi()) return;
  modal("News", `
    <div class="notice-list">
      ${state.news.map((n) => `<div class="notice-item"><strong>${esc(n.title || "Update")}</strong><p>${esc(n.message || "")}</p></div>`).join("") || `<p class="muted">No news yet.</p>`}
    </div>
  `);
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
  const titleLower = String(title).toLowerCase();
  const wide = titleLower.includes("inbounds") || titleLower.includes("audit logs") ? " wide-modal" : "";
  const compact = titleLower.includes("edit vpn account") || titleLower.includes("edit user") || titleLower.includes("edit panel") || titleLower.includes("edit reseller") ? " edit-modal" : "";
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
      <label>Subscription URL Prefix<input name="subscriptionUrl" placeholder="https://panel.example.com" /></label>
      <small class="muted block">Matches Marzban XRAY_SUBSCRIPTION_URL_PREFIX</small>
      <label>Subscription Path<input name="subscriptionPath" placeholder="sub" /></label>
      <small class="muted block">Matches Marzban XRAY_SUBSCRIPTION_PATH. Default: sub</small>
      <label class="check-row"><input name="allowInsecureTls" type="checkbox" /> <span>Allow insecure TLS</span></label>
      <small class="muted block">Use only for test/self-signed/IP certificate panels.</small>
      <label>Username<input name="username" placeholder="panel admin, if needed" /></label>
      <label>Secret / API key<input name="secret" placeholder="stored locally for connector use" /></label>
      <button class="primary" type="submit">Create panel</button>
    </form>
  `);
}

async function showEditPanelForm(id) {
  if (!requireSuperadminUi()) return;
  state.editPanelId = id;
  state.editPanel = null;
  state.editPanelError = "";
  state.editPanelLoading = true;
  modal("Edit panel", `<p class="muted">Loading panel...</p>`);
  try {
    state.editPanel = await api(`/api/superadmin/panels/${id}`);
    state.editPanelLoading = false;
    setModal("Edit panel", editPanelModalBody());
  } catch (error) {
    state.editPanelLoading = false;
    setModal("Edit panel", `<p class="alert danger">${esc(error.message)}</p>`);
  }
}

function editPanelModalBody() {
  const panel = state.editPanel || {};
  return `
    <form class="form edit-panel-form" onsubmit="window.Aegis.savePanel(event)">
      <div class="edit-panel-main">
        <label>Name<input name="name" required value="${esc(panel.name || "")}" placeholder="Edge Tehran 01" /></label>
        <label>Panel URL<input name="url" required value="${esc(panel.url || "")}" placeholder="https://panel.example.com" /></label>
        <label>Subscription URL Prefix<input name="subscriptionUrl" value="${esc(panel.subscriptionUrl || "")}" placeholder="https://panel.example.com" /></label>
        <small class="muted block">Matches Marzban XRAY_SUBSCRIPTION_URL_PREFIX</small>
        <label>Username<input name="username" required value="${esc(panel.username || "")}" placeholder="panel admin, if needed" /></label>
        <label>Secret/API key<input name="secret" type="password" placeholder="Leave blank to keep existing" /></label>
        <label class="check-row"><input name="allowInsecureTls" type="checkbox"${panel.allowInsecureTls || panel.insecureTls ? " checked" : ""} /> <span>Allow insecure TLS</span></label>
        <small class="muted block">Use only for test/self-signed/IP certificate panels.</small>
      </div>
      <div class="edit-panel-side">
        <label>Type<select name="type" disabled><option value="${esc(panel.type || "")}" selected>${esc(panelLabel(panel.type) || panel.type || "-")}</option></select></label>
        <label>Subscription Path<input name="subscriptionPath" value="${esc(panel.subscriptionPath || "sub")}" placeholder="sub" /></label>
        <small class="muted block">Matches Marzban XRAY_SUBSCRIPTION_PATH. Default: sub</small>
        <label class="switch-field">
          <span>
            <strong>Status</strong>
            <small>${panel.active ? "Panel is active" : "Panel is disabled"}</small>
          </span>
          <span class="switch-control">
            <input name="active" type="checkbox"${panel.active !== false ? " checked" : ""} />
            <span class="switch-track" aria-hidden="true"></span>
          </span>
        </label>
        <label>Sync interval seconds<input name="syncIntervalSeconds" type="number" min="0" step="1" value="${esc(panel.syncIntervalSeconds ?? 300)}" /></label>
      </div>
      <div class="edit-panel-footer">
        <div id="edit-panel-error">${state.editPanelError ? `<p class="alert danger">${esc(state.editPanelError)}</p>` : ""}</div>
        <button class="primary" type="submit">Save panel</button>
      </div>
    </form>
  `;
}

function showAdminForm() {
  if (!requireSuperadminUi()) return;
  state.createAdminPanelId = state.data?.panels?.[0]?.id || "";
  state.createAdminInbounds = [];
  state.createAdminInboundsLoading = Boolean(state.createAdminPanelId && panelSupportsInboundLoading(state.data?.panels?.find((panel) => panel.id === state.createAdminPanelId)));
  state.createAdminInboundsError = "";
  state.createAdminInboundIds = [];
  modal("New reseller", createAdminModalBody());
  if (state.createAdminPanelId) {
    void loadCreateAdminInbounds(state.createAdminPanelId, { silent: true });
  }
}

function showEditAdminForm(id) {
  if (!requireSuperadminUi()) return;
  const admin = (state.admins || []).find((item) => item.id === id);
  if (!admin || admin.role !== "admin") {
    state.error = "Reseller not found";
    renderApp();
    return;
  }
  state.error = "";
  state.notice = "";
  state.editAdminId = admin.id;
  state.editAdminUsername = admin.username || "";
  state.editAdminPanelId = admin.panelId || "";
  state.editAdminLimitGb = admin.trafficLimitBytes == null ? "" : bytesToGbInputValue(admin.trafficLimitBytes);
  state.editAdminRemainingGb = admin.trafficRemainingBytes == null
    ? (admin.trafficLimitBytes == null ? "" : bytesToGbInputValue(admin.trafficLimitBytes))
    : bytesToGbInputValue(admin.trafficRemainingBytes);
  state.editAdminValidUntilDate = normalizeDateInputValue(admin.validUntil ?? admin.expiresAt);
  state.editAdminInboundIds = Array.isArray(admin.inboundIds) ? admin.inboundIds.filter((value) => typeof value === "string" && value.trim()) : [];
  state.editAdminInbounds = [];
  state.editAdminInboundsLoading = Boolean(admin.panelId && panelSupportsInboundLoading(state.data?.panels?.find((panel) => panel.id === admin.panelId)));
  state.editAdminInboundsError = "";
  state.editAdminActive = admin.active !== false;
  state.editAdminDeleteReturnTraffic = admin.deleteReturnTraffic !== false;
  state.editAdminUpdateReturnTraffic = admin.updateReturnTraffic !== false;
  state.editAdminError = "";
  modal("Edit reseller", editAdminModalBody());
  if (admin.panelId) {
    void loadEditAdminInbounds(admin.panelId, admin.id, { silent: true });
  }
}

function createAdminModalBody() {
  const panels = state.data?.panels || [];
  const panelOptions = panels.map((panel) => `<option value="${panel.id}"${panel.id === state.createAdminPanelId ? " selected" : ""}>${esc(panel.name)}</option>`).join("");
  const panel = panels.find((item) => item.id === state.createAdminPanelId);
  return `
    <form class="form edit-panel-form edit-admin-form" onsubmit="window.Aegis.createAdmin(event)">
      <div class="edit-panel-main">
        <label>Username<input name="username" required placeholder="reseller-01" /></label>
        <label>Password<input name="password" required type="password" placeholder="Strong password" /></label>
        <label>Role<select name="role"><option value="admin">Reseller</option><option value="superadmin">SuperAdmin</option></select></label>
        <label>Panel<select name="panelId" onchange="window.Aegis.loadCreateAdminInbounds(this.value)"><option value="">No fixed panel</option>${panelOptions}</select></label>
        <label>Traffic limit (GB)<input name="trafficGb" type="number" min="0" step="1" placeholder="100" /></label>
        <label>Valid until<input name="validUntilDate" type="date" /></label>
      </div>
      <div class="edit-panel-side">
        <div id="create-admin-inbounds-field">${createAdminInboundsField(panel)}</div>
      </div>
      <div class="edit-panel-footer">
        <div class="check-row"><label><input name="deleteReturnTraffic" type="checkbox" checked /> Return traffic on delete</label><label><input name="updateReturnTraffic" type="checkbox" checked /> Return traffic on update</label></div>
        <button class="primary" type="submit">Create reseller</button>
      </div>
    </form>
  `;
}

function editAdminInboundsField() {
  const panel = state.data?.panels?.find((item) => item.id === state.editAdminPanelId);
  if (!panelSupportsInboundLoading(panel)) {
    return `<p class="muted">This panel does not expose selectable inbounds.</p>`;
  }
  if (state.editAdminInboundsLoading) {
    return `<p class="muted">Loading inbounds...</p>`;
  }
  if (state.editAdminInboundsError) {
    return `<p class="alert danger">${esc(state.editAdminInboundsError)}</p>`;
  }
  return renderMarzbanInboundPicker({
    title: "Allowed inbounds",
    inbounds: state.editAdminInbounds,
    selectedIds: state.editAdminInboundIds,
    loading: false,
    error: "",
    emptyMessage: "This panel has no selectable inbounds yet.",
    toggleAction: "toggleEditAdminInboundSelection",
    selectAllAction: "selectAllEditAdminInbounds",
    clearAction: "clearEditAdminInbounds"
  });
}

function createAdminInboundsField(panel = state.data?.panels?.find((item) => item.id === state.createAdminPanelId)) {
  if (!panelSupportsInboundLoading(panel)) {
    return `<p class="muted">Select a panel to load allowed inbounds.</p>`;
  }
  if (state.createAdminInboundsLoading) {
    return `<p class="muted">Loading inbounds...</p>`;
  }
  if (state.createAdminInboundsError) {
    return `<p class="alert danger">${esc(state.createAdminInboundsError)}</p>`;
  }
  return renderMarzbanInboundPicker({
    title: "Allowed inbounds",
    inbounds: state.createAdminInbounds,
    selectedIds: state.createAdminInboundIds,
    loading: false,
    error: "",
    emptyMessage: "This panel has no selectable inbounds yet.",
    toggleAction: "toggleCreateAdminInboundSelection",
    selectAllAction: "selectAllCreateAdminInbounds",
    clearAction: "clearCreateAdminInbounds"
  });
}

function editAdminModalBody() {
  const panelOptions = (state.data?.panels || []).map((panel) => `<option value="${panel.id}"${panel.id === state.editAdminPanelId ? " selected" : ""}>${esc(panel.name)}</option>`).join("");
  return `
    <form class="form edit-panel-form edit-admin-form" onsubmit="window.Aegis.saveAdmin(event)">
      <div class="edit-panel-main">
        <label>Username<input name="username" readonly value="${esc(state.editAdminUsername)}" /></label>
        <label>Assigned Panel<select name="panelId" onchange="window.Aegis.loadEditAdminInbounds(this.value)"><option value=""${state.editAdminPanelId ? "" : " selected"}>No fixed panel</option>${panelOptions}</select></label>
        <label class="unit-field">
          <span>Traffic limit (GB)</span>
          <div class="unit-input">
            <input name="trafficLimitGb" type="number" min="0" step="any" value="${esc(state.editAdminLimitGb)}" />
            <span>GB</span>
          </div>
        </label>
        <label class="unit-field">
          <span>Traffic remaining (GB)</span>
          <div class="unit-input">
            <input name="trafficRemainingGb" type="number" min="0" step="any" value="${esc(state.editAdminRemainingGb)}" />
            <span>GB</span>
          </div>
        </label>
        <label>Valid until<input name="validUntilDate" type="date" value="${esc(state.editAdminValidUntilDate)}" /></label>
      </div>
      <div class="edit-panel-side">
        <div id="edit-admin-inbounds-field">${editAdminInboundsField()}</div>
        <label class="switch-field">
          <span>
            <strong>Status</strong>
            <small>${state.editAdminActive ? "Reseller is active" : "Reseller is disabled"}</small>
          </span>
          <span class="switch-control">
            <input name="active" type="checkbox"${state.editAdminActive ? " checked" : ""} />
            <span class="switch-track" aria-hidden="true"></span>
          </span>
        </label>
        <label class="switch-field">
          <span>
            <strong>Return traffic on delete</strong>
            <small>${state.editAdminDeleteReturnTraffic ? "Traffic is returned on delete" : "Traffic is not returned on delete"}</small>
          </span>
          <span class="switch-control">
            <input name="deleteReturnTraffic" type="checkbox"${state.editAdminDeleteReturnTraffic ? " checked" : ""} />
            <span class="switch-track" aria-hidden="true"></span>
          </span>
        </label>
        <label class="switch-field">
          <span>
            <strong>Return traffic on update</strong>
            <small>${state.editAdminUpdateReturnTraffic ? "Traffic is returned on update" : "Traffic is not returned on update"}</small>
          </span>
          <span class="switch-control">
            <input name="updateReturnTraffic" type="checkbox"${state.editAdminUpdateReturnTraffic ? " checked" : ""} />
            <span class="switch-track" aria-hidden="true"></span>
          </span>
        </label>
        <label>New password<input name="password" type="password" placeholder="Leave blank to keep existing" /></label>
      </div>
      <div class="edit-panel-footer">
        <div id="edit-admin-error">${state.editAdminError ? `<p class="alert danger">${esc(state.editAdminError)}</p>` : ""}</div>
        <button class="primary" type="submit">Save reseller</button>
      </div>
    </form>
  `;
}

function refreshEditAdminError() {
  const field = document.querySelector("#edit-admin-error");
  if (!field) {
    setModal("Edit reseller", editAdminModalBody());
    return;
  }
  field.innerHTML = state.editAdminError ? `<p class="alert danger">${esc(state.editAdminError)}</p>` : "";
}

async function saveAdmin(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  state.error = "";
  state.editAdminError = "";
  refreshEditAdminError();
  try {
    await api(`/api/superadmin/admins/${state.editAdminId}`, {
      method: "PUT",
      body: {
        username: form.get("username"),
        panelId: form.get("panelId") || null,
        inboundIds: state.editAdminInboundIds,
        trafficLimitBytes: form.get("trafficLimitGb") === "" ? null : gbToBytes(form.get("trafficLimitGb")),
        trafficRemainingBytes: form.get("trafficRemainingGb") === "" ? null : gbToBytes(form.get("trafficRemainingGb")),
        validUntil: resolveLocalDateEndOfDay(form.get("validUntilDate")),
        active: form.has("active"),
        deleteReturnTraffic: form.has("deleteReturnTraffic"),
        updateReturnTraffic: form.has("updateReturnTraffic"),
        password: form.get("password") || ""
      }
    });
    closeModal();
    state.notice = "Reseller updated";
    await load();
  } catch (error) {
    state.editAdminError = error.message;
    refreshEditAdminError();
  }
}

function showUserForm() {
  state.error = "";
  state.createUserError = "";
  state.createUserPanelId = isSuperadmin() ? state.data?.panels?.[0]?.id || "" : state.admin?.panelId || "";
  state.createUserInbounds = [];
  state.createUserInboundsLoading = false;
  state.createUserInboundsError = "";
  state.createUserInboundId = "";
  state.createUserInboundIds = [];
  state.createUserExpiryDate = "";
  modal(createUserModalTitle(), createUserModalBody());
  if (isSuperadmin() && state.createUserPanelId) {
    void loadUserInbounds(state.createUserPanelId, { silent: true });
  }
}

function createUserModalTitle() {
  return isReseller() ? "Create User" : "Create VPN account";
}

function createUserModalBody() {
  return isSuperadmin() ? createUserAdvancedModalBody() : createUserSimpleModalBody();
}

function createUserSimpleModalBody() {
  return `
    <form class="form create-user-form" onsubmit="window.Aegis.createUser(event)">
      <label>Username<input name="username" required placeholder="client-name" /></label>
      <label>Data Limit<div class="unit-input"><input name="limitGb" type="number" min="0" step="any" value="25" /><span>GB</span></div></label>
      <div id="user-expiry-field">${createUserExpiryField()}</div>
      <label>Note<textarea name="note" rows="3" placeholder="Optional note for operators, bots, or integrations"></textarea></label>
      <label class="switch-field">
        <span>
          <strong>Status</strong>
          <small>Active account</small>
        </span>
        <span class="switch-control">
          <input name="active" type="checkbox" checked />
          <span class="switch-track" aria-hidden="true"></span>
        </span>
      </label>
      <div id="user-create-error">${state.createUserError ? `<p class="alert danger">${esc(state.createUserError)}</p>` : ""}</div>
      <button class="primary" type="submit">${createUserLabel()}</button>
    </form>
  `;
}

function createUserAdvancedModalBody() {
  return `
    <form class="form create-user-form" onsubmit="window.Aegis.createUser(event)">
      <label>Username<input name="username" required placeholder="client-name" /></label>
      <label>Panel<select name="panelId" required onchange="window.Aegis.loadUserInbounds(this.value)">${(state.data?.panels || []).map((p) => `<option value="${p.id}"${p.id === state.createUserPanelId ? " selected" : ""}>${esc(p.name)}</option>`).join("")}</select></label>
      <div id="user-inbound-field">${createUserInboundField()}</div>
      <label>Flow<input name="flow" placeholder="xtls-rprx-vision, optional" /></label>
      <label>Data Limit<div class="unit-input"><input name="limitGb" type="number" min="0" step="any" value="25" /><span>GB</span></div></label>
      <div id="user-expiry-field">${createUserExpiryField()}</div>
      <label>Note<textarea name="note" rows="3" placeholder="Optional note for operators, bots, or integrations"></textarea></label>
      <label class="switch-field">
        <span>
          <strong>Status</strong>
          <small>Active account</small>
        </span>
        <span class="switch-control">
          <input name="active" type="checkbox" checked />
          <span class="switch-track" aria-hidden="true"></span>
        </span>
      </label>
      <div id="user-create-error">${state.createUserError ? `<p class="alert danger">${esc(state.createUserError)}</p>` : ""}</div>
      <button class="primary" type="submit">${createUserLabel()}</button>
    </form>
  `;
}

function createUserInboundField() {
  const panel = state.data?.panels?.find((item) => item.id === state.createUserPanelId);
  if (!panelSupportsInboundLoading(panel)) {
    return `<label>Inbound<input name="inboundId" placeholder="default" value="${esc(state.createUserInboundId || "")}" /></label>`;
  }
  return renderMarzbanInboundPicker({
    title: "Inbounds",
    inbounds: state.createUserInbounds,
    selectedIds: state.createUserInboundIds,
    loading: state.createUserInboundsLoading,
    error: state.createUserInboundsError,
    emptyMessage: "No inbounds available yet. Load inbounds before creating a VPN account.",
    toggleAction: "toggleMarzbanInboundSelection",
    selectAllAction: "selectAllMarzbanInbounds",
    clearAction: "clearMarzbanInbounds"
  });
}

function refreshUserInboundField() {
  const field = document.querySelector("#user-inbound-field");
  if (!field) {
    setModal(createUserModalTitle(), createUserModalBody());
    return;
  }
  field.innerHTML = createUserInboundField();
}

function refreshCreateUserError() {
  const field = document.querySelector("#user-create-error");
  if (!field) {
    setModal(createUserModalTitle(), createUserModalBody());
    return;
  }
  field.innerHTML = state.createUserError ? `<p class="alert danger">${esc(state.createUserError)}</p>` : "";
}

function refreshUserExpiryField() {
  const field = document.querySelector("#user-expiry-field");
  if (!field) {
    setModal(createUserModalTitle(), createUserModalBody());
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

function panelSupportsInboundLoading(panel) {
  return Boolean(panel?.capabilities?.canListInbounds);
}

function normalMarzbanInboundIds(inbounds) {
  return (inbounds || []).map((inbound) => inbound.id);
}

function preferredMarzbanInboundId(inboundIds, fallbackId = "") {
  const selected = Array.isArray(inboundIds) ? inboundIds.filter((id) => typeof id === "string" && id.trim()) : [];
  return selected[0] || fallbackId || "default";
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
    return `<p class="muted">Loading inbounds...</p>`;
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

function editUserProtocolDefs() {
  return [
    { key: "vmess", label: "VMess", description: "VMess configs" },
    { key: "vless", label: "VLess", description: "VLess configs" },
    { key: "trojan", label: "Trojan", description: "Trojan configs" },
    { key: "shadowsocks", label: "Shadowsocks", description: "Shadowsocks configs" }
  ];
}

function protocolKey(value) {
  return String(value || "").toLowerCase();
}

function editUserProtocolInbounds(protocol) {
  const key = protocolKey(protocol);
  return state.editUserInbounds.filter((inbound) => protocolKey(inbound.protocol) === key);
}

function editUserProtocolSelectedCount(protocolInbounds) {
  return protocolInbounds.filter((inbound) => state.editUserInboundIds.includes(inbound.id)).length;
}

function editUserProtocolSelectionSummary(protocolInbounds) {
  const total = protocolInbounds.length;
  const selected = editUserProtocolSelectedCount(protocolInbounds);
  if (!total) return "No configs available";
  if (!selected) return `${total} config${total === 1 ? "" : "s"} available`;
  return `${selected}/${total} selected`;
}

function renderEditUserProtocolCard({ key, label, description }, protocolInbounds) {
  const hasInbounds = protocolInbounds.length > 0;
  const open = state.editUserProtocolOpen === key;
  return `
    <div class="protocol-card${hasInbounds ? "" : " disabled"}${open ? " open" : ""}">
      <div class="protocol-card-body">
        <strong>${esc(label)}</strong>
        <small>${esc(hasInbounds ? editUserProtocolSelectionSummary(protocolInbounds) : "No configs available")}</small>
        <span>${esc(description)}</span>
      </div>
      <button
        type="button"
        class="protocol-card-menu"
        ${hasInbounds ? "" : "disabled"}
        aria-label="${esc(open ? `Close ${label} configs` : `Open ${label} configs`)}"
        aria-expanded="${open ? "true" : "false"}"
        onclick="window.Aegis.toggleEditUserProtocolPanel('${esc(key)}')"
      >⋮</button>
    </div>
  `;
}

function editUserProtocolsField() {
  if (state.editUserInboundsLoading) {
    return `
      <div class="compact-panel protocols-panel">
        <p class="muted">Loading inbounds...</p>
      </div>
    `;
  }
  if (state.editUserInboundsError) {
    return `
      <div class="compact-panel protocols-panel">
        <p class="alert danger">${esc(state.editUserInboundsError)}</p>
      </div>
    `;
  }
  const defs = editUserProtocolDefs();
  const openKey = state.editUserProtocolOpen;
  const openDef = defs.find((item) => item.key === openKey);
  const openInbounds = openDef ? editUserProtocolInbounds(openKey) : [];
  return `
    <div class="compact-panel protocols-panel">
      <div class="card-head compact-head">
        <div>
          <h4>Protocols</h4>
          <small class="muted">Open a protocol with the 3-dots menu to edit its configs.</small>
        </div>
      </div>
      <div class="protocol-grid">
        ${defs.map((def) => renderEditUserProtocolCard(def, editUserProtocolInbounds(def.key))).join("")}
      </div>
      ${openDef ? `
        <div class="protocol-popover">
          <div class="card-head compact-head">
            <div>
              <h4>${esc(openDef.label)} configs</h4>
              <small class="muted">${esc(editUserProtocolSelectionSummary(openInbounds))}</small>
            </div>
            <div class="actions">
              <button type="button" class="ghost" onclick="window.Aegis.selectEditUserProtocolInbounds('${esc(openDef.key)}')">Select all</button>
              <button type="button" class="ghost" onclick="window.Aegis.clearEditUserProtocolInbounds('${esc(openDef.key)}')">Clear</button>
            </div>
          </div>
          ${openInbounds.length ? `
            <div class="protocol-checklist">
              ${openInbounds.map((inbound) => `
                <label class="protocol-option ${state.editUserInboundIds.includes(inbound.id) ? "selected" : ""}">
                  <input
                    type="checkbox"
                    value="${esc(inbound.id)}"
                    ${state.editUserInboundIds.includes(inbound.id) ? "checked" : ""}
                    onchange="window.Aegis.toggleEditUserProtocolSelection('${esc(openDef.key)}', this.value, this.checked)"
                  />
                  <span>
                    <strong>${esc(formatInboundOption(inbound))}</strong>
                    <small>${esc(formatInboundDetails(inbound))}</small>
                  </span>
                </label>
              `).join("")}
            </div>
          ` : `<p class="muted">No configs available for this protocol.</p>`}
        </div>
      ` : ""}
    </div>
  `;
}

async function loadCreateAdminInbounds(panelId, { silent = false } = {}) {
  state.createAdminPanelId = panelId;
  const panel = state.data?.panels?.find((item) => item.id === panelId);
  if (!panel) {
    state.createAdminInbounds = [];
    state.createAdminInboundsError = "Select a panel to load inbounds.";
    state.createAdminInboundsLoading = false;
    state.createAdminInboundIds = [];
    refreshCreateAdminInboundsField();
    return;
  }
  if (!panelSupportsInboundLoading(panel)) {
    state.createAdminInbounds = [];
    state.createAdminInboundsError = "";
    state.createAdminInboundsLoading = false;
    state.createAdminInboundIds = [];
    refreshCreateAdminInboundsField();
    return;
  }
  state.createAdminInboundsLoading = true;
  state.createAdminInboundsError = "";
  state.createAdminInbounds = [];
  state.createAdminInboundIds = [];
  refreshCreateAdminInboundsField();
  try {
    const rows = await api(`/api/admin/panels/${panelId}/inbounds`);
    state.createAdminInbounds = rows;
    state.createAdminInboundIds = normalMarzbanInboundIds(rows);
    state.createAdminInboundsError = state.createAdminInboundIds.length > 0 ? "" : "This panel has no selectable inbounds yet.";
  } catch (error) {
    state.createAdminInbounds = [];
    state.createAdminInboundIds = [];
    state.createAdminInboundsError = error.message || "Failed to load inbounds";
  } finally {
    state.createAdminInboundsLoading = false;
    refreshCreateAdminInboundsField();
  }
}

async function loadEditAdminInbounds(panelId, adminId, { silent = false } = {}) {
  state.editAdminPanelId = panelId;
  const panel = state.data?.panels?.find((item) => item.id === panelId);
  if (!panel) {
    state.editAdminInbounds = [];
    state.editAdminInboundsError = "Select a panel to load inbounds.";
    state.editAdminInboundsLoading = false;
    state.editAdminInboundIds = [];
    refreshEditAdminInboundsField();
    refreshEditAdminError();
    return;
  }
  if (!panelSupportsInboundLoading(panel)) {
    state.editAdminInbounds = [];
    state.editAdminInboundsError = "";
    state.editAdminInboundsLoading = false;
    state.editAdminInboundIds = [];
    refreshEditAdminInboundsField();
    refreshEditAdminError();
    return;
  }
  state.editAdminInboundsLoading = true;
  state.editAdminInboundsError = "";
  state.editAdminInbounds = [];
  if (!silent) refreshEditAdminInboundsField();
  refreshEditAdminError();
  try {
    const rows = await api(`/api/admin/panels/${panelId}/inbounds`);
    state.editAdminInbounds = rows;
    const existing = state.editAdminInboundIds.length ? state.editAdminInboundIds : (state.admins || []).find((item) => item.id === adminId)?.inboundIds || [];
    const selected = existing.filter((id) => rows.some((row) => row.id === id));
    state.editAdminInboundIds = selected;
    if (!rows.length) {
      state.editAdminInboundsError = "This panel has no selectable inbounds yet.";
    } else if (selected.length) {
      state.editAdminInboundsError = "";
    } else if (existing.length) {
      state.editAdminInboundsError = "Saved allowed inbounds are no longer available on this panel.";
    } else {
      state.editAdminInboundsError = "Select allowed inbounds for this reseller.";
    }
  } catch (error) {
    state.editAdminInbounds = [];
    state.editAdminInboundIds = [];
    state.editAdminInboundsError = error.message || "Failed to load inbounds";
  } finally {
    state.editAdminInboundsLoading = false;
    refreshEditAdminInboundsField();
    refreshEditAdminError();
  }
}

function toggleCreateAdminInboundSelection(id, checked) {
  const selected = new Set(state.createAdminInboundIds);
  if (checked) selected.add(id);
  else selected.delete(id);
  state.createAdminInboundIds = [...selected];
  state.createAdminInboundsError = "";
  refreshCreateAdminInboundsField();
}

function selectAllCreateAdminInbounds() {
  state.createAdminInboundIds = normalMarzbanInboundIds(state.createAdminInbounds);
  state.createAdminInboundsError = "";
  refreshCreateAdminInboundsField();
}

function clearCreateAdminInbounds() {
  state.createAdminInboundIds = [];
  state.createAdminInboundsError = "";
  refreshCreateAdminInboundsField();
}

function toggleEditAdminInboundSelection(id, checked) {
  const selected = new Set(state.editAdminInboundIds);
  if (checked) selected.add(id);
  else selected.delete(id);
  state.editAdminInboundIds = [...selected];
  state.editAdminInboundsError = "";
  refreshEditAdminInboundsField();
}

function selectAllEditAdminInbounds() {
  state.editAdminInboundIds = normalMarzbanInboundIds(state.editAdminInbounds);
  state.editAdminInboundsError = "";
  refreshEditAdminInboundsField();
}

function clearEditAdminInbounds() {
  state.editAdminInboundIds = [];
  state.editAdminInboundsError = "";
  refreshEditAdminInboundsField();
}

function refreshCreateAdminInboundsField() {
  const field = document.querySelector("#create-admin-inbounds-field");
  if (!field) {
    setModal("New reseller", createAdminModalBody());
    return;
  }
  field.innerHTML = createAdminInboundsField();
}

function refreshEditAdminInboundsField() {
  const field = document.querySelector("#edit-admin-inbounds-field");
  if (!field) {
    setModal("Edit reseller", editAdminModalBody());
    return;
  }
  field.innerHTML = editAdminInboundsField();
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
    valueName: "editExpiresAtDate",
    showRelative: true
  });
}

function renderExpiryField({ value, openAction, changeAction, clearAction, valueName, showRelative = false }) {
  const currentValue = value || "";
  const relativeText = showRelative ? relativeExpiryText(currentValue) : "";
  const minValue = todayDateInputValue();
  return `
    <div class="expiry-picker">
      <label>Expiry Date</label>
      <div class="expiry-shell${currentValue ? " has-value" : ""}">
        <button type="button" class="expiry-display" onclick="window.Aegis.${openAction}(event)" aria-label="Select expiry date">
          <span class="expiry-display-value">${esc(currentValue)}</span>
          <span class="expiry-display-icon" aria-hidden="true">${calendarIcon()}</span>
        </button>
        <input class="expiry-native" name="${esc(valueName)}" type="date" value="${esc(currentValue)}" min="${esc(minValue)}" onchange="window.Aegis.${changeAction}(this.value)" />
        ${currentValue ? `<button type="button" class="expiry-clear" onclick="window.Aegis.${clearAction}(event)" aria-label="Clear expiry date">×</button>` : ""}
      </div>
      ${relativeText ? `<small class="expiry-relative">${esc(relativeText)}</small>` : ""}
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
  if (!panelSupportsInboundLoading(panel)) {
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
    state.createUserInboundsError = state.createUserInboundIds.length > 0 ? "" : "This panel has no selectable inbounds yet.";
  } catch (error) {
    state.createUserInbounds = [];
    state.createUserInboundId = "";
    state.createUserInboundIds = [];
    state.createUserInboundsError = error.message || "Failed to load inbounds";
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
      body: {
        ...Object.fromEntries(form.entries()),
        allowInsecureTls: form.has("allowInsecureTls")
      }
    });
  }, "Panel created");
}

function refreshEditPanelError() {
  const field = document.querySelector("#edit-panel-error");
  if (!field) {
    setModal("Edit panel", editPanelModalBody());
    return;
  }
  field.innerHTML = state.editPanelError ? `<p class="alert danger">${esc(state.editPanelError)}</p>` : "";
}

async function savePanel(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const panel = state.editPanel;
  state.error = "";
  state.editPanelError = "";
  refreshEditPanelError();
  try {
    if (!panel?.id) throw new Error("Panel not found");
    await api(`/api/superadmin/panels/${panel.id}`, {
      method: "PUT",
      body: {
        name: form.get("name"),
        url: form.get("url"),
        subscriptionUrl: form.get("subscriptionUrl") || "",
        subscriptionPath: form.get("subscriptionPath") || "",
        allowInsecureTls: form.has("allowInsecureTls"),
        username: form.get("username"),
        secret: form.get("secret") || "",
        active: form.has("active"),
        syncIntervalSeconds: form.get("syncIntervalSeconds")
      }
    });
    closeModal();
    state.notice = "Panel updated";
    await load();
  } catch (error) {
    state.editPanelError = error.message;
    refreshEditPanelError();
  }
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
        inboundIds: state.createAdminInboundIds,
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
  const isSuperadminUser = isSuperadmin();
  const panelId = isSuperadminUser ? form.get("panelId") : state.admin?.panelId || state.createUserPanelId || "";
  const panel = state.data?.panels?.find((item) => item.id === panelId);
  state.error = "";
  state.createUserError = "";
  refreshCreateUserError();
  try {
    if (!panel) {
      throw new Error("Valid panelId is required");
    }
    if (isSuperadminUser && panelSupportsInboundLoading(panel)) {
      if (state.createUserInboundsLoading) {
        throw new Error("Please wait for inbounds to load.");
      }
      const selectableInbounds = state.createUserInbounds;
      const selectableInboundIds = selectableInbounds.map((inbound) => inbound.id);
      const selectedInbounds = state.createUserInboundIds
        .map((id) => selectableInbounds.find((inbound) => inbound.id === id))
        .filter(Boolean);
      if (!selectedInbounds.length) {
        throw new Error("Select an inbound before creating the VPN account.");
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
          inboundMode: inboundModeFromSelection(inboundIds, selectableInboundIds),
          note: form.get("note") || "",
          active: form.has("active")
        }
      });
    } else if (isSuperadminUser) {
      await api("/api/admin/users", {
        method: "POST",
        body: {
          username: form.get("username"),
          panelId,
          flow: form.get("flow") || "",
          limitBytes: gbToBytes(form.get("limitGb")),
          expiresAt: resolveCreateUserExpiry(form),
          note: form.get("note") || "",
          active: form.has("active"),
          inboundId: form.get("inboundId") || "default"
        }
      });
    } else {
      await api("/api/admin/users", {
        method: "POST",
        body: {
          username: form.get("username"),
          limitBytes: gbToBytes(form.get("limitGb")),
          expiresAt: resolveCreateUserExpiry(form),
          note: form.get("note") || "",
          active: form.has("active")
        }
      });
    }
    closeModal();
    state.notice = `${singleUserLabel()} created`;
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
  const panel = state.data?.panels?.find((item) => item.id === user.panelId);
  const advanced = isSuperadmin();
  state.editUserInbounds = [];
  state.editUserInboundsLoading = advanced && panelSupportsInboundLoading(panel);
  state.editUserInboundsError = "";
  state.editUserInboundIds = Array.isArray(user.inboundIds) && user.inboundIds.length
    ? user.inboundIds.filter((value) => typeof value === "string" && value.trim())
    : [user.inboundId].filter(Boolean);
  state.editUserInboundId = preferredMarzbanInboundId(state.editUserInboundIds, user.inboundId);
  state.editUserLimitGb = bytesToGbInputValue(user.limitBytes);
  state.editUserExpiryDate = normalizeDateInputValue(user.expiresAt);
  state.editUserNote = user.note || "";
  state.editUserFlow = advanced ? user.flow || "" : "";
  state.editUserActive = user.active !== false;
  state.editUserProtocolOpen = "";
  state.editUserError = "";
  modal(editUserModalTitle(), editUserModalBody());
  if (advanced && panelSupportsInboundLoading(panel)) {
    void loadEditUserInbounds(user.id, user.panelId, { silent: true });
  } else {
    state.editUserInboundsLoading = false;
  }
}

function editUserModalBody() {
  return isSuperadmin() ? editUserAdvancedModalBody() : editUserSimpleModalBody();
}

function editUserModalTitle() {
  return isReseller() ? editUserLabel() : "Edit VPN account";
}


function editUserSimpleModalBody() {
  return `
    <form class="form edit-user-form edit-user-simple" onsubmit="window.Aegis.saveEditUser(event)">
      <div class="edit-user-main">
        <label>Username<input name="username" readonly value="${esc(state.editUserUsername)}" /></label>
        <label class="unit-field">
          <span>Data Limit</span>
          <div class="unit-input">
            <input name="limitGb" type="number" min="0" step="any" value="${esc(state.editUserLimitGb)}" />
            <span>GB</span>
          </div>
        </label>
        <div id="edit-user-expiry-field">${editUserExpiryField()}</div>
        <label>Note<textarea name="note" rows="3" placeholder="Optional note for operators, bots, or integrations">${esc(state.editUserNote)}</textarea></label>
        <label class="switch-field">
          <span>
            <strong>Status</strong>
            <small>${state.editUserActive ? "Active account" : "Paused account"}</small>
          </span>
          <span class="switch-control">
            <input name="active" type="checkbox"${state.editUserActive ? " checked" : ""} />
            <span class="switch-track" aria-hidden="true"></span>
          </span>
        </label>
      </div>
      <div class="edit-user-footer">
        <div id="edit-user-error">${state.editUserError ? `<p class="alert danger">${esc(state.editUserError)}</p>` : ""}</div>
        <button class="primary" type="submit">${saveUserLabel()}</button>
      </div>
    </form>
  `;
}

function editUserAdvancedModalBody() {
  const panel = state.data?.panels?.find((item) => item.id === state.editUserPanelId);
  return `
    <form class="form edit-user-form" onsubmit="window.Aegis.saveEditUser(event)">
      <div class="edit-user-main">
        <label>Username<input name="username" readonly value="${esc(state.editUserUsername)}" /></label>
        <label>Panel<input readonly value="${esc(panelName(state.editUserPanelId))}" /></label>
        <label class="unit-field">
          <span>Data Limit</span>
          <div class="unit-input">
            <input name="limitGb" type="number" min="0" step="any" value="${esc(state.editUserLimitGb)}" />
            <span>GB</span>
          </div>
        </label>
        <div id="edit-user-expiry-field">${editUserExpiryField()}</div>
        <label>Note<textarea name="note" rows="3" placeholder="Optional note for operators, bots, or integrations">${esc(state.editUserNote)}</textarea></label>
        <label>Flow<input name="flow" value="${esc(state.editUserFlow)}" placeholder="xtls-rprx-vision, optional" /></label>
        <label class="switch-field">
          <span>
            <strong>Status</strong>
            <small>${state.editUserActive ? "Active account" : "Paused account"}</small>
          </span>
          <span class="switch-control">
            <input name="active" type="checkbox"${state.editUserActive ? " checked" : ""} />
            <span class="switch-track" aria-hidden="true"></span>
          </span>
        </label>
      </div>
      <div class="edit-user-side" id="edit-user-inbound-field">${editUserInboundField()}</div>
      <div class="edit-user-footer">
        <div id="edit-user-error">${state.editUserError ? `<p class="alert danger">${esc(state.editUserError)}</p>` : ""}</div>
        <button class="primary" type="submit">${saveUserLabel()}</button>
      </div>
    </form>
  `;
}

function editUserInboundField() {
  const panel = state.data?.panels?.find((item) => item.id === state.editUserPanelId);
  if (!panelSupportsInboundLoading(panel)) {
    return `<div class="compact-panel"><div class="card-head compact-head"><h4>Protocols</h4></div><label>Inbound<input name="inboundId" value="${esc(state.editUserInboundId || "")}" /></label></div>`;
  }
  return editUserProtocolsField();
}

function refreshEditUserInboundField() {
  const field = document.querySelector("#edit-user-inbound-field");
  if (!field) {
    setModal(editUserModalTitle(), editUserModalBody());
    return;
  }
  field.innerHTML = editUserInboundField();
}

function refreshEditUserProtocolsField() {
  refreshEditUserInboundField();
}

function toggleEditUserProtocolPanel(protocol) {
  state.editUserProtocolOpen = state.editUserProtocolOpen === protocol ? "" : protocol;
  refreshEditUserProtocolsField();
}

function toggleEditUserProtocolSelection(protocol, id, checked) {
  const selected = new Set(state.editUserInboundIds);
  if (checked) selected.add(id);
  else selected.delete(id);
  state.editUserInboundIds = [...selected];
  state.editUserError = "";
  refreshEditUserProtocolsField();
  refreshEditUserError();
}

function selectEditUserProtocolInbounds(protocol) {
  const ids = editUserProtocolInbounds(protocol).map((inbound) => inbound.id);
  const selected = new Set(state.editUserInboundIds);
  ids.forEach((id) => selected.add(id));
  state.editUserInboundIds = [...selected];
  state.editUserError = "";
  refreshEditUserProtocolsField();
  refreshEditUserError();
}

function clearEditUserProtocolInbounds(protocol) {
  const ids = new Set(editUserProtocolInbounds(protocol).map((inbound) => inbound.id));
  state.editUserInboundIds = state.editUserInboundIds.filter((id) => !ids.has(id));
  state.editUserError = "";
  refreshEditUserProtocolsField();
  refreshEditUserError();
}

function refreshEditUserError() {
  const field = document.querySelector("#edit-user-error");
  if (!field) {
    setModal(editUserModalTitle(), editUserModalBody());
    return;
  }
  field.innerHTML = state.editUserError ? `<p class="alert danger">${esc(state.editUserError)}</p>` : "";
}

function refreshEditUserExpiryField() {
  const field = document.querySelector("#edit-user-expiry-field");
  if (!field) {
    setModal(editUserModalTitle(), editUserModalBody());
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
  state.editUserInboundIds = normalMarzbanInboundIds(state.editUserInbounds);
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
  if (!panelSupportsInboundLoading(panel)) {
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
    state.editUserInboundsError = state.editUserInboundIds.length > 0 ? "" : "No inbounds available yet. Load inbounds before editing this VPN account.";
  } catch (error) {
    state.editUserInbounds = [];
    state.editUserInboundIds = [];
    state.editUserInboundId = "";
    state.editUserInboundsError = error.message || "Failed to load inbounds";
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
  const advanced = isSuperadmin();
  state.error = "";
  state.editUserError = "";
  refreshEditUserError();
  try {
    if (!user) throw new Error("User not found");
    if (advanced && panelSupportsInboundLoading(panel)) {
      if (state.editUserInboundsLoading) {
        throw new Error("Please wait for inbounds to load.");
      }
      const selectableInbounds = state.editUserInbounds;
      const selectableInboundIds = selectableInbounds.map((inbound) => inbound.id);
      const selectedInbounds = state.editUserInboundIds
        .map((id) => selectableInbounds.find((inbound) => inbound.id === id))
        .filter(Boolean);
      if (!selectedInbounds.length) {
        throw new Error("Select an inbound before saving the VPN account.");
      }
      const inboundIds = selectedInbounds.map((inbound) => inbound.id);
      const expiresAt = resolveEditUserExpiry(form);
      await api(`/api/admin/users/${user.id}`, {
        method: "PUT",
        body: {
          inboundIds,
          inboundId: preferredMarzbanInboundId(inboundIds),
          inboundMode: inboundModeFromSelection(inboundIds, selectableInboundIds),
          limitBytes: gbToBytes(form.get("limitGb")),
          expiresAt,
          note: form.get("note") || "",
          flow: form.get("flow") || "",
          active: form.has("active")
        }
      });
    } else if (advanced) {
      await api(`/api/admin/users/${user.id}`, {
        method: "PUT",
        body: {
          inboundId: form.get("inboundId") || user.inboundId || "default",
          limitBytes: gbToBytes(form.get("limitGb")),
          expiresAt: resolveEditUserExpiry(form),
          note: form.get("note") || "",
          flow: form.get("flow") || "",
          active: form.has("active")
        }
      });
    } else {
      await api(`/api/admin/users/${user.id}`, {
        method: "PUT",
        body: {
          limitBytes: gbToBytes(form.get("limitGb")),
          expiresAt: resolveEditUserExpiry(form),
          note: form.get("note") || "",
          active: form.has("active")
        }
      });
    }
    closeModal();
    state.notice = `${singleUserLabel()} updated`;
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
  const today = todayDateInputValue();
  if (String(value) < today) {
    throw new Error(errorMessage);
  }
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

async function testPanelConnection(id) {
  if (!requireSuperadminUi()) return;
  state.testingPanelId = id;
  state.error = "";
  state.notice = "";
  renderApp();
  try {
    const result = await api(`/api/superadmin/panels/${id}/test-connection`, { method: "POST" });
    state.notice = result.message || `Connection OK: ${result.inboundCount} inbounds`;
    state.error = "";
  } catch (error) {
    state.error = error.message || "Panel connection test failed";
  } finally {
    state.testingPanelId = null;
    renderApp();
  }
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
    state.users = state.users.map((user) => (user.id === id ? { ...user, ...updated } : user));
    if (state.data?.users) {
      state.data = {
        ...state.data,
        users: state.users
      };
    }
    state.notice = `${singleUserLabel()} traffic synced`;
    state.error = "";
  } catch (error) {
    state.error = error.message || "Traffic sync failed";
  } finally {
    state.syncingUserId = previous;
    renderApp();
  }
}

async function copySubscriptionLink(id) {
  const user = state.users?.find((item) => item.id === id);
  const link = user?.subscriptionUrl;
  if (!isValidSubscriptionUrl(link)) {
    state.error = "Could not copy subscription link";
    renderApp();
    return;
  }
  try {
    if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
    await navigator.clipboard.writeText(link);
    state.error = "";
    state.notice = "Subscription link copied";
  } catch (error) {
    state.error = "Could not copy subscription link";
  }
  renderApp();
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
  if (!confirm(`Delete this ${singleUserLabel().toLowerCase()}? Remaining traffic will return when enabled.`)) return;
  await runAction(() => api(`/api/admin/users/${id}`, { method: "DELETE" }), `${singleUserLabel()} deleted`);
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
  link.download = formatBackupFilename();
  link.click();
  URL.revokeObjectURL(url);
}

function formatBackupFilename(date = new Date()) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hour = String(date.getHours()).padStart(2, "0");
  const minute = String(date.getMinutes()).padStart(2, "0");
  return `aegispanel-backup-${year}-${month}-${day}-${hour}-${minute}.json`;
}

function refreshRestoreBackupError() {
  const field = document.querySelector("#restore-backup-error");
  if (!field) {
    renderApp();
    return;
  }
  field.innerHTML = state.restoreBackupError ? `<p class="alert danger">${esc(state.restoreBackupError)}</p>` : "";
}

function clearRestoreBackupError() {
  state.restoreBackupError = "";
  refreshRestoreBackupError();
}

async function restoreBackup(event) {
  event.preventDefault();
  if (!requireSuperadminUi()) return;
  const form = new FormData(event.target);
  const file = form.get("backupFile");
  const confirmation = String(form.get("confirmation") || "").trim();
  state.restoreBackupError = "";
  refreshRestoreBackupError();
  try {
    if (!(file instanceof File) || file.size === 0) {
      throw new Error("Select a backup file.");
    }
    if (confirmation !== "RESTORE") {
      throw new Error("Type RESTORE to confirm restore.");
    }
    let backup;
    try {
      backup = JSON.parse(await file.text());
    } catch {
      throw new Error("Invalid JSON backup file.");
    }
    await api("/api/superadmin/restore", {
      method: "POST",
      body: { confirmation, backup }
    });
    state.restoreBackupError = "";
    state.notice = "Backup restored";
    await load();
  } catch (error) {
    state.restoreBackupError = error.message || "Restore failed";
    refreshRestoreBackupError();
  }
}

window.Aegis = {
  login,
  logout,
  load,
  closeModal,
  showPanelForm,
  showEditPanelForm,
  showAdminForm,
  showEditAdminForm,
  showUserForm,
  showEditUserForm,
  showNewsForm,
  createPanel,
  savePanel,
  createAdmin,
  saveAdmin,
  loadCreateAdminInbounds,
  loadEditAdminInbounds,
  toggleCreateAdminInboundSelection,
  selectAllCreateAdminInbounds,
  clearCreateAdminInbounds,
  toggleEditAdminInboundSelection,
  selectAllEditAdminInbounds,
  clearEditAdminInbounds,
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
  toggleEditUserProtocolPanel,
  toggleEditUserProtocolSelection,
  selectEditUserProtocolInbounds,
  clearEditUserProtocolInbounds,
  toggleEditMarzbanInboundSelection,
  selectAllEditMarzbanInbounds,
  clearEditMarzbanInbounds,
  setEditUserExpiryDate,
  clearEditUserExpiry,
  openEditUserExpiryPicker,
  createNews,
  showRestoreBackupForm,
  showAuditLogs,
  showNewsList,
  syncPanel,
  testPanelConnection,
  syncUserTraffic,
  copySubscriptionLink,
  loadPanelInbounds,
  deletePanel,
  deleteAdmin,
  deleteUser,
  downloadBackup,
  restoreBackup,
  clearRestoreBackupError,
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
