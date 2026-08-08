"use strict";

const $ = (id) => document.getElementById(id);

let token = "";
let principal = null;
let usingRunToken = false;
let currentDomain = null;
let currentSite = {};
let allSites = [];
let pendingConfig = null;
let pendingPhpSettings = null;
let pendingCache = null;
let currentCache = null;
let pendingSecurity = null;
let currentSecurity = null;
let securityAuthDirty = false;
let securityFail2banDirty = false;
let securityRevision = 0;
let oneTimeCopyText = "";
let detailRequest = 0;
let metricRanges = [];
let hostMetricSamples = [];
let currentFilesPath = "";
let openFilePath = null;
let pendingFilePath = null;
let fileRequest = 0;

const WORDPRESS_FLAVORS = new Set([
  "wp", "wpfc", "wpredis", "wpsc", "wprocket", "wpce", "wpsubdir", "wpsubdomain",
]);

/* ---- authentication ---- */

function readTokenFromHash() {
  const match = /[#&]token=([^&]+)/.exec(location.hash);
  if (match) {
    usingRunToken = true;
    history.replaceState(null, "", location.pathname);
    return decodeURIComponent(match[1]);
  }
  return sessionStorage.getItem("wpfy-panel-token") || "";
}

function clearSession() {
  sessionStorage.removeItem("wpfy-panel-token");
  token = "";
  principal = null;
  usingRunToken = false;
  dismissOneTime();
}

function showGate(rejected, rateLimited = false) {
  $("app")?.classList.add("hidden");
  $("gate")?.classList.remove("hidden");
  $("login-error")?.classList.toggle("hidden", !rejected);
  if ($("login-status")) {
    $("login-status").textContent = rateLimited ? "This client is rate limited. Wait before trying again." : "";
  }
  $("login-username")?.focus();
}

function showApp() {
  $("gate")?.classList.add("hidden");
  $("app")?.classList.remove("hidden");
}

function isAdmin() {
  return principal?.role === "admin";
}

function applyPrincipal() {
  const admin = isAdmin();
  const label = principal ? `${principal.username} · ${principal.role}` : "temporary run access";
  $("chip-account-label").textContent = label;
  $("account-name").textContent = principal ? principal.username : "";
  $("account-role").textContent = principal ? principal.role : "";
  $("foot-principal").textContent = principal ? `wpfy panel · signed in as ${principal.username}` : "wpfy panel";
  $("btn-users")?.classList.toggle("hidden", !admin);
  $("chip-health")?.classList.toggle("hidden", !admin);
  $("chip-jobs")?.classList.toggle("hidden", !admin);
  ["metrics-panel", "services-panel", "diagnostics-panel"].forEach((id) =>
    $(id)?.classList.toggle("hidden", Boolean(principal) && !admin));
  $("stats")?.classList.toggle("hidden", Boolean(principal) && !admin);
  $("btn-new-site")?.classList.toggle("hidden", Boolean(principal) && !admin);
  if (principal && !admin) {
    setNewSiteOpen(false);
    setUsersOpen(false);
  }
}

async function loadPrincipal() {
  const response = await fetch("/api/auth/me", {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (response.status === 401 && usingRunToken) return null;
  if (response.status === 401) {
    clearSession();
    showGate(true);
    throw new Error("unauthorized");
  }
  if (!response.ok) throw new Error("Unable to load your account.");
  principal = await response.json();
  applyPrincipal();
  return principal;
}

async function setupRequest(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || `request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function showSetup() {
  $("gate")?.classList.add("hidden");
  $("app")?.classList.add("hidden");
  $("setup")?.classList.remove("hidden");
  $("setup-first-name")?.focus();
}

async function beginSetupTotp() {
  const payload = await setupRequest("/api/setup/totp", {
    method: "POST",
    body: JSON.stringify({ action: "begin" }),
  });
  $("setup-account")?.classList.add("hidden");
  $("setup-totp")?.classList.remove("hidden");
  $("setup-step-one")?.classList.remove("active");
  $("setup-step-two")?.classList.add("active");
  $("setup-totp-secret").value = payload.secret;
  const qr = $("setup-qr");
  qr.replaceChildren();
  new QRCode(qr, { text: payload.uri, width: 220, height: 220, correctLevel: QRCode.CorrectLevel.M });
  $("setup-totp-code")?.focus();
}

async function submitSetup(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  await withBusy(button, async () => {
    $("setup-account-error")?.classList.add("hidden");
    try {
      const payload = await setupRequest("/api/setup", {
        method: "POST",
        body: JSON.stringify({
          first_name: $("setup-first-name").value,
          last_name: $("setup-last-name").value,
          username: $("setup-username").value,
          email: $("setup-email").value,
          password: $("setup-password").value,
          confirm_password: $("setup-confirm-password").value,
          license_accepted: $("setup-license").checked,
          telemetry_enabled: $("setup-telemetry").checked,
        }),
      });
      token = payload.token;
      usingRunToken = false;
      sessionStorage.setItem("wpfy-panel-token", token);
      principal = { username: payload.username, role: payload.role, sites: payload.sites };
      await beginSetupTotp();
    } catch (error) {
      const node = $("setup-account-error");
      node.textContent = error.message;
      node.classList.remove("hidden");
    }
  });
}

async function finishSetup() {
  $("setup")?.classList.add("hidden");
  principal = await loadPrincipal();
  await refreshDashboard();
  showApp();
  await handleRoute(location.pathname).catch(() => {});
}

async function verifySetupTotp() {
  const status = $("setup-totp-status");
  status.textContent = "Checking code…";
  try {
    await setupRequest("/api/setup/totp", {
      method: "POST",
      body: JSON.stringify({ action: "verify", code: $("setup-totp-code").value }),
    });
    status.textContent = "Second factor enrolled.";
    await finishSetup();
  } catch (error) {
    status.textContent = error.message;
  }
}

function revealSetupSkip() {
  $("setup-totp-warning")?.classList.remove("hidden");
  $("btn-setup-totp-confirm-skip")?.classList.remove("hidden");
  $("btn-setup-totp-confirm-skip")?.focus();
}

async function confirmSetupSkip() {
  await setupRequest("/api/setup/totp", {
    method: "POST",
    body: JSON.stringify({ action: "skip", confirm: true }),
  });
  await finishSetup();
}

/* ---- api ---- */

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
  });
  if (response.status === 401) {
    clearSession();
    showGate(true);
    throw new Error("unauthorized");
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(response.status === 403
      ? "Not allowed."
      : payload.error || payload.message || payload.nginx_test_output || `request failed (${response.status})`);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

async function apiUpload(path, file) {
  const response = await fetch(path, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: file,
  });
  const payload = await response.json().catch(() => ({}));
  if (response.status === 401) {
    clearSession();
    showGate(true);
    throw new Error("unauthorized");
  }
  if (!response.ok) throw new Error(response.status === 403 ? "Not allowed." : payload.error || `upload failed (${response.status})`);
  return payload;
}

async function apiDownload(path, name) {
  const response = await fetch(path, { headers: { Authorization: `Bearer ${token}` } });
  if (response.status === 401) {
    clearSession();
    showGate(true);
    throw new Error("unauthorized");
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(response.status === 403 ? "Not allowed." : payload.error || `download failed (${response.status})`);
  }
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/* ---- ui helpers ---- */

let toastTimer = null;
function toast(message, isError) {
  const node = $("toast");
  if (!node) return;
  node.textContent = message;
  node.classList.toggle("error", Boolean(isError));
  node.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.add("hidden"), 5000);
}

function confirmDialog({ title, message, confirmLabel = "Confirm", intent = "default" }) {
  return new Promise((resolve) => {
    const backdrop = document.createElement("div");
    backdrop.className = "dialog-backdrop";
    const dialog = document.createElement("div");
    dialog.className = "dialog-panel";
    dialog.setAttribute("role", "alertdialog");
    dialog.setAttribute("aria-labelledby", "confirm-dialog-title");
    dialog.innerHTML = `
      <h2 id="confirm-dialog-title">${_esc(title)}</h2>
      <p>${_esc(message)}</p>
      <div class="dialog-actions">
        <button class="btn btn-primary" data-result="confirm">${_esc(confirmLabel)}</button>
        <button class="btn" data-result="cancel">Cancel</button>
      </div>`;
    backdrop.appendChild(dialog);
    document.body.appendChild(backdrop);
    const confirmBtn = dialog.querySelector("[data-result=confirm]");
    const cancelBtn = dialog.querySelector("[data-result=cancel]");
    function cleanup() { backdrop.remove(); }
    confirmBtn.addEventListener("click", () => { cleanup(); resolve(true); });
    cancelBtn.addEventListener("click", () => { cleanup(); resolve(false); });
    backdrop.addEventListener("click", (e) => { if (e.target === backdrop) { cleanup(); resolve(false); } });
    dialog.addEventListener("keydown", (e) => { if (e.key === "Escape") { cleanup(); resolve(false); } });
    confirmBtn.focus();
  });
}

function typedConfirm({ title, message, keyword, confirmLabel = "Confirm", inventory = null }) {
  return new Promise((resolve) => {
    const backdrop = document.createElement("div");
    backdrop.className = "dialog-backdrop";
    const dialog = document.createElement("div");
    dialog.className = "dialog-panel";
    dialog.setAttribute("role", "alertdialog");
    dialog.setAttribute("aria-labelledby", "typed-confirm-title");
    const invHtml = inventory ? `<dl class="kv dialog-inventory">${Object.entries(inventory).map(([k, v]) => `<dt>${_esc(k)}</dt><dd>${_esc(String(v))}</dd>`).join("")}</dl>` : "";
    dialog.innerHTML = `
      <h2 id="typed-confirm-title">${_esc(title)}</h2>
      <p>${_esc(message)}</p>
      ${invHtml}
      <label class="confirm-field">Type <strong>${_esc(keyword)}</strong> to confirm
        <input type="text" autocomplete="off" spellcheck="false" data-typed-input>
      </label>
      <div class="dialog-actions">
        <button class="btn btn-danger-ghost" data-result="confirm" disabled>${_esc(confirmLabel)}</button>
        <button class="btn" data-result="cancel">Cancel</button>
      </div>`;
    backdrop.appendChild(dialog);
    document.body.appendChild(backdrop);
    const input = dialog.querySelector("[data-typed-input]");
    const confirmBtn = dialog.querySelector("[data-result=confirm]");
    const cancelBtn = dialog.querySelector("[data-result=cancel]");
    function cleanup() { backdrop.remove(); }
    input.addEventListener("input", () => { confirmBtn.disabled = input.value !== keyword; });
    input.addEventListener("keydown", (e) => { if (e.key === "Enter" && input.value === keyword) { cleanup(); resolve(true); } });
    confirmBtn.addEventListener("click", () => { cleanup(); resolve(true); });
    cancelBtn.addEventListener("click", () => { cleanup(); resolve(false); });
    backdrop.addEventListener("click", (e) => { if (e.target === backdrop) { cleanup(); resolve(false); } });
    dialog.addEventListener("keydown", (e) => { if (e.key === "Escape") { cleanup(); resolve(false); } });
    input.focus();
  });
}

async function withBusy(button, work) {
  button.disabled = true;
  try {
    return await work();
  } catch (error) {
    if (error.message !== "unauthorized") toast(error.message, true);
    throw error;
  } finally {
    button.disabled = false;
  }
}

function runBusy(button, work, after) {
  if (!button) return Promise.resolve();
  return withBusy(button, work)
    .catch(() => undefined)
    .finally(() => {
      if (after) after();
    });
}

function listen(id, eventName, handler) {
  const node = $(id);
  if (node) node.addEventListener(eventName, handler);
}

function badge(text, on) {
  const span = document.createElement("span");
  span.className = `badge ${on ? "on" : "off"}`;
  span.textContent = text;
  return span;
}

function checkItem(check) {
  const li = document.createElement("li");
  const label = document.createElement("span");
  const state = check.state || (check.ok === true ? "pass" : check.ok === false ? "fail" : "warn");
  label.className = `check-label check-${state}`;
  label.textContent = state.toUpperCase();
  const name = document.createElement("span");
  name.className = "check-name";
  name.textContent = check.name;
  const msg = document.createElement("span");
  msg.className = "check-msg";
  msg.textContent = check.message;
  li.append(label, name, msg);
  return li;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = "B";
  for (const next of units) {
    if (value < 1024) break;
    value /= 1024;
    unit = next;
  }
  return `${value.toFixed(1)} ${unit}`;
}

function formatTime(value) {
  if (!value) return "–";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function isWordPressFlavor(flavor) {
  return WORDPRESS_FLAVORS.has(String(flavor || "").toLowerCase());
}

const sslOn = (value) => ["enabled", "letsencrypt", "wildcard", "1", "true"].includes(String(value).toLowerCase());
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function stepText(step) {
  if (typeof step === "string") return step;
  if (!step || typeof step !== "object") return String(step ?? "");
  return [step.name || step.action, step.state, step.message || step.detail].filter(Boolean).join(" · ");
}

async function pollJob(jobId, onStep) {
  const deadline = Date.now() + 300000;
  let capturedOneTime = null;
  let seenSteps = 0;

  while (Date.now() < deadline) {
    const job = await api(`/api/jobs/${encodeURIComponent(jobId)}`);
    if (Object.prototype.hasOwnProperty.call(job, "one_time")) {
      capturedOneTime = job.one_time;
    }
    const steps = Array.isArray(job.steps) ? job.steps : [];
    if (steps.length > seenSteps) {
      seenSteps = steps.length;
      if (onStep) onStep(steps, job);
    }
    if (job.state === "succeeded" || job.state === "failed") {
      return { ...job, one_time: capturedOneTime };
    }
    await sleep(750);
  }

  throw new Error("The operation is still running after 5 minutes. Check Events or refresh the panel for its final status.");
}

function flattenOneTime(value, prefix = "") {
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, item]) => {
    const label = prefix ? `${prefix} ${key}` : key;
    if (item && typeof item === "object") return flattenOneTime(item, label);
    return item === undefined || item === null ? [] : [[label, String(item)]];
  });
}

function renderOneTime(title, oneTime) {
  const panel = $("one-time-panel");
  const values = $("one-time-values");
  const entries = flattenOneTime(oneTime);
  if (!panel || !values || entries.length === 0) return;

  $("one-time-title").textContent = title;
  const rows = entries.flatMap(([key, value]) => {
    const dt = document.createElement("dt");
    dt.textContent = key.replaceAll("_", " ");
    const dd = document.createElement("dd");
    dd.className = "credential-value";
    dd.textContent = value;
    return [dt, dd];
  });
  values.replaceChildren(...rows);
  oneTimeCopyText = entries.map(([key, value]) => `${key.replaceAll("_", " ")}: ${value}`).join("\n");
  if ($("one-time-copy-status")) $("one-time-copy-status").textContent = "";
  panel.classList.remove("hidden");
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function dismissOneTime() {
  oneTimeCopyText = "";
  $("one-time-values")?.replaceChildren();
  if ($("one-time-copy-status")) $("one-time-copy-status").textContent = "";
  $("one-time-panel")?.classList.add("hidden");
}

/* ---- account and user management ---- */

function siteList(value) {
  return String(value || "").split(",").map((site) => site.trim()).filter(Boolean);
}

function setUsersOpen(open) {
  $("users-panel")?.classList.toggle("hidden", !open);
  $("btn-users")?.setAttribute("aria-expanded", String(open));
  if (open) {
    loadUsers().catch((error) => {
      if (error.message !== "unauthorized") toast(error.message, true);
    });
    $("users-panel")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function userSites(sites) {
  const wrap = document.createElement("div");
  wrap.className = "user-sites";
  (sites || []).forEach((site) => wrap.append(badge(site, false)));
  if (!wrap.childElementCount) wrap.textContent = "–";
  return wrap;
}

function userActionButton(label, className, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", () => runBusy(button, handler));
  return button;
}

function renderUsers(users) {
  const table = $("users-table");
  const empty = $("users-empty");
  if (!table || !empty) return;
  empty.classList.toggle("hidden", users.length > 0);
  table.classList.toggle("hidden", users.length === 0);
  const tbody = table.querySelector("tbody");
  tbody.replaceChildren(...users.map((user) => {
    const row = document.createElement("tr");
    const username = eventCell(user.username, "domain", "Username");
    const role = eventCell(user.role, "", "Role");
    const sites = document.createElement("td");
    sites.setAttribute("data-label", "Assigned sites");
    sites.append(userSites(user.sites));
    const totp = document.createElement("td");
    totp.setAttribute("data-label", "TOTP");
    totp.append(badge(user.totp_enabled ? "enabled" : "not enrolled", Boolean(user.totp_enabled)));
    const actions = document.createElement("td");
    actions.setAttribute("data-label", "Actions");
    const controls = document.createElement("div");
    controls.className = "user-actions";
    const roleSelect = document.createElement("select");
    ["admin", "site-manager"].forEach((value) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      option.selected = value === user.role;
      roleSelect.append(option);
    });
    const assignedSites = document.createElement("input");
    assignedSites.type = "text";
    assignedSites.value = (user.sites || []).join(", ");
    assignedSites.placeholder = "assigned sites";
    assignedSites.setAttribute("aria-label", `Assigned sites for ${user.username}`);
    const syncSites = () => { assignedSites.disabled = roleSelect.value !== "site-manager"; };
    roleSelect.addEventListener("change", syncSites);
    syncSites();
    const save = userActionButton("Save", "btn", async () => {
      await api(`/api/users/${encodeURIComponent(user.username)}`, {
        method: "PUT",
        body: JSON.stringify({
          role: roleSelect.value,
          sites: roleSelect.value === "site-manager" ? siteList(assignedSites.value) : [],
        }),
      });
      await loadUsers();
      toast(`${user.username} updated`, false);
    });
    controls.append(roleSelect, assignedSites, save);
    if (user.totp_enabled) {
      controls.append(userActionButton("Disable TOTP", "btn", async () => {
        if (!confirm(`Disable TOTP for ${user.username}?`)) return;
        await api(`/api/users/${encodeURIComponent(user.username)}/totp`, { method: "DELETE" });
        await loadUsers();
        toast(`TOTP disabled for ${user.username}`, false);
      }));
    }
    controls.append(userActionButton("Delete", "btn btn-danger-ghost", async () => {
      if (!confirm(`Delete user ${user.username}?`)) return;
      await api(`/api/users/${encodeURIComponent(user.username)}`, { method: "DELETE" });
      await loadUsers();
      toast(`${user.username} deleted`, false);
    }));
    actions.append(controls);
    row.append(username, role, sites, totp, actions);
    return row;
  }));
}

async function loadUsers() {
  const data = await api("/api/users");
  renderUsers(data.users || []);
}

async function createUser() {
  const username = $("user-create-username").value.trim();
  const password = $("user-create-password").value;
  const role = $("user-create-role").value;
  const sites = role === "site-manager" ? siteList($("user-create-sites").value) : [];
  $("user-create-status").textContent = "creating…";
  try {
    await api("/api/users", { method: "POST", body: JSON.stringify({ username, password, role, sites }) });
    $("user-create-form").reset();
    await loadUsers();
    toast(`${username} created`, false);
  } finally {
    $("user-create-status").textContent = "";
  }
}

async function enrollTotp() {
  $("account-status").textContent = "creating one-time enrollment details…";
  try {
    const result = await api("/api/auth/totp", { method: "POST", body: JSON.stringify({}) });
    renderOneTime("TOTP enrollment", { secret: result.secret, uri: result.uri });
    $("account-totp-verify")?.classList.remove("hidden");
    $("account-status").textContent = "Enter one current authenticator code to finish enrollment.";
    $("account-totp-code")?.focus();
  } finally {
    if (!oneTimeCopyText) $("account-status").textContent = "";
  }
}

async function verifyAccountTotp() {
  const code = $("account-totp-code").value.trim();
  const status = $("account-status");
  status.textContent = "checking authenticator code…";
  try {
    await api("/api/auth/totp", { method: "POST", body: JSON.stringify({ code }) });
    $("account-totp-verify")?.classList.add("hidden");
    dismissOneTime();
    status.textContent = "Two-factor authentication is enabled.";
  } catch (error) {
    status.textContent = error.message;
  }
}

async function signIn() {
  const username = $("login-username").value.trim();
  const password = $("login-password").value;
  const totp = $("login-totp").value.trim();
  $("login-error").classList.add("hidden");
  $("login-status").textContent = "Signing in…";
  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, totp }),
    });
    if (!response.ok) {
      $("login-status").textContent = response.status === 429
        ? "This client is rate limited. Wait before trying again."
        : "";
      $("login-error").classList.remove("hidden");
      return;
    }
    const data = await response.json();
    token = data.token;
    usingRunToken = false;
    sessionStorage.setItem("wpfy-panel-token", token);
    $("login-password").value = "";
    $("login-totp").value = "";
    $("login-status").textContent = "";
    await boot();
  } catch (_) {
    $("login-status").textContent = "";
    $("login-error").classList.remove("hidden");
  }
}

async function logout() {
  try {
    await fetch("/api/auth/logout", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
  } finally {
    clearSession();
    showGate(false);
  }
}

/* ---- overview + sites ---- */

async function loadOverview() {
  const data = await api("/api/overview");
  $("chip-version").textContent = `wpfy ${data.version}`;

  const stats = [
    { label: "managed sites", value: data.site_count },
    { label: "docker", value: data.docker_version },
    { label: "warnings", value: data.warnings, warn: data.warnings > 0 },
  ];
  $("stats").replaceChildren(...stats.map((stat) => {
    const div = document.createElement("div");
    div.className = `stat${stat.warn ? " warn" : ""}`;
    const value = document.createElement("div");
    value.className = "value";
    value.textContent = stat.value;
    value.title = String(stat.value);
    const label = document.createElement("div");
    label.className = "mono-label";
    label.textContent = stat.label;
    div.append(value, label);
    return div;
  }));
}

let _sitesSort = { key: "domain", asc: true };
const SITE_SORT_LABELS = {
  domain: "Domain", flavor: "Type", php_version: "PHP", ssl: "SSL", cache: "Cache",
};

function renderSites() {
  const query = ($("sites-search")?.value || "").trim().toLowerCase();
  const flavorFilter = $("sites-flavor-filter")?.value || "";
  let sites = allSites.filter((site) => String(site.domain || "").toLowerCase().includes(query));
  if (flavorFilter) sites = sites.filter((s) => s.flavor === flavorFilter || s.flavor?.startsWith(flavorFilter));
  sites.sort((a, b) => {
    let va = String(a[_sitesSort.key] ?? "").toLowerCase();
    let vb = String(b[_sitesSort.key] ?? "").toLowerCase();
    if (_sitesSort.key === "ssl") {
      va = sslOn(a.ssl ?? a.ssl_enabled) ? "1" : "0";
      vb = sslOn(b.ssl ?? b.ssl_enabled) ? "1" : "0";
    }
    if (va < vb) return _sitesSort.asc ? -1 : 1;
    if (va > vb) return _sitesSort.asc ? 1 : -1;
    return 0;
  });
  $("sites-count").textContent = query || flavorFilter ? `${sites.length} of ${allSites.length}` : `${allSites.length} total`;
  const empty = $("sites-empty");
  empty.textContent = allSites.length === 0
    ? "No managed sites yet. Select New site to create one."
    : "No sites match this filter.";
  empty.classList.toggle("hidden", sites.length > 0);
  $("sites-table").classList.toggle("hidden", sites.length === 0);

  const thead = $("sites-table").querySelector("thead tr");
  thead.replaceChildren(...Object.keys(SITE_SORT_LABELS).map((key) => {
    const th = document.createElement("th");
    th.style.cursor = "pointer";
    th.textContent = SITE_SORT_LABELS[key];
    if (_sitesSort.key === key) th.textContent += _sitesSort.asc ? " \u25B4" : " \u25BE";
    th.addEventListener("click", () => {
      if (_sitesSort.key === key) _sitesSort.asc = !_sitesSort.asc;
      else { _sitesSort.key = key; _sitesSort.asc = true; }
      renderSites();
    });
    return th;
  }));
  const actionTh = document.createElement("th");
  thead.appendChild(actionTh);

  const tbody = $("sites-table").querySelector("tbody");
  tbody.replaceChildren(...sites.map((site) => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.addEventListener("click", (e) => { if (!e.target.closest("button,a")) navigate(`/site/${encodeURIComponent(site.domain)}`); });
    const domainCell = document.createElement("td");
    domainCell.className = "domain";
    domainCell.setAttribute("data-label", "Domain");
    domainCell.textContent = site.domain;
    const flavorCell = document.createElement("td");
    flavorCell.setAttribute("data-label", "Type");
    flavorCell.textContent = site.flavor || "?";
    const phpCell = document.createElement("td");
    phpCell.setAttribute("data-label", "PHP");
    phpCell.textContent = site.php_version || "–";
    const sslCell = document.createElement("td");
    sslCell.setAttribute("data-label", "SSL");
    const enabled = sslOn(site.ssl ?? site.ssl_enabled);
    sslCell.append(badge(enabled ? "ssl" : "http", enabled));
    const cacheCell = document.createElement("td");
    cacheCell.setAttribute("data-label", "Cache");
    cacheCell.textContent = site.cache_type || (String(site.redis) === "1" ? "redis" : "basic");
    const actionCell = document.createElement("td");
    actionCell.setAttribute("data-label", "Actions");
    const manage = document.createElement("button");
    manage.className = "btn";
    manage.textContent = "Manage";
    manage.addEventListener("click", (e) => { e.stopPropagation(); navigate(`/site/${encodeURIComponent(site.domain)}`); });
    actionCell.append(manage);
    tr.append(domainCell, flavorCell, phpCell, sslCell, cacheCell, actionCell);
    return tr;
  }));
}

function _seedSiteFilters() {
  const select = $("sites-flavor-filter");
  if (!select) return;
  const flavors = [...new Set(allSites.map((s) => s.flavor).filter(Boolean))].sort();
  const current = select.value;
  select.replaceChildren(...[{ value: "", label: "All types" }, ...flavors.map((f) => ({ value: f, label: f }))].map(({ value, label }) => {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = label;
    if (value === current) opt.selected = true;
    return opt;
  }));
}

async function loadSites() {
  const data = await api("/api/sites");
  allSites = data.sites || [];
  _seedSiteFilters();
  renderSites();
}

const METRIC_CHARTS = [
  { key: "cpu_percent", label: "CPU", unit: "%", value: (sample) => Number(sample.cpu_percent || 0) },
  { key: "memory", label: "Memory", unit: "%", bounded: true, value: (sample) => sample.memory_total ? (sample.memory_used / sample.memory_total) * 100 : 0 },
  { key: "disk", label: "Disk", unit: "%", bounded: true, value: (sample) => sample.disk_total ? (sample.disk_used / sample.disk_total) * 100 : 0 },
  { key: "load1", label: "Load (1 min)", unit: "", value: (sample) => Number(sample.load1 || 0) },
];

function syncRangeSelectors(ranges) {
  metricRanges = ranges;
  ["metrics-range", "activity-range"].forEach((id) => {
    const select = $(id);
    if (!select) return;
    const selected = select.value || "1h";
    select.replaceChildren(...ranges.map((range) => {
      const option = document.createElement("option");
      option.value = range;
      option.textContent = range;
      return option;
    }));
    select.value = ranges.includes(selected) ? selected : (ranges.includes("1h") ? "1h" : ranges[0] || "");
  });
}

const _chartInstances = {};

function _chartId(containerId) {
  return `chart_${containerId}`;
}

function _destroyCharts(containerId) {
  const key = _chartId(containerId);
  if (_chartInstances[key]) {
    _chartInstances[key].forEach((c) => c.destroy());
    _chartInstances[key] = [];
  }
}

function drawMetricChart(canvas, samples, metric) {
  if (typeof Chart === "undefined") return null;
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  const labels = samples.map((s) => new Date(Number(s.timestamp) * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
  const values = samples.map(metric.value);
  const color = getComputedStyle(document.documentElement).getPropertyValue("--action-blue").trim() || "#1863dc";
  const hairline = getComputedStyle(document.documentElement).getPropertyValue("--hairline").trim() || "#d9d9dd";
  return new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: metric.label,
        data: values,
        borderColor: color,
        backgroundColor: `${color}15`,
        fill: true,
        tension: 0.3,
        pointRadius: 0,
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 300 },
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          titleFont: { family: "ui-monospace, monospace", size: 12 },
          bodyFont: { family: "ui-monospace, monospace", size: 12 },
        },
      },
      scales: {
        x: { display: true, grid: { color: hairline }, ticks: { font: { family: "ui-monospace, monospace", size: 10 }, maxRotation: 0, maxTicksLimit: 6 } },
        y: {
          display: true,
          grid: { color: hairline },
          beginAtZero: false,
          ticks: { font: { family: "ui-monospace, monospace", size: 10 }, callback: (v) => `${v}${metric.unit}` },
        },
      },
    },
  });
}

function renderMetricCharts(containerId, emptyId, samples) {
  const container = $(containerId);
  const empty = $(emptyId);
  if (!container || !empty) return;
  empty.classList.toggle("hidden", samples.length > 0);
  container.classList.toggle("hidden", samples.length === 0);
  _destroyCharts(containerId);
  if (!samples.length) { container.replaceChildren(); return; }
  const charts = [];
  const figures = METRIC_CHARTS.map((metric) => {
    const figure = document.createElement("figure");
    figure.className = "chart-card";
    const caption = document.createElement("figcaption");
    caption.textContent = metric.label;
    const wrapper = document.createElement("div");
    wrapper.className = "chart-wrapper";
    wrapper.style.cssText = "position:relative;height:190px;width:100%";
    const canvas = document.createElement("canvas");
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", `${metric.label} over time`);
    wrapper.appendChild(canvas);
    figure.append(caption, wrapper);
    requestAnimationFrame(() => {
      const c = drawMetricChart(canvas, samples, metric);
      if (c) charts.push(c);
    });
    return figure;
  });
  container.replaceChildren(...figures);
  _chartInstances[_chartId(containerId)] = charts;
}

function renderMetricTable(samples) {
  const tbody = $("host-metrics-table")?.querySelector("tbody");
  if (!tbody) return;
  tbody.replaceChildren(...samples.map((sample) => {
    const row = document.createElement("tr");
    row.append(
      eventCell(new Date(Number(sample.timestamp) * 1000).toLocaleString(), "", "Time"),
      eventCell(Number(sample.cpu_percent || 0).toFixed(1), "", "CPU %"),
      eventCell(`${formatBytes(sample.memory_used || 0)} / ${formatBytes(sample.memory_total || 0)}`, "", "Memory"),
      eventCell(`${formatBytes(sample.disk_used || 0)} / ${formatBytes(sample.disk_total || 0)}`, "", "Disk"),
      eventCell(Number(sample.load1 || 0).toFixed(2), "", "Load"),
    );
    return row;
  }));
}

async function loadHostMetrics() {
  const range = $("metrics-range")?.value || "1h";
  const data = await api(`/api/metrics?${new URLSearchParams({ scope: "host", range })}`);
  if (!metricRanges.length) syncRangeSelectors(data.ranges || []);
  hostMetricSamples = data.samples || [];
  renderMetricCharts("host-charts", "host-metrics-empty", hostMetricSamples);
  renderMetricTable(hostMetricSamples);
}

async function loadActivityMetrics() {
  if (!currentDomain) return;
  const domain = currentDomain;
  const range = $("activity-range")?.value || $("metrics-range")?.value || "1h";
  const data = await api(`/api/metrics?${new URLSearchParams({ scope: domain, range })}`);
  if (currentDomain !== domain) return;
  renderMetricCharts("activity-charts", "activity-metrics-empty", data.samples || []);
}

function updateCreateFields() {
  const wordpress = isWordPressFlavor($("new-flavor")?.value);
  document.querySelectorAll(".wp-create-field").forEach((field) => field.classList.toggle("hidden", !wordpress));
}

function setNewSiteOpen(open) {
  $("new-site-panel")?.classList.toggle("hidden", !open);
  $("btn-new-site")?.setAttribute("aria-expanded", String(open));
  if (open) $("new-domain")?.focus();
}

function updateProgress(outputId, statusId, steps, state) {
  const output = $(outputId);
  const status = $(statusId);
  if (!output || !status) return;
  output.textContent = steps.map(stepText).filter(Boolean).join("\n") || "Waiting for the first job step…";
  output.classList.remove("hidden");
  status.textContent = state === "running" ? "job running…" : state;
}

async function createSite() {
  const domain = $("new-domain").value.trim();
  const flavor = $("new-flavor").value;
  const payload = {
    domain,
    flavor,
    php_version: $("new-php").value,
    letsencrypt: $("new-letsencrypt").checked ? "enabled" : "disabled",
  };
  if (isWordPressFlavor(flavor)) {
    const adminUser = $("new-admin-user").value.trim();
    const adminEmail = $("new-admin-email").value.trim();
    if (adminUser) payload.admin_user = adminUser;
    if (adminEmail) payload.admin_email = adminEmail;
  }

  $("create-job-status").textContent = "starting job…";
  $("create-job-progress").classList.remove("hidden");
  $("create-job-progress").textContent = "Submitting site creation…";
  const accepted = await api("/api/sites", { method: "POST", body: JSON.stringify(payload) });
  const job = await pollJob(accepted.job_id, (steps, current) =>
    updateProgress("create-job-progress", "create-job-status", steps, current.state));
  updateProgress("create-job-progress", "create-job-status", job.steps || [], job.state);

  if (job.state === "failed") {
    toast(job.result?.error || "site creation failed", true);
    return;
  }

  await Promise.all([loadSites(), loadOverview(), loadEvents()]);
  if (job.one_time) renderOneTime(`Credentials for ${domain}`, job.one_time);
  toast(`${domain} created`, false);
  $("new-site-panel").reset();
  $("new-php").value = "8.4";
  updateCreateFields();
  setNewSiteOpen(false);
}

/* ---- detail ---- */

function selectTab(name) {
  document.querySelectorAll(".tab").forEach((tab) => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
  });
  document.querySelectorAll(".tab-body").forEach((body) =>
    body.classList.toggle("hidden", body.id !== `tab-${name}`));
  if (name === "sftp") refreshSftp().catch((error) => {
    if (error.message !== "unauthorized") toast(error.message, true);
  });
  if (name === "backups") refreshBackups().catch((error) => {
    if (error.message !== "unauthorized") toast(error.message, true);
  });
  if (name === "activity") Promise.all([refreshActivity(), loadActivityMetrics()]).catch((error) => {
    if (error.message !== "unauthorized") toast(error.message, true);
  });
  if (name === "databases") refreshDatabases();
  if (name === "php") refreshPhpSettings().catch((error) => {
    if (error.message !== "unauthorized") toast(error.message, true);
  });
  if (name === "vhost") refreshVhost().catch((error) => {
    if (error.message !== "unauthorized") toast(error.message, true);
  });
  if (name === "cache") refreshCache().catch((error) => {
    if (error.message !== "unauthorized") toast(error.message, true);
  });
  if (name === "security") refreshSecurity().catch((error) => {
    if (error.message !== "unauthorized") toast(error.message, true);
  });
  if (name === "cron") refreshCron().catch((error) => {
    if (error.message !== "unauthorized") toast(error.message, true);
  });
  if (name === "files") refreshFiles(currentFilesPath).catch((error) => {
    if (error.message !== "unauthorized") toast(error.message, true);
  });
}

function syncConfigFields(site) {
  if (site.php_version) $("config-php").value = site.php_version;
  if (site.flavor) $("config-flavor").value = site.flavor;
  $("config-letsencrypt").checked = sslOn(site.ssl ?? site.ssl_enabled);
  $("config-password").value = "";
  $("config-password-field").classList.toggle("hidden", !isWordPressFlavor(site.flavor));
  clearConfigPreview();
}

async function openDetail(domain) {
  const requestId = ++detailRequest;
  currentDomain = domain;
  $("detail-domain").textContent = domain;
  $("delete-domain-label").textContent = domain;
  $("delete-confirm").value = "";
  syncDeleteButton();
  $("detail").classList.remove("hidden");
  $("health-result").replaceChildren();
  $("diag-result").replaceChildren();
  $("log-output").textContent = "No logs fetched yet.";
  $("wp-output").textContent = "No command run yet.";
  $("vhost-test-output").textContent = "No validation run yet.";
  $("vhost-result-message").classList.add("hidden");
  pendingPhpSettings = null;
  pendingCache = null;
  currentCache = null;
  pendingSecurity = null;
  currentSecurity = null;
  securityAuthDirty = false;
  securityFail2banDirty = false;
  securityRevision += 1;
  currentFilesPath = "";
  openFilePath = null;
  pendingFilePath = null;
  fileRequest += 1;
  $("file-editor-section")?.classList.add("hidden");
  selectTab("overview");
  const data = await api(`/api/sites/${encodeURIComponent(domain)}`);
  if (requestId !== detailRequest || currentDomain !== domain) return;
  currentSite = data.site || {};
  const rows = ["domain", "flavor", "php_version", "ssl", "cache_type", "created_at", "path"]
    .filter((key) => currentSite[key] !== undefined && currentSite[key] !== "")
    .flatMap((key) => {
      const dt = document.createElement("dt");
      dt.textContent = key.replaceAll("_", " ");
      const dd = document.createElement("dd");
      dd.textContent = currentSite[key];
      return [dt, dd];
    });
  $("site-kv").replaceChildren(...rows);
  syncConfigFields(currentSite);
  syncAdminerFields();
  syncGeneratedVhost();
  $("detail").scrollIntoView({ behavior: "smooth", block: "start" });
}

function closeDetail() {
  detailRequest += 1;
  $("detail")?.classList.add("hidden");
  currentDomain = null;
  currentSite = {};
  pendingConfig = null;
  pendingPhpSettings = null;
  currentFilesPath = "";
  openFilePath = null;
  pendingFilePath = null;
  fileRequest += 1;
}

async function refreshSftp() {
  if (!currentDomain) return;
  $("sftp-output").textContent = "Loading…";
  try {
    const data = await api(`/api/sites/${encodeURIComponent(currentDomain)}/sftp`);
    $("sftp-output").textContent = data.message || "no status";
  } catch (error) {
    $("sftp-output").textContent = error.message;
    throw error;
  }
}

async function refreshBackups() {
  if (!currentDomain) return;
  const data = await api(`/api/sites/${encodeURIComponent(currentDomain)}/backups`);
  const backups = data.backups || [];
  $("backups-empty").classList.toggle("hidden", backups.length > 0);
  const tbody = $("backups-table").querySelector("tbody");
  tbody.replaceChildren(...backups.map((backup) => {
    const tr = document.createElement("tr");
    const nameCell = document.createElement("td");
    nameCell.className = "domain";
    nameCell.setAttribute("data-label", "Archive");
    nameCell.textContent = backup.name;
    const sizeCell = document.createElement("td");
    sizeCell.setAttribute("data-label", "Size");
    sizeCell.textContent = formatBytes(backup.size_bytes);
    const dateCell = document.createElement("td");
    dateCell.setAttribute("data-label", "Created");
    dateCell.textContent = new Date(backup.modified_at * 1000).toLocaleString();
    const actionCell = document.createElement("td");
    actionCell.setAttribute("data-label", "Actions");
    const restore = document.createElement("button");
    restore.className = "btn btn-danger-ghost";
    restore.textContent = "Restore…";
    restore.addEventListener("click", () => runBusy(restore, async () => {
      const sure = confirm(
        `Restore ${currentDomain} from ${backup.name}?\n\nThis replaces the site's current files and database.`);
      if (!sure) return;
      const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/restore`, {
        method: "POST",
        body: JSON.stringify({ archive: backup.name }),
      });
      toast(result.message || "restore finished", !result.ok);
    }));
    actionCell.append(restore);
    tr.append(nameCell, sizeCell, dateCell, actionCell);
    return tr;
  }));
}

function syncDeleteButton() {
  const button = $("btn-delete-site");
  if (button) button.disabled = !currentDomain || $("delete-confirm")?.value !== currentDomain;
}

async function deleteCurrentSite() {
  const domain = currentDomain;
  if (!domain || $("delete-confirm").value !== domain) return;
  $("delete-job-status").textContent = "starting backup and delete job…";
  $("delete-job-progress").classList.remove("hidden");
  $("delete-job-progress").textContent = "Submitting deletion…";
  const accepted = await api(`/api/sites/${encodeURIComponent(domain)}`, {
    method: "DELETE",
    body: JSON.stringify({ confirm: domain }),
  });
  const job = await pollJob(accepted.job_id, (steps, current) =>
    updateProgress("delete-job-progress", "delete-job-status", steps, current.state));
  updateProgress("delete-job-progress", "delete-job-status", job.steps || [], job.state);

  if (job.state === "failed") {
    toast(job.result?.error || "site deletion failed", true);
    return;
  }

  closeDetail();
  await Promise.all([loadSites(), loadOverview(), loadEvents()]);
  toast(`${domain} backed up and deleted`, false);
}

/* ---- databases + PHP settings + vhost ---- */

function exactConfirmAction(name, actionLabel, action) {
  const wrap = document.createElement("div");
  wrap.className = "table-action";
  const input = document.createElement("input");
  input.type = "text";
  input.placeholder = `Type ${name}`;
  input.autocomplete = "off";
  input.spellcheck = false;
  input.setAttribute("aria-label", `Type ${name} to confirm ${actionLabel.toLowerCase()}`);
  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn btn-danger-ghost";
  button.textContent = actionLabel;
  button.disabled = true;
  const sync = () => { button.disabled = input.value !== name; };
  input.addEventListener("input", sync);
  button.addEventListener("click", () => runBusy(button, action, sync));
  wrap.append(input, button);
  return wrap;
}

function renderDatabases(databases) {
  const table = $("databases-table");
  const empty = $("databases-empty");
  empty.textContent = "No application databases found.";
  empty.classList.toggle("hidden", databases.length > 0);
  table.classList.toggle("hidden", databases.length === 0);
  const tbody = table.querySelector("tbody");
  tbody.replaceChildren(...databases.map((name) => {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    nameCell.className = "domain";
    nameCell.setAttribute("data-label", "Database");
    nameCell.textContent = name;
    const actionCell = document.createElement("td");
    actionCell.setAttribute("data-label", "Type exact name to drop");
    actionCell.append(exactConfirmAction(name, "Drop database", async () => {
      const result = await api(
        `/api/sites/${encodeURIComponent(currentDomain)}/databases/${encodeURIComponent(name)}`,
        { method: "DELETE", body: JSON.stringify({ confirm: name }) },
      );
      toast(result.message || `database ${name} dropped`, !result.ok);
      await Promise.all([refreshDatabases(), loadEvents()]);
    }));
    row.append(nameCell, actionCell);
    return row;
  }));

  const select = $("db-user-database");
  const selected = select.value;
  const none = document.createElement("option");
  none.value = "";
  none.textContent = "No initial grant";
  const options = databases.map((name) => {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    return option;
  });
  select.replaceChildren(none, ...options);
  if (databases.includes(selected)) select.value = selected;
}

function renderDbUsers(users) {
  const table = $("db-users-table");
  const empty = $("db-users-empty");
  empty.textContent = "No scoped database users found.";
  empty.classList.toggle("hidden", users.length > 0);
  table.classList.toggle("hidden", users.length === 0);
  const tbody = table.querySelector("tbody");
  tbody.replaceChildren(...users.map((user) => {
    const row = document.createElement("tr");
    const userCell = document.createElement("td");
    userCell.className = "domain";
    userCell.setAttribute("data-label", "User");
    userCell.textContent = user;
    const passwordCell = document.createElement("td");
    passwordCell.setAttribute("data-label", "Password");
    const rotate = document.createElement("button");
    rotate.type = "button";
    rotate.className = "btn";
    rotate.textContent = "Rotate password";
    rotate.addEventListener("click", () => runBusy(rotate, async () => {
      $("db-user-job-status").textContent = `rotating ${user} password…`;
      const accepted = await api(
        `/api/sites/${encodeURIComponent(currentDomain)}/db-users/${encodeURIComponent(user)}/password`,
        { method: "POST", body: JSON.stringify({}) },
      );
      const job = await pollJob(accepted.job_id, (steps, current) => {
        $("db-user-job-status").textContent = `${current.state} · ${stepText(steps.at(-1))}`;
      });
      $("db-user-job-status").textContent = job.state;
      if (job.state === "failed") throw new Error(job.result?.error || "database password rotation failed");
      if (job.one_time) renderOneTime(`Database password for ${user} on ${currentDomain}`, job.one_time);
      await loadEvents();
      toast(`password rotated for ${user}`, false);
    }).finally(() => { $("db-user-job-status").textContent = ""; }));
    passwordCell.append(rotate);
    const actionCell = document.createElement("td");
    actionCell.setAttribute("data-label", "Type exact name to drop");
    actionCell.append(exactConfirmAction(user, "Drop user", async () => {
      const result = await api(
        `/api/sites/${encodeURIComponent(currentDomain)}/db-users/${encodeURIComponent(user)}`,
        { method: "DELETE", body: JSON.stringify({ confirm: user }) },
      );
      toast(result.message || `database user ${user} dropped`, !result.ok);
      await Promise.all([refreshDatabases(), loadEvents()]);
    }));
    row.append(userCell, passwordCell, actionCell);
    return row;
  }));
}

async function refreshDatabases() {
  if (!currentDomain) return;
  $("databases-status").textContent = "loading…";
  $("db-users-status").textContent = "loading…";
  const domain = encodeURIComponent(currentDomain);
  const [databaseResult, userResult] = await Promise.allSettled([
    api(`/api/sites/${domain}/databases`),
    api(`/api/sites/${domain}/db-users`),
  ]);
  const errors = [];
  if (databaseResult.status === "fulfilled") {
    renderDatabases(databaseResult.value.databases || []);
    $("databases-status").textContent = "";
  } else {
    renderDatabases([]);
    $("databases-empty").textContent = databaseResult.reason.message;
    $("databases-status").textContent = databaseResult.reason.status === 503 ? "runtime unavailable" : "load failed";
    errors.push(databaseResult.reason);
  }
  if (userResult.status === "fulfilled") {
    renderDbUsers(userResult.value.users || []);
    $("db-users-status").textContent = "";
  } else {
    renderDbUsers([]);
    $("db-users-empty").textContent = userResult.reason.message;
    $("db-users-status").textContent = userResult.reason.status === 503 ? "runtime unavailable" : "load failed";
    errors.push(userResult.reason);
  }
  syncAdminerFields();
  if (errors.length && errors[0].message !== "unauthorized") toast(errors[0].message, true);
}

function adminerEnabled() {
  return Boolean(currentSite.adminer_port) || [true, 1, "1", "true", "enabled"].includes(currentSite.adminer_enabled);
}

function syncAdminerFields() {
  const enabled = adminerEnabled();
  $("adminer-enabled").checked = enabled;
  $("adminer-port").value = currentSite.adminer_port || "";
  const badgeNode = $("adminer-badge");
  badgeNode.textContent = enabled ? "on" : "off";
  badgeNode.className = `badge ${enabled ? "on" : "off"}`;
  $("adminer-output").textContent = enabled
    ? `Adminer: http://127.0.0.1:${currentSite.adminer_port}\nReachable only from the server itself or through an SSH tunnel.`
    : "Adminer is disabled.";
}

async function createDatabase() {
  const name = $("database-name").value.trim();
  const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/databases`, {
    method: "POST",
    body: JSON.stringify({ name }),
  });
  $("database-name").value = "";
  toast(result.message || `database ${name} ready`, !result.ok);
  await Promise.all([refreshDatabases(), loadEvents()]);
}

async function createDatabaseUser() {
  const user = $("db-user-name").value.trim();
  const database = $("db-user-database").value;
  const payload = { user };
  if (database) payload.database = database;
  $("db-user-job-status").textContent = "starting job…";
  try {
    const accepted = await api(`/api/sites/${encodeURIComponent(currentDomain)}/db-users`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    const job = await pollJob(accepted.job_id, (steps, current) => {
      $("db-user-job-status").textContent = `${current.state} · ${stepText(steps.at(-1))}`;
    });
    $("db-user-job-status").textContent = job.state;
    if (job.state === "failed") throw new Error(job.result?.error || "database user creation failed");
    $("db-user-name").value = "";
    $("db-user-database").value = "";
    if (job.one_time) renderOneTime(`Database credentials for ${user} on ${currentDomain}`, job.one_time);
    await Promise.all([refreshDatabases(), loadEvents()]);
    toast(`database user ${user} ready`, false);
  } finally {
    $("db-user-job-status").textContent = "";
  }
}

async function saveAdminer() {
  const enabled = $("adminer-enabled").checked;
  const port = $("adminer-port").value.trim();
  const payload = { action: enabled ? "on" : "off" };
  if (enabled && port) payload.port = Number(port);
  const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/adminer`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  const detail = await api(`/api/sites/${encodeURIComponent(currentDomain)}`);
  currentSite = detail.site || currentSite;
  syncAdminerFields();
  await Promise.all([loadSites(), loadEvents()]);
  toast(result.message || `Adminer ${enabled ? "enabled" : "disabled"}`, !result.ok);
}

function phpSettingsPayload() {
  return {
    php_memory_limit: $("php-memory-limit").value.trim(),
    php_max_execution_time: $("php-max-execution-time").value.trim(),
    php_max_input_time: $("php-max-input-time").value.trim(),
    php_max_input_vars: $("php-max-input-vars").value.trim(),
    php_upload_max_size: $("php-upload-max-size").value.trim(),
  };
}

function clearPhpPreview() {
  pendingPhpSettings = null;
  $("php-preview").classList.add("hidden");
  $("btn-php-apply").classList.add("hidden");
}

async function refreshPhpSettings() {
  if (!currentDomain) return;
  const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/php-settings`);
  const settings = result.settings || {};
  $("php-memory-limit").value = settings.php_memory_limit || "";
  $("php-max-execution-time").value = settings.php_max_execution_time || "";
  $("php-max-input-time").value = settings.php_max_input_time || "";
  $("php-max-input-vars").value = settings.php_max_input_vars || "";
  $("php-upload-max-size").value = settings.php_upload_max_size || "";
  $("php-output").textContent = "Current managed PHP settings loaded.";
  clearPhpPreview();
}

async function previewPhpSettings() {
  const payload = phpSettingsPayload();
  try {
    const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/php-settings`, {
      method: "POST",
      body: JSON.stringify({ ...payload, dry_run: true }),
    });
    pendingPhpSettings = payload;
    renderConfigPreview(result, {
      preview: "php-preview",
      summary: "php-preview-summary",
      changes: "php-preview-changes",
      apply: "btn-php-apply",
      output: "php-output",
    });
  } catch (error) {
    $("php-output").textContent = error.message;
    throw error;
  }
}

async function applyPhpSettings() {
  if (!pendingPhpSettings) return;
  const payload = pendingPhpSettings;
  try {
    const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/php-settings`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    pendingPhpSettings = null;
    $("php-preview").classList.add("hidden");
    $("btn-php-apply").classList.add("hidden");
    $("php-output").textContent = result.message || "PHP settings applied.";
    await Promise.all([loadSites(), loadEvents()]);
    toast(result.message || "PHP settings applied", !result.ok);
  } catch (error) {
    $("php-output").textContent = error.message;
    throw error;
  }
}

function syncGeneratedVhost() {
  const path = currentSite.path ? `${currentSite.path}/nginx/default.conf` : "nginx/default.conf";
  $("vhost-generated").textContent = [
    `wpfy-owned generated file: ${path}`,
    "",
    "Content is not exposed by the current panel API. Inspect this read-only file on the server.",
  ].join("\n");
}

async function refreshVhost() {
  if (!currentDomain) return;
  syncGeneratedVhost();
  const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/nginx-custom`);
  $("vhost-custom").value = result.content || "";
  $("vhost-save-status").textContent = "";
}

function showVhostResult(message, isError) {
  const node = $("vhost-result-message");
  node.textContent = message;
  node.className = `validation-message ${isError ? "error" : "success"}`;
}

async function saveVhost() {
  $("vhost-save-status").textContent = "validating…";
  try {
    const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/nginx-custom`, {
      method: "PUT",
      body: JSON.stringify({ content: $("vhost-custom").value }),
    });
    $("vhost-test-output").textContent = result.nginx_test_output || "(no nginx validation output)";
    showVhostResult("Validation passed. The live operator include was updated.", false);
    await loadEvents();
    toast("nginx custom include validated and saved", false);
  } catch (error) {
    const output = error.payload?.nginx_test_output || error.message;
    $("vhost-test-output").textContent = output;
    const message = error.status === 503
      ? "Validation needs the site runtime running. The live config was not changed."
      : "Nginx rejected this snippet. The live config was not changed; your text remains in the editor.";
    showVhostResult(message, true);
    throw error;
  } finally {
    $("vhost-save-status").textContent = "";
  }
}

/* ---- cache ---- */

function selectedCachePlugin() {
  return document.querySelector("input[name='cache-page-cache']:checked")?.value || "none";
}

function syncCacheUpload() {
  const selected = selectedCachePlugin();
  const option = (currentCache?.page_cache_options || []).find((item) => item.value === selected);
  const byo = option?.source === "byo";
  $("cache-upload-instructions")?.classList.toggle("hidden", !byo);
  if (byo && currentCache?.byo_plugin?.upload_path) {
    $("cache-upload-path").textContent = currentCache.byo_plugin.upload_path;
    $("cache-upload-state").textContent = selected === currentCache.page_cache
      ? "The server-side nginx rule and WP_CACHE constant are already staged."
      : "Applying this choice will stage the server-side nginx rule and WP_CACHE constant.";
  }
}

function renderCacheChoices(options, selected) {
  const container = $("cache-page-options");
  if (!container) return;
  container.replaceChildren(...options.map((option) => {
    const label = document.createElement("label");
    label.className = "cache-choice";
    const input = document.createElement("input");
    input.type = "radio";
    input.name = "cache-page-cache";
    input.value = option.value;
    input.checked = option.value === selected;
    input.addEventListener("change", () => {
      clearCachePreview();
      syncCacheUpload();
    });
    const copy = document.createElement("span");
    copy.className = "cache-choice-copy";
    const title = document.createElement("strong");
    title.textContent = option.label;
    const detail = document.createElement("span");
    detail.className = "cache-choice-detail";
    detail.textContent = option.value === "none" ? "Disable page caching" : option.auto_install
      ? "Installed and activated by wpfy"
      : "Upload and activate the plugin yourself";
    copy.append(title, detail);
    copy.append(badge(option.badge, option.source === "free"));
    label.append(input, copy);
    return label;
  }));
  syncCacheUpload();
}

function clearCachePreview() {
  pendingCache = null;
  $("cache-preview")?.classList.add("hidden");
  $("btn-cache-apply")?.classList.add("hidden");
  if ($("cache-output")) $("cache-output").textContent = "No changes previewed yet.";
}

async function refreshCache() {
  if (!currentDomain) return;
  const domain = currentDomain;
  const result = await api(`/api/sites/${encodeURIComponent(domain)}/cache`);
  if (currentDomain !== domain) return;
  currentCache = result;
  renderCacheChoices(result.page_cache_options || [], result.page_cache);
  $("cache-redis").checked = result.object_cache === "redis";
  const current = (result.page_cache_options || []).find((option) => option.value === result.page_cache);
  $("cache-current-badge").textContent = current?.label || result.page_cache || "unknown";
  $("cache-current-badge").className = `badge ${current?.source === "byo" ? "off" : "on"}`;
  $("cache-snippet-path").textContent = result.snippet_path || "not available";
  $("cache-output").textContent = "Current cache settings loaded.";
  clearCachePreview();
}

function cachePayload() {
  return {
    page_cache: selectedCachePlugin(),
    object_cache: $("cache-redis").checked ? "redis" : "none",
  };
}

function renderCacheOperations(operations) {
  $("cache-preview-operations")?.replaceChildren(...(operations || []).map((operation) =>
    checkItem({
      name: operation.operation || "operation",
      state: operation.status === "planned" ? "plan"
        : operation.status === "ok" ? "pass"
          : operation.status === "error" ? "fail" : "warn",
      message: operation.message || operation.status || "planned",
    })));
}

async function previewCache() {
  const domain = currentDomain;
  const payload = cachePayload();
  const result = await api(`/api/sites/${encodeURIComponent(domain)}/cache`, {
    method: "PUT",
    body: JSON.stringify({ ...payload, dry_run: true }),
  });
  if (currentDomain !== domain || JSON.stringify(cachePayload()) !== JSON.stringify(payload)) return;
  pendingCache = { domain, payload };
  renderConfigPreview(result, {
    preview: "cache-preview",
    summary: "cache-preview-summary",
    changes: "cache-preview-changes",
    apply: "btn-cache-apply",
    output: "cache-output",
  });
  renderCacheOperations(result.operations);
}

async function applyCache() {
  if (!pendingCache || pendingCache.domain !== currentDomain) return;
  const { domain, payload } = pendingCache;
  const result = await api(`/api/sites/${encodeURIComponent(domain)}/cache`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
  pendingCache = null;
  if (currentDomain !== domain) return;
  await Promise.all([loadSites(), loadOverview(), loadEvents()]);
  await refreshCache();
  const actionLines = (result.actions || []).map((action) =>
    `${action.status}: ${action.message}`);
  $("cache-output").textContent = [
    `state: ${result.state || (result.ok ? "ok" : "error")}`,
    ...actionLines,
    result.snippet_path ? `snippet: ${result.snippet_path}` : "",
  ].filter(Boolean).join("\n");
  toast(result.message || "cache configuration applied", !result.ok);
}

function renderCachePurge(result) {
  const outcomes = result?.outcomes || [];
  $("cache-purge-outcomes")?.replaceChildren(...outcomes.map((outcome) => checkItem({
    name: outcome.cache || "cache layer",
    ok: outcome.status === "ok" ? true : outcome.status === "error" ? false : null,
    message: `${outcome.status}: ${outcome.message || "no details"}`,
  })));
  $("cache-purge-output").textContent = result?.message || "No purge details returned.";
}

async function purgeCache() {
  $("cache-purge-status").textContent = "purging…";
  try {
    const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/cache/purge`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    renderCachePurge(result);
    toast(result.message || "cache purge complete", !result.ok);
  } catch (error) {
    if (error.payload) renderCachePurge(error.payload);
    throw error;
  } finally {
    $("cache-purge-status").textContent = "";
  }
}

/* ---- security ---- */

function lineValues(id) {
  return ($(id)?.value || "").split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
}

function securityPayload() {
  const payload = {
    deny_ips: lineValues("security-deny-ips"),
    ua_blocks: lineValues("security-ua-blocks"),
    cloudflare_only: $("security-cloudflare-only").checked,
    login_rate_limit: $("security-login-rate-limit").checked,
  };
  if (securityFail2banDirty) payload.fail2ban = $("security-fail2ban").checked;
  if (securityAuthDirty) {
    const basicAuth = {
      enabled: $("security-basic-enabled").checked,
      username: $("security-basic-username").value.trim() || null,
    };
    const password = $("security-basic-password").value;
    if (password) basicAuth.password = password;
    payload.basic_auth = basicAuth;
  }
  return payload;
}

function clearSecurityPreview() {
  pendingSecurity = null;
  $("security-preview")?.classList.add("hidden");
  $("btn-security-apply")?.classList.add("hidden");
  $("btn-security-acknowledge")?.classList.add("hidden");
}

function syncSecurityFields(state) {
  $("security-deny-ips").value = (state.deny_ips || []).join("\n");
  $("security-ua-blocks").value = (state.ua_blocks || []).join("\n");
  $("security-basic-enabled").checked = Boolean(state.basic_auth?.enabled);
  $("security-basic-username").value = state.basic_auth?.username || "";
  $("security-basic-password").value = "";
  securityAuthDirty = false;
  $("security-cloudflare-only").checked = Boolean(state.cloudflare_only);
  $("security-login-rate-limit").checked = Boolean(state.login_rate_limit);
  $("security-fail2ban").checked = Boolean(state.fail2ban);
  securityFail2banDirty = false;
  $("security-snippet-path").textContent = state.snippet_path || "not available";
  $("security-trusted-sources").textContent = (state.trusted_edge_sources || []).join(", ") || "not available";
  renderLoginShield(state.login_shield, state.protected_surfaces);
}

function renderLoginShield(status, protectedSurfaces) {
  const summary = $("login-shield-summary");
  const scope = $("login-shield-ban-scope");
  if (!summary || !scope) return;
  scope.textContent = "";
  if (!status) {
    summary.replaceChildren();
    return;
  }
  const items = [];
  const enabled = Boolean(status.enabled);
  items.push(checkItem({
    name: "State",
    state: enabled ? "pass" : "warn",
    message: enabled ? "Login Shield enabled" : "Login Shield disabled",
  }));

  const hostInstalled = Boolean(status.host_fail2ban_installed);
  const hostHealth = status.host_fail2ban_health || "unknown";
  items.push(checkItem({
    name: "Host service",
    state: hostInstalled ? (hostHealth === "ok" ? "pass" : "fail") : "warn",
    message: hostInstalled ? `fail2ban service ${hostHealth}` : "fail2ban not installed on host",
  }));

  const plugin = status.plugin || {};
  if (plugin.active === true) {
    const ownership = plugin.ownership ? ` (${plugin.ownership})` : "";
    items.push(checkItem({
      name: "Plugin",
      ok: true,
      message: `wp-fail2ban ${plugin.version || "active"}${ownership}`,
    }));
  } else {
    items.push(checkItem({
      name: "Plugin",
      state: "warn",
      message: plugin.slug ? "wp-fail2ban plugin inactive" : "wp-fail2ban plugin not installed",
    }));
  }

  const logHealth = status.event_log_health || "unknown";
  const matched = Number.isInteger(status.recent_matched_failures) ? `${status.recent_matched_failures} recent` : "no recent";
  items.push(checkItem({
    name: "Logging pipeline",
    state: logHealth === "ok" ? "pass" : "warn",
    message: `event log ${logHealth}; ${matched} matched failures`,
  }));

  const proxy = status.trusted_proxy_health || "edge-trust-unavailable";
  items.push(checkItem({
    name: "Trusted proxy",
    state: proxy === "edge-trust-configured" ? "pass" : "warn",
    message: proxy,
  }));

  items.push(checkItem({
    name: "Last blocked attempt",
    state: status.last_detected_failure ? "pass" : "warn",
    message: status.last_detected_failure || "no blocked attempts recorded yet",
  }));

  if (Number.isInteger(status.recent_bans) || Number.isInteger(status.total_bans)) {
    items.push(checkItem({
      name: "Recent bans",
      ok: true,
      message: `${status.recent_bans ?? 0} currently banned; ${status.total_bans ?? 0} total`,
    }));
  } else {
    items.push(checkItem({ name: "Recent bans", state: "warn", message: "unknown (runtime not probed)" }));
  }

  if (protectedSurfaces && protectedSurfaces.length) {
    items.push(checkItem({ name: "Protected surfaces", ok: true, message: protectedSurfaces.join(", ") }));
  }

  if (status.health === "degraded") {
    items.push(checkItem({
      name: "Health",
      state: "warn",
      message: status.degraded_reason || "degraded; re-render required",
    }));
  }

  summary.replaceChildren(...items);
  if (status.ban_scope) scope.textContent = status.ban_scope;
}

async function refreshSecurity() {
  if (!currentDomain) return;
  const domain = currentDomain;
  $("security-status").textContent = "loading…";
  const result = await api(`/api/sites/${encodeURIComponent(domain)}/security`);
  if (currentDomain !== domain) return;
  currentSecurity = result;
  syncSecurityFields(result);
  clearSecurityPreview();
  $("security-output").textContent = "Current security settings loaded.";
  $("security-status").textContent = "";
}

function renderSecurityPreview(result) {
  const rows = [];
  [["scope", result.scope || "site"], ["restarts", (result.restarts || []).join(", ") || "none"]]
    .forEach(([key, value]) => {
      const dt = document.createElement("dt");
      dt.textContent = key;
      const dd = document.createElement("dd");
      dd.textContent = value;
      rows.push(dt, dd);
    });
  $("security-preview-summary").replaceChildren(...rows);
  const changes = result.changes || [];
  $("security-preview-changes").replaceChildren(...(changes.length
    ? changes.map((change) => checkItem({ name: "change", state: "plan", message: change }))
    : [checkItem({ name: "no-op", ok: true, message: "No changes are needed." })]));
  const warnings = result.warnings || [];
  $("security-preview-warnings").replaceChildren(...warnings.map((warning) =>
    checkItem({ name: "lockout risk", state: "warn", message: warning })));
  $("security-preview").classList.remove("hidden");
  $("btn-security-apply").classList.toggle("hidden", changes.length === 0 || warnings.length > 0);
  $("btn-security-acknowledge").classList.toggle("hidden", changes.length === 0 || warnings.length === 0);
  $("security-output").textContent = warnings.length
    ? "Warning: this change was not applied. Review the lockout risk, then acknowledge it deliberately."
    : changes.length ? "Review the preview above, then explicitly apply it." : "Security settings are unchanged.";
}

async function previewSecurity() {
  const domain = currentDomain;
  const revision = securityRevision;
  const payload = securityPayload();
  const result = await api(`/api/sites/${encodeURIComponent(domain)}/security`, {
    method: "PUT",
    body: JSON.stringify({ ...payload, dry_run: true }),
  });
  if (currentDomain !== domain || securityRevision !== revision) return;
  pendingSecurity = { domain, payload };
  $("security-basic-password").value = "";
  renderSecurityPreview(result);
}

async function applySecurity(acknowledgeWarnings) {
  if (!pendingSecurity || pendingSecurity.domain !== currentDomain) return;
  const { domain, payload } = pendingSecurity;
  $("security-status").textContent = "applying…";
  try {
    const result = await api(`/api/sites/${encodeURIComponent(domain)}/security`, {
      method: "PUT",
      body: JSON.stringify({ ...payload, acknowledge_warnings: Boolean(acknowledgeWarnings) }),
    });
    if (result.acknowledgement_required) {
      renderSecurityPreview(result);
      return;
    }
    pendingSecurity = null;
    if (result.one_time) renderOneTime(`Basic-auth credentials for ${domain}`, result.one_time);
    await Promise.all([loadEvents(), refreshSecurity()]);
    $("security-output").textContent = result.message || "Security configuration applied.";
    toast(result.message || "security configuration applied", !result.ok);
  } finally {
    $("security-status").textContent = "";
  }
}

/* ---- cron ---- */

function cronLastRunText(lastRun) {
  if (!lastRun) return "Never";
  return `${lastRun.outcome || "unknown"} · ${formatTime(lastRun.timestamp)}`;
}

function cronActionButton(label, className, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", () => runBusy(button, handler));
  return button;
}

function renderCronJobs(jobs) {
  const table = $("cron-table");
  $("cron-empty").classList.toggle("hidden", jobs.length > 0);
  table.classList.toggle("hidden", jobs.length === 0);
  const rowDomain = currentDomain;
  table.querySelector("tbody").replaceChildren(...jobs.map((job) => {
    const row = document.createElement("tr");
    const schedule = eventCell(job.schedule, "domain", "Schedule");
    const command = eventCell(job.command, "domain cron-command", "Command");
    command.title = job.command;
    const service = eventCell(job.service, "domain", "Service");
    const enabled = document.createElement("td");
    enabled.setAttribute("data-label", "Enabled");
    enabled.append(badge(job.enabled ? "enabled" : "disabled", job.enabled));
    const timeout = eventCell(`${job.timeout}s`, "", "Timeout");
    const lastRun = eventCell(cronLastRunText(job.last_run), "cron-last-run", "Last run");
    const actions = document.createElement("td");
    actions.setAttribute("data-label", "Actions");
    const wrap = document.createElement("div");
    wrap.className = "cron-actions";
    const run = cronActionButton("Run now", "btn", async () => {
      if (currentDomain !== rowDomain) return;
      try {
        const result = await api(
          `/api/sites/${encodeURIComponent(rowDomain)}/cron/${encodeURIComponent(job.id)}/run`,
          { method: "POST", body: JSON.stringify({}) },
        );
        $("cron-run-output").textContent = `${result.outcome}: ${result.message}\nduration: ${Number(result.duration || 0).toFixed(3)}s`;
        toast(`cron run ${result.outcome}: ${result.message}`, result.outcome !== "ok");
      } catch (error) {
        const result = error.payload;
        if (result?.outcome) $("cron-run-output").textContent = `${result.outcome}: ${result.message}`;
        throw error;
      }
      await Promise.all([refreshCron(), loadEvents()]);
    });
    const toggle = cronActionButton(job.enabled ? "Disable" : "Enable", "btn", async () => {
      if (currentDomain !== rowDomain) return;
      await api(`/api/sites/${encodeURIComponent(rowDomain)}/cron/${encodeURIComponent(job.id)}`, {
        method: "PUT",
        body: JSON.stringify({ enabled: !job.enabled }),
      });
      await Promise.all([refreshCron(), loadEvents()]);
    });
    const remove = cronActionButton("Delete", "btn btn-danger-ghost", async () => {
      if (currentDomain !== rowDomain) return;
      if (!confirm(`Delete cron job ${job.id}?\n\n${job.schedule} · ${job.command}`)) return;
      await api(`/api/sites/${encodeURIComponent(rowDomain)}/cron/${encodeURIComponent(job.id)}`, {
        method: "DELETE",
        body: JSON.stringify({}),
      });
      await Promise.all([refreshCron(), loadEvents()]);
      toast("cron job deleted", false);
    });
    wrap.append(run, toggle, remove);
    actions.append(wrap);
    row.append(schedule, command, service, enabled, timeout, lastRun, actions);
    return row;
  }));
}

function syncCronServices(services) {
  const select = $("cron-service");
  const selected = select.value;
  const options = services.map((service) => {
    const option = document.createElement("option");
    option.value = service;
    option.textContent = service;
    return option;
  });
  select.replaceChildren(...options);
  select.value = services.includes(selected) ? selected : (services.includes("app") ? "app" : services[0] || "");
}

async function refreshCron() {
  if (!currentDomain) return;
  const domain = currentDomain;
  $("cron-status").textContent = "loading…";
  const result = await api(`/api/sites/${encodeURIComponent(domain)}/cron`);
  if (currentDomain !== domain) return;
  renderCronJobs(result.jobs || []);
  syncCronServices(result.services || []);
  $("cron-status").textContent = "";
}

async function addCronJob() {
  const payload = {
    schedule: $("cron-schedule").value.trim(),
    command: $("cron-command").value.trim(),
    service: $("cron-service").value,
    timeout: Number($("cron-timeout").value),
  };
  const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/cron`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  $("cron-command").value = "";
  await Promise.all([refreshCron(), loadEvents()]);
  toast(`cron job ${result.id} added`, false);
}

/* ---- files ---- */

function joinFilePath(parent, name) {
  return [parent, name].filter(Boolean).join("/");
}

function renderFileBreadcrumbs(path) {
  const parts = path ? path.split("/") : [];
  const nodes = [];
  const root = document.createElement("button");
  root.type = "button";
  root.textContent = "app";
  root.addEventListener("click", () => refreshFiles(""));
  nodes.push(root);
  parts.forEach((part, index) => {
    const separator = document.createElement("span");
    separator.textContent = "/";
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = part;
    button.addEventListener("click", () => refreshFiles(parts.slice(0, index + 1).join("/")));
    nodes.push(separator, button);
  });
  $("files-breadcrumbs").replaceChildren(...nodes);
}

function fileActionButton(label, className, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", () => runBusy(button, handler));
  return button;
}

function renderFileEntries(entries) {
  const table = $("files-table");
  table.classList.toggle("hidden", entries.length === 0);
  $("files-empty").classList.toggle("hidden", entries.length > 0);
  table.querySelector("tbody").replaceChildren(...entries.map((entry) => {
    const row = document.createElement("tr");
    const path = joinFilePath(currentFilesPath, entry.name);
    const name = document.createElement("td");
    name.className = "domain";
    name.setAttribute("data-label", "Name");
    if (["dir", "file"].includes(entry.type)) {
      const open = document.createElement("button");
      open.type = "button";
      open.className = "file-name-button";
      open.textContent = entry.name;
      open.addEventListener("click", () => entry.type === "dir" ? refreshFiles(path) : openManagedFile(path));
      name.append(open);
    } else {
      name.textContent = entry.name;
    }
    const type = eventCell(entry.type, "", "Type");
    const size = eventCell(entry.type === "dir" ? "—" : formatBytes(entry.size), "", "Size");
    const mode = eventCell(entry.mode, "domain", "Mode");
    const modified = eventCell(new Date(entry.modified * 1000).toLocaleString(), "", "Modified");
    const actions = document.createElement("td");
    actions.setAttribute("data-label", "Actions");
    const wrap = document.createElement("div");
    wrap.className = "file-actions";
    if (entry.type === "file") {
      wrap.append(
        fileActionButton("Edit", "btn", () => openManagedFile(path)),
        fileActionButton("Download", "btn", () => downloadManagedFile(path)),
      );
    }
    if (["file", "dir"].includes(entry.type)) {
      wrap.append(
        fileActionButton("Rename", "btn", async () => openRenameDialog(path)),
        fileActionButton("Permissions", "btn", async () => openChmodDialog(path, entry.mode)),
        fileActionButton("Delete", "btn btn-danger-ghost", () => deleteManagedEntry(path, entry.type)),
      );
    }
    actions.append(wrap);
    row.append(name, type, size, mode, modified, actions);
    return row;
  }));
}

async function refreshFiles(path = "") {
  if (!currentDomain) return;
  const domain = currentDomain;
  $("files-status").textContent = "loading…";
  const query = new URLSearchParams({ path });
  try {
    const result = await api(`/api/sites/${encodeURIComponent(domain)}/files?${query}`);
    if (currentDomain !== domain) return;
    currentFilesPath = result.path || "";
    renderFileBreadcrumbs(currentFilesPath);
    renderFileEntries(result.entries || []);
  } finally {
    $("files-status").textContent = "";
  }
}

async function openManagedFile(path) {
  const domain = currentDomain;
  const detailRequestId = detailRequest;
  const fileRequestId = ++fileRequest;
  const query = new URLSearchParams({ path });
  const result = await api(`/api/sites/${encodeURIComponent(domain)}/files/content?${query}`);
  if (currentDomain !== domain || detailRequest !== detailRequestId || fileRequest !== fileRequestId) return;
  openFilePath = result.path;
  $("file-editor-title").textContent = `Edit ${result.path}`;
  $("file-editor").value = result.content;
  $("file-wp-config-warning").classList.toggle("hidden", result.path.split("/").pop() !== "wp-config.php");
  $("file-editor-section").classList.remove("hidden");
  $("file-editor-section").scrollIntoView({ behavior: "smooth", block: "start" });
}

function closeManagedFile() {
  fileRequest += 1;
  openFilePath = null;
  $("file-editor").value = "";
  $("file-editor-section").classList.add("hidden");
}

async function saveManagedFile() {
  if (!openFilePath) return;
  await api(`/api/sites/${encodeURIComponent(currentDomain)}/files/content`, {
    method: "PUT",
    body: JSON.stringify({ path: openFilePath, content: $("file-editor").value }),
  });
  await Promise.all([refreshFiles(currentFilesPath), loadEvents()]);
  toast(`${openFilePath} saved`, false);
}

async function downloadManagedFile(path) {
  const query = new URLSearchParams({ path });
  await apiDownload(
    `/api/sites/${encodeURIComponent(currentDomain)}/files/download?${query}`,
    path.split("/").pop() || "download",
  );
}

async function uploadManagedFile(file) {
  if (!file) return;
  const path = joinFilePath(currentFilesPath, file.name);
  $("files-status").textContent = `uploading ${file.name}…`;
  try {
    const query = new URLSearchParams({ path });
    await apiUpload(`/api/sites/${encodeURIComponent(currentDomain)}/files/upload?${query}`, file);
    await Promise.all([refreshFiles(currentFilesPath), loadEvents()]);
    toast(`${file.name} uploaded`, false);
  } finally {
    $("files-status").textContent = "";
    $("file-upload-input").value = "";
  }
}

async function createManagedDirectory() {
  const name = $("file-mkdir-name").value.trim();
  if (!name) return;
  await api(`/api/sites/${encodeURIComponent(currentDomain)}/files/mkdir`, {
    method: "POST",
    body: JSON.stringify({ path: joinFilePath(currentFilesPath, name) }),
  });
  $("file-mkdir-name").value = "";
  await Promise.all([refreshFiles(currentFilesPath), loadEvents()]);
  toast(`${name} created`, false);
}

function openRenameDialog(path) {
  pendingFilePath = path;
  $("file-rename-to").value = path;
  $("file-rename-dialog").showModal();
}

async function renameManagedPath() {
  if (!pendingFilePath) return;
  const target = $("file-rename-to").value.trim();
  await api(`/api/sites/${encodeURIComponent(currentDomain)}/files/rename`, {
    method: "POST",
    body: JSON.stringify({ path: pendingFilePath, to: target }),
  });
  if (openFilePath === pendingFilePath) closeManagedFile();
  pendingFilePath = null;
  $("file-rename-dialog").close();
  await Promise.all([refreshFiles(currentFilesPath), loadEvents()]);
  toast("path renamed", false);
}

function openChmodDialog(path, mode) {
  pendingFilePath = path;
  $("file-chmod-mode").value = mode;
  $("file-chmod-dialog").showModal();
}

async function chmodManagedPath() {
  if (!pendingFilePath) return;
  await api(`/api/sites/${encodeURIComponent(currentDomain)}/files/chmod`, {
    method: "POST",
    body: JSON.stringify({ path: pendingFilePath, mode: $("file-chmod-mode").value }),
  });
  pendingFilePath = null;
  $("file-chmod-dialog").close();
  await Promise.all([refreshFiles(currentFilesPath), loadEvents()]);
  toast("permissions updated", false);
}

function openDeleteDialog(path) {
  pendingFilePath = path;
  const name = path.split("/").pop();
  $("file-delete-name").textContent = name;
  $("file-delete-confirm").value = "";
  $("btn-file-delete-confirm").disabled = true;
  $("file-delete-dialog").showModal();
}

async function deleteManagedEntry(path, type, confirmName = null) {
  if (type === "dir" && !confirmName) {
    const query = new URLSearchParams({ path });
    const listing = await api(`/api/sites/${encodeURIComponent(currentDomain)}/files?${query}`);
    if ((listing.entries || []).length > 0) {
      openDeleteDialog(path);
      return;
    }
  }
  await api(`/api/sites/${encodeURIComponent(currentDomain)}/files`, {
    method: "DELETE",
    body: JSON.stringify({ path, ...(confirmName ? { confirm: confirmName } : {}) }),
  });
  if (openFilePath === path) closeManagedFile();
  await Promise.all([refreshFiles(currentFilesPath), loadEvents()]);
  toast(`${path} deleted`, false);
}

async function confirmManagedDirectoryDelete() {
  if (!pendingFilePath) return;
  const path = pendingFilePath;
  const name = path.split("/").pop();
  await deleteManagedEntry(path, "dir", name);
  pendingFilePath = null;
  $("file-delete-dialog").close();
}

/* ---- config preview ---- */

function configPayload() {
  const payload = {
    php_version: $("config-php").value,
    flavor: $("config-flavor").value,
    letsencrypt: $("config-letsencrypt").checked ? "enabled" : "disabled",
  };
  const password = $("config-password").value;
  if (password) payload.password = password;
  return payload;
}

function clearConfigPreview() {
  pendingConfig = null;
  $("config-preview")?.classList.add("hidden");
  $("btn-config-apply")?.classList.add("hidden");
  if ($("config-output")) $("config-output").textContent = "No changes previewed yet.";
}

function renderConfigPreview(result, ids = {}) {
  const target = {
    preview: ids.preview || "config-preview",
    summary: ids.summary || "config-preview-summary",
    changes: ids.changes || "config-preview-changes",
    apply: ids.apply || "btn-config-apply",
    output: ids.output || "config-output",
  };
  const summary = $(target.summary);
  const rows = [];
  [["scope", result.scope || "site"], ["restarts", (result.restarts || []).join(", ") || "none"]].forEach(([key, value]) => {
    const dt = document.createElement("dt");
    dt.textContent = key;
    const dd = document.createElement("dd");
    dd.textContent = value;
    rows.push(dt, dd);
  });
  summary.replaceChildren(...rows);
  const changes = result.changes || [];
  $(target.changes).replaceChildren(...(changes.length
    ? changes.map((change) => checkItem({ name: "change", state: "plan", message: change }))
    : [checkItem({ name: "no-op", ok: true, message: "No changes are needed." })]));
  $(target.preview).classList.remove("hidden");
  $(target.apply).classList.toggle("hidden", changes.length === 0);
  $(target.output).textContent = changes.length
    ? "Review the preview above, then explicitly apply it."
    : "The current configuration already matches these values.";
}

async function previewConfig() {
  const payload = configPayload();
  pendingConfig = payload;
  $("config-password").value = "";
  const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/config`, {
    method: "POST",
    body: JSON.stringify({ ...payload, dry_run: true }),
  });
  renderConfigPreview(result);
}

async function applyConfig() {
  if (!pendingConfig) return;
  const payload = pendingConfig;
  const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/config`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  pendingConfig = null;
  $("config-password").value = "";
  $("config-output").textContent = [
    result.changes?.length ? `changes:\n- ${result.changes.join("\n- ")}` : "no changes needed",
    result.runtime?.message ? `runtime: ${result.runtime.message}` : "runtime: unchanged",
  ].join("\n");
  $("config-preview").classList.add("hidden");
  $("btn-config-apply").classList.add("hidden");
  await Promise.all([loadSites(), loadOverview(), loadEvents(), openDetail(currentDomain)]);
  toast("site configuration applied", !result.ok);
}

/* ---- services + events ---- */

async function restartService(domain, service, button) {
  const result = await api(
    `/api/sites/${encodeURIComponent(domain)}/services/${encodeURIComponent(service)}/restart`,
    { method: "POST", body: JSON.stringify({}) },
  );
  toast(result.message || `${domain}:${service} restarted`, !result.ok);
  await Promise.all([loadServices(), loadEvents()]);
  button?.focus();
}

function renderServices(services) {
  const table = $("services-table");
  const empty = $("services-empty");
  empty.classList.toggle("hidden", services.length > 0);
  table.classList.toggle("hidden", services.length === 0);
  table.querySelector("tbody").replaceChildren(...services.map((service) => {
    const row = document.createElement("tr");
    const name = eventCell(service.name, "domain", "Service");
    const status = eventCell(service.status || "unknown", "", "Status");
    const action = document.createElement("td");
    action.setAttribute("data-label", "Action");
    const separator = service.name.indexOf(":");
    if (separator > 0) {
      const domain = service.name.slice(0, separator);
      const serviceName = service.name.slice(separator + 1);
      const restart = document.createElement("button");
      restart.type = "button";
      restart.className = "btn";
      restart.textContent = "Restart";
      restart.addEventListener("click", () => runBusy(restart, () => restartService(domain, serviceName, restart)));
      action.append(restart);
    } else {
      action.textContent = "Use typed confirmation below";
    }
    row.append(name, status, action);
    return row;
  }));
}

async function loadServices() {
  const data = await api("/api/system/services");
  renderServices(data.services || []);
}

function syncEdgeRestart() {
  $("btn-edge-restart").disabled = $("edge-confirm").value !== "wpfy-traefik";
}

async function restartEdge() {
  const confirmation = $("edge-confirm").value;
  const result = await api("/api/system/traefik/restart", {
    method: "POST",
    body: JSON.stringify({ confirm: confirmation }),
  });
  $("edge-confirm").value = "";
  syncEdgeRestart();
  await Promise.all([loadServices(), loadEvents()]);
  toast(result.message || "Traefik edge restarted; every site was affected", !result.ok);
}

function eventOutcomeOk(outcome) {
  return ["ok", "succeeded", "success", "passed"].includes(String(outcome || "").toLowerCase());
}

function eventCell(text, className = "", label = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  if (label) cell.setAttribute("data-label", label);
  cell.textContent = text ?? "–";
  return cell;
}

function renderEventRows(tableId, emptyId, events, includeDomain) {
  const table = $(tableId);
  const empty = $(emptyId);
  if (!table || !empty) return;
  empty.classList.toggle("hidden", events.length > 0);
  table.classList.toggle("hidden", events.length === 0);
  const tbody = table.querySelector("tbody");
  tbody.replaceChildren(...events.map((event) => {
    const tr = document.createElement("tr");
    const outcomeCell = eventCell(event.outcome || "unknown", "", includeDomain ? "Outcome" : "Outcome");
    outcomeCell.className = eventOutcomeOk(event.outcome) ? "check-pass event-outcome" : "check-fail event-outcome";
    const cells = [
      eventCell(formatTime(event.timestamp), "", "Time"),
      eventCell(event.action || "–", "domain", "Action"),
    ];
    if (includeDomain) cells.push(eventCell(event.domain || "–", "domain", "Domain"));
    cells.push(outcomeCell, eventCell(event.actor || "–", "", "Actor"), eventCell(event.job_id || "–", "domain", "Job"));
    tr.append(...cells);
    return tr;
  }));
}

async function loadEvents() {
  const query = new URLSearchParams({ limit: "50" });
  const domain = $("events-domain")?.value.trim();
  const action = $("events-action")?.value.trim();
  if (domain) query.set("domain", domain);
  if (action) query.set("action", action);
  const data = await api(`/api/events?${query}`);
  renderEventRows("events-table", "events-empty", data.events || [], true);
}

async function refreshDashboard() {
  const work = [loadSites(), loadEvents()];
  if (!principal || isAdmin()) work.push(loadOverview(), loadHostMetrics(), loadServices(), loadHealth(), loadJobsTray());
  await Promise.all(work);
}

async function loadHealth() {
  try {
    const data = await api("/api/system/services");
    const services = data.services || [];
    const degraded = services.filter((s) => s.status !== "running").length;
    const dot = $("chip-health")?.querySelector(".dot");
    if (dot) {
      dot.className = `dot ${degraded === 0 ? "green" : services.length === degraded ? "red" : "amber"}`;
    }
    $("chip-health-text").textContent = degraded === 0 ? "Healthy" : `${degraded} degraded`;
    $("chip-health").title = services.map((s) => `${s.name}: ${s.status}`).join(", ");
    const degradedNames = services.filter((s) => s.status !== "running").map((s) => s.name);
    $("degraded-banner").classList.toggle("hidden", degraded === 0);
    if (degraded > 0) $("degraded-banner-text").textContent = `${degraded} service${degraded === 1 ? "" : "s"} degraded: ${degradedNames.join(", ")}.`;
  } catch (error) {
    $("chip-health-text").textContent = "–";
  }
}

async function loadOnboarding() {
  if (!principal || !isAdmin()) return;
  if (localStorage.getItem("wpfy-onboarding-dismissed")) return;
  if (allSites.length > 0) { $("onboarding-panel")?.classList.add("hidden"); return; }
  $("onboarding-panel")?.classList.remove("hidden");
}

async function loadBackupsSummary() {
  if (!principal || !isAdmin()) return;
  try {
    let allBackups = [];
    for (const site of allSites) {
      try {
        const data = await api(`/api/sites/${encodeURIComponent(site.domain)}/backups`);
        if (data.backups && data.backups.length) {
          allBackups.push({ domain: site.domain, latest: data.backups[0] });
        }
      } catch (e) { /* skip sites where backups fail */ }
    }
    $("backups-summary-panel").classList.toggle("hidden", allBackups.length === 0);
    $("backups-summary-empty").classList.toggle("hidden", allBackups.length > 0);
    const tbody = $("backups-summary-table").querySelector("tbody");
    tbody.replaceChildren(...allBackups.map(({ domain, latest }) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="domain" data-label="Site"><a href="/site/${encodeURIComponent(domain)}/backups" data-route="true">${_esc(domain)}</a></td>
        <td data-label="Latest backup">${new Date(latest.modified_at * 1000).toLocaleString()}</td>
        <td data-label="Size">${formatBytes(latest.size_bytes)}</td>
        <td data-label=""><a class="btn" href="/site/${encodeURIComponent(domain)}/backups" data-route="true">Manage</a></td>`;
      return tr;
    }));
  } catch (e) {
    // non-critical
  }
}

async function refreshDashboard() {
  const work = [loadSites(), loadEvents()];
  if (!principal || isAdmin()) work.push(loadOverview(), loadHostMetrics(), loadServices(), loadHealth(), loadJobsTray());
  await Promise.all(work);
  if (isAdmin()) {
    await loadOnboarding();
    loadBackupsSummary().catch(() => {});
  }
}

let _jobsPollTimer = 0;

async function loadJobsTray() {
  try {
    const data = await api("/api/jobs");
    const active = (data.jobs || []).filter((j) => j.state === "running" || j.state === "pending").length;
    $("chip-jobs-text").textContent = active === 0 ? "0 jobs" : `${active} job${active === 1 ? "" : "s"}`;
    $("chip-jobs")?.querySelector(".spinner")?.classList.toggle("hidden", active === 0);
    if (active === 0 && _jobsPollTimer) { clearInterval(_jobsPollTimer); _jobsPollTimer = 0; }
    if (active > 0 && !_jobsPollTimer) _jobsPollTimer = setInterval(loadJobsTray, 10000);
  } catch (error) {
    $("chip-jobs-text").textContent = "–";
  }
}

/* ---- dark mode ---- */

function initTheme() {
  const stored = localStorage.getItem("wpfy-panel-theme") || "auto";
  applyTheme(stored);
  const control = $("theme-control");
  if (control) {
    control.querySelectorAll("button").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.theme === stored);
      btn.addEventListener("click", () => {
        const value = btn.dataset.theme;
        localStorage.setItem("wpfy-panel-theme", value);
        applyTheme(value);
        control.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.theme === value));
      });
    });
  }
}

function applyTheme(value) {
  if (value === "dark") document.documentElement.setAttribute("data-theme", "dark");
  else if (value === "light") document.documentElement.setAttribute("data-theme", "light");
  else document.documentElement.removeAttribute("data-theme");
}

/* ---- account menu ---- */

function wireAccountMenu() {
  const chip = $("chip-account");
  const menu = $("account-menu");
  if (!chip || !menu) return;
  chip.addEventListener("click", (event) => {
    event.stopPropagation();
    menu.classList.toggle("hidden");
  });
  document.addEventListener("click", (event) => {
    if (!chip.contains(event.target) && !menu.contains(event.target)) menu.classList.add("hidden");
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") menu.classList.add("hidden");
  });
  menu.querySelectorAll("a[data-route]").forEach((a) => {
    a.addEventListener("click", () => menu.classList.add("hidden"));
  });
}

/* ---- hamburger nav ---- */

function wireHamburger() {
  const toggle = $("nav-toggle");
  const nav = $("topnav");
  if (!toggle || !nav) return;
  toggle.addEventListener("click", () => {
    const open = nav.classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(open));
    if (open) {
      const overlay = document.createElement("div");
      overlay.className = "nav-overlay";
      overlay.id = "nav-overlay";
      overlay.addEventListener("click", closeHamburger);
      document.body.appendChild(overlay);
    } else {
      closeHamburger();
    }
  });
  nav.addEventListener("click", (event) => {
    if (event.target.closest("a")) closeHamburger();
  });
}

function closeHamburger() {
  const nav = $("topnav");
  const toggle = $("nav-toggle");
  if (nav) nav.classList.remove("open");
  if (toggle) toggle.setAttribute("aria-expanded", "false");
  $("nav-overlay")?.remove();
}

/* ---- breadcrumbs ---- */

function renderSiteBreadcrumbs(domain) {
  $("route-breadcrumb").replaceChildren(
    linkEl("/dashboard", "Dashboard"),
    crumbSep(),
    linkEl("/sites", "Sites"),
    crumbSep(),
    document.createTextNode(domain),
  );
}

async function refreshActivity() {
  if (!currentDomain) return;
  const query = new URLSearchParams({ domain: currentDomain, limit: "50" });
  const data = await api(`/api/events?${query}`);
  renderEventRows("activity-table", "activity-empty", data.events || [], false);
}

/* ---- wiring ---- */

function wire() {
  listen("setup-account-form", "submit", submitSetup);
  listen("btn-setup-totp-verify", "click", (event) => runBusy(event.currentTarget, verifySetupTotp));
  listen("btn-setup-totp-skip", "click", revealSetupSkip);
  listen("btn-setup-totp-confirm-skip", "click", (event) => runBusy(event.currentTarget, confirmSetupSkip));
  listen("setup-totp-code", "keydown", (event) => {
    if (event.key === "Enter") $("btn-setup-totp-verify")?.click();
  });

  listen("login-form", "submit", (event) => {
    event.preventDefault();
    runBusy(event.currentTarget.querySelector("button[type='submit']"), signIn);
  });

  listen("btn-refresh", "click", (event) => runBusy(event.currentTarget, refreshDashboard));
  listen("btn-onboarding-dismiss", "click", () => {
    localStorage.setItem("wpfy-onboarding-dismissed", "1");
    $("onboarding-panel")?.classList.add("hidden");
  });
  listen("btn-users", "click", () => setUsersOpen($("users-panel")?.classList.contains("hidden")));
  listen("btn-users-close", "click", () => setUsersOpen(false));
  listen("user-create-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-user-create"), createUser);
  });
  listen("btn-totp-enroll", "click", (event) => runBusy(event.currentTarget, enrollTotp));
  listen("btn-account-totp-verify", "click", (event) => runBusy(event.currentTarget, verifyAccountTotp));
  listen("account-totp-code", "keydown", (event) => {
    if (event.key === "Enter") $("btn-account-totp-verify")?.click();
  });
  listen("metrics-range", "change", (event) => runBusy(event.currentTarget, loadHostMetrics));
  listen("activity-range", "change", (event) => runBusy(event.currentTarget, loadActivityMetrics));
  listen("btn-services-refresh", "click", (event) => runBusy(event.currentTarget, loadServices));
  listen("edge-confirm", "input", syncEdgeRestart);
  listen("btn-edge-restart", "click", (event) => runBusy(event.currentTarget, restartEdge, syncEdgeRestart));

  listen("btn-lock", "click", (event) => runBusy(event.currentTarget, logout));

  listen("btn-one-time-dismiss", "click", (event) =>
    runBusy(event.currentTarget, async () => dismissOneTime()));

  listen("btn-one-time-copy", "click", (event) => runBusy(event.currentTarget, async () => {
    if (!oneTimeCopyText) return;
    await navigator.clipboard.writeText(oneTimeCopyText);
    $("one-time-copy-status").textContent = "copied";
  }));

  listen("btn-new-site", "click", () => navigate("/sites/new"));
  listen("btn-new-site-close", "click", (event) => runBusy(event.currentTarget, async () => setNewSiteOpen(false)));
  listen("new-flavor", "change", updateCreateFields);
  listen("new-site-panel", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-create-site"), createSite);
  });
  listen("sites-search", "input", renderSites);
  listen("sites-flavor-filter", "change", renderSites);

  listen("detail-close", "click", (event) => runBusy(event.currentTarget, async () => closeDetail()));

  $("tabs")?.setAttribute("role", "tablist");
  const tabs = Array.from(document.querySelectorAll(".tab"));
  tabs.forEach((tab, index) => {
    const panelId = `tab-${tab.dataset.tab}`;
    const panel = $(panelId);
    tab.id = `tab-button-${tab.dataset.tab}`;
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-controls", panelId);
    tab.setAttribute("aria-selected", String(tab.classList.contains("active")));
    tab.tabIndex = tab.classList.contains("active") ? 0 : -1;
    if (panel) {
      panel.setAttribute("role", "tabpanel");
      panel.setAttribute("aria-labelledby", tab.id);
    }
    tab.addEventListener("click", () => selectTab(tab.dataset.tab));
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
      event.preventDefault();
      const offset = event.key === "ArrowRight" ? 1 : -1;
      const next = tabs[(index + offset + tabs.length) % tabs.length];
      selectTab(next.dataset.tab);
      next.focus();
    });
  });

  document.querySelectorAll("[data-runtime]").forEach((button) =>
    button.addEventListener("click", () => runBusy(button, async () => {
      const action = button.dataset.runtime;
      if (action === "stop" && !confirm(`Stop all containers for ${currentDomain}?`)) return;
      const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/runtime`, {
        method: "POST",
        body: JSON.stringify({ action }),
      });
      toast(result.message || `${action} finished`, !result.ok);
      await loadEvents();
    })));

  listen("btn-health", "click", (event) => runBusy(event.currentTarget, async () => {
    const data = await api(`/api/sites/${encodeURIComponent(currentDomain)}/health`);
    const health = data.health;
    const list = document.createElement("ul");
    list.className = "checks";
    list.append(
      checkItem({ name: "status", ok: health.status === "ready", message: health.status }),
      checkItem({ name: "scaffold", ok: health.scaffold_ready, message: health.scaffold_ready ? "ready" : "missing" }),
      checkItem({ name: "bootstrap", ok: health.bootstrap_ready, message: health.bootstrap_ready ? "ready" : "missing" }),
      checkItem({ name: "runtime", ok: health.runtime_ready, message: health.message }),
    );
    $("health-result").replaceChildren(list);
  }));

  listen("btn-diagnostics", "click", (event) => runBusy(event.currentTarget, async () => {
    const data = await api(`/api/sites/${encodeURIComponent(currentDomain)}/diagnostics`);
    $("diag-result").replaceChildren(...(data.checks || []).map(checkItem));
  }));

  listen("btn-logs", "click", (event) => runBusy(event.currentTarget, async () => {
    const service = $("log-service").value;
    const lines = $("log-lines").value || 200;
    const query = new URLSearchParams({ lines });
    if (service) query.set("service", service);
    const data = await api(`/api/sites/${encodeURIComponent(currentDomain)}/logs?${query}`);
    $("log-output").textContent = data.logs || "(no output)";
  }));

  listen("btn-backup", "click", (event) => runBusy(event.currentTarget, async () => {
    $("backup-status").textContent = "creating backup…";
    try {
      const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/backups`, { method: "POST" });
      toast(result.message || "backup finished", !result.ok);
      await Promise.all([refreshBackups(), loadEvents()]);
    } finally {
      $("backup-status").textContent = "";
    }
  }));

  listen("btn-sftp-enable", "click", (event) => runBusy(event.currentTarget, async () => {
    const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/sftp`, {
      method: "POST",
      body: JSON.stringify({ action: "enable" }),
    });
    $("sftp-output").textContent = result.message || "enabled";
    await loadEvents();
  }));

  listen("btn-sftp-rotate", "click", (event) => runBusy(event.currentTarget, async () => {
    const domain = currentDomain;
    const result = await api(`/api/sites/${encodeURIComponent(domain)}/sftp`, {
      method: "POST",
      body: JSON.stringify({ action: "rotate" }),
    });
    $("sftp-output").textContent = result.message || "password rotated";
    if (result.one_time) renderOneTime(`SFTP credentials for ${domain}`, result.one_time);
    await loadEvents();
  }));

  listen("btn-sftp-disable", "click", (event) => runBusy(event.currentTarget, async () => {
    if (!confirm(`Disable SFTP access for ${currentDomain}?`)) return;
    const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/sftp`, {
      method: "POST",
      body: JSON.stringify({ action: "disable" }),
    });
    $("sftp-output").textContent = result.message || "disabled";
    await loadEvents();
  }));

  listen("btn-wp", "click", (event) => runBusy(event.currentTarget, async () => {
    const raw = $("wp-input").value.trim();
    if (!raw) return;
    const args = raw.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)
      .map((arg) => arg.replace(/^["']|["']$/g, ""));
    const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/wp`, {
      method: "POST",
      body: JSON.stringify({ args }),
    });
    const parts = [];
    if (result.stdout) parts.push(result.stdout);
    if (result.stderr) parts.push(result.stderr);
    parts.push(`(exit ${result.exit_code})`);
    $("wp-output").textContent = parts.join("\n");
  }));

  listen("database-create-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-database-create"), createDatabase);
  });
  listen("db-user-create-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-db-user-create"), createDatabaseUser);
  });
  listen("adminer-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-adminer-save"), saveAdminer);
  });

  listen("php-settings-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-php-preview"), previewPhpSettings);
  });
  listen("btn-php-apply", "click", (event) => runBusy(event.currentTarget, applyPhpSettings));
  listen("cache-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-cache-preview"), previewCache);
  });
  listen("btn-cache-apply", "click", (event) => runBusy(event.currentTarget, applyCache));
  listen("btn-cache-purge", "click", (event) => runBusy(event.currentTarget, purgeCache));
  listen("cache-redis", "change", clearCachePreview);

  listen("security-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-security-preview"), previewSecurity);
  });
  listen("btn-security-apply", "click", (event) =>
    runBusy(event.currentTarget, () => applySecurity(false)));
  listen("btn-security-acknowledge", "click", (event) =>
    runBusy(event.currentTarget, () => applySecurity(true)));
  [
    "security-deny-ips", "security-ua-blocks",
  ].forEach((id) => listen(id, "input", () => { securityRevision += 1; clearSecurityPreview(); }));
  ["security-basic-username", "security-basic-password"].forEach((id) =>
    listen(id, "input", () => { securityAuthDirty = true; securityRevision += 1; clearSecurityPreview(); }));
  listen("security-basic-enabled", "change", () => {
    securityAuthDirty = true;
    securityRevision += 1;
    clearSecurityPreview();
  });
  ["security-cloudflare-only", "security-login-rate-limit"].forEach((id) =>
    listen(id, "change", () => { securityRevision += 1; clearSecurityPreview(); }));
  listen("security-fail2ban", "change", () => {
    securityFail2banDirty = true;
    securityRevision += 1;
    clearSecurityPreview();
  });

  listen("cron-add-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-cron-add"), addCronJob);
  });

  listen("file-mkdir-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-file-mkdir"), createManagedDirectory);
  });
  listen("file-upload-input", "change", (event) => uploadManagedFile(event.currentTarget.files?.[0]).catch((error) => {
    if (error.message !== "unauthorized") toast(error.message, true);
  }));
  ["dragenter", "dragover"].forEach((name) => listen("file-drop-zone", name, (event) => {
    event.preventDefault();
    event.currentTarget.classList.add("dragging");
  }));
  ["dragleave", "drop"].forEach((name) => listen("file-drop-zone", name, (event) => {
    event.preventDefault();
    event.currentTarget.classList.remove("dragging");
  }));
  listen("file-drop-zone", "drop", (event) => uploadManagedFile(event.dataTransfer?.files?.[0]).catch((error) => {
    if (error.message !== "unauthorized") toast(error.message, true);
  }));
  listen("btn-file-save", "click", (event) => runBusy(event.currentTarget, saveManagedFile));
  listen("btn-file-download-open", "click", (event) => runBusy(event.currentTarget, () => {
    if (openFilePath) return downloadManagedFile(openFilePath);
    return undefined;
  }));
  listen("btn-file-close", "click", (event) => runBusy(event.currentTarget, async () => closeManagedFile()));
  listen("file-rename-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-file-rename"), renameManagedPath);
  });
  listen("file-chmod-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-file-chmod"), chmodManagedPath);
  });
  listen("file-delete-confirm", "input", (event) => {
    $("btn-file-delete-confirm").disabled = event.currentTarget.value !== $("file-delete-name").textContent;
  });
  listen("file-delete-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-file-delete-confirm"), confirmManagedDirectoryDelete);
  });
  document.querySelectorAll("[data-dialog-close]").forEach((button) => button.addEventListener("click", () => {
    $(button.dataset.dialogClose)?.close();
    pendingFilePath = null;
  }));

  [
    "php-memory-limit", "php-max-execution-time", "php-max-input-time",
    "php-max-input-vars", "php-upload-max-size",
  ].forEach((id) => listen(id, "input", clearPhpPreview));

  listen("vhost-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-vhost-save"), saveVhost);
  });

  listen("config-form", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-config-preview"), previewConfig);
  });
  listen("btn-config-apply", "click", (event) => runBusy(event.currentTarget, applyConfig));
  ["config-php", "config-flavor", "config-letsencrypt", "config-password"].forEach((id) => {
    listen(id, id === "config-password" ? "input" : "change", () => {
      clearConfigPreview();
      if (id === "config-flavor" && $("config-password-field") && $("config-flavor")) {
        $("config-password-field").classList.toggle("hidden", !isWordPressFlavor($("config-flavor").value));
      }
    });
  });

  listen("delete-confirm", "input", syncDeleteButton);
  listen("btn-delete-site", "click", (event) =>
    runBusy(event.currentTarget, deleteCurrentSite, syncDeleteButton));

  listen("btn-events-refresh", "click", (event) => runBusy(event.currentTarget, loadEvents));
  ["events-domain", "events-action"].forEach((id) => listen(id, "keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      $("btn-events-refresh")?.click();
    }
  }));
  listen("btn-activity-refresh", "click", (event) =>
    runBusy(event.currentTarget, () => Promise.all([refreshActivity(), loadActivityMetrics()])));

  listen("btn-sysdiag", "click", (event) => runBusy(event.currentTarget, async () => {
    const data = await api("/api/system/diagnostics");
    $("sysdiag-result").replaceChildren(...(data.checks || []).map(checkItem));
  }));

  listen("wp-input", "keydown", (event) => {
    if (event.key === "Enter") $("btn-wp")?.click();
  });

  updateCreateFields();
}

async function boot() {
  if (!token) {
    showGate(false);
    return;
  }
  try {
    try {
      const setup = await setupRequest("/api/setup/status");
      if (setup.setup_available) {
        showSetup();
        return;
      }
    } catch (error) {
      if (error.status !== 410) throw error;
    }
    principal = await loadPrincipal();
    await refreshDashboard();
    showApp();
    await handleRoute(location.pathname).catch(() => {});
  } catch (error) {
    if (error.status === 401 || error.message === "unauthorized") {
      showGate(true);
      return;
    }
    toast(error.message || "Unable to load the panel.", true);
    showApp();
  }
}

/* ---- add-site wizard ---- */

const WIZARD_STORAGE_PREFIX = "wpfy.wizard.";
const WIZARD_STEPS = [
  { n: 1, label: "Basics" },
  { n: 2, label: "Runtime" },
  { n: 3, label: "Cache" },
  { n: 4, label: "SSL" },
  { n: 5, label: "Notify" },
  { n: 6, label: "Security" },
  { n: 7, label: "Review" },
];

function _wizKey(domain) { return WIZARD_STORAGE_PREFIX + (domain || ""); }

function getWizardState(domain) {
  const raw = sessionStorage.getItem(_wizKey(domain));
  return raw ? JSON.parse(raw) : null;
}

function saveWizardState(state) {
  if (state.domain) sessionStorage.setItem(_wizKey(state.domain), JSON.stringify(state));
}

function clearWizardState(domain) {
  sessionStorage.removeItem(_wizKey(domain));
}

function _wizDefault(domain) {
  return { step: 1, domain: domain || "", flavor: "wp", php_version: "8.4", multisite_type: null, object_cache: "none", page_cache: null, letsencrypt: "default", dns_provider: null, dns_preflight_passed: false, notification_channel: "off", enable_backups: false, backup_retention: 7, enable_sftp: false, admin_user: null, admin_email: null, job_id: null };
}

function renderWizard(state) {
  showSection("stub");
  const body = $("route-stub-body");
  $("route-stub-title").textContent = "Create a site";
  $("route-stub-text").textContent = "";
  $("route-breadcrumb").replaceChildren(linkEl("/dashboard", "Dashboard"), crumbSep(), linkEl("/sites", "Sites"), crumbSep(), document.createTextNode("New site"));
  const html = `<div class="wizard">
    <nav class="wizard-steps" aria-label="Wizard progress"><ol>${WIZARD_STEPS.map((s) => {
      const cls = s.n === state.step ? "active" : s.n < state.step ? "done" : "";
      return `<li class="wizard-step ${cls}" data-step="${s.n}"><span>${s.n}</span> ${s.label}</li>`;
    }).join("")}</ol></nav>
    <div class="wizard-body" id="wizard-body"></div>
    <div class="wizard-actions" id="wizard-actions"></div>
  </div>`;
  body.innerHTML = html;
  document.querySelectorAll(".wizard-step.done").forEach((el) => {
    el.addEventListener("click", () => {
      const step = parseInt(el.dataset.step, 10);
      if (step < state.step) { state.step = step; renderWizard(state); }
    });
  });
  renderWizardStep(state);
}

function renderWizardStep(state) {
  const wbody = $("wizard-body");
  const wactions = $("wizard-actions");
  if (!wbody || !wactions) return;
  switch (state.step) {
    case 1: _renderStep1(state, wbody, wactions); break;
    case 2: _renderStep2(state, wbody, wactions); break;
    case 3: _renderStep3(state, wbody, wactions); break;
    case 4: _renderStep4(state, wbody, wactions); break;
    case 5: _renderStep5(state, wbody, wactions); break;
    case 6: _renderStep6(state, wbody, wactions); break;
    case 7: _renderStep7(state, wbody, wactions); break;
  }
}

function _wizButtons(wactions, state, nextEnabled) {
  wactions.innerHTML = state.step > 1
    ? `<button class="btn" id="btn-wiz-back">Back</button><button class="btn btn-primary" id="btn-wiz-next"${nextEnabled ? "" : " disabled"}>Next</button>`
    : `<button class="btn btn-primary" id="btn-wiz-next"${nextEnabled ? "" : " disabled"}>Next</button>`;
  $("btn-wiz-next")?.addEventListener("click", () => { state.step++; saveWizardState(state); renderWizard(state); });
  $("btn-wiz-back")?.addEventListener("click", () => { state.step--; saveWizardState(state); renderWizard(state); });
}

function _renderStep1(state, wbody, wactions) {
  wbody.innerHTML = `<div class="form-grid">
    <label>Domain<input id="wiz-domain" type="text" inputmode="url" autocomplete="off" placeholder="example.com" value="${_esc(state.domain)}"></label>
    <label>Site type<select id="wiz-flavor">${_flavorOptions(state.flavor)}</select></label>
    <label>PHP version<select id="wiz-php">${_phpOptions(state.php_version)}</select></label>
  </div>`;
  _wizButtons(wactions, state, true);
  $("wiz-domain")?.addEventListener("keydown", (e) => { if (e.key === "Enter") $("btn-wiz-next")?.click(); });
  $("btn-wiz-next")?.addEventListener("click", () => {
    const domain = $("wiz-domain").value.trim();
    if (!domain) { toast("Enter a domain name.", true); return; }
    state.domain = domain;
    state.flavor = $("wiz-flavor").value;
    state.php_version = $("wiz-php").value;
    state.step++; saveWizardState(state); renderWizard(state);
  }, { once: true });
}

function _renderStep2(state, wbody, wactions) {
  let extra = "";
  if (isWordPressFlavor(state.flavor)) {
    extra = `<label>Multisite type<select id="wiz-multisite"><option value="">Standard install</option><option value="subdir"${state.multisite_type === "subdir" ? " selected" : ""}>Subdirectory</option><option value="subdomain"${state.multisite_type === "subdomain" ? " selected" : ""}>Subdomain</option></select></label>`;
  }
  wbody.innerHTML = `<div class="form-grid">
    ${extra}
    <label>Object cache<select id="wiz-object-cache"><option value="none"${state.object_cache === "none" ? " selected" : ""}>None</option><option value="redis"${state.object_cache === "redis" ? " selected" : ""}>Redis</option></select></label>
  </div>`;
  _wizButtons(wactions, state, true);
}

function _renderStep3(state, wbody, wactions) {
  const flavorCacheMap = { wpfc: "FastCGI cache", wprocket: "WP Rocket", wpsc: "Super Cache", wpce: "cache-enabler", wpredis: "Redis page cache", wp: "Nginx FastCGI cache" };
  const cacheLabel = flavorCacheMap[state.flavor] || "Nginx FastCGI cache";
  wbody.innerHTML = `<dl class="kv">
    <dt>Page cache</dt><dd>${_esc(cacheLabel)} <span class="badge on">recommended</span></dd>
    <dt>Object cache</dt><dd>${state.object_cache === "redis" ? "Redis" : "None"}</dd>
  </dl><p class="hint">Cache options are determined by your site type. You can change the page-cache integration later in Site Settings.</p>`;
  _wizButtons(wactions, state, true);
}

function _renderStep4(state, wbody, wactions) {
  wbody.innerHTML = `<div class="form-grid">
    <label>Let’s Encrypt mode<select id="wiz-letsencrypt"><option value="default"${state.letsencrypt === "default" ? " selected" : ""}>Default</option><option value="wildcard"${state.letsencrypt === "wildcard" ? " selected" : ""}>Wildcard</option><option value="off"${state.letsencrypt === "off" ? " selected" : ""}>Off</option></select></label>
    <label>DNS provider<select id="wiz-dns"><option value="">None</option><option value="cloudflare"${state.dns_provider === "cloudflare" ? " selected" : ""}>Cloudflare</option></select></label>
  </div>
  <p class="hint" id="wiz-dns-note">DNS preflight runs on the server during site creation. Ensure the domain resolves to this server’s public IP.</p>
  <div id="wiz-preflight-result"></div>`;
  _wizButtons(wactions, state, true);
}

function _renderStep5(state, wbody, wactions) {
  wbody.innerHTML = `<div class="form-grid">
    <label>Notifications<select id="wiz-notify"><option value="off"${state.notification_channel === "off" ? " selected" : ""}>Off</option><option value="email" disabled>Email (coming soon)</option><option value="webhook" disabled>Webhook (coming soon)</option></select></label>
  </div><p class="hint">Notification channels are configured per-site and can be changed later.</p>`;
  _wizButtons(wactions, state, true);
}

function _renderStep6(state, wbody, wactions) {
  wbody.innerHTML = `<div class="form-grid">
    <label class="toggle-field"><input id="wiz-backups" type="checkbox"${state.enable_backups ? " checked" : ""}><span>Enable backups</span></label>
    <label>Retention (days)<input id="wiz-retention" type="number" min="1" max="90" value="${state.backup_retention}"></label>
    <label class="toggle-field"><input id="wiz-sftp" type="checkbox"${state.enable_sftp ? " checked" : ""}><span>Enable SFTP</span></label>
    <label>Admin user<span class="optional">optional</span><input id="wiz-admin-user" type="text" autocomplete="username" value="${_esc(state.admin_user || "")}"></label>
    <label>Admin email<span class="optional">optional</span><input id="wiz-admin-email" type="email" autocomplete="email" value="${_esc(state.admin_email || "")}"></label>
  </div>`;
  _wizButtons(wactions, state, true);
}

function _renderStep7(state, wbody, wactions) {
  const letsencryptLabel = state.letsencrypt === "default" ? "Default" : state.letsencrypt === "wildcard" ? "Wildcard" : "Off";
  wbody.innerHTML = `<div class="wizard-summary">
    <h3>Review your site</h3>
    <dl>
      <dt>Domain</dt><dd>${_esc(state.domain)} <span class="edit-link" data-goto="1">edit</span></dd>
      <dt>Site type</dt><dd>${_esc(state.flavor)} <span class="edit-link" data-goto="1">edit</span></dd>
      <dt>PHP version</dt><dd>${_esc(state.php_version)} <span class="edit-link" data-goto="1">edit</span></dd>
      <dt>Object cache</dt><dd>${state.object_cache === "redis" ? "Redis" : "None"} <span class="edit-link" data-goto="2">edit</span></dd>
      <dt>Let’s Encrypt</dt><dd>${letsencryptLabel} <span class="edit-link" data-goto="4">edit</span></dd>
      <dt>DNS provider</dt><dd>${state.dns_provider || "none"} <span class="edit-link" data-goto="4">edit</span></dd>
      <dt>Notifications</dt><dd>${state.notification_channel} <span class="edit-link" data-goto="5">edit</span></dd>
      <dt>Backups</dt><dd>${state.enable_backups ? `Enabled · ${state.backup_retention}d retention` : "Disabled"} <span class="edit-link" data-goto="6">edit</span></dd>
      <dt>SFTP</dt><dd>${state.enable_sftp ? "Enabled" : "Disabled"} <span class="edit-link" data-goto="6">edit</span></dd>
      <dt>Admin user</dt><dd>${state.admin_user || "admin (default)"} <span class="edit-link" data-goto="6">edit</span></dd>
      <dt>Admin email</dt><dd>${state.admin_email || `admin@${state.domain}`} <span class="edit-link" data-goto="6">edit</span></dd>
    </dl>
  </div>`;
  wactions.innerHTML = `<button class="btn" id="btn-wiz-back">Back</button><button class="btn btn-primary" id="btn-wiz-create">Create site</button>`;
  $("btn-wiz-back")?.addEventListener("click", () => { state.step--; saveWizardState(state); renderWizard(state); });
  wbody.querySelectorAll(".edit-link").forEach((link) => {
    link.addEventListener("click", () => { state.step = parseInt(link.dataset.goto, 10); saveWizardState(state); renderWizard(state); });
  });
  $("btn-wiz-create")?.addEventListener("click", async () => {
    const payload = { domain: state.domain, flavor: state.flavor, php_version: state.php_version, letsencrypt: state.letsencrypt === "off" ? "disabled" : "enabled" };
    if (state.dns_provider) payload.dns_provider = state.dns_provider;
    if (state.object_cache === "redis") payload.object_cache = state.object_cache;
    if (state.admin_user) payload.admin_user = state.admin_user;
    if (state.admin_email) payload.admin_email = state.admin_email;
    try {
      const accepted = await api("/api/sites", { method: "POST", body: JSON.stringify(payload) });
      state.job_id = accepted.job_id;
      saveWizardState(state);
      navigate(`/sites/new/progress/${encodeURIComponent(accepted.job_id)}`);
    } catch (error) {
      toast(error.message || "Site creation failed", true);
    }
  });
}

function renderWizardProgress(jobId) {
  showSection("stub");
  const body = $("route-stub-body");
  $("route-stub-title").textContent = "Creating site…";
  $("route-stub-text").textContent = "";
  $("route-breadcrumb").replaceChildren(linkEl("/dashboard", "Dashboard"), crumbSep(), linkEl("/sites", "Sites"), crumbSep(), document.createTextNode("Creating site"));
  body.innerHTML = `<div class="wizard-progress">
    <div class="wizard-progress-bar"><div class="fill" id="wiz-progress-fill" style="width:0%"></div></div>
    <p class="hint" id="wiz-progress-status">Starting job…</p>
    <ul class="wizard-stages" id="wiz-stages"></ul>
    <p class="hint" id="wiz-elapsed"></p>
  </div>
  <div class="row"><button class="btn btn-ghost" id="btn-wiz-cancel">Cancel</button></div>`;
  $("btn-wiz-cancel")?.addEventListener("click", () => navigate("/sites"));
  const start = Date.now();
  pollJob(jobId, (steps) => {
    const pct = Math.min(95, Math.round((steps.length / 10) * 100));
    $("wiz-progress-fill").style.width = `${pct}%`;
    $("wiz-progress-status").textContent = `Stage ${steps.length}: ${stepText(steps[steps.length - 1])}`;
    $("wiz-stages").innerHTML = steps.map((s) => {
      const t = stepText(s);
      const cls = s.state === "failed" ? "fail" : "ok";
      return `<li class="wizard-stage"><span class="stage-name">${_esc(t)}</span><span class="stage-state ${cls}">${_esc(s.state || "running")}</span></li>`;
    }).join("");
    $("wiz-elapsed").textContent = `Elapsed: ${Math.round((Date.now() - start) / 1000)}s`;
  }).then((job) => {
    if (job.state === "failed") {
      $("wiz-progress-fill").style.width = "100%";
      $("wiz-progress-status").textContent = job.result?.error || "Site creation failed";
      return;
    }
    $("wiz-progress-fill").style.width = "100%";
    navigate(`/sites/new/success/${encodeURIComponent(jobId)}`);
  }).catch((error) => {
    toast(error.message || "The operation is taking longer than expected.", true);
  });
}

function renderWizardSuccess(jobId) {
  showSection("stub");
  const body = $("route-stub-body");
  $("route-stub-title").textContent = "Site created";
  $("route-stub-text").textContent = "";
  $("route-breadcrumb").replaceChildren(linkEl("/dashboard", "Dashboard"), crumbSep(), linkEl("/sites", "Sites"), crumbSep(), document.createTextNode("Success"));
  body.innerHTML = `<div class="wizard-success">
    <p>Your site has been created. Below are one-time credentials. Copy them now — they will not be shown again.</p>
    <div id="wiz-credentials"></div>
    <ul class="checklist">
      <li><span class="checkmark">&#x2713;</span> Site files written</li>
      <li><span class="checkmark">&#x2713;</span> Docker containers started</li>
      <li><span class="checkmark">&#x2713;</span> Let’s Encrypt configured</li>
      <li><span class="checkmark">&#x2713;</span> Site health check passed</li>
    </ul>
    <div class="row">
      <a class="btn" href="/site/${encodeURIComponent(jobId)}" data-route="true">Manage site</a>
      <button class="btn btn-primary" id="btn-wiz-dismiss">Done</button>
    </div>
  </div>`;
  api(`/api/jobs/${encodeURIComponent(jobId)}`).then((job) => {
    if (job.one_time) {
      const creds = flattenOneTime(job.one_time);
      const container = $("wiz-credentials");
      if (container && creds.length) {
        const dl = document.createElement("dl");
        dl.className = "kv";
        creds.forEach(([key, value]) => {
          const dt = document.createElement("dt"); dt.textContent = key.replaceAll("_", " ");
          const dd = document.createElement("dd"); dd.className = "credential-value"; dd.textContent = value;
          dl.append(dt, dd);
        });
        const copyBtn = document.createElement("button");
        copyBtn.className = "btn";
        copyBtn.textContent = "Copy credentials";
        copyBtn.addEventListener("click", async () => {
          await navigator.clipboard.writeText(creds.map(([k, v]) => `${k.replaceAll("_", " ")}: ${v}`).join("\n"));
          copyBtn.textContent = "Copied";
        });
        container.append(dl, copyBtn);
      }
    }
  }).catch(() => {});
  $("btn-wiz-dismiss")?.addEventListener("click", () => {
    const domain = jobId.split("_").slice(1).join("_") || "";
    if (domain) clearWizardState(domain);
    loadSites().then(() => navigate("/sites"));
  });
}

function _esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }

function _flavorOptions(selected) {
  const opts = [
    ["wp", "WordPress"], ["wpfc", "WordPress + FastCGI cache"], ["wpredis", "WordPress + Redis"],
    ["wpsc", "WordPress + Super Cache"], ["wprocket", "WordPress + WP Rocket"], ["wpce", "WordPress cache-enabled"],
    ["wpsubdir", "WordPress multisite (subdir)"], ["wpsubdomain", "WordPress multisite (subdomain)"],
    ["php", "PHP site"], ["html", "Static HTML"],
  ];
  return opts.map(([v, label]) => `<option value="${v}"${v === selected ? " selected" : ""}>${label}</option>`).join("");
}

function _phpOptions(selected) {
  return ["7.4", "8.0", "8.1", "8.2", "8.3", "8.4"].map((v) => `<option${v === selected ? " selected" : ""}>${v}</option>`).join("");
}

/* ---- file manager workspace ---- */

let _fmDomain = null;
let _fmState = "disabled";
let _fmLeaseTimer = 0;
let _fmStatePollTimer = 0;

function renderFileManager(domain) {
  _fmDomain = domain;
  _clearFmPolling();
  $("file-manager-workspace")?.classList.remove("hidden");
  $("fm-domain").textContent = domain;
  $("fm-root").textContent = "Loading…";
  _fetchFmStatus();
  _fmStatePollTimer = setInterval(_fetchFmStatus, 5000);
}

async function _fetchFmStatus() {
  if (!_fmDomain) return;
  try {
    const data = await api(`/api/sites/${encodeURIComponent(_fmDomain)}/file-manager`);
    _fmTransition(data.state, data);
  } catch (error) {
    if (error.message === "unauthorized") return;
    _fmTransition("disabled", {});
  }
}

function _fmTransition(newState, data) {
  if (newState === _fmState) return;
  _fmState = newState;
  ["fm-disabled", "fm-starting", "fm-ready", "fm-warning", "fm-failed"].forEach((id) => $(id)?.classList.add("hidden"));
  $(`fm-${newState}`)?.classList.remove("hidden");
  $("fm-status-badge").textContent = newState;
  $("fm-status-badge").className = `badge ${newState === "ready" ? "on" : "off"}`;
  if (data.root) $("fm-root").textContent = data.root;
  if (data.error) $("fm-error-text").textContent = data.error;
  if (newState === "ready") {
    _startFmLease();
    $("fm-iframe").src = `/api/sites/${encodeURIComponent(_fmDomain)}/file-manager/proxy/`;
  }
  if (newState === "disabled" || newState === "failed") _stopFmLease();
}

function _startFmLease() {
  _stopFmLease();
  _sendFmLease();
  _fmLeaseTimer = setInterval(_sendFmLease, 60000);
  document.addEventListener("visibilitychange", _onFmVisibility);
}

function _stopFmLease() {
  clearInterval(_fmLeaseTimer);
  _fmLeaseTimer = 0;
  document.removeEventListener("visibilitychange", _onFmVisibility);
}

function _clearFmPolling() {
  clearInterval(_fmStatePollTimer);
  _fmStatePollTimer = 0;
  _stopFmLease();
}

async function _sendFmLease() {
  if (!_fmDomain || document.hidden) return;
  try {
    const data = await api(`/api/sites/${encodeURIComponent(_fmDomain)}/file-manager/lease`, { method: "POST", body: "{}" });
    $("fm-idle-label").textContent = data.idle_expires_at ? `Idle until ${new Date(data.idle_expires_at).toLocaleTimeString()}` : "";
  } catch (error) {
    // lease failures are non-fatal
  }
}

function _onFmVisibility() {
  if (!document.hidden) _sendFmLease();
}

async function _enableFm() {
  if (!_fmDomain) return;
  _fmTransition("starting", {});
  try {
    const data = await api(`/api/sites/${encodeURIComponent(_fmDomain)}/file-manager/enable`, { method: "POST", body: "{}" });
    if (data.state === "ready") _fmTransition("ready", data);
  } catch (error) {
    _fmTransition("failed", { error: error.message });
  }
}

async function _disableFm() {
  if (!_fmDomain) return;
  try {
    await api(`/api/sites/${encodeURIComponent(_fmDomain)}/file-manager`, { method: "DELETE" });
    _fmTransition("disabled", {});
  } catch (error) {
    toast(error.message, true);
  }
}

function wireFm() {
  listen("btn-fm-enable", "click", () => runBusy($("btn-fm-enable"), _enableFm));
  listen("btn-fm-retry", "click", () => runBusy($("btn-fm-retry"), _enableFm));
  listen("btn-fm-disable", "click", () => runBusy($("btn-fm-disable"), _disableFm));
  listen("btn-fm-disable-now", "click", () => runBusy($("btn-fm-disable-now"), _disableFm));
  listen("btn-fm-keep", "click", () => _sendFmLease());
  listen("btn-fm-keep-warn", "click", () => { _sendFmLease(); _fmTransition("ready", {}); });
}

/* ---- router (MPA) ---- */

const NAV_LINKS = [
  { href: "/dashboard", label: "Dashboard", scope: "global" },
  { href: "/sites", label: "Sites", scope: "global" },
  { href: "/events", label: "Events", scope: "global" },
  { href: "/admin/users", label: "Users", scope: "admin" },
  { href: "/admin/jobs", label: "Jobs", scope: "admin" },
  { href: "/admin/services", label: "Services", scope: "admin" },
  { href: "/admin/settings", label: "Settings", scope: "admin" },
  { href: "/account/settings", label: "Account", scope: "session" },
];

const CLIENT_ROUTE_PREFIXES = [
  "/dashboard", "/sites", "/site/", "/events", "/notifications", "/account/", "/admin/",
];

const SECTION_IDS = {
  dashboard: ["stats", "metrics-panel", "sites-panel", "services-panel", "events-panel", "diagnostics-panel"],
  sites: ["sites-panel"],
  events: ["events-panel"],
  account: ["account-panel"],
  users: ["users-panel"],
  detail: ["detail"],
  stub: [],
};

function showSection(name) {
  const visible = new Set(SECTION_IDS[name] || []);
  Object.values(SECTION_IDS).flat().forEach((id) => {
    const node = $(id);
    if (node) node.classList.toggle("hidden", !visible.has(id));
  });
  $("route-stub")?.classList.toggle("hidden", name !== "stub");
}

function renderRouteStub(title, text, bodyHtml = "") {
  showSection("stub");
  $("route-stub-title").textContent = title;
  $("route-stub-text").textContent = text;
  const body = $("route-stub-body");
  body.replaceChildren();
  if (bodyHtml) body.insertAdjacentHTML("beforeend", bodyHtml);
  $("route-breadcrumb").replaceChildren(
    linkEl("/dashboard", "Dashboard"),
    crumbSep(), document.createTextNode(title),
  );
}

function renderNotFound() {
  renderRouteStub(
    "Not found",
    "This page does not exist. Check the address or return to the dashboard.",
    `<a class="btn" href="/dashboard" data-route="true">Return to dashboard</a>`,
  );
}

function renderForbidden() {
  renderRouteStub(
    "Not allowed",
    "Your account does not have permission to view this page.",
    `<a class="btn" href="/dashboard" data-route="true">Return to dashboard</a>`,
  );
}

function crumbSep() {
  const span = document.createElement("span");
  span.className = "crumb-sep";
  span.textContent = " / ";
  return span;
}

function linkEl(href, label, route = true) {
  const a = document.createElement("a");
  a.href = href;
  a.textContent = label;
  if (route) a.dataset.route = "true";
  return a;
}

function renderTopnav() {
  const nav = $("topnav");
  if (!nav) return;
  nav.replaceChildren(...NAV_LINKS.filter((link) => {
    if (link.scope === "admin") return isAdmin();
    return true;
  }).map((link) => {
    const a = linkEl(link.href, link.label);
    a.dataset.routerLink = "true";
    return a;
  }));
}

function routeActive(path) {
  document.querySelectorAll("#topnav a[data-router-link]").forEach((a) => {
    const href = a.getAttribute("href");
    const active = href === path || (href !== "/" && href !== "/dashboard" && path.startsWith(`${href}/`)) || (href === "/dashboard" && path === "/");
    a.classList.toggle("active", active);
    if (active) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
}

const TAB_ALIASES = {
  "overview": "overview", "logs": "logs", "backups": "backups", "sftp": "sftp",
  "wp-cli": "wp", "databases": "databases", "php": "php", "vhost": "vhost",
  "cache": "cache", "security": "security", "cron": "cron", "files": "files",
  "config": "config", "activity": "activity", "settings": "config",
  "metrics": "activity", "runtime": "overview", "ssl": "overview", "access": "sftp",
  "danger": "overview",
};

const SITE_STUB_PAGES = new Set([]);

function tabFromPath(part) {
  return TAB_ALIASES[part] || null;
}

const VALID_TABS = new Set(Object.values(TAB_ALIASES).filter((v) => v !== "settings"));

async function renderSiteRoute(match) {
  const domain = decodeURIComponent(match[1]);
  const tab = match[2] ? tabFromPath(match[2]) : "overview";
  if (match[2] && SITE_STUB_PAGES.has(match[2])) {
    showSection("stub");
    renderSiteBreadcrumbs(domain);
    $("detail")?.classList.add("hidden");
    const labels = { metrics: "Metrics", runtime: "Runtime", ssl: "SSL", danger: "Danger zone", access: "Access" };
    renderRouteStub(labels[match[2]], `${labels[match[2]]} page for ${domain} lands in a later phase.`);
    return;
  }
  if (tab === "files") {
    showSection("stub");
    renderSiteBreadcrumbs(domain);
    $("detail")?.classList.add("hidden");
    renderFileManager(domain);
    return;
  }
  showSection("detail");
  renderSiteBreadcrumbs(domain);
  await openDetail(domain);
  if (tab && VALID_TABS.has(tab)) selectTab(tab);
  $("detail").scrollIntoView({ block: "start" });
}

async function handleRoute(path) {
  renderTopnav();
  routeActive(path);

  const siteMatch = /^\/site\/([^/]+)(?:\/([a-z0-9-]+))?\/?$/.exec(path);
  if (siteMatch) {
    await renderSiteRoute(siteMatch);
    return;
  }

  if (path === "/dashboard" || path === "/" || path === "/index.html") {
    showSection("dashboard");
    applyPrincipal();
    return;
  }
  if (path === "/sites" || path === "/sites/") {
    showSection("sites");
    return;
  }
  if (path === "/events" || path === "/events/") {
    showSection("events");
    return;
  }
  if (path === "/account/settings") {
    showSection("account");
    return;
  }
  if (path === "/account/security") {
    renderRouteStub("Security", "Two-factor authentication management moves here in a later phase.");
    return;
  }
  if (path === "/notifications") {
    renderRouteStub("Notifications", "The notification center arrives in a later phase.");
    return;
  }
  if (path === "/sites/new" || path === "/sites/new/") {
    const state = _wizDefault("");
    renderWizard(state);
    return;
  }
  const progressMatch = /^\/sites\/new\/progress\/([^/]+)\/?$/.exec(path);
  if (progressMatch) {
    renderWizardProgress(decodeURIComponent(progressMatch[1]));
    return;
  }
  const successMatch = /^\/sites\/new\/success\/([^/]+)\/?$/.exec(path);
  if (successMatch) {
    renderWizardSuccess(decodeURIComponent(successMatch[1]));
    return;
  }
  if (path === "/admin/users") {
    if (!isAdmin()) { renderForbidden(); return; }
    showSection("users");
    return;
  }
  if (path === "/admin/events") {
    if (!isAdmin()) { renderForbidden(); return; }
    showSection("events");
    return;
  }
  if (path === "/admin/services") {
    if (!isAdmin()) { renderForbidden(); return; }
    showSection("services");
    loadServices();
    return;
  }
  if (path === "/admin/jobs" || path === "/admin/jobs/") {
    if (!isAdmin()) { renderForbidden(); return; }
    renderAdminJobs();
    return;
  }
  const jobDetailMatch = /^\/admin\/jobs\/([^/]+)\/?$/.exec(path);
  if (jobDetailMatch) {
    if (!isAdmin()) { renderForbidden(); return; }
    renderAdminJobDetail(decodeURIComponent(jobDetailMatch[1]));
    return;
  }
  if (path.startsWith("/admin/")) {
    if (!isAdmin()) { renderForbidden(); return; }
    renderAdminStub(adminPageTitle(path));
    return;
  }

  renderNotFound();
}

function adminPageTitle(path) {
  const parts = path.split("/").filter(Boolean).slice(1);
  if (!parts.length) return "Admin";
  const labels = {
    jobs: "Jobs", services: "Services", instance: "Instance", "remote-backup": "Remote backup",
    firewall: "Firewall", "basic-auth": "Basic auth", settings: "Settings",
    hetzner: "Hetzner", notifications: "Notifications", users: "Users",
  };
  return labels[parts[0]] || parts[0];
}

function renderAdminStub(title) {
  renderRouteStub(
    title,
    `${title} page lands in a later phase.`,
    `<a class="btn" href="/dashboard" data-route="true">Return to dashboard</a>`,
  );
}

async function renderAdminJobs() {
  showSection("stub");
  const body = $("route-stub-body");
  $("route-stub-title").textContent = "Jobs";
  $("route-stub-text").textContent = "Active and recent panel jobs.";
  $("route-breadcrumb").replaceChildren(
    linkEl("/dashboard", "Dashboard"),
    crumbSep(),
    linkEl("/admin/services", "Admin"),
    crumbSep(),
    document.createTextNode("Jobs"),
  );
  try {
    const data = await api("/api/jobs");
    const jobs = data.jobs || [];
    const rows = jobs.map((j) => `<tr>
      <td class="domain" data-label="Job"><a href="/admin/jobs/${_esc(j.job_id)}" data-route="true">${_esc(j.job_id)}</a></td>
      <td data-label="Action">${_esc(j.action || "")}</td>
      <td data-label="Site">${_esc(j.domain || "")}</td>
      <td data-label="State">${_esc(j.state || "")}</td>
      <td data-label="Progress">${j.progress != null ? j.progress + "%" : "–"}</td>
      <td data-label="Started">${j.started_at ? new Date(j.started_at).toLocaleString() : "–"}</td>
    </tr>`).join("");
    body.innerHTML = `<div class="table-wrap"><table><thead><tr><th>Job</th><th>Action</th><th>Site</th><th>State</th><th>Progress</th><th>Started</th></tr></thead><tbody>${rows || "<tr><td colspan='6'>No jobs recorded.</td></tr>"}</tbody></table></div>`;
  } catch (err) {
    body.innerHTML = `<p class="error">${_esc(err.message)}</p>`;
  }
}

async function renderAdminJobDetail(jobId) {
  showSection("stub");
  const body = $("route-stub-body");
  $("route-stub-title").textContent = `Job ${jobId}`;
  $("route-stub-text").textContent = "";
  $("route-breadcrumb").replaceChildren(
    linkEl("/dashboard", "Dashboard"),
    crumbSep(),
    linkEl("/admin/jobs", "Jobs"),
    crumbSep(),
    document.createTextNode(jobId),
  );
  try {
    const job = await api(`/api/jobs/${encodeURIComponent(jobId)}`);
    const stages = (job.stages || []).map((s) => `<li class="wizard-step ${s.completed ? "done" : s.active ? "active" : ""}"><span>${_esc(s.label)}</span></li>`).join("");
    body.innerHTML = `<dl class="kv">
      <dt>State</dt><dd>${_esc(job.state || "–")}</dd>
      <dt>Action</dt><dd>${_esc(job.action || "–")}</dd>
      <dt>Site</dt><dd>${_esc(job.domain || "–")}</dd>
      <dt>Started</dt><dd>${job.started_at ? new Date(job.started_at).toLocaleString() : "–"}</dd>
      <dt>Ended</dt><dd>${job.ended_at ? new Date(job.ended_at).toLocaleString() : "–"}</dd>
    </dl>
    ${stages ? `<h3>Stages</h3><ol class="wizard-stages" style="list-style:none;display:flex;gap:1em;flex-wrap:wrap">${stages}</ol>` : ""}
    ${job.result?.error ? `<p class="error">${_esc(job.result.error)}</p>` : ""}
    <div class="row"><a class="btn" href="/admin/jobs" data-route="true">Back to jobs</a></div>`;
  } catch (err) {
    body.innerHTML = `<p class="error">${_esc(err.message)}</p><a class="btn" href="/admin/jobs" data-route="true">Back to jobs</a>`;
  }
}

async function navigate(path) {
  if (path !== location.pathname) {
    history.pushState({ path }, "", path);
  }
  await handleRoute(path);
}

function isClientRoute(href) {
  return CLIENT_ROUTE_PREFIXES.some((prefix) => href === prefix || href.startsWith(prefix));
}

function wireRouter() {
  document.addEventListener("click", (event) => {
    const anchor = event.target.closest("a[href]");
    if (!anchor) return;
    const href = anchor.getAttribute("href");
    if (!href || href.startsWith("http") || href.startsWith("/api") || href.startsWith("#")) return;
    if (!isClientRoute(href)) return;
    event.preventDefault();
    navigate(href).catch((error) => toast(error.message || "Unable to navigate.", true));
  });

  window.addEventListener("popstate", () => {
    handleRoute(location.pathname).catch((error) => toast(error.message || "Unable to navigate.", true));
  });

  renderTopnav();
}

wire();
wireRouter();
wireAccountMenu();
wireHamburger();
wireFm();
initTheme();
token = readTokenFromHash();
boot();
