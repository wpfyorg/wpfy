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
  $("chip-principal").textContent = label;
  $("foot-principal").textContent = principal ? `wpfy panel · signed in as ${principal.username}` : "wpfy panel";
  $("btn-users")?.classList.toggle("hidden", !admin);
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
    const username = eventCell(user.username, "domain");
    const role = eventCell(user.role);
    const sites = document.createElement("td");
    sites.append(userSites(user.sites));
    const totp = document.createElement("td");
    totp.append(badge(user.totp_enabled ? "enabled" : "not enrolled", Boolean(user.totp_enabled)));
    const actions = document.createElement("td");
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
  $("chip-docker").textContent = `docker: ${data.docker_version}`;
  $("chip-traefik").textContent = `traefik: ${data.traefik}`;
  $("chip-traefik").title = data.traefik;
  $("chip-warnings").textContent = `warnings: ${data.warnings}`;
  $("chip-warnings").classList.toggle("warn", data.warnings > 0);

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

function renderSites() {
  const query = ($("sites-search")?.value || "").trim().toLowerCase();
  const sites = allSites.filter((site) => String(site.domain || "").toLowerCase().includes(query));
  $("sites-count").textContent = query ? `${sites.length} of ${allSites.length}` : `${allSites.length} total`;
  const empty = $("sites-empty");
  empty.textContent = allSites.length === 0
    ? "No managed sites yet. Select New site to create one."
    : "No sites match this search.";
  empty.classList.toggle("hidden", sites.length > 0);
  $("sites-table").classList.toggle("hidden", sites.length === 0);

  const tbody = $("sites-table").querySelector("tbody");
  tbody.replaceChildren(...sites.map((site) => {
    const tr = document.createElement("tr");
    const domainCell = document.createElement("td");
    domainCell.className = "domain";
    domainCell.textContent = site.domain;
    const flavorCell = document.createElement("td");
    flavorCell.textContent = site.flavor || "?";
    const phpCell = document.createElement("td");
    phpCell.textContent = site.php_version || "–";
    const sslCell = document.createElement("td");
    const enabled = sslOn(site.ssl ?? site.ssl_enabled);
    sslCell.append(badge(enabled ? "ssl" : "http", enabled));
    const cacheCell = document.createElement("td");
    cacheCell.textContent = site.cache_type || (String(site.redis) === "1" ? "redis" : "basic");
    const actionCell = document.createElement("td");
    const manage = document.createElement("button");
    manage.className = "btn";
    manage.textContent = "Manage";
    manage.addEventListener("click", () => runBusy(manage, () => openDetail(site.domain)));
    actionCell.append(manage);
    tr.append(domainCell, flavorCell, phpCell, sslCell, cacheCell, actionCell);
    return tr;
  }));
}

async function loadSites() {
  const data = await api("/api/sites");
  allSites = data.sites || [];
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

function drawMetricChart(canvas, samples, metric) {
  const width = Math.max(260, Math.floor(canvas.parentElement.clientWidth));
  const height = 190;
  const ratio = window.devicePixelRatio || 1;
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  const context = canvas.getContext("2d");
  context.scale(ratio, ratio);
  const padding = { top: 18, right: 14, bottom: 34, left: 46 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const values = samples.map(metric.value);
  const maximum = metric.bounded ? 100 : Math.max(metric.unit === "%" ? 100 : 1, ...values) * 1.1;
  const first = Number(samples[0].timestamp) * 1000;
  const last = Number(samples.at(-1).timestamp) * 1000;
  const span = Math.max(last - first, 1);

  context.font = "11px ui-monospace, monospace";
  context.fillStyle = "#686874";
  context.strokeStyle = "#d9d9dd";
  context.lineWidth = 1;
  [0, 0.5, 1].forEach((step) => {
    const y = padding.top + plotHeight * step;
    context.beginPath(); context.moveTo(padding.left, y); context.lineTo(width - padding.right, y); context.stroke();
    const value = maximum * (1 - step);
    context.fillText(`${value.toFixed(metric.unit === "%" ? 0 : 1)}${metric.unit}`, 4, y + 4);
  });
  context.fillText(new Date(first).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), padding.left, height - 10);
  const endLabel = new Date(last).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  context.fillText(endLabel, width - padding.right - context.measureText(endLabel).width, height - 10);

  context.strokeStyle = "#1863dc";
  context.lineWidth = 2;
  context.lineJoin = "round";
  context.beginPath();
  values.forEach((value, index) => {
    const x = padding.left + (((Number(samples[index].timestamp) * 1000) - first) / span) * plotWidth;
    const y = padding.top + plotHeight - (Math.min(Math.max(value, 0), maximum) / maximum) * plotHeight;
    if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
  });
  context.stroke();
  const lastValue = values.at(-1);
  context.fillStyle = "#212121";
  context.fillText(`Latest ${lastValue.toFixed(metric.unit === "%" ? 1 : 2)}${metric.unit}`, padding.left, 12);
}

function renderMetricCharts(containerId, emptyId, samples) {
  const container = $(containerId);
  const empty = $(emptyId);
  if (!container || !empty) return;
  empty.classList.toggle("hidden", samples.length > 0);
  container.classList.toggle("hidden", samples.length === 0);
  if (!samples.length) {
    container.replaceChildren();
    return;
  }
  container.replaceChildren(...METRIC_CHARTS.map((metric) => {
    const figure = document.createElement("figure");
    figure.className = "chart-card";
    const caption = document.createElement("figcaption");
    caption.textContent = metric.label;
    const canvas = document.createElement("canvas");
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", `${metric.label} over time with labelled value and time axes`);
    figure.append(caption, canvas);
    requestAnimationFrame(() => drawMetricChart(canvas, samples, metric));
    return figure;
  }));
}

function renderMetricTable(samples) {
  const tbody = $("host-metrics-table")?.querySelector("tbody");
  if (!tbody) return;
  tbody.replaceChildren(...samples.map((sample) => {
    const row = document.createElement("tr");
    row.append(
      eventCell(new Date(Number(sample.timestamp) * 1000).toLocaleString()),
      eventCell(Number(sample.cpu_percent || 0).toFixed(1)),
      eventCell(`${formatBytes(sample.memory_used || 0)} / ${formatBytes(sample.memory_total || 0)}`),
      eventCell(`${formatBytes(sample.disk_used || 0)} / ${formatBytes(sample.disk_total || 0)}`),
      eventCell(Number(sample.load1 || 0).toFixed(2)),
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
    nameCell.textContent = backup.name;
    const sizeCell = document.createElement("td");
    sizeCell.textContent = formatBytes(backup.size_bytes);
    const dateCell = document.createElement("td");
    dateCell.textContent = new Date(backup.modified_at * 1000).toLocaleString();
    const actionCell = document.createElement("td");
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
    nameCell.textContent = name;
    const actionCell = document.createElement("td");
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
    userCell.textContent = user;
    const passwordCell = document.createElement("td");
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
  $("security-snippet-path").textContent = state.snippet_path || "not available";
  $("security-trusted-sources").textContent = (state.trusted_edge_sources || []).join(", ") || "not available";
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
    const schedule = eventCell(job.schedule, "domain");
    const command = eventCell(job.command, "domain cron-command");
    command.title = job.command;
    const service = eventCell(job.service, "domain");
    const enabled = document.createElement("td");
    enabled.append(badge(job.enabled ? "enabled" : "disabled", job.enabled));
    const timeout = eventCell(`${job.timeout}s`);
    const lastRun = eventCell(cronLastRunText(job.last_run), "cron-last-run");
    const actions = document.createElement("td");
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
    const type = eventCell(entry.type);
    const size = eventCell(entry.type === "dir" ? "—" : formatBytes(entry.size));
    const mode = eventCell(entry.mode, "domain");
    const modified = eventCell(new Date(entry.modified * 1000).toLocaleString());
    const actions = document.createElement("td");
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
    const name = eventCell(service.name, "domain");
    const status = eventCell(service.status || "unknown");
    const action = document.createElement("td");
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

function eventCell(text, className = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
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
    const outcomeCell = eventCell(event.outcome || "unknown");
    outcomeCell.className = eventOutcomeOk(event.outcome) ? "check-pass event-outcome" : "check-fail event-outcome";
    const cells = [
      eventCell(formatTime(event.timestamp)),
      eventCell(event.action || "–", "domain"),
    ];
    if (includeDomain) cells.push(eventCell(event.domain || "–", "domain"));
    cells.push(outcomeCell, eventCell(event.actor || "–"), eventCell(event.job_id || "–", "domain"));
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
  if (!principal || isAdmin()) work.push(loadOverview(), loadHostMetrics(), loadServices());
  await Promise.all(work);
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

  listen("btn-new-site", "click", (event) => runBusy(event.currentTarget, async () => {
    setNewSiteOpen($("new-site-panel").classList.contains("hidden"));
  }));
  listen("btn-new-site-close", "click", (event) => runBusy(event.currentTarget, async () => setNewSiteOpen(false)));
  listen("new-flavor", "change", updateCreateFields);
  listen("new-site-panel", "submit", (event) => {
    event.preventDefault();
    runBusy($("btn-create-site"), createSite);
  });
  listen("sites-search", "input", renderSites);

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
  } catch (error) {
    if (error.status === 401 || error.message === "unauthorized") {
      showGate(true);
      return;
    }
    toast(error.message || "Unable to load the panel.", true);
    showApp();
  }
}

wire();
token = readTokenFromHash();
boot();
