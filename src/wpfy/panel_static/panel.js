"use strict";

const $ = (id) => document.getElementById(id);

let token = "";
let currentDomain = null;

/* ---- token handling ---- */

function readTokenFromHash() {
  const match = /[#&]token=([^&]+)/.exec(location.hash);
  if (match) {
    sessionStorage.setItem("wpfy-panel-token", decodeURIComponent(match[1]));
    history.replaceState(null, "", location.pathname);
  }
  return sessionStorage.getItem("wpfy-panel-token") || "";
}

function showGate(rejected) {
  $("app").classList.add("hidden");
  $("gate").classList.remove("hidden");
  $("gate-error").classList.toggle("hidden", !rejected);
  $("gate-token").focus();
}

function showApp() {
  $("gate").classList.add("hidden");
  $("app").classList.remove("hidden");
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
    sessionStorage.removeItem("wpfy-panel-token");
    showGate(true);
    throw new Error("unauthorized");
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok && payload.error) throw new Error(payload.error);
  if (!response.ok) throw new Error(`request failed (${response.status})`);
  return payload;
}

/* ---- ui helpers ---- */

let toastTimer = null;
function toast(message, isError) {
  const node = $("toast");
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

function badge(text, on) {
  const span = document.createElement("span");
  span.className = `badge ${on ? "on" : "off"}`;
  span.textContent = text;
  return span;
}

function checkItem(check) {
  const li = document.createElement("li");
  const label = document.createElement("span");
  const state = check.ok === true ? "pass" : check.ok === false ? "fail" : "warn";
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

const sslOn = (value) => ["enabled", "letsencrypt", "wildcard", "1", "true"].includes(String(value).toLowerCase());

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

async function loadSites() {
  const data = await api("/api/sites");
  const sites = data.sites || [];
  $("sites-count").textContent = `${sites.length} total`;
  $("sites-empty").classList.toggle("hidden", sites.length > 0);
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
    sslCell.append(badge(sslOn(site.ssl ?? site.ssl_enabled) ? "ssl" : "http", sslOn(site.ssl ?? site.ssl_enabled)));
    const cacheCell = document.createElement("td");
    cacheCell.textContent = site.cache_type || (String(site.redis) === "1" ? "redis" : "basic");
    const actionCell = document.createElement("td");
    const manage = document.createElement("button");
    manage.className = "btn";
    manage.textContent = "Manage";
    manage.addEventListener("click", () => openDetail(site.domain));
    actionCell.append(manage);
    tr.append(domainCell, flavorCell, phpCell, sslCell, cacheCell, actionCell);
    return tr;
  }));
}

/* ---- detail ---- */

function selectTab(name) {
  document.querySelectorAll(".tab").forEach((tab) =>
    tab.classList.toggle("active", tab.dataset.tab === name));
  document.querySelectorAll(".tab-body").forEach((body) =>
    body.classList.toggle("hidden", body.id !== `tab-${name}`));
  if (name === "sftp") refreshSftp();
  if (name === "backups") refreshBackups();
}

async function openDetail(domain) {
  currentDomain = domain;
  $("detail-domain").textContent = domain;
  $("detail").classList.remove("hidden");
  $("health-result").replaceChildren();
  $("diag-result").replaceChildren();
  $("log-output").textContent = "No logs fetched yet.";
  $("wp-output").textContent = "No command run yet.";
  selectTab("overview");
  const data = await api(`/api/sites/${encodeURIComponent(domain)}`);
  const site = data.site || {};
  const rows = ["domain", "flavor", "php_version", "ssl", "cache_type", "created_at", "path"]
    .filter((key) => site[key] !== undefined && site[key] !== "")
    .flatMap((key) => {
      const dt = document.createElement("dt");
      dt.textContent = key.replaceAll("_", " ");
      const dd = document.createElement("dd");
      dd.textContent = site[key];
      return [dt, dd];
    });
  $("site-kv").replaceChildren(...rows);
  if (site.php_version) $("config-php").value = site.php_version;
  $("detail").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function refreshSftp() {
  if (!currentDomain) return;
  $("sftp-output").textContent = "Loading…";
  try {
    const data = await api(`/api/sites/${encodeURIComponent(currentDomain)}/sftp`);
    $("sftp-output").textContent = data.message || "no status";
  } catch (error) {
    $("sftp-output").textContent = error.message;
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
    restore.addEventListener("click", () => withBusy(restore, async () => {
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

/* ---- wiring ---- */

function wire() {
  $("gate-form").addEventListener("submit", (event) => {
    event.preventDefault();
    token = $("gate-token").value.trim();
    sessionStorage.setItem("wpfy-panel-token", token);
    $("gate-token").value = "";
    boot();
  });

  $("btn-refresh").addEventListener("click", (event) =>
    withBusy(event.target, () => Promise.all([loadOverview(), loadSites()])));

  $("btn-lock").addEventListener("click", () => {
    sessionStorage.removeItem("wpfy-panel-token");
    token = "";
    showGate(false);
  });

  $("detail-close").addEventListener("click", () => {
    $("detail").classList.add("hidden");
    currentDomain = null;
  });

  document.querySelectorAll(".tab").forEach((tab) =>
    tab.addEventListener("click", () => selectTab(tab.dataset.tab)));

  document.querySelectorAll("[data-runtime]").forEach((button) =>
    button.addEventListener("click", () => withBusy(button, async () => {
      const action = button.dataset.runtime;
      if (action === "stop" && !confirm(`Stop all containers for ${currentDomain}?`)) return;
      const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/runtime`, {
        method: "POST",
        body: JSON.stringify({ action }),
      });
      toast(result.message || `${action} finished`, !result.ok);
    })));

  $("btn-health").addEventListener("click", (event) => withBusy(event.target, async () => {
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

  $("btn-diagnostics").addEventListener("click", (event) => withBusy(event.target, async () => {
    const data = await api(`/api/sites/${encodeURIComponent(currentDomain)}/diagnostics`);
    $("diag-result").replaceChildren(...(data.checks || []).map(checkItem));
  }));

  $("btn-logs").addEventListener("click", (event) => withBusy(event.target, async () => {
    const service = $("log-service").value;
    const lines = $("log-lines").value || 200;
    const query = new URLSearchParams({ lines });
    if (service) query.set("service", service);
    const data = await api(`/api/sites/${encodeURIComponent(currentDomain)}/logs?${query}`);
    $("log-output").textContent = data.logs || "(no output)";
  }));

  $("btn-backup").addEventListener("click", (event) => withBusy(event.target, async () => {
    $("backup-status").textContent = "creating backup…";
    try {
      const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/backups`, { method: "POST" });
      toast(result.message || "backup finished", !result.ok);
      await refreshBackups();
    } finally {
      $("backup-status").textContent = "";
    }
  }));

  $("btn-sftp-enable").addEventListener("click", (event) => withBusy(event.target, async () => {
    const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/sftp`, {
      method: "POST",
      body: JSON.stringify({ action: "enable" }),
    });
    $("sftp-output").textContent = result.message || "enabled";
  }));

  $("btn-sftp-disable").addEventListener("click", (event) => withBusy(event.target, async () => {
    if (!confirm(`Disable SFTP access for ${currentDomain}?`)) return;
    const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/sftp`, {
      method: "POST",
      body: JSON.stringify({ action: "disable" }),
    });
    $("sftp-output").textContent = result.message || "disabled";
  }));

  $("btn-wp").addEventListener("click", (event) => withBusy(event.target, async () => {
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

  $("btn-config").addEventListener("click", (event) => withBusy(event.target, async () => {
    const phpVersion = $("config-php").value;
    if (!confirm(`Switch ${currentDomain} to PHP ${phpVersion}? Containers will restart.`)) return;
    const result = await api(`/api/sites/${encodeURIComponent(currentDomain)}/config`, {
      method: "POST",
      body: JSON.stringify({ php_version: phpVersion }),
    });
    $("config-output").textContent = [
      result.changes && result.changes.length ? `changes:\n- ${result.changes.join("\n- ")}` : "no changes needed",
      `runtime: ${result.runtime.message}`,
    ].join("\n");
    await loadSites();
  }));

  $("btn-sysdiag").addEventListener("click", (event) => withBusy(event.target, async () => {
    const data = await api("/api/system/diagnostics");
    $("sysdiag-result").replaceChildren(...(data.checks || []).map(checkItem));
  }));

  $("wp-input").addEventListener("keydown", (event) => {
    if (event.key === "Enter") $("btn-wp").click();
  });
}

async function boot() {
  if (!token) {
    showGate(false);
    return;
  }
  try {
    await Promise.all([loadOverview(), loadSites()]);
    showApp();
  } catch (error) {
    if (error.message !== "unauthorized") {
      toast(error.message, true);
      showApp();
    }
  }
}

wire();
token = readTokenFromHash();
boot();
