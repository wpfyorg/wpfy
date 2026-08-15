/* wpfy panel — application core.
 *
 * This file owns the shell: session, transport, the router, and the four
 * primitives every page shares (toast, confirm, job progress, event stream).
 * It renders no page of its own.
 *
 * Pages live in their own `page-*.js` module and register themselves:
 *
 *     import { registerPage, el, api } from "./panel.js";
 *     registerPage("dashboard", (ctx) => { ... });
 *
 * A page render receives `ctx`:
 *   ctx.params   route captures (e.g. the site domain)
 *   ctx.signal   AbortSignal, fired when the user navigates away. Pass it to
 *                every fetch and check `ctx.signal.aborted` after each await —
 *                this is what stops site A's response rendering under site B.
 *   ctx.mount    the element to render into (already emptied)
 *   ctx.header   setPageHeader(), for title/subtitle/breadcrumb/actions
 *   ctx.onLeave  register a teardown callback (timers, listeners, charts)
 *
 * Constraints that are not negotiable here:
 *   - CSP is `default-src 'self'` with no `'unsafe-inline'`: no inline styles,
 *     no inline handlers, and no innerHTML with interpolated data. Build DOM
 *     with el().
 *   - Nothing loads from a third-party origin. Tabler is vendored.
 */

"use strict";

/* ---- dom helpers ---- */

export const $ = (id) => document.getElementById(id);

/** Build an element. `attrs` maps to properties, `data-*`, `aria-*`, and
 *  `onclick`-style listeners; children may be nodes, strings, or nullish. */
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "icon") continue;  // prepended last: `text` would overwrite it
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "html") throw new Error("el(): innerHTML is not allowed under this CSP");
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else if (key in node && key !== "list") node[key] = value;
    else node.setAttribute(key, value === true ? "" : value);
  }
  node.append(...children.flat().filter((child) => child !== null && child !== undefined && child !== false));
  // After `text`, which assigns textContent and would drop an earlier child.
  if (attrs.icon) node.prepend(icon(attrs.icon, "icon me-1"));
  return node;
}

/** An icon from the sprite in index.html. */
export function icon(name, className = "icon") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", className);
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#i-${name}`);
  svg.append(use);
  return svg;
}

/**
 * Tabler's empty block, with a glyph.
 *
 * "Nothing here" is the state a panel spends most of its life in on a fresh
 * install, and a bare line of grey text reads like a failure. The icon gives
 * the block a shape, and `action` puts the way out of the empty state inside
 * it rather than leaving the reader to find it.
 */
export function emptyState(glyph, title, subtitle = "", action = null) {
  return el("div", { class: "empty py-4" },
    glyph ? el("div", { class: "empty-icon" }, icon(glyph, "icon icon-lg")) : null,
    el("p", { class: "empty-title", text: title }),
    subtitle ? el("p", { class: "empty-subtitle text-secondary", text: subtitle }) : null,
    action ? el("div", { class: "empty-action" }, action) : null);
}

/** The same idea sized for one table row, where a full empty block is too tall. */
export function emptyRow(columns, glyph, text) {
  return el("tr", {}, el("td", { colspan: columns, class: "text-secondary text-center py-4" },
    glyph ? icon(glyph, "icon me-2 empty-row-icon") : null,
    el("span", { text })));
}

const show = (node, visible) => node?.classList.toggle("d-none", !visible);
const tabler = () => window.tabler;

/* ---- session state ---- */

let token = "";
let principal = null;
let usingRunToken = false;
let signingOut = false;

export const session = {
  get principal() { return principal; },
  get isAdmin() { return principal?.role === "admin"; },
  /** True before any account exists — the run token from the printed URL. */
  get isRunToken() { return usingRunToken; },
};

/* A panel published without a domain has no SSH tunnel in front of first-run
   setup, so `wpfy panel expose --no-domain` prints a one-time secret in the URL
   fragment and the setup form sends it with the account. The fragment is used
   rather than a query string because browsers never transmit it: it stays out
   of access logs, out of Referer headers, and out of anything a proxy records.
   It is read once here and stripped from the address bar immediately. */
let setupSecret = "";

function readSetupSecretFromHash() {
  const match = /[#&]setup=([^&]+)/.exec(location.hash);
  if (!match) return "";
  history.replaceState(null, "", location.pathname);
  return decodeURIComponent(match[1]);
}

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
  stopStream();
  // The operations poll re-arms itself while a job runs; left alone it keeps
  // polling after sign-out, 401s, and bounces the user out of the login form.
  clearTimeout(jobsPollTimer);
  dismissOneTime();
}

function showGate(rejected, rateLimited = false) {
  show($("setup"), false);
  show($("app"), false);
  show($("gate"), true);
  show($("login-error"), rejected);
  $("login-status").textContent = rateLimited
    ? "This client is rate limited. Wait before trying again."
    : "";
  $("login-username")?.focus();
}

function showApp() {
  show($("setup"), false);
  show($("gate"), false);
  show($("app"), true);
}

function showSetup() {
  show($("gate"), false);
  show($("app"), false);
  show($("setup"), true);
  $("setup-first-name")?.focus();
}

/* ---- transport ---- */

/**
 * Every API call goes through here first: a request issued after sign-out
 * cannot succeed, and letting it run only produces a spurious 401.
 */
function requireSession() {
  if (!token) throw new Error("unauthorized");
}

/**
 * The single 401 handler.
 *
 * Signing out revokes the session server-side while requests issued moments
 * earlier are still in flight, so those come back 401 during an entirely
 * normal sign-out. Reporting them as a rejection puts "Sign-in failed" on the
 * login screen of someone who just clicked Sign out — so the rejected state is
 * claimed only when we were not the ones ending the session.
 */
function onUnauthorized() {
  clearSession();
  showGate(!signingOut);
  return new Error("unauthorized");
}

function authHeaders(body) {
  return {
    Authorization: `Bearer ${token}`,
    ...(body ? { "Content-Type": "application/json" } : {}),
  };
}

async function failure(response) {
  const payload = await response.json().catch(() => ({}));
  const message = response.status === 403
    ? "Not allowed."
    : payload.error || payload.message || payload.nginx_test_output || `request failed (${response.status})`;
  const error = new Error(message);
  error.status = response.status;
  error.payload = payload;
  return error;
}

/* Container state vocabulary, shared so every surface agrees on what "fine"
   means. Docker reports `healthy` for a container that declares a healthcheck
   and `running` for one that does not -- treating only `running` as good marks
   the edge proxy, and every site image with a healthcheck, as degraded.
   `unavailable`/`unknown` mean the panel could not look, which is neither. */
const SERVICE_HEALTHY = new Set(["running", "healthy"]);
const SERVICE_UNKNOWN = new Set(["unavailable", "unknown", "starting", ""]);

export function isServiceHealthy(status) {
  return SERVICE_HEALTHY.has(String(status || "").toLowerCase());
}

export function isServiceUnknown(status) {
  return SERVICE_UNKNOWN.has(String(status || "").toLowerCase());
}

/** JSON request against the panel API. `options.body` may be a plain object. */
export async function api(path, options = {}) {
  requireSession();
  const body = options.body && typeof options.body === "object" && !(options.body instanceof Blob)
    ? JSON.stringify(options.body)
    : options.body;
  const response = await fetch(path, { ...options, body, headers: { ...authHeaders(body), ...options.headers } });
  if (response.status === 401) throw onUnauthorized();
  if (!response.ok) throw await failure(response);
  return response.json().catch(() => ({}));
}

export async function apiUpload(path, file, options = {}) {
  requireSession();
  const response = await fetch(path, {
    ...options,
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: file,
  });
  if (response.status === 401) throw onUnauthorized();
  if (!response.ok) throw await failure(response);
  return response.json().catch(() => ({}));
}

export async function apiDownload(path, name, options = {}) {
  requireSession();
  const response = await fetch(path, { ...options, headers: { Authorization: `Bearer ${token}` } });
  if (response.status === 401) throw onUnauthorized();
  if (!response.ok) throw await failure(response);
  const url = URL.createObjectURL(await response.blob());
  const link = el("a", { href: url, download: name });
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/** Requests made before an account exists (the setup window). */
async function setupRequest(path, options = {}) {
  const body = options.body && typeof options.body === "object" ? JSON.stringify(options.body) : options.body;
  const response = await fetch(path, { ...options, body, headers: authHeaders(body) });
  if (!response.ok) throw await failure(response);
  return response.json().catch(() => ({}));
}

/* ---- feedback: toast, confirm, busy ---- */

export function toast(message, isError = false) {
  const container = $("toast-container");
  if (!container) return;
  const node = el("div", {
    class: `toast align-items-center border-0 ${isError ? "text-bg-danger" : "text-bg-dark"}`,
    role: isError ? "alert" : "status",
    "aria-live": isError ? "assertive" : "polite",
    "aria-atomic": "true",
  }, el("div", { class: "d-flex" },
    el("div", { class: "toast-body", text: message }),
    el("button", {
      type: "button",
      class: "btn-close btn-close-white me-2 m-auto",
      "data-bs-dismiss": "toast",
      "aria-label": "Close",
    })));
  container.append(node);
  const toastApi = new (tabler().Toast)(node, { delay: isError ? 8000 : 5000 });
  node.addEventListener("hidden.bs.toast", () => node.remove());
  toastApi.show();
}

/**
 * The panel's single destructive-confirm pattern. Pass `keyword` to require
 * the operator to type it (site domains, database names) — anything that
 * destroys data or publishes something should. Bootstrap's modal brings the
 * focus trap and focus restoration the old hand-rolled dialogs lacked.
 *
 * Escape, backdrop, and Cancel all resolve false. An explicit confirm resolves
 * true, or — when `keyword` was required — the exact text the operator typed,
 * so a caller can forward it as the server's confirmation field. Both are
 * truthy, so `if (await confirmAction(...))` reads the same either way.
 *
 * Handing the typed value back matters: routes like `DELETE /api/sites/{d}`
 * gate on `confirm === domain` precisely so a human types the destination. A
 * caller that fills that field from a value it already holds has turned the
 * guard back into a checkbox.
 */
export function confirmAction({ title, message, detail = "", confirmLabel = "Confirm", danger = true, keyword = null }) {
  return new Promise((resolve) => {
    const input = keyword
      ? el("input", { type: "text", class: "form-control", autocomplete: "off", spellcheck: false,
                      "aria-label": `Type ${keyword} to confirm` })
      : null;
    const confirm = el("button", {
      type: "button",
      class: `btn ${danger ? "btn-danger" : "btn-primary"} w-100`,
      text: confirmLabel,
      disabled: Boolean(keyword),
    });
    if (input) {
      input.addEventListener("input", () => { confirm.disabled = input.value !== keyword; });
    }

    const modal = el("div", { class: "modal modal-blur fade", tabindex: "-1", role: "dialog", "aria-modal": "true" },
      el("div", { class: "modal-dialog modal-sm modal-dialog-centered", role: "document" },
        el("div", { class: "modal-content" },
          el("div", { class: `modal-status ${danger ? "bg-danger" : "bg-primary"}` }),
          el("div", { class: "modal-body text-center py-4" },
            el("h3", { class: "mb-2", text: title }),
            el("div", { class: "text-secondary", text: message }),
            detail ? el("div", { class: "text-secondary small mt-2", text: detail }) : null,
            keyword
              ? el("div", { class: "mt-3 text-start" },
                  el("label", { class: "form-label", text: `Type ${keyword} to confirm` }),
                  input)
              : null),
          el("div", { class: "modal-footer" },
            el("div", { class: "w-100" },
              el("div", { class: "row" },
                el("div", { class: "col" },
                  el("button", { type: "button", class: "btn w-100", "data-bs-dismiss": "modal", text: "Cancel" })),
                el("div", { class: "col" }, confirm)))))));

    document.body.append(modal);
    const api = new (tabler().Modal)(modal);
    let outcome = false;
    confirm.addEventListener("click", () => { outcome = keyword ? input.value : true; api.hide(); });
    modal.addEventListener("hidden.bs.modal", () => { modal.remove(); resolve(outcome); });
    modal.addEventListener("shown.bs.modal", () => (input || confirm).focus());
    api.show();
  });
}

/** Disable a button for the duration of `work`, surfacing failures as a toast. */
export async function withBusy(button, work) {
  if (!button) return work();
  button.disabled = true;
  const spinner = el("span", { class: "spinner-border spinner-border-sm me-2", role: "status" });
  button.prepend(spinner);
  try {
    return await work();
  } catch (error) {
    if (error.message !== "unauthorized") toast(error.message, true);
    throw error;
  } finally {
    spinner.remove();
    button.disabled = false;
  }
}

/* ---- formatting ---- */

export function formatBytes(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value)) return "–";
  if (value < 1024) return `${value} B`;
  let scaled = value;
  let unit = "B";
  for (const next of ["KB", "MB", "GB", "TB"]) {
    if (scaled < 1024) break;
    scaled /= 1024;
    unit = next;
  }
  return `${scaled.toFixed(1)} ${unit}`;
}

export function formatTime(value) {
  if (!value) return "–";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

export const sleep = (ms, signal) => new Promise((resolve, reject) => {
  const timer = setTimeout(resolve, ms);
  signal?.addEventListener("abort", () => { clearTimeout(timer); reject(new DOMException("aborted", "AbortError")); },
                           { once: true });
});

export function stepText(step) {
  if (typeof step === "string") return step;
  if (!step || typeof step !== "object") return String(step ?? "");
  return [step.name || step.action, step.state, step.message || step.detail].filter(Boolean).join(" · ");
}

/* ---- jobs ---- */

/**
 * Follow a job to completion. Cancellable: pass the page's AbortSignal so
 * navigating away stops the poll instead of leaving it running for minutes.
 *
 * A job id the server does not know is reported rather than waited on — jobs
 * live in memory, so a panel restart makes every in-flight id vanish, and the
 * old client spun on that forever.
 */
export async function pollJob(jobId, { onStep, signal, timeoutMs = 1800000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let oneTime = null;
  let seen = 0;
  while (Date.now() < deadline) {
    if (signal?.aborted) throw new DOMException("aborted", "AbortError");
    let job;
    try {
      job = await api(`/api/jobs/${encodeURIComponent(jobId)}`, { signal });
    } catch (error) {
      if (error.status === 404) {
        throw new Error("This operation is no longer tracked — the panel restarted. Check Events for its outcome.");
      }
      throw error;
    }
    if (Object.prototype.hasOwnProperty.call(job, "one_time")) oneTime = job.one_time ?? oneTime;
    const steps = Array.isArray(job.steps) ? job.steps : [];
    if (steps.length > seen) {
      seen = steps.length;
      onStep?.(steps, job);
    }
    if (job.state === "succeeded" || job.state === "failed") return { ...job, one_time: oneTime };
    await sleep(750, signal);
  }
  throw new Error("The operation is still running. Check Events or the Jobs page for its final status.");
}

/* ---- one-time credentials ---- */

let oneTimeCopyText = "";

function flattenOneTime(value, prefix = "") {
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, item]) => {
    const label = prefix ? `${prefix} ${key}` : key;
    if (item && typeof item === "object") return flattenOneTime(item, label);
    return item === undefined || item === null ? [] : [[label, String(item)]];
  });
}

/** Render credentials the server will never show again. */
export function renderOneTime(title, oneTime) {
  const panel = $("one-time-panel");
  const values = $("one-time-values");
  const entries = flattenOneTime(oneTime);
  if (!panel || !values || entries.length === 0) return;
  $("one-time-title").textContent = title;
  values.replaceChildren(...entries.flatMap(([key, value]) => [
    el("dt", { class: "col-5 col-md-3 text-secondary", text: key.replaceAll("_", " ") }),
    el("dd", { class: "col-7 col-md-9 font-monospace text-break", text: value }),
  ]));
  oneTimeCopyText = entries.map(([key, value]) => `${key.replaceAll("_", " ")}: ${value}`).join("\n");
  $("one-time-copy-status").textContent = "";
  show(panel, true);
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

export function dismissOneTime() {
  oneTimeCopyText = "";
  $("one-time-values")?.replaceChildren();
  if ($("one-time-copy-status")) $("one-time-copy-status").textContent = "";
  show($("one-time-panel"), false);
}

/* ---- event stream (GET /api/stream) ---------------------------------------
 *
 * fetch + ReadableStream, not EventSource: EventSource cannot send an
 * Authorization header, and moving the token into the query string would write
 * the credential into every access log.
 */

const streamListeners = new Set();
let streamAbort = null;
let streamRunning = false;

/** Subscribe to panel events. Returns an unsubscribe function. */
export function onPanelEvent(handler) {
  streamListeners.add(handler);
  return () => streamListeners.delete(handler);
}

function dispatchEvent(event) {
  for (const handler of streamListeners) {
    try {
      handler(event);
    } catch (error) {
      console.error("event handler failed", error);
    }
  }
}

function parseFrames(buffer) {
  const frames = [];
  let rest = buffer;
  let index = rest.indexOf("\n\n");
  while (index !== -1) {
    const block = rest.slice(0, index);
    rest = rest.slice(index + 2);
    index = rest.indexOf("\n\n");
    const data = block.split("\n")
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .join("\n");
    if (!data) continue;  // `: keepalive` comment frames carry no data
    try {
      frames.push(JSON.parse(data));
    } catch (error) {
      console.warn("unparseable event frame", error);
    }
  }
  return [frames, rest];
}

async function readStream(signal) {
  const response = await fetch("/api/stream", { headers: { Authorization: `Bearer ${token}` }, signal });
  if (response.status === 401) {
    onUnauthorized();
    return false;
  }
  if (!response.ok) throw new Error(`stream unavailable (${response.status})`);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return true;
    buffer += decoder.decode(value, { stream: true });
    const [frames, rest] = parseFrames(buffer);
    buffer = rest;
    frames.forEach(dispatchEvent);
  }
}

async function runStream() {
  let backoff = 1000;
  while (token && streamRunning) {
    streamAbort = new AbortController();
    try {
      const clean = await readStream(streamAbort.signal);
      if (!clean) return;              // 401: the session is gone
      backoff = 1000;                  // the server closes idle streams; reconnect at once
    } catch (error) {
      if (error.name === "AbortError") return;
      backoff = Math.min(backoff * 2, 30000);
    }
    if (!token || !streamRunning) return;
    try {
      await sleep(backoff, streamAbort.signal);
    } catch {
      return;
    }
  }
}

function startStream() {
  if (streamRunning) return;
  streamRunning = true;
  runStream().catch(() => { streamRunning = false; });
}

function stopStream() {
  streamRunning = false;
  streamAbort?.abort();
  streamAbort = null;
}

/* ---- theme ---- */

function applyTheme(value) {
  const root = document.documentElement;
  const dark = value === "dark"
    || (value === "auto" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  // `data-theme` is the panel's own token switch; `data-bs-theme` is Tabler's.
  // They move together so a component never renders half-light.
  if (value === "auto") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", value);
  root.setAttribute("data-bs-theme", dark ? "dark" : "light");
}

function initTheme() {
  const stored = localStorage.getItem("wpfy-panel-theme") || "auto";
  applyTheme(stored);
  const control = $("theme-control");
  const sync = (value) => control?.querySelectorAll("button").forEach((button) => {
    const active = button.dataset.theme === value;
    button.classList.toggle("btn-primary", active);
    button.setAttribute("aria-checked", String(active));
  });
  sync(stored);
  control?.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => {
      const value = button.dataset.theme;
      localStorage.setItem("wpfy-panel-theme", value);
      applyTheme(value);
      sync(value);
    });
  });
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if ((localStorage.getItem("wpfy-panel-theme") || "auto") === "auto") applyTheme("auto");
  });
}

/* ---- navigation ---- */

const NAV_LINKS = [
  { href: "/dashboard", label: "Dashboard", icon: "layout-dashboard" },
  { href: "/sites", label: "Sites", icon: "world" },
  // No Jobs entry: running operations live in the header popover, which stays
  // visible across navigation. Their durable record is Events.
  { href: "/events", label: "Events", icon: "activity" },
  { href: "/admin/users", label: "Users", icon: "users", admin: true },
  { href: "/admin/services", label: "Services", icon: "server-2", admin: true },
  { href: "/admin/backup", label: "Remote backup", icon: "cloud-upload", admin: true },
  { href: "/admin/firewall", label: "Firewall", icon: "shield-lock", admin: true },
  // "Mail", not "Notifications": the page configures an SMTP transport. Nothing
  // in wpfy sends mail on its own yet, and a nav entry promising alerts that do
  // not exist is the same lie the old wizard's fake steps told.
  { href: "/admin/mail", label: "Mail", icon: "bell", admin: true },
  { href: "/admin/basic-auth", label: "Basic auth", icon: "key", admin: true },
  { href: "/admin/settings", label: "Settings", icon: "settings", admin: true },
  { href: "/admin/instance", label: "Instance", icon: "info-circle", admin: true },
];

function renderNav() {
  const nav = $("nav-primary");
  if (!nav) return;
  nav.replaceChildren(...NAV_LINKS
    .filter((link) => !link.admin || session.isAdmin)
    .map((link) => el("li", { class: "nav-item", dataset: { navHref: link.href } },
      el("a", { class: "nav-link", href: link.href, dataset: { route: "true" } },
        el("span", { class: "nav-link-icon d-md-none d-lg-inline-block" }, icon(link.icon)),
        el("span", { class: "nav-link-title", text: link.label })))));
  markActiveNav(location.pathname);
}

function markActiveNav(path) {
  document.querySelectorAll("#nav-primary li[data-nav-href]").forEach((item) => {
    const href = item.dataset.navHref;
    const active = href === path
      || (href === "/dashboard" && path === "/")
      || (href === "/sites" && path.startsWith("/site/"))
      || (href !== "/dashboard" && path.startsWith(`${href}/`));
    item.classList.toggle("active", active);
    const link = item.querySelector("a");
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
}

/** Set the page header. Pages call this through `ctx.header`. */
export function setPageHeader({ title = "", subtitle = "", breadcrumb = [], actions = [], icon: glyph = "" } = {}) {
  $("page-title").textContent = title;
  // Decorative: the title already names the page, so the icon carries no label
  // of its own and `icon()` marks it aria-hidden.
  if (glyph) $("page-title").prepend(icon(glyph, "icon page-title-icon"));
  $("page-subtitle").textContent = subtitle;
  document.title = title ? `${title} · wpfy panel` : "wpfy panel";
  $("page-breadcrumb").replaceChildren(...breadcrumb.map(([href, label], index) =>
    el("li", { class: `breadcrumb-item${index === breadcrumb.length - 1 ? " active" : ""}` },
      href ? el("a", { href, dataset: { route: "true" }, text: label }) : label)));
  $("page-actions").replaceChildren(...actions);
}

/* ---- shell chips ---- */

function applyPrincipal() {
  const name = principal ? principal.username : "run token";
  $("account-name").textContent = name;
  $("account-role").textContent = principal ? principal.role : "temporary access";
  $("account-avatar").textContent = name.slice(0, 2).toUpperCase();
  $("foot-principal").textContent = principal
    ? `wpfy panel · signed in as ${principal.username}`
    : "wpfy panel";
  show($("chip-health"), session.isAdmin);
  show($("chip-jobs"), true);
  renderNav();
}

async function refreshHealthChip() {
  if (!session.isAdmin) return;
  try {
    const data = await api("/api/system/services");
    const services = data.services || [];
    const degraded = services.filter(
      (service) => !isServiceHealthy(service.status) && !isServiceUnknown(service.status));
    const status = $("chip-health-status");
    status.className = `status status-${degraded.length === 0 ? "green" : degraded.length === services.length ? "red" : "yellow"}`;
    $("chip-health-text").textContent = degraded.length === 0 ? "Healthy" : `${degraded.length} degraded`;
    $("chip-health").title = services.map((service) => `${service.name}: ${service.status}`).join(", ");
    show($("degraded-banner"), degraded.length > 0);
    if (degraded.length > 0) {
      $("degraded-banner-text").textContent =
        `${degraded.length} service${degraded.length === 1 ? "" : "s"} degraded: ${degraded.map((s) => s.name).join(", ")}.`;
    }
  } catch (error) {
    // A failed probe is unknown health, not good health — say so rather than
    // leaving the last reading on screen.
    $("chip-health-text").textContent = "unknown";
    $("chip-health-status").className = "status status-secondary";
  }
}

/* ---- operations popover -------------------------------------------------
 *
 * Jobs live in the shell, not on a page: an operation started from the site
 * detail used to vanish the moment the operator navigated away, because the
 * only place it was rendered was the page that started it. Here it stays
 * visible until it finishes, wherever they go.
 *
 * The bar is deliberately indeterminate. `panel_jobs` appends step strings and
 * never declares how many there will be, so a percentage would have to invent
 * its own denominator -- a bar that sits at 80% for four minutes says something
 * false. The current step says something true.
 */

const JOB_STATE_BADGE = {
  running: "bg-blue-lt text-blue", pending: "bg-secondary-lt text-secondary",
  succeeded: "bg-green-lt text-green", failed: "bg-red-lt text-red",
};

let jobsPollTimer = null;

function jobRow(job) {
  const running = job.state === "running" || job.state === "pending";
  const steps = Array.isArray(job.steps) ? job.steps : [];
  const current = steps.length ? stepText(steps[steps.length - 1]) : "";
  // A failed job's reason lives in `result.error` -- `fail_job` puts it there
  // and the payload carries no top-level error field.
  const failure = job.state === "failed" ? (job.result?.error || "This operation failed.") : "";
  return el("a", {
    class: "dropdown-item d-block", href: `/admin/jobs/${encodeURIComponent(job.id)}`, dataset: { route: "true" },
  },
    el("div", { class: "d-flex align-items-center gap-2" },
      el("span", { class: "flex-fill text-truncate", text: job.domain ? `${job.action} · ${job.domain}` : job.action }),
      el("span", { class: `badge ${JOB_STATE_BADGE[job.state] || "bg-secondary-lt text-secondary"}`, text: job.state })),
    running && current ? el("div", { class: "text-secondary small text-truncate", text: current }) : null,
    running ? el("div", { class: "progress progress-sm mt-1" },
      el("div", { class: "progress-bar progress-bar-indeterminate" })) : null,
    failure ? el("div", { class: "text-danger small text-truncate", text: failure }) : null);
}

function renderJobsMenu(jobs) {
  const body = $("jobs-menu-body");
  if (!body) return;
  if (!jobs.length) {
    body.replaceChildren(el("div", { class: "dropdown-item text-secondary", text: "Nothing running." }));
    return;
  }
  body.replaceChildren(...jobs.map(jobRow));
}

async function refreshJobsChip() {
  try {
    const data = await api("/api/jobs");
    const jobs = (data.jobs || []).slice().sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
    const active = jobs.filter((job) => job.state === "running" || job.state === "pending").length;
    $("chip-jobs-text").textContent = active === 0 ? "0 jobs" : `${active} job${active === 1 ? "" : "s"}`;
    show($("chip-jobs-spinner"), active > 0);
    renderJobsMenu(jobs.slice(0, 8));
    // Only poll while something is actually running. A completed job emits its
    // event on the stream, so an idle panel needs no timer at all.
    clearTimeout(jobsPollTimer);
    if (active > 0) jobsPollTimer = setTimeout(refreshJobsChip, 2000);
  } catch (error) {
    $("chip-jobs-text").textContent = "–";
    show($("chip-jobs-spinner"), false);
    renderJobsMenu([]);
  }
}

async function refreshVersionChip() {
  if (!session.isAdmin) return;
  try {
    const data = await api("/api/overview");
    $("chip-version").textContent = `wpfy ${data.version}`;
  } catch (error) {
    $("chip-version").textContent = "wpfy";
  }
}

/* ---- router ---- */

const PAGES = new Map();

/** Register a page renderer. Called by each `page-*.js` module at import. */
export function registerPage(name, render) {
  PAGES.set(name, render);
}

/**
 * Page modules are loaded on first visit, not at boot.
 *
 * They are imported dynamically rather than with a static `import` because a
 * page module imports this one: a static cycle would run the page's
 * `registerPage(...)` call while `PAGES` is still in its temporal dead zone.
 * Dynamic import runs after this module's body, so the cycle is harmless.
 *
 * A name with no entry — or an entry whose file is not written yet — renders
 * the "not built" card instead of a blank page.
 */
const PAGE_MODULES = {
  dashboard: "./page-dashboard.js",
  sites: "./page-sites.js",
  "site-detail": "./page-site.js",
  "site-create": "./page-site-create.js",
  events: "./page-events.js",
  "job-detail": "./page-job.js",
  users: "./page-users.js",
  services: "./page-services.js",
  settings: "./page-settings.js",
  instance: "./page-instance.js",
  "remote-backup": "./page-backup.js",
  firewall: "./page-firewall.js",
  notifications: "./page-mail.js",
  "basic-auth": "./page-basic-auth.js",
};

async function loadPage(name) {
  if (PAGES.has(name)) return PAGES.get(name);
  const source = PAGE_MODULES[name];
  if (!source) return null;
  try {
    await import(source);
  } catch (error) {
    console.error(`page module ${source} failed to load`, error);
    return null;
  }
  return PAGES.get(name) || null;
}

/**
 * The five-tab site IA. Every pre-rebuild tab path maps onto one of them so
 * existing bookmarks and the links in `wpfy-docs/docs/commands/panel.md` keep
 * working; the redirect table goes away one release after the rebuild ships.
 */
const SITE_TABS = ["overview", "settings", "data", "access", "automation"];
const SITE_TAB_REDIRECTS = {
  logs: "overview", activity: "overview", metrics: "overview", runtime: "overview", ssl: "overview",
  config: "settings", php: "settings", cache: "settings", vhost: "settings", security: "settings",
  danger: "settings",
  databases: "data", backups: "data",
  sftp: "access", files: "access", wp: "access", "wp-cli": "access",
  cron: "automation",
};

const ROUTES = [
  { pattern: /^\/(?:dashboard)?$/, page: "dashboard" },
  { pattern: /^\/sites$/, page: "sites" },
  { pattern: /^\/sites\/new$/, page: "site-create" },
  { pattern: /^\/site\/([^/]+)(?:\/([^/]+))?$/, page: "site-detail", params: ["domain", "tab"] },
  { pattern: /^\/events$/, page: "events" },
  // The jobs list is the header popover. `/admin/jobs` redirects to the durable
  // record rather than 404ing an address that used to work.
  { pattern: /^\/admin\/jobs$/, page: "events", redirect: "/events" },
  { pattern: /^\/admin\/jobs\/([^/]+)$/, page: "job-detail", params: ["jobId"] },
  { pattern: /^\/admin\/users$/, page: "users", admin: true },
  { pattern: /^\/admin\/services$/, page: "services", admin: true },
  { pattern: /^\/admin\/settings$/, page: "settings", admin: true },
  { pattern: /^\/admin\/instance$/, page: "instance", admin: true },
  { pattern: /^\/admin\/backup$/, page: "remote-backup", admin: true },
  { pattern: /^\/admin\/firewall$/, page: "firewall", admin: true },
  { pattern: /^\/admin\/mail$/, page: "notifications", admin: true },
  { pattern: /^\/admin\/notifications$/, page: "notifications", admin: true, redirect: "/admin/mail" },
  { pattern: /^\/admin\/basic-auth$/, page: "basic-auth", admin: true },
  { pattern: /^\/account\/settings$/, page: "account" },
  { pattern: /^\/account\/security$/, page: "account-security" },
];

const CLIENT_ROUTE_PREFIXES = ["/dashboard", "/sites", "/site/", "/events", "/account/", "/admin/"];

let pageAbort = null;
let pageTeardown = [];
let navGeneration = 0;

function teardownPage() {
  pageAbort?.abort();
  pageAbort = null;
  for (const fn of pageTeardown.splice(0)) {
    try {
      fn();
    } catch (error) {
      console.error("page teardown failed", error);
    }
  }
}

function renderMessage(title, message, action = null) {
  setPageHeader({ title, breadcrumb: [["/dashboard", "Dashboard"], [null, title]] });
  $("page").replaceChildren(el("div", { class: "card" },
    el("div", { class: "card-body text-center py-5" },
      el("h3", { class: "mb-2", text: title }),
      el("p", { class: "text-secondary", text: message }),
      action)));
}

async function handleRoute(path) {
  const generation = ++navGeneration;
  teardownPage();
  dismissOneTime();          // one-time credentials never survive a navigation
  markActiveNav(path);

  const route = ROUTES.find((candidate) => candidate.pattern.test(path));
  if (!route) {
    renderMessage("Not found", "This page does not exist. Check the address or return to the dashboard.",
                  el("a", { class: "btn btn-primary", href: "/dashboard", dataset: { route: "true" }, text: "Return to dashboard" }));
    return;
  }
  if (route.redirect) {
    await navigate(route.redirect, { replace: true });
    return;
  }
  if (route.admin && !session.isAdmin) {
    renderMessage("Not allowed", "Your account does not have permission to view this page.",
                  el("a", { class: "btn", href: "/dashboard", dataset: { route: "true" }, text: "Return to dashboard" }));
    return;
  }

  const match = route.pattern.exec(path);
  const params = {};
  (route.params || []).forEach((name, index) => {
    const value = match[index + 1];
    if (value !== undefined) params[name] = decodeURIComponent(value);
  });

  // Old site-tab paths redirect into the five-tab IA rather than 404.
  if (route.page === "site-detail") {
    const tab = params.tab || "overview";
    if (!SITE_TABS.includes(tab)) {
      const target = SITE_TAB_REDIRECTS[tab];
      if (!target) {
        renderMessage("Not found", `${params.domain} has no “${tab}” tab.`,
                      el("a", { class: "btn", href: `/site/${encodeURIComponent(params.domain)}`, dataset: { route: "true" }, text: "Open the site" }));
        return;
      }
      await navigate(`/site/${encodeURIComponent(params.domain)}/${target}`, { replace: true });
      return;
    }
    params.tab = tab;
  }

  const render = await loadPage(route.page);
  if (generation !== navGeneration) return;   // navigated again while the module loaded
  if (!render) {
    renderMessage("Not built yet", `The “${route.page}” page is part of a later stage of the panel rebuild.`);
    return;
  }

  pageAbort = new AbortController();
  const mount = $("page");
  mount.replaceChildren();
  const ctx = {
    params,
    mount,
    signal: pageAbort.signal,
    header: setPageHeader,
    onLeave: (fn) => pageTeardown.push(fn),
  };
  try {
    await render(ctx);
  } catch (error) {
    if (error.name === "AbortError" || error.message === "unauthorized") return;
    renderMessage("Something went wrong", error.message || "This page could not be loaded.");
  }
}

export async function navigate(path, { replace = false } = {}) {
  if (path !== location.pathname) {
    if (replace) history.replaceState({ path }, "", path);
    else history.pushState({ path }, "", path);
  }
  await handleRoute(path);
}

function isClientRoute(href) {
  return CLIENT_ROUTE_PREFIXES.some((prefix) => href === prefix || href.startsWith(prefix));
}

function wireRouter() {
  document.addEventListener("click", (event) => {
    const anchor = event.target.closest("a[href]");
    if (!anchor || event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
    const href = anchor.getAttribute("href");
    if (!href || href.startsWith("http") || href.startsWith("/api") || href.startsWith("#")) return;
    if (!isClientRoute(href)) return;
    event.preventDefault();
    navigate(href).catch((error) => toast(error.message || "Unable to navigate.", true));
    // Close the mobile sidebar; on desktop the collapse is not active.
    const menu = $("sidebar-menu");
    if (menu?.classList.contains("show")) tabler().Collapse.getOrCreateInstance(menu).hide();
  });

  window.addEventListener("popstate", () => {
    handleRoute(location.pathname).catch((error) => toast(error.message || "Unable to navigate.", true));
  });
}

/* ---- setup, sign-in, sign-out ---- */

async function loadPrincipal() {
  const response = await fetch("/api/auth/me", { headers: { Authorization: `Bearer ${token}` } });
  if (response.status === 401 && usingRunToken) return null;
  if (response.status === 401) throw onUnauthorized();
  if (!response.ok) throw new Error("Unable to load your account.");
  principal = await response.json();
  return principal;
}

async function beginSetupTotp() {
  const payload = await setupRequest("/api/setup/totp", { method: "POST", body: { action: "begin" } });
  show($("setup-account"), false);
  show($("setup-totp"), true);
  $("setup-step-one").classList.remove("active");
  $("setup-step-two").classList.add("active");
  $("setup-totp-secret").value = payload.secret;
  const target = $("setup-qr");
  target.replaceChildren();
  new QRCode(target, { text: payload.uri, width: 220, height: 220, correctLevel: QRCode.CorrectLevel.M });
  $("setup-totp-code")?.focus();
}

async function submitSetup(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  const error = $("setup-account-error");
  show(error, false);
  // Checked here as well as on the server: a mistyped password the operator
  // cannot see is the one setup mistake that locks them out of a fresh panel.
  if ($("setup-password").value !== $("setup-confirm-password").value) {
    error.textContent = "The two passwords do not match.";
    show(error, true);
    $("setup-confirm-password").focus();
    return;
  }
  button.disabled = true;
  try {
    const payload = await setupRequest("/api/setup", {
      method: "POST",
      body: {
        first_name: $("setup-first-name").value,
        last_name: $("setup-last-name").value,
        username: $("setup-username").value,
        email: $("setup-email").value,
        password: $("setup-password").value,
        confirm_password: $("setup-confirm-password").value,
        license_accepted: $("setup-license").checked,
        telemetry_enabled: $("setup-telemetry").checked,
        // Only present when the panel was published without a domain. It
        // arrives in the URL fragment, which browsers never send to the
        // server, so the secret stays out of access logs and Referer headers
        // until the client puts it in a request body itself.
        ...(setupSecret ? { setup_secret: setupSecret } : {}),
      },
    });
    token = payload.token;
    usingRunToken = false;
    sessionStorage.setItem("wpfy-panel-token", token);
    principal = { username: payload.username, role: payload.role, sites: payload.sites };
    await beginSetupTotp();
  } catch (failed) {
    error.textContent = failed.message;
    show(error, true);
  } finally {
    button.disabled = false;
  }
}

async function finishSetup() {
  show($("setup"), false);
  principal = await loadPrincipal();
  applyPrincipal();
  showApp();
  startStream();
  await Promise.all([refreshVersionChip(), refreshHealthChip(), refreshJobsChip()]);
  await handleRoute(location.pathname);
}

async function verifySetupTotp() {
  const status = $("setup-totp-status");
  status.textContent = "Checking code…";
  try {
    await setupRequest("/api/setup/totp", { method: "POST", body: { action: "verify", code: $("setup-totp-code").value } });
    status.textContent = "Second factor enrolled.";
    await finishSetup();
  } catch (error) {
    status.textContent = error.message;
  }
}

async function signIn(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  show($("login-error"), false);
  $("login-status").textContent = "Signing in…";
  button.disabled = true;
  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: $("login-username").value.trim(),
        password: $("login-password").value,
        totp: $("login-totp").value.trim(),
      }),
    });
    if (!response.ok) {
      // A network failure and a rejected password are different problems, and
      // telling the operator the wrong one sends them to reset a good password.
      $("login-status").textContent = response.status === 429
        ? "This client is rate limited. Wait before trying again."
        : "";
      show($("login-error"), true);
      $("login-error").textContent = response.status >= 500
        ? "The panel could not process the sign-in. Check the server and try again."
        : "Sign-in failed. Check your details and try again.";
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
  } catch (error) {
    $("login-status").textContent = "";
    $("login-error").textContent = "The panel is unreachable. Check that it is still running.";
    show($("login-error"), true);
  } finally {
    button.disabled = false;
  }
}

async function logout() {
  signingOut = true;
  // Before the request, not after: a live stream event would otherwise kick off
  // a chip refresh that outlives the session it was authorised under.
  stopStream();
  teardownPage();
  try {
    await fetch("/api/auth/logout", { method: "POST", headers: { Authorization: `Bearer ${token}` } });
  } catch (error) {
    toast("The panel could not be reached; this browser has been signed out anyway.", true);
  } finally {
    clearSession();
    showGate(false);
    signingOut = false;
  }
}

/* ---- boot ---- */

function wireShell() {
  $("setup-account-form")?.addEventListener("submit", submitSetup);
  $("btn-setup-totp-verify")?.addEventListener("click", (event) => withBusy(event.currentTarget, verifySetupTotp).catch(() => {}));
  $("btn-setup-totp-skip")?.addEventListener("click", () => {
    show($("setup-totp-warning"), true);
    show($("btn-setup-totp-confirm-skip"), true);
    $("btn-setup-totp-confirm-skip").focus();
  });
  $("btn-setup-totp-confirm-skip")?.addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
    await setupRequest("/api/setup/totp", { method: "POST", body: { action: "skip", confirm: true } });
    await finishSetup();
  }).catch(() => {}));
  $("setup-totp-code")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      $("btn-setup-totp-verify").click();
    }
  });

  $("login-form")?.addEventListener("submit", signIn);
  $("btn-lock")?.addEventListener("click", () => logout());

  $("btn-one-time-dismiss")?.addEventListener("click", dismissOneTime);
  $("btn-one-time-copy")?.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(oneTimeCopyText);
      $("one-time-copy-status").textContent = "Copied.";
    } catch (error) {
      $("one-time-copy-status").textContent = "Copy failed — select the values and copy manually.";
    }
  });

  // The stream is the shell's only refresh trigger: no polling timers to leak.
  onPanelEvent((event) => {
    refreshJobsChip();
    if (String(event.action || "").startsWith("system.") || event.job_id) refreshHealthChip();
  });
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
    applyPrincipal();
    showApp();
    startStream();
    await Promise.all([refreshVersionChip(), refreshHealthChip(), refreshJobsChip()]);
    await handleRoute(location.pathname);
  } catch (error) {
    if (error.status === 401 || error.message === "unauthorized") {
      showGate(true);
      return;
    }
    toast(error.message || "Unable to load the panel.", true);
    showApp();
  }
}

wireShell();
wireRouter();
initTheme();
// Before the token read, which rewrites the address bar and would drop it.
setupSecret = readSetupSecretFromHash();
token = readTokenFromHash();
/* A domainless panel prints no run token — the setup link is the only
   credential the browser has, so it is also the bearer. The server accepts it
   for the setup routes and nothing else, and only account creation spends it. */
if (!token && setupSecret) token = setupSecret;
boot();
