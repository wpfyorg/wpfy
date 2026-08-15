import { el, api, confirmAction, withBusy, onPanelEvent, toast, formatTime,
         isServiceHealthy, isServiceUnknown, emptyRow } from "./panel.js";

function card(title, body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header" }, el("h3", { class: "card-title", text: title })),
    el("div", { class: "card-body" }, body));
}

function errorCard(message) {
  return el("div", { class: "alert alert-danger mb-0", role: "alert", text: message });
}

/* `site_health` emits ready | running | degraded | down | needs-bootstrap |
   <status>-bootstrap. It never emits "healthy", which is what this tested for,
   so green was unreachable and a fully working site showed its status in red.
   Anything up but not finished is amber; only "down" is red. */
const SITE_STATUS_TONES = {
  ready: "bg-green-lt text-green",
  down: "bg-red-lt text-red",
};

function statusDot(status) {
  const key = String(status || "").toLowerCase();
  if (key === "ready") return "green";
  if (key === "down") return "red";
  return !key || key === "unknown" ? "secondary" : "yellow";
}

function statusClass(status) {
  const key = String(status || "").toLowerCase();
  if (SITE_STATUS_TONES[key]) return SITE_STATUS_TONES[key];
  if (!key || key === "unknown") return "bg-secondary-lt text-secondary";
  return "bg-yellow-lt text-yellow";
}

function renderHealth(health) {
  const readiness = [
    ["Scaffold", health.scaffold_ready],
    ["Bootstrap", health.bootstrap_ready],
    ["Runtime", health.runtime_ready],
    ["HTTP", health.http_ready],
  ];
  return el("div", {},
    el("div", { class: "d-flex align-items-center gap-2 mb-2" },
      el("span", { class: `status status-${statusDot(health.status)}` }),
      el("span", { class: `badge ${statusClass(health.status)}`, text: health.status || "unknown" })),
    el("p", { class: "text-secondary", text: health.message || "No health message available." }),
    el("ul", { class: "list-unstyled mb-0" }, readiness.map(([label, ready]) => el("li", { class: ready ? "text-green" : "text-danger" },
      el("span", { text: ready ? "✓ " : "✕ " }), `${label}: ${ready ? "ready" : "not ready"}`))));
}

function renderFacts(site) {
  const facts = [
    ["Domain", site.domain], ["Flavor", site.flavor], ["PHP", site.php_version],
    ["SSL", site.ssl_enabled ? "Enabled" : "Disabled"], ["Page cache", site.page_cache],
    ["Object cache", site.object_cache], ["Cache type", site.cache_type], ["Site UID", site.site_uid],
    // `site.ssl` is the mode word ("enabled"/"letsencrypt"/"disabled") and
    // `site.redis` is "1"/"0" — neither is a path, and neither reads as
    // anything useful raw. SSL is already covered by ssl_enabled above.
    ["Redis", site.redis === "1" || site.redis === true ? "Enabled" : "Disabled"],
    ["Created", formatTime(site.created_at)], ["Path", site.path], ["Compose", site.compose],
    ["Environment", site.env], ["Nginx", site.nginx],
  ].filter(([, value]) => value !== null && value !== undefined && value !== "");
  return el("div", { class: "scroll-x" }, el("dl", { class: "row mb-0" }, facts.flatMap(([label, value]) => [
    el("dt", { class: "col-sm-3", text: label }),
    el("dd", { class: "col-sm-9 font-monospace text-break", text: String(value) }),
  ])));
}

function renderDiagnostics(checks) {
  if (!checks.length) return el("p", { class: "text-secondary mb-0", text: "No diagnostics were reported." });
  return el("div", { class: "table-responsive" }, el("table", { class: "table table-vcenter mb-0" },
    el("thead", {}, el("tr", {}, el("th", { text: "Status" }), el("th", { text: "Check" }), el("th", { text: "Message" }))),
    el("tbody", {}, checks.map((check) => el("tr", {},
      el("td", { class: check.ok ? "text-green" : "text-danger", text: check.ok ? "Pass" : "Fail" }),
      el("td", { text: check.name || "–" }),
      el("td", { text: check.message || "–" }))))));
}

function activityRows(events) {
  if (!events.length) return [emptyRow(4, "activity", "No activity recorded yet.")];
  return events.map((event) => el("tr", {},
    el("td", { text: formatTime(event.timestamp) }),
    el("td", { text: event.action || "–" }),
    el("td", {}, el("span", { class: `badge ${event.outcome === "ok" ? "bg-green-lt text-green" : "bg-red-lt text-red"}`, text: event.outcome || "unknown" })),
    el("td", { text: event.detail || event.actor || "–" })));
}

function serviceRows(services) {
  if (!services.length) return [emptyRow(2, "server-2", "No services reported.")];
  return services.map((service) => el("tr", {},
    el("td", { class: "font-monospace", text: service.name }),
    el("td", {}, el("span", {
      class: `badge ${isServiceHealthy(service.status) ? "bg-green-lt text-green" : isServiceUnknown(service.status) ? "bg-secondary-lt text-secondary" : "bg-red-lt text-red"}`,
      text: service.status || "unknown",
    }))));
}

export async function render(ctx, domain, site) {
  const encodedDomain = encodeURIComponent(domain);
  const healthBody = el("div", { class: "text-secondary", text: "Loading health…" });
  const diagnosticsBody = el("div", { class: "text-secondary", text: "Loading diagnostics…" });
  const activityBody = el("tbody", {});
  const healthCard = card("Health", healthBody);
  const factsCard = card("Site facts", renderFacts(site));
  const diagnosticsCard = card("Diagnostics", diagnosticsBody);
  const activityCard = card("Recent activity", el("div", { class: "table-responsive" }, el("table", { class: "table table-vcenter mb-0" },
    el("thead", {}, el("tr", {}, el("th", { text: "Time" }), el("th", { text: "Action" }), el("th", { text: "Outcome" }), el("th", { text: "Detail" }))), activityBody)));
  ctx.mount.append(healthCard, factsCard, diagnosticsCard);

  async function refreshHealth() {
    try {
      const payload = await api(`/api/sites/${encodedDomain}/health`, { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      healthBody.replaceChildren(renderHealth(payload.health || {}));
    } catch (error) {
      if (ctx.signal.aborted) return;
      healthBody.replaceChildren(errorCard(`Unable to load health: ${error.message}`));
    }
  }

  async function refreshDiagnostics() {
    try {
      const payload = await api(`/api/sites/${encodedDomain}/diagnostics`, { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      diagnosticsBody.replaceChildren(renderDiagnostics(payload.checks || []));
    } catch (error) {
      if (ctx.signal.aborted) return;
      diagnosticsBody.replaceChildren(errorCard(`Unable to load diagnostics: ${error.message}`));
    }
  }

  const controls = ["start", "stop", "restart"].map((action) => el("button", {
    type: "button",
    class: `btn ${action === "start" ? "btn-primary" : "btn-outline-danger"}`,
    text: action[0].toUpperCase() + action.slice(1),
    onclick: async (event) => {
      if (["stop", "restart"].includes(action)) {
        const confirmed = await confirmAction({
          title: `${action[0].toUpperCase() + action.slice(1)} site?`,
          message: `${action[0].toUpperCase() + action.slice(1)} interrupts the live site.`,
          confirmLabel: action[0].toUpperCase() + action.slice(1),
        });
        if (ctx.signal.aborted || !confirmed) return;
      }
      try {
        await withBusy(event.currentTarget, async () => {
          await api(`/api/sites/${encodedDomain}/runtime`, { method: "POST", body: { action }, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          await refreshHealth();
          if (ctx.signal.aborted) return;
          toast(`Site ${action} requested.`);
        });
      } catch (error) {
        if (!ctx.signal.aborted) toast(`Unable to ${action} site: ${error.message}`, true);
      }
    },
  }));
  const runtimeCard = card("Runtime controls", el("div", { class: "d-flex flex-wrap gap-2" }, controls));

  const service = el("select", { class: "form-select", "aria-label": "Log service" },
    el("option", { value: "", text: "All services" }),
    ["web", "app", "db", "redis", "sftp"].map((value) => el("option", { value, text: value })));
  const lines = el("input", { class: "form-control", type: "number", min: 1, max: 2000, value: 200, "aria-label": "Log lines" });
  const logResult = el("div", {});
  const loadLogs = el("button", { class: "btn btn-primary", type: "button", text: "Load logs" });
  const logsCard = card("Logs", el("div", {},
    el("div", { class: "row g-2 mb-3" },
      el("div", { class: "col-md" }, service),
      el("div", { class: "col-md-3" }, lines),
      el("div", { class: "col-md-auto" }, loadLogs)),
    logResult));

  loadLogs.addEventListener("click", async () => {
    let count = Number.parseInt(lines.value, 10);
    if (!Number.isFinite(count)) count = 200;
    const clamped = Math.min(2000, Math.max(1, count));
    if (clamped !== count) toast(`Log lines clamped to ${clamped}.`);
    lines.value = clamped;
    const query = new URLSearchParams({ lines: String(clamped) });
    if (service.value) query.set("service", service.value);
    try {
      await withBusy(loadLogs, async () => {
        const payload = await api(`/api/sites/${encodedDomain}/logs?${query}`, { signal: ctx.signal });
        if (ctx.signal.aborted) return;
        logResult.replaceChildren(el("pre", { class: "log-output mb-0", text: payload.logs || "No log output." }));
      });
    } catch (error) {
      if (!ctx.signal.aborted) logResult.replaceChildren(errorCard(`Unable to load logs: ${error.message}`));
    }
  });

  // The cross-site Services page is admin-only, so this is where a site-manager
  // sees the containers of the site they are responsible for.
  const servicesBody = el("tbody", {});
  const servicesCard = card("Services", el("div", { class: "table-responsive" },
    el("table", { class: "table table-vcenter mb-0" },
      el("thead", {}, el("tr", {}, el("th", { text: "Service" }), el("th", { text: "Status" }))),
      servicesBody)));

  async function refreshServices() {
    try {
      const payload = await api(`/api/sites/${encodedDomain}/services`, { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      servicesBody.replaceChildren(...serviceRows(payload.services || []));
    } catch (error) {
      if (ctx.signal.aborted) return;
      servicesBody.replaceChildren(el("tr", {}, el("td", {
        colspan: 2, class: "text-danger", text: `Unable to load services: ${error.message}`,
      })));
    }
  }

  async function refreshActivity() {
    try {
      const payload = await api(`/api/events?domain=${encodedDomain}&limit=25`, { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      activityBody.replaceChildren(...activityRows(payload.events || []));
    } catch (error) {
      if (ctx.signal.aborted) return;
      activityBody.replaceChildren(el("tr", {}, el("td", { colspan: 4, class: "text-danger", text: `Unable to load recent activity: ${error.message}` })));
    }
  }

  ctx.mount.append(servicesCard, runtimeCard, logsCard, activityCard);
  await Promise.all([refreshHealth(), refreshDiagnostics(), refreshServices(), refreshActivity()]);
  if (ctx.signal.aborted) return;
  ctx.onLeave(onPanelEvent((event) => {
    if (!ctx.signal.aborted && event.domain === domain) refreshActivity();
  }));
}
