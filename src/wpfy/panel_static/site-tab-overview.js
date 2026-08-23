import { el, api, confirmAction, withBusy, onPanelEvent, toast, formatTime, emptyRow,
         recentOverview, renderOneTime, copyText } from "./panel.js";

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
  // Domain and Site UID live in Connection details now; they describe where the
  // site is reached, not what it is made of.
  const facts = [
    ["Flavor", site.flavor], ["PHP", site.php_version],
    ["SSL", site.ssl_enabled ? "Enabled" : "Disabled"], ["Page cache", site.page_cache],
    ["Object cache", site.object_cache], ["Cache type", site.cache_type],
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

function activityRows(events) {
  if (!events.length) return [emptyRow(4, "activity", "No activity recorded yet.")];
  return events.map((event) => el("tr", {},
    el("td", { text: formatTime(event.timestamp) }),
    el("td", { text: event.action || "–" }),
    el("td", {}, el("span", { class: `badge ${event.outcome === "ok" ? "bg-green-lt text-green" : "bg-red-lt text-red"}`, text: event.outcome || "unknown" })),
    el("td", { text: event.detail || event.actor || "–" })));
}

/* Runtime actions derive from the health reading instead of always offering
   all three: a stopped or never-bootstrapped site has nothing to stop or
   restart. `site_health` also emits `<status>-bootstrap` variants and can be
   unreadable entirely, and every state outside the up-set offers Start only --
   the one action that moves those states forward. */
const RUNTIME_UP = new Set(["running", "ready", "degraded"]);

export async function render(ctx, domain, site) {
  const encodedDomain = encodeURIComponent(domain);
  const publicIp = recentOverview()?.public_ip || "";
  const healthBody = el("div", { class: "text-secondary", text: "Loading health…" });
  const activityBody = el("tbody", {});
  const sftpBody = el("div", { class: "text-secondary", text: "Loading SFTP status…" });
  const runtimeBody = el("div", { class: "text-secondary", text: "Loading health…" });
  let runtimeStatus = "";
  let sftpConnection = null;

  const detailList = () => {
    // Site managers get a 403 from /api/overview, so the SFTP status payload
    // (site-scoped) is the authoritative source for host/port/user here.
    const ip = publicIp || sftpConnection?.host || "";
    return [
      ["Domain", site.domain || domain],
      ["IP address", ip],
      ["Site UID", site.site_uid],
      ["SFTP host", sftpConnection?.host || ip],
      ["SFTP port", sftpConnection?.port],
      ["SFTP user", sftpConnection?.user],
    ].filter(([, value]) => value !== null && value !== undefined && value !== "");
  };
  const detailNode = el("dl", { class: "row mb-3" });
  const renderDetails = () => {
    detailNode.replaceChildren(...detailList().flatMap(([label, value]) => [
      el("dt", { class: "col-sm-3", text: label }),
      el("dd", { class: "col-sm-9 font-monospace text-break", text: String(value) }),
    ]));
  };
  renderDetails();
  const connectionCard = card("Connection details", el("div", {},
    detailNode,
    el("h3", { class: "card-title", text: "SFTP" }),
    sftpBody));

  ctx.mount.append(
    card("Health", healthBody),
    card("Runtime controls", runtimeBody),
    card("Site facts", renderFacts(site)),
    connectionCard,
    card("Recent activity", el("div", { class: "table-responsive" }, el("table", { class: "table table-vcenter mb-0" },
      el("thead", {}, el("tr", {}, el("th", { text: "Time" }), el("th", { text: "Action" }), el("th", { text: "Outcome" }), el("th", { text: "Detail" }))), activityBody))));

  function renderRuntimeControls() {
    const actions = RUNTIME_UP.has(String(runtimeStatus).toLowerCase()) ? ["stop", "restart"] : ["start"];
    const buttons = actions.map((action) => el("button", {
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
    runtimeBody.replaceChildren(el("div", { class: "d-flex flex-wrap gap-2" }, buttons));
  }

  async function refreshHealth() {
    try {
      const payload = await api(`/api/sites/${encodedDomain}/health`, { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      runtimeStatus = payload.health?.status || "";
      healthBody.replaceChildren(renderHealth(payload.health || {}));
    } catch (error) {
      if (ctx.signal.aborted) return;
      // An unreadable state must never keep stale Stop/Restart controls alive:
      // reset to unknown so the controls degrade to Start-only.
      runtimeStatus = "";
      healthBody.replaceChildren(errorCard(`Unable to load health: ${error.message}`));
    }
    renderRuntimeControls();
  }

  async function refreshSftp() {
    try {
      const payload = await api(`/api/sites/${encodedDomain}/sftp`, { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      sftpConnection = payload.connection || null;
      renderDetails();
      renderSftp(payload);
    } catch (failed) {
      if (ctx.signal.aborted) return;
      renderSftp(failed.payload || { message: failed.message, ok: false });
    }
  }

  function sftpMessage(payload, fallback) {
    return payload?.message || payload?.error || fallback;
  }

  function renderSftp(payload) {
    const status = el("div", {
      class: `alert alert-${payload.ok === false ? "warning" : "secondary"} mb-3`, role: "status",
      text: sftpMessage(payload, "SFTP status is unavailable."),
    });
    const actionResult = el("div", { class: "mt-3" });

    async function action(name, button) {
      try {
        await withBusy(button, async () => {
          const response = await api(`/api/sites/${encodedDomain}/sftp`, {
            method: "POST", body: { action: name }, signal: ctx.signal,
          });
          if (ctx.signal.aborted) return;
          if (response.ok === false) throw new Error(sftpMessage(response, `Unable to ${name} SFTP.`));
          if (response.one_time) renderOneTime(`One-time SFTP password for ${domain}`, response.one_time);
          actionResult.replaceChildren(el("div", { class: "alert alert-success mb-0", role: "status", text: sftpMessage(response, `SFTP ${name}d.`) }));
          await refreshSftp();
          if (ctx.signal.aborted) return;
          toast(`SFTP ${name}d.`);
        });
        if (ctx.signal.aborted) return;
      } catch (failed) {
        if (ctx.signal.aborted) return;
        actionResult.replaceChildren(errorCard(`Unable to ${name} SFTP: ${failed.message}`));
      }
    }

    // Tri-state derived strictly from payload.enabled: true renders the
    // connection card; false renders exactly the explanation and Enable;
    // anything else (error, missing field) renders status only — never a
    // guessed action set.
    const enabled = payload.enabled === true;
    const knownDisabled = payload.enabled === false;

    if (!enabled) {
      if (!knownDisabled) {
        sftpBody.replaceChildren(status);
        return;
      }
      const enable = el("button", { class: "btn btn-primary", type: "button", text: "Enable SFTP" });
      enable.addEventListener("click", () => action("enable", enable));
      sftpBody.replaceChildren(
        el("p", { class: "text-secondary mb-2", text: "Starts a per-site SFTP container on a public port and opens the firewall rule for it." }),
        el("div", { class: "btn-list" }, enable),
        actionResult);
      return;
    }

    const connection = payload.connection || {};
    const host = connection.host || recentOverview()?.public_ip || "";
    const port = connection.port || "";
    const user = connection.user || "";
    let revealed = false;
    const passwordValue = el("code", { class: "font-monospace text-break", text: "••••••••••••" });
    const reveal = el("button", { class: "btn btn-outline-secondary btn-sm", type: "button", text: "Show" });
    reveal.addEventListener("click", () => {
      revealed = !revealed;
      passwordValue.textContent = revealed ? (payload.password || "–") : "••••••••••••";
      reveal.textContent = revealed ? "Hide" : "Show";
    });

    const detailRow = (label, valueNode) => el("div", { class: "row mb-1" },
      el("dt", { class: "col-sm-3", text: label }),
      el("dd", { class: "col-sm-9" }, valueNode));
    const details = el("dl", { class: "mb-3" },
      detailRow("Host", el("span", { class: "font-monospace text-break", text: host || "–" })),
      detailRow("Port", el("span", { class: "font-monospace", text: port || "–" })),
      detailRow("Username", el("span", { class: "font-monospace", text: user || "–" })),
      detailRow("Password", el("span", { class: "d-inline-flex align-items-center gap-2" }, passwordValue, reveal)));

    // The connection string is only offered when it can be valid: every field
    // present, and IPv6 literals bracketed so `sftp://user@::1:22` never happens.
    const connectionFields = [host, port, user].every((value) => String(value || "").trim());
    const uriHost = host && host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
    const filezillaBlock = connectionFields ? (() => {
      const uri = `sftp://${user}@${uriHost}:${port}`;
      const copyUri = el("button", { class: "btn btn-outline-secondary btn-sm", type: "button", text: "Copy connection string" });
      copyUri.addEventListener("click", async () => {
        try {
          await copyText(uri);
          copyUri.textContent = "Copied";
        } catch {
          copyUri.textContent = "Copy failed";
        }
        window.setTimeout(() => { copyUri.textContent = "Copy connection string"; }, 2000);
      });
      return el("div", { class: "card card-sm mb-3" },
        el("div", { class: "card-body" },
          el("h4", { class: "card-title", text: "Connect with FileZilla" }),
          el("p", { class: "text-secondary mb-2", text: "Protocol: SFTP · Host and port as above · Logon Type: Normal." }),
          el("div", { class: "d-flex align-items-center gap-2" },
            el("code", { class: "font-monospace text-break", text: uri }), copyUri)));
    })() : null;

    const rotate = el("button", { class: "btn btn-outline-danger", type: "button", text: "Rotate password" });
    rotate.addEventListener("click", async () => {
      const confirmed = await confirmAction({
        title: "Rotate SFTP password?",
        message: "The existing SFTP password will stop working.",
        confirmLabel: "Rotate password",
      });
      if (ctx.signal.aborted || !confirmed) return;
      action("rotate", rotate);
    });
    const disable = el("button", { class: "btn btn-outline-danger", type: "button", text: "Disable" });
    disable.addEventListener("click", async () => {
      const confirmed = await confirmAction({
        title: "Disable SFTP?",
        message: "Existing SFTP access will stop working.",
        confirmLabel: "Disable SFTP",
      });
      if (ctx.signal.aborted || !confirmed) return;
      action("disable", disable);
    });

    sftpBody.replaceChildren(status, details, filezillaBlock,
      el("div", { class: "btn-list" }, rotate, disable), actionResult);
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

  await Promise.all([refreshHealth(), refreshSftp(), refreshActivity()]);
  if (ctx.signal.aborted) return;
  // Stream events re-read activity at once and health on a short debounce, so a
  // job's burst of completion events triggers one health re-render, not one per
  // event -- the same shape page-services.js uses for its own refresh.
  let healthTimer = 0;
  ctx.onLeave(() => clearTimeout(healthTimer));
  ctx.onLeave(onPanelEvent((event) => {
    if (ctx.signal.aborted || event.domain !== domain) return;
    refreshActivity();
    clearTimeout(healthTimer);
    healthTimer = setTimeout(() => { refreshHealth(); }, 300);
  }));
}
