import { registerPage, el, api, formatBytes, formatTime, onPanelEvent, session,
         isServiceHealthy, isServiceUnknown, emptyRow } from "./panel.js";

const METRIC_CHARTS = [
  { key: "cpu", title: "CPU", danger: 85, value: (sample) => sample.cpu_percent, format: (value) => `${value.toFixed(1)}%` },
  { key: "memory", title: "Memory", danger: 90, bounded: true, value: (sample) => sample.memory_total ? sample.memory_used / sample.memory_total * 100 : null, format: (value) => `${value.toFixed(1)}%` },
  { key: "disk", title: "Disk", danger: 85, bounded: true, value: (sample) => sample.disk_total ? sample.disk_used / sample.disk_total * 100 : null, format: (value) => `${value.toFixed(1)}%` },
  { key: "load", title: "Load", value: (sample) => sample.load1, format: (value) => value.toFixed(2) },
];

function timestamp(value) {
  return typeof value === "number" && value < 10_000_000_000 ? value * 1000 : value;
}

function _chartDomain(values, { bounded = false } = {}) {
  if (bounded) return [0, 100];
  const finite = values.filter(Number.isFinite);
  if (!finite.length) return [0, 1];
  const low = Math.min(...finite);
  const high = Math.max(...finite);
  const padding = (high - low || 1) * 0.1;
  return [Math.max(0, low - padding), high + padding];
}

function _tickPrecision(span) {
  if (span >= 10) return 0;
  if (span >= 1) return 1;
  return Math.min(6, Math.ceil(-Math.log10(span / 4)) + 1);
}

function _paintMetricChart(canvas, chart, samples) {
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(1, Math.round(rect.width));
  const height = Math.max(1, Math.round(rect.height));
  const scale = window.devicePixelRatio || 1;
  canvas.width = width * scale;
  canvas.height = height * scale;
  const context = canvas.getContext("2d");
  context.setTransform(scale, 0, 0, scale, 0, 0);
  context.clearRect(0, 0, width, height);

  const css = getComputedStyle(document.documentElement);
  const grid = css.getPropertyValue("--chart-grid").trim();
  const text = css.getPropertyValue("--chart-text").trim();
  const values = samples.map(chart.value);
  const line = css.getPropertyValue(values.some((value) => Number.isFinite(value) && value >= chart.danger)
    ? "--chart-alert"
    : "--chart-ok").trim();
  const [minimum, maximum] = _chartDomain(values, chart);
  const padding = { top: 12, right: 12, bottom: 24, left: 42 };
  const plotWidth = Math.max(1, width - padding.left - padding.right);
  const plotHeight = Math.max(1, height - padding.top - padding.bottom);
  const precision = _tickPrecision(maximum - minimum);

  context.font = "12px system-ui, sans-serif";
  context.lineWidth = 1;
  context.strokeStyle = grid;
  context.fillStyle = text;
  for (let index = 0; index <= 4; index += 1) {
    const y = padding.top + plotHeight * index / 4;
    const value = maximum - (maximum - minimum) * index / 4;
    context.beginPath();
    context.moveTo(padding.left, y);
    context.lineTo(width - padding.right, y);
    context.stroke();
    context.fillText(value.toFixed(precision), 2, y + 4);
  }

  const valid = samples
    .map((sample, index) => ({ index, value: chart.value(sample) }))
    .filter((point) => Number.isFinite(point.value));
  if (!valid.length) return;
  context.strokeStyle = line;
  context.lineWidth = 2;
  context.lineJoin = "round";
  context.lineCap = "round";
  context.beginPath();
  valid.forEach((point, index) => {
    const x = padding.left + plotWidth * point.index / Math.max(samples.length - 1, 1);
    const y = padding.top + plotHeight * (1 - (point.value - minimum) / (maximum - minimum || 1));
    if (index === 0) context.moveTo(x, y);
    else context.lineTo(x, y);
  });
  context.stroke();
}

function drawMetricChart(canvas, chart, samples) {
  _paintMetricChart(canvas, chart, samples);
}

function renderMetricCharts(samples) {
  const canvases = [];
  const charts = el("div", { class: "row row-deck row-cards" }, METRIC_CHARTS.map((chart) => {
    const canvas = el("canvas", { class: "chart-canvas", role: "img", "aria-label": `${chart.title} history` });
    canvases.push([canvas, chart]);
    return el("div", { class: "col-md-6" },
      el("div", { class: "card" },
        el("div", { class: "card-body" },
          el("h3", { class: "card-title", text: chart.title }),
          canvas)));
  }));
  const redraw = () => canvases.forEach(([canvas, chart]) => drawMetricChart(canvas, chart, samples));
  return { charts, redraw };
}

function renderMetricTable(samples) {
  return el("details", { class: "mt-3" },
    el("summary", { text: "Metric data table" }),
    el("div", { class: "table-responsive mt-2" },
      el("table", { class: "table table-sm table-vcenter" },
        el("thead", {}, el("tr", {},
          el("th", { text: "Time" }), el("th", { text: "CPU" }), el("th", { text: "Memory" }),
          el("th", { text: "Disk" }), el("th", { text: "Load" }))),
        el("tbody", {}, samples.map((sample) => el("tr", {},
          el("td", { text: formatTime(timestamp(sample.timestamp)) }),
          el("td", { text: `${Number(sample.cpu_percent || 0).toFixed(1)}%` }),
          el("td", { text: `${formatBytes(sample.memory_used)} / ${formatBytes(sample.memory_total)}` }),
          el("td", { text: `${formatBytes(sample.disk_used)} / ${formatBytes(sample.disk_total)}` }),
          el("td", { text: Number(sample.load1 || 0).toFixed(2) })))))));
}

function card(title, body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header" }, el("h3", { class: "card-title", text: title })),
    el("div", { class: "card-body" }, body));
}

function statCard(label, value, detail = null) {
  return el("div", { class: "col-sm-6 col-lg-3" },
    el("div", { class: "card" },
      el("div", { class: "card-body" },
        el("div", { class: "subheader", text: label }),
        typeof value === "string" || typeof value === "number"
          ? el("div", { class: "h1 mb-0", text: String(value ?? "–") })
          : value,
        detail)));
}

/**
 * `/api/overview` reports Traefik as a whole sentence, and a sentence in an
 * `h1` wraps to three lines and breaks the stat row. The card shows the state
 * as a word, and keeps the reason underneath — an operator who sees "Degraded"
 * with no explanation has to go hunting for it.
 */
function traefikCard(status) {
  /* One parsed container state, not the `docker compose ps` table this used to
     receive — the card printed "NAME IMAGE COMMAND SE…" as its own subtext, and
     the substring search for "error" ran across a whole table of container
     names and could match one by accident. */
  const text = String(status || "unknown");
  const healthy = isServiceHealthy(text);
  const unknown = isServiceUnknown(text);
  return statCard("Traefik",
    el("div", { class: "d-flex align-items-center gap-2" },
      el("span", { class: `status-dot ${healthy ? "bg-green" : unknown ? "bg-secondary" : "bg-red"}` }),
      el("span", { class: "h1 mb-0", text: healthy ? "Running" : unknown ? "Unknown" : "Degraded" })),
    el("div", { class: "text-secondary text-truncate mt-1", title: text, text }));
}

function tableError(message, columns) {
  return el("tr", {}, el("td", { class: "text-danger", colspan: columns, text: message }));
}

function eventTime(value) {
  return formatTime(timestamp(value));
}

function activityRows(events) {
  if (!events.length) return [emptyRow(4, "activity", "No activity recorded yet.")];
  return events.map((event) => el("tr", {},
    el("td", { text: eventTime(event.timestamp) }),
    el("td", { text: event.action || "–" }),
    el("td", {}, event.domain
      ? el("a", { href: `/site/${encodeURIComponent(event.domain)}`, dataset: { route: "true" }, text: event.domain })
      : "–"),
    el("td", {}, el("span", {
      class: `badge ${event.outcome === "ok" ? "bg-green-lt text-green" : "bg-red-lt text-red"}`,
      text: event.outcome || "unknown",
    }))));
}

registerPage("dashboard", async (ctx) => {
  // The dashboard is the root of the trail, so it is one entry, not a link to
  // itself followed by itself.
  ctx.header({ icon: "layout-dashboard", title: "Dashboard", subtitle: "Server and site activity", breadcrumb: [[null, "Dashboard"]] });

  const activityBody = el("div", { class: "table-responsive" });
  const activityTable = el("table", { class: "table table-vcenter" },
    el("thead", {}, el("tr", {}, el("th", { text: "Time" }), el("th", { text: "Action" }), el("th", { text: "Domain" }), el("th", { text: "Outcome" }))),
    el("tbody", {}));
  activityBody.append(activityTable);
  const activityCard = card("Recent activity", activityBody);
  ctx.mount.append(activityCard);

  let refreshBackups = () => {};
  async function refreshActivity() {
    try {
      const payload = await api("/api/events?limit=10", { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      activityTable.tBodies[0].replaceChildren(...activityRows(payload.events || []));
    } catch (error) {
      if (ctx.signal.aborted) return;
      activityTable.tBodies[0].replaceChildren(tableError(`Unable to load recent activity: ${error.message}`, 4));
    }
  }

  if (session.isAdmin) {
    const stats = el("div", { class: "row row-deck row-cards mb-3" });
    const metricsBody = el("div", {});
    const range = el("select", { class: "form-select form-select-sm", "aria-label": "Metrics range", disabled: true });
    const metricsCard = card("Host metrics", el("div", {},
      el("div", { class: "d-flex justify-content-end mb-3" }, range), metricsBody));
    const backupBody = el("div", { class: "table-responsive" });
    const backupsCard = card("Recent backups", backupBody);
    ctx.mount.prepend(stats, metricsCard);

    async function loadOverview() {
      try {
        const overview = await api("/api/overview", { signal: ctx.signal });
        if (ctx.signal.aborted) return;
        stats.replaceChildren(
          statCard("Sites", overview.site_count),
          statCard("wpfy", overview.version),
          statCard("Docker", overview.docker_version || "unavailable"),
          traefikCard(overview.traefik));
      } catch (error) {
        if (ctx.signal.aborted) return;
        stats.replaceChildren(el("div", { class: "col-12" }, el("div", { class: "alert alert-danger", role: "alert", text: `Unable to load overview: ${error.message}` })));
      }
    }

    let redrawMetrics = () => {};
    let pendingFrame = 0;
    const onResize = () => redrawMetrics();
    window.addEventListener("resize", onResize);
    ctx.onLeave(() => {
      window.removeEventListener("resize", onResize);
      cancelAnimationFrame(pendingFrame);
    });

    async function loadMetrics(selectedRange = "1h") {
      metricsBody.replaceChildren(el("div", { class: "text-secondary", text: "Loading metrics…" }));
      try {
        const payload = await api(`/api/metrics?scope=host&range=${encodeURIComponent(selectedRange)}`, { signal: ctx.signal });
        if (ctx.signal.aborted) return;
        range.replaceChildren(...(payload.ranges || []).map((value) => el("option", { value, text: value, selected: value === payload.range })));
        range.disabled = false;
        const samples = payload.samples || [];
        if (!samples.length) {
          redrawMetrics = () => {};
          // `empty-header` is Tabler's display-size slot for a full-page empty
          // state; inside a card it renders larger than everything else on the
          // dashboard. Title + subtitle is the in-card pairing.
          metricsBody.replaceChildren(el("div", { class: "empty" },
            el("p", { class: "empty-title", text: "No metrics yet" }),
            el("p", { class: "empty-subtitle text-secondary" },
              "Run ", el("code", { text: "wpfy cron install" }), " to start collecting host metrics.")));
          return;
        }
        const rendered = renderMetricCharts(samples);
        redrawMetrics = rendered.redraw;
        metricsBody.replaceChildren(rendered.charts, renderMetricTable(samples));
        // Cancellable: navigating away between the schedule and the frame would
        // otherwise paint a canvas belonging to a page that no longer exists.
        cancelAnimationFrame(pendingFrame);
        pendingFrame = requestAnimationFrame(redrawMetrics);
      } catch (error) {
        if (ctx.signal.aborted) return;
        redrawMetrics = () => {};
        metricsBody.replaceChildren(el("div", { class: "alert alert-danger mb-0", role: "alert", text: `Unable to load host metrics: ${error.message}` }));
      }
    }
    range.addEventListener("change", () => { loadMetrics(range.value); });

    async function loadBackups() {
      try {
        const sitesPayload = await api("/api/sites", { signal: ctx.signal });
        if (ctx.signal.aborted) return;
        const sites = sitesPayload.sites || [];
        if (!sites.length) {
          backupsCard.remove();
          return;
        }
        ctx.mount.append(backupsCard);
        backupBody.replaceChildren(el("div", { class: "text-secondary", text: "Loading backups…" }));
        const results = await Promise.allSettled(sites.map((site) => api(`/api/sites/${encodeURIComponent(site.domain)}/backups`, { signal: ctx.signal })));
        if (ctx.signal.aborted) return;
        backupBody.replaceChildren(el("table", { class: "table table-vcenter" },
          el("thead", {}, el("tr", {}, el("th", { text: "Domain" }), el("th", { text: "Latest backup" }), el("th", { text: "Size" }), el("th", { text: "Created" }))),
          el("tbody", {}, sites.map((site, index) => {
            const result = results[index];
            if (result.status === "rejected") return el("tr", {},
              el("td", {}, el("a", { href: `/site/${encodeURIComponent(site.domain)}`, dataset: { route: "true" }, text: site.domain })),
              el("td", { colspan: 3, class: "text-danger", text: `Unavailable: ${result.reason.message}` }));
            const backups = result.value.backups || [];
            const latest = backups.slice().sort((left, right) => String(right.created_at).localeCompare(String(left.created_at)))[0];
            return el("tr", {},
              el("td", {}, el("a", { href: `/site/${encodeURIComponent(site.domain)}`, dataset: { route: "true" }, text: site.domain })),
              el("td", { text: latest?.name || "No backups" }),
              el("td", { text: latest ? formatBytes(latest.size) : "–" }),
              el("td", { text: latest ? eventTime(latest.created_at) : "–" }));
          }))));
      } catch (error) {
        if (ctx.signal.aborted) return;
        ctx.mount.append(backupsCard);
        backupBody.replaceChildren(el("div", { class: "alert alert-danger mb-0", role: "alert", text: `Unable to load backups: ${error.message}` }));
      }
    }
    refreshBackups = loadBackups;
    await Promise.all([loadOverview(), loadMetrics(), loadBackups()]);
    if (ctx.signal.aborted) return;
  }

  await refreshActivity();
  if (ctx.signal.aborted) return;
  ctx.onLeave(onPanelEvent((event) => {
    if (ctx.signal.aborted) return;
    refreshActivity();
    if (String(event.action || "").startsWith("backup.")) refreshBackups();
  }));
});
