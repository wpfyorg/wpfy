import { registerPage, el, api, formatTime, onPanelEvent } from "./panel.js";

function eventTime(value) {
  const timestamp = typeof value === "number" && value < 10_000_000_000 ? value * 1000 : value;
  return formatTime(timestamp);
}

function eventTimestamp(event) {
  const value = event.timestamp;
  return typeof value === "number" && value < 10_000_000_000 ? value * 1000 : new Date(value).getTime() || 0;
}

function matches(event, query) {
  if (!query) return true;
  return [event.action, event.actor, event.detail].some((value) => String(value || "").toLowerCase().includes(query));
}

function outcomeBadge(outcome) {
  const ok = outcome === "ok";
  return el("span", { class: `badge ${ok ? "bg-green-lt text-green" : "bg-red-lt text-red"}`, text: outcome || "unknown" });
}

registerPage("events", async (ctx) => {
  const limit = el("select", { class: "form-select", "aria-label": "Event limit" },
    [50, 200, 500].map((value) => el("option", { value, selected: value === 200, text: String(value) })));
  const filter = el("input", { class: "form-control", type: "search", placeholder: "Filter action, actor, or detail", "aria-label": "Filter events" });
  const groupsMount = el("div", {});
  const status = el("div", { class: "text-secondary small" });
  let events = [];
  let refreshTimer = 0;

  ctx.header({ icon: "activity",
    title: "Events",
    subtitle: "Durable record of panel, host, and site operations",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "Events"]],
  });
  ctx.mount.append(
    el("div", { class: "card mb-3" },
      el("div", { class: "card-body" }, el("div", { class: "row g-2 align-items-end" },
        el("div", { class: "col-md-2" }, el("label", { class: "form-label", for: "events-limit", text: "Show" }), limit),
        el("div", { class: "col-md" }, el("label", { class: "form-label", for: "events-filter", text: "Filter" }), filter)))),
    status,
    groupsMount);

  limit.id = "events-limit";
  filter.id = "events-filter";

  function render() {
    const query = filter.value.trim().toLowerCase();
    const grouped = new Map();
    for (const event of events.filter((item) => matches(item, query))) {
      const key = event.domain || "";
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key).push(event);
    }
    const groups = [...grouped.entries()]
      .map(([domain, rows]) => [domain, rows.sort((left, right) => eventTimestamp(right) - eventTimestamp(left))])
      .sort(([leftDomain, leftRows], [rightDomain, rightRows]) => {
        if (!leftDomain) return -1;
        if (!rightDomain) return 1;
        return eventTimestamp(rightRows[0]) - eventTimestamp(leftRows[0]);
      });

    if (!groups.length) {
      groupsMount.replaceChildren(el("div", { class: "empty py-5" },
        el("p", { class: "empty-title", text: events.length ? "No events match this filter." : "No events recorded yet." }),
        events.length ? el("p", { class: "empty-subtitle text-secondary", text: "Change the filter and try again." }) : null));
      status.textContent = events.length ? "0 events shown" : "";
      return;
    }

    groupsMount.replaceChildren(...groups.map(([domain, rows]) => {
      const body = el("tbody", {});
      body.append(...rows.map((event) => el("tr", {},
        el("td", { class: "text-nowrap", text: eventTime(event.timestamp) }),
        el("td", { text: event.action || "–" }),
        el("td", {}, outcomeBadge(event.outcome)),
        el("td", { class: "text-break", text: event.detail || event.actor || "–" }))));
      const table = el("table", { class: "table table-vcenter mb-0" },
        el("thead", {}, el("tr", {},
          el("th", { scope: "col", text: "Time" }), el("th", { scope: "col", text: "Action" }),
          el("th", { scope: "col", text: "Outcome" }), el("th", { scope: "col", text: "Detail" }))),
        body);
      return el("div", { class: "card mb-3" },
        el("div", { class: "card-header d-block" },
          el("h3", { class: "card-title mb-0", text: domain || "Panel & host" }),
          el("p", { class: "text-secondary small mb-0", text: `${rows.length} event${rows.length === 1 ? "" : "s"}` })),
        el("div", { class: "table-responsive" }, table));
    }));
    const shown = groups.reduce((total, [, rows]) => total + rows.length, 0);
    status.textContent = `${shown} event${shown === 1 ? "" : "s"} shown`
      + (shown === events.length ? "" : ` of ${events.length}`);
  }

  async function refresh() {
    status.textContent = "Loading events…";
    try {
      const payload = await api(`/api/events?limit=${encodeURIComponent(limit.value)}`, { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      events = Array.isArray(payload.events) ? payload.events.slice().sort((left, right) => eventTimestamp(right) - eventTimestamp(left)) : [];
      render();
    } catch (error) {
      if (ctx.signal.aborted) return;
      status.textContent = "Events unavailable";
      groupsMount.replaceChildren(el("div", { class: "alert alert-danger", role: "alert", text: `Unable to load events: ${error.message}` }));
    }
  }

  function queueRefresh() {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => { refresh(); }, 300);
  }

  filter.addEventListener("input", render);
  limit.addEventListener("change", refresh);
  await refresh();
  if (ctx.signal.aborted) return;
  ctx.onLeave(() => clearTimeout(refreshTimer));
  ctx.onLeave(onPanelEvent(() => { if (!ctx.signal.aborted) queueRefresh(); }));
});
