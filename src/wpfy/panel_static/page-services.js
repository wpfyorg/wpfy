import { registerPage, el, icon, api, confirmAction, withBusy, toast, formatBytes, pollJob, onPanelEvent,
         isServiceHealthy, isServiceUnknown, emptyState } from "./panel.js";

/* The healthy/unknown vocabulary lives in panel.js so every surface agrees:
   `unavailable` means the panel could not reach Docker, which is "not known",
   not "not running" -- painting it red tells the operator their sites are down
   when the panel simply could not look. */
const isUnknown = isServiceUnknown;

function statusBadge(status) {
  const tone = isServiceHealthy(status) ? "bg-green-lt text-green"
    : isUnknown(status) ? "bg-secondary-lt text-secondary"
    : "bg-red-lt text-red";
  return el("span", { class: `badge ${tone}`, text: status || "unknown" });
}

function serviceGroups(services) {
  const groups = new Map();
  for (const service of services) {
    const split = String(service.name || "").indexOf(":");
    const domain = split === -1 ? "" : service.name.slice(0, split);
    const name = split === -1 ? service.name : service.name.slice(split + 1);
    if (!groups.has(domain)) groups.set(domain, []);
    groups.get(domain).push({ ...service, domain, service: name });
  }
  return [...groups.entries()].sort(([leftDomain, left], [rightDomain, right]) => {
    if (!leftDomain) return -1;
    if (!rightDomain) return 1;
    const leftFailed = left.some((service) => !isServiceHealthy(service.status) && !isUnknown(service.status));
    const rightFailed = right.some((service) => !isServiceHealthy(service.status) && !isUnknown(service.status));
    if (leftFailed !== rightFailed) return leftFailed ? -1 : 1;
    return leftDomain.localeCompare(rightDomain);
  });
}

function reading(sample) {
  if (!sample) return el("span", { class: "text-secondary", text: "No current reading" });
  return el("div", { class: "d-flex flex-wrap gap-3 text-secondary small" },
    el("span", { text: `CPU ${Number(sample.cpu_percent || 0).toFixed(1)}%` }),
    el("span", { text: `Memory ${formatBytes(sample.memory_used)} / ${formatBytes(sample.memory_total)}` }),
    el("span", { text: `Disk ${formatBytes(sample.disk_used)} / ${formatBytes(sample.disk_total)}` }));
}

registerPage("services", async (ctx) => {
  const mount = el("div", {});
  const refreshButton = el("button", { class: "btn btn-primary", type: "button" }, icon("refresh"), "Refresh");
  let refreshTimer = 0;

  ctx.header({ icon: "server-2",
    title: "Services",
    subtitle: "Runtime status and current resource readings",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "Services"]],
    actions: [refreshButton],
  });
  ctx.mount.append(mount);

  async function restartSite(button, domain, service) {
    const confirmed = await confirmAction({
      title: `Restart ${service}?`, message: `This interrupts ${domain} while ${service} starts again.`, confirmLabel: "Restart service",
    });
    if (ctx.signal.aborted || !confirmed) return;
    try {
      await withBusy(button, async () => {
        const response = await api(`/api/sites/${encodeURIComponent(domain)}/services/${encodeURIComponent(service)}/restart`, {
          method: "POST", body: {}, signal: ctx.signal,
        });
        if (ctx.signal.aborted) return;
        toast(response.message || `${service} restarted.`);
        await refresh();
        if (ctx.signal.aborted) return;
      });
    } catch (error) {
      if (!ctx.signal.aborted) toast(error.message, true);
    }
  }

  async function restartTraefik(button) {
    const typed = await confirmAction({
      title: "Restart Traefik?", message: "This affects every site on this host while the shared edge proxy restarts.", detail: "Type the container name to confirm this host-wide interruption.", confirmLabel: "Restart Traefik", keyword: "wpfy-traefik",
    });
    if (ctx.signal.aborted || typed !== "wpfy-traefik") return;
    try {
      await withBusy(button, async () => {
        const response = await api("/api/system/traefik/restart", { method: "POST", body: { confirm: typed }, signal: ctx.signal });
        if (ctx.signal.aborted) return;
        const job = await pollJob(response.job_id, { signal: ctx.signal });
        if (ctx.signal.aborted) return;
        if (job.state === "succeeded") toast("Traefik restarted.");
        else toast(job.result?.error || "Traefik restart failed.", true);
        await refresh();
        if (ctx.signal.aborted) return;
      });
    } catch (error) {
      if (!ctx.signal.aborted) toast(error.message, true);
    }
  }

  function serviceRow(item) {
    const restart = el("button", { class: "btn btn-sm btn-outline-primary", type: "button", text: "Restart" });
    restart.addEventListener("click", () => item.domain ? restartSite(restart, item.domain, item.service) : restartTraefik(restart));
    return el("tr", {}, el("td", { text: item.service || "–" }), el("td", {}, statusBadge(item.status)), el("td", { class: "text-end" }, restart));
  }

  function card(domain, services, sample) {
    const failed = services.some((service) => !isServiceHealthy(service.status) && !isUnknown(service.status));
    const unknown = !failed && services.some((service) => isUnknown(service.status));
    const running = services.filter((service) => isServiceHealthy(service.status)).length;
    const title = domain
      ? el("a", { href: `/site/${encodeURIComponent(domain)}/overview`, dataset: { route: "true" }, text: domain })
      : el("span", { text: "Panel & host" });
    const summary = failed ? `${running} of ${services.length} running`
      : unknown ? `${services.length} service${services.length === 1 ? "" : "s"}, status unknown`
      : `${running} service${running === 1 ? "" : "s"} running`;
    return el("div", { class: `card mb-3 ${failed ? "border-start border-danger border-4" : unknown ? "border-start border-warning border-4" : ""}` },
      el("div", { class: "card-header d-block" },
        el("div", { class: "d-flex align-items-center gap-2" },
          failed
            ? el("span", { class: "text-danger", title: "One or more services are not running", "aria-label": "One or more services are not running" }, "⚠")
            : unknown
              ? el("span", { class: "text-warning", title: "Service status could not be read", "aria-label": "Service status could not be read" }, "?")
              : null,
          el("h3", { class: "card-title mb-0" }, title)),
        el("p", { class: "text-secondary small mb-0", text: summary })),
      el("div", { class: "card-body py-2" }, reading(sample)),
      el("div", { class: "table-responsive" }, el("table", { class: "table table-vcenter mb-0" },
        el("thead", {}, el("tr", {}, el("th", { scope: "col", text: "Service" }), el("th", { scope: "col", text: "Status" }), el("th", { scope: "col", class: "text-end", text: "Action" }))),
        el("tbody", {}, services.map(serviceRow)))));
  }

  async function refresh() {
    // Only the first paint gets a loading state. A stream-driven refresh that
    // blanks the page throws away the operator's scroll position and flashes
    // every card, several times over when a job emits a burst of events.
    if (!mount.firstChild) mount.replaceChildren(el("div", { class: "text-secondary", text: "Loading services…" }));
    try {
      const [servicesResult, metricsResult] = await Promise.allSettled([
        api("/api/system/services", { signal: ctx.signal }),
        api("/api/metrics/latest", { signal: ctx.signal }),
      ]);
      if (ctx.signal.aborted) return;
      if (servicesResult.status === "rejected") throw servicesResult.reason;
      const services = Array.isArray(servicesResult.value.services) ? servicesResult.value.services : [];
      const samples = metricsResult.status === "fulfilled" && Array.isArray(metricsResult.value.samples) ? metricsResult.value.samples : [];
      const readings = new Map(samples.map((sample) => [sample.scope, sample]));
      const hostScope = metricsResult.status === "fulfilled" ? metricsResult.value.host_scope : "host";
      const groups = serviceGroups(services);
      if (!groups.length) {
        mount.replaceChildren(emptyState("server-2", "No services found.", "No site is running containers on this host yet."));
        return;
      }
      mount.replaceChildren(...groups.map(([domain, group]) => card(domain, group, readings.get(domain || hostScope))));
    } catch (error) {
      if (ctx.signal.aborted) return;
      mount.replaceChildren(el("div", { class: "alert alert-danger", role: "alert", text: `Unable to load services: ${error.message}` }));
    }
  }

  function queueRefresh() {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => { refresh(); }, 300);
  }

  refreshButton.addEventListener("click", refresh);
  await refresh();
  if (ctx.signal.aborted) return;
  ctx.onLeave(() => clearTimeout(refreshTimer));
  ctx.onLeave(onPanelEvent(() => { if (!ctx.signal.aborted) queueRefresh(); }));
});
