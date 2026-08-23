import { el, api, withBusy, toast } from "./panel.js";

function card(title, body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header" }, el("h3", { class: "card-title", text: title })),
    el("div", { class: "card-body" }, body));
}

function errorCard(message) {
  return el("div", { class: "alert alert-danger mb-0", role: "alert", text: message });
}

export async function render(ctx, domain) {
  const encodedDomain = encodeURIComponent(domain);
  const service = el("select", { class: "form-select", "aria-label": "Log service" },
    el("option", { value: "", text: "All services" }),
    ["web", "app", "db", "redis", "sftp"].map((value) => el("option", { value, text: value })));
  const lines = el("input", { class: "form-control", type: "number", min: 1, max: 2000, value: 200, "aria-label": "Log lines" });
  const logResult = el("div", {});
  const loadLogs = el("button", { class: "btn btn-primary", type: "button", text: "Load logs" });
  ctx.mount.append(card("Logs", el("div", {},
    el("div", { class: "row g-2 mb-3" },
      el("div", { class: "col-md" }, service),
      el("div", { class: "col-md-3" }, lines),
      el("div", { class: "col-md-auto" }, loadLogs)),
    logResult)));

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
}
