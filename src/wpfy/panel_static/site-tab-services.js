import { el, api, isServiceHealthy, isServiceUnknown, emptyRow } from "./panel.js";

function card(title, body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header" }, el("h3", { class: "card-title", text: title })),
    el("div", { class: "card-body" }, body));
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

export async function render(ctx, domain) {
  const encodedDomain = encodeURIComponent(domain);
  // The cross-site Services page is admin-only, so this is where a site-manager
  // sees the containers of the site they are responsible for.
  const servicesBody = el("tbody", {});
  ctx.mount.append(card("Services", el("div", { class: "table-responsive" },
    el("table", { class: "table table-vcenter mb-0" },
      el("thead", {}, el("tr", {}, el("th", { text: "Service" }), el("th", { text: "Status" }))),
      servicesBody))));

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
