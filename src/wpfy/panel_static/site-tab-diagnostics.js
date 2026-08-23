import { el, api } from "./panel.js";

function card(title, body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header" }, el("h3", { class: "card-title", text: title })),
    el("div", { class: "card-body" }, body));
}

function errorCard(message) {
  return el("div", { class: "alert alert-danger mb-0", role: "alert", text: message });
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

export async function render(ctx, domain) {
  const encodedDomain = encodeURIComponent(domain);
  const diagnosticsBody = el("div", { class: "text-secondary", text: "Loading diagnostics…" });
  ctx.mount.append(card("Diagnostics", diagnosticsBody));

  try {
    const payload = await api(`/api/sites/${encodedDomain}/diagnostics`, { signal: ctx.signal });
    if (ctx.signal.aborted) return;
    diagnosticsBody.replaceChildren(renderDiagnostics(payload.checks || []));
  } catch (error) {
    if (ctx.signal.aborted) return;
    diagnosticsBody.replaceChildren(errorCard(`Unable to load diagnostics: ${error.message}`));
  }
}
