/* Basic auth across every site, read-only on purpose.
 *
 * There is no host-level basic-auth subsystem: it exists per site, written by
 * `PUT /api/sites/{domain}/security`, which carries the whole security document
 * -- deny lists, login shield, basic auth -- as one payload. `GET
 * /api/security/basic-auth` returns only the basic-auth slice, so toggling from
 * here would mean PUTting a document reconstructed from a list that does not
 * contain the rest of it. That is precisely how the site Settings tab used to
 * overwrite sections nobody had touched, so the change happens where the whole
 * document is loaded: on the site itself.
 */

import { registerPage, el, api, emptyState } from "./panel.js";

registerPage("basic-auth", async (ctx) => {
  ctx.header({ icon: "key",
    title: "Basic auth",
    subtitle: "HTTP authentication in front of each site",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "Basic auth"]],
  });

  const mount = el("div", {});
  ctx.mount.append(mount);

  function row(entry) {
    const href = `/site/${encodeURIComponent(entry.domain)}/settings`;
    return el("tr", {},
      el("td", {}, el("a", { href, dataset: { route: "true" }, text: entry.domain })),
      el("td", {}, el("span", {
        class: `badge ${entry.enabled ? "bg-green-lt text-green" : "bg-secondary-lt text-secondary"}`,
        text: entry.enabled ? "Enabled" : "Off",
      })),
      el("td", { class: "font-monospace", text: entry.username || "–" }),
      el("td", { class: "text-end" },
        el("a", { class: "btn btn-sm", href, dataset: { route: "true" }, text: entry.enabled ? "Change" : "Enable" })));
  }

  try {
    const payload = await api("/api/security/basic-auth", { signal: ctx.signal });
    if (ctx.signal.aborted) return;
    const rows = payload.basic_auth || [];
    const enabled = rows.filter((entry) => entry.enabled).length;

    mount.replaceChildren(el("div", { class: "card" },
      el("div", { class: "card-header d-block" },
        el("h3", { class: "card-title mb-0", text: "Sites" }),
        el("p", { class: "text-secondary mb-0 small", text: rows.length
          ? `${enabled} of ${rows.length} site${rows.length === 1 ? "" : "s"} behind basic auth`
          : "No sites yet" })),
      rows.length
        ? el("div", { class: "table-responsive" }, el("table", { class: "table table-vcenter card-table" },
          el("thead", {}, el("tr", {},
            el("th", { text: "Site" }), el("th", { text: "Basic auth" }),
            el("th", { text: "Username" }), el("th", { class: "text-end", text: "" }))),
          el("tbody", {}, rows.map(row))))
        : el("div", { class: "card-body" },
          emptyState("key", "No sites",
            "Basic auth is configured per site, so this list fills in as you create them.")),
      el("div", { class: "card-footer text-secondary small" },
        "Basic auth is part of each site's security settings, alongside its deny list and login shield. Changing it there keeps the rest of that site's security document intact.")));
  } catch (error) {
    if (ctx.signal.aborted) return;
    mount.replaceChildren(el("div", { class: "alert alert-danger", role: "alert", text: `Unable to read the basic-auth inventory: ${error.message}` }));
  }
});
