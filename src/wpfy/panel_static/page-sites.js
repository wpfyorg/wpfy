import { registerPage, el, api, session } from "./panel.js";

function text(value) {
  return String(value ?? "").toLowerCase();
}

function formatCreated(value) {
  if (!value) return "–";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function cacheLabel(site) {
  const cache = site.cache_type || [site.page_cache, site.object_cache].filter((value) => value && value !== "none").join(", ");
  return cache || "None";
}

registerPage("sites", async (ctx) => {
  const create = session.isAdmin
    ? el("a", { class: "btn btn-primary", href: "/sites/new", dataset: { route: "true" } }, "Create site")
    : null;
  ctx.header({ icon: "world",
    title: "Sites",
    subtitle: "Manage your WordPress sites",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "Sites"]],
    actions: create ? [create] : [],
  });

  const filter = el("input", { class: "form-control", type: "search", placeholder: "Filter domains", "aria-label": "Filter domains" });
  const flavor = el("select", { class: "form-select", "aria-label": "Filter by flavor" }, el("option", { value: "", text: "All flavors" }));
  const count = el("div", { class: "text-secondary small" });
  const body = el("tbody", {});
  const columns = [
    ["domain", "Domain"], ["flavor", "Flavor"], ["php_version", "PHP"], ["ssl_enabled", "SSL"], ["cache", "Cache"], ["created_at", "Created"],
  ];
  let sites = [];
  let sortKey = "domain";
  let direction = 1;

  const headers = columns.map(([key, label]) => {
    const button = el("button", {
      class: "btn btn-link p-0 text-reset text-decoration-none",
      type: "button",
      text: label,
      onclick: () => {
        direction = sortKey === key ? -direction : 1;
        sortKey = key;
        render();
      },
    });
    return [key, label, button];
  });
  const table = el("table", { class: "table table-vcenter" },
    el("thead", {}, el("tr", {}, headers.map(([key, label, button]) => el("th", { scope: "col", "aria-sort": "none", dataset: { sortKey: key } }, button)))),
    body);
  const card = el("div", { class: "card" },
    el("div", { class: "card-header" }, el("h3", { class: "card-title", text: "Sites" })),
    el("div", { class: "card-body border-bottom py-3" },
      el("div", { class: "row g-2" },
        el("div", { class: "col-md" }, filter),
        el("div", { class: "col-md-3" }, flavor))),
    el("div", { class: "table-responsive" }, table),
    el("div", { class: "card-footer" }, count));
  ctx.mount.append(card);

  function sortedFiltered() {
    const query = text(filter.value).trim();
    const selectedFlavor = flavor.value;
    return sites
      .filter((site) => text(site.domain).includes(query) && (!selectedFlavor || site.flavor === selectedFlavor))
      .sort((left, right) => {
        const value = (site) => sortKey === "cache" ? cacheLabel(site) : site[sortKey];
        return text(value(left)).localeCompare(text(value(right)), undefined, { numeric: true }) * direction;
      });
  }

  function render() {
    const visible = sortedFiltered();
    headers.forEach(([key, label, button]) => {
      const active = key === sortKey;
      button.textContent = active ? `${label} ${direction === 1 ? "▲" : "▼"}` : label;
      button.closest("th").setAttribute("aria-sort", active ? direction === 1 ? "ascending" : "descending" : "none");
    });
    if (!sites.length) {
      body.replaceChildren(el("tr", {}, el("td", { colspan: columns.length },
        el("div", { class: "empty py-4" },
          el("p", { class: "empty-title", text: "No sites exist yet." }),
          el("p", { class: "empty-subtitle text-secondary", text: "Create your first site to start managing it here." }),
          session.isAdmin ? el("a", { class: "btn btn-primary", href: "/sites/new", dataset: { route: "true" }, text: "Create site" }) : null))));
      count.textContent = "0 total";
      return;
    }
    if (!visible.length) {
      body.replaceChildren(el("tr", {}, el("td", { colspan: columns.length },
        el("div", { class: "empty py-4" },
          el("p", { class: "empty-title", text: "No sites match this filter." }),
          el("p", { class: "empty-subtitle text-secondary", text: "Change the domain or flavor filter and try again." })) )));
      count.textContent = `0 of ${sites.length}`;
      return;
    }
    body.replaceChildren(...visible.map((site) => el("tr", {},
      el("td", {}, el("a", { href: `/site/${encodeURIComponent(site.domain)}`, dataset: { route: "true" }, text: site.domain })),
      el("td", { text: site.flavor || "–" }),
      el("td", { text: site.php_version || "–" }),
      el("td", {}, el("span", { class: `badge ${site.ssl_enabled ? "bg-green-lt text-green" : "bg-secondary-lt"}`, text: site.ssl_enabled ? "Enabled" : "Disabled" })),
      el("td", { text: cacheLabel(site) }),
      el("td", { text: formatCreated(site.created_at) }))));
    count.textContent = visible.length === sites.length ? `${sites.length} total` : `${visible.length} of ${sites.length}`;
  }

  filter.addEventListener("input", render);
  flavor.addEventListener("change", render);
  try {
    const payload = await api("/api/sites", { signal: ctx.signal });
    if (ctx.signal.aborted) return;
    sites = payload.sites || [];
    const flavors = [...new Set(sites.map((site) => site.flavor).filter(Boolean))].sort();
    flavor.append(...flavors.map((value) => el("option", { value, text: value })));
    render();
  } catch (error) {
    if (ctx.signal.aborted) return;
    body.replaceChildren(el("tr", {}, el("td", { colspan: columns.length, class: "text-danger", text: `Unable to load sites: ${error.message}` })));
    count.textContent = "Sites unavailable";
  }
});
