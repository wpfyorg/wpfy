import { registerPage, el, api } from "./panel.js";

const TABS = [
  ["overview", "Overview"],
  ["settings", "Settings"],
  ["data", "Data"],
  ["file-manager", "File Manager"],
  ["cron", "Cron"],
  ["logs", "Logs"],
  ["diagnostics", "Diagnostics"],
  ["services", "Services"],
  ["wp-cli", "WP-CLI"],
];

const TAB_MODULES = {
  overview: () => import("./site-tab-overview.js"),
  settings: () => import("./site-tab-settings.js"),
  data: () => import("./site-tab-data.js"),
  "file-manager": () => import("./site-tab-file-manager.js"),
  cron: () => import("./site-tab-cron.js"),
  logs: () => import("./site-tab-logs.js"),
  diagnostics: () => import("./site-tab-diagnostics.js"),
  services: () => import("./site-tab-services.js"),
  "wp-cli": () => import("./site-tab-wpcli.js"),
};

function card(title, message, action = null) {
  return el("div", { class: "card" },
    el("div", { class: "card-body text-center py-5" },
      el("h3", { class: "mb-2", text: title }),
      el("p", { class: "text-secondary", text: message }),
      action));
}

function placeholder(tab) {
  return card("Not built yet", `The “${tab}” tab is part of a later stage of the panel rebuild.`);
}

registerPage("site-detail", async (ctx) => {
  const { domain, tab } = ctx.params;
  let site;
  try {
    const payload = await api(`/api/sites/${encodeURIComponent(domain)}`, { signal: ctx.signal });
    if (ctx.signal.aborted) return;
    site = payload.site || payload;
  } catch (error) {
    if (ctx.signal.aborted) return;
    if (error.status === 404) {
      ctx.header({
        title: "Site not found",
        breadcrumb: [["/sites", "Sites"], [null, domain]],
      });
      ctx.mount.append(card("Site not found", `No managed site named ${domain} exists.`,
        el("a", { class: "btn btn-primary", href: "/sites", dataset: { route: "true" }, text: "Return to sites" })));
      return;
    }
    ctx.header({ title: domain, breadcrumb: [["/sites", "Sites"], [null, domain]] });
    ctx.mount.append(card("Unable to load site", error.message));
    return;
  }

  ctx.header({
    title: site.domain || domain,
    subtitle: [site.flavor, site.php_version].filter(Boolean).join(" · "),
    breadcrumb: [["/sites", "Sites"], [null, site.domain || domain]],
  });
  const encodedDomain = encodeURIComponent(domain);
  // No `role="tablist"` / `role="presentation"` here, deliberately: these are
  // real navigation links to real routes, not a tab widget. A tablist whose
  // children carry no `role="tab"` and no `aria-selected` promises a widget
  // that does not exist and suppresses the list semantics on the way -- worse
  // than no role at all. `aria-current="page"` below is what conveys which
  // section is open, and it is the correct vocabulary for links.
  ctx.mount.append(el("ul", { class: "nav nav-tabs mb-3" },
    TABS.map(([name, label]) => el("li", { class: "nav-item" },
      el("a", {
        class: `nav-link${name === tab ? " active" : ""}`,
        href: `/site/${encodedDomain}/${name}`,
        dataset: { route: "true" },
        "aria-current": name === tab ? "page" : null,
        text: label,
      })))));

  // "Not built yet" is claimed only for a tab with no module — never for one
  // that failed. A broken tab reported as unbuilt is how a syntax error hides
  // in plain sight: the page looks deliberately incomplete instead of broken,
  // and nobody goes looking.
  const load = TAB_MODULES[tab];
  if (!load) {
    ctx.mount.append(placeholder(tab));
    return;
  }

  let module;
  try {
    module = await load();
  } catch (error) {
    if (ctx.signal.aborted) return;
    console.error(`site tab ${tab} failed to load`, error);
    ctx.mount.append(card(`The ${tab} tab failed to load`, error.message));
    return;
  }
  if (ctx.signal.aborted) return;

  try {
    await module.render(ctx, domain, site);
  } catch (error) {
    if (ctx.signal.aborted) return;
    console.error(`site tab ${tab} failed to render`, error);
    ctx.mount.append(card(`The ${tab} tab could not be displayed`, error.message));
  }
});
