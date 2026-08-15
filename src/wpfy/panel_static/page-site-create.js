import { el, api, withBusy, pollJob, renderOneTime, stepText, registerPage } from "./panel.js";

const STORAGE_KEY = "wpfy.site-create";
const WORDPRESS_FLAVORS = new Set(["wp", "wpfc", "wpredis", "wpsc", "wprocket", "wpce", "wpsubdir", "wpsubdomain"]);
const FLAVORS = [
  ["php", "PHP"], ["html", "Static HTML"], ["wp", "WordPress"], ["wpfc", "WordPress + FastCGI cache"],
  ["wpredis", "WordPress + Redis"], ["wpsc", "WordPress + WP Super Cache"], ["wprocket", "WordPress + WP Rocket"],
  ["wpce", "WordPress + Cache Enabler"], ["wpsubdir", "WordPress multisite (subdirectory)"],
  ["wpsubdomain", "WordPress multisite (subdomain)"],
];
const PHP_VERSIONS = ["", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4"];
const PAGE_CACHES = [
  ["none", "None"], ["wpfc", "FastCGI cache"], ["wp-super-cache", "WP Super Cache"], ["w3-total-cache", "W3 Total Cache"],
  ["cache-enabler", "Cache Enabler"], ["wp-fastest-cache", "WP Fastest Cache"], ["wp-rocket", "WP Rocket"], ["flying-press", "FlyingPress"],
];
const DEFAULT_STATE = {
  domain: "",
  flavor: "wp",
  php_version: "",
  letsencrypt: "default",
  dns_provider: "cloudflare",
  enable_sftp: false,
  object_cache: "none",
  page_cache: "none",
  admin_user: "",
  admin_email: "",
};

function isWordPress(state) {
  return WORDPRESS_FLAVORS.has(state.flavor);
}

function restoredState() {
  try {
    const stored = JSON.parse(sessionStorage.getItem(STORAGE_KEY));
    if (!stored || typeof stored !== "object") return { ...DEFAULT_STATE };
    return {
      ...DEFAULT_STATE,
      ...Object.fromEntries(Object.keys(DEFAULT_STATE).map((key) => [key, stored[key] ?? DEFAULT_STATE[key]])),
      flavor: FLAVORS.some(([value]) => value === stored.flavor) ? stored.flavor : DEFAULT_STATE.flavor,
      php_version: PHP_VERSIONS.includes(stored.php_version) ? stored.php_version : DEFAULT_STATE.php_version,
      letsencrypt: ["default", "wildcard", "off"].includes(stored.letsencrypt) ? stored.letsencrypt : DEFAULT_STATE.letsencrypt,
      dns_provider: stored.dns_provider === "cloudflare" ? "cloudflare" : DEFAULT_STATE.dns_provider,
      object_cache: ["none", "redis"].includes(stored.object_cache) ? stored.object_cache : DEFAULT_STATE.object_cache,
      page_cache: PAGE_CACHES.some(([value]) => value === stored.page_cache) ? stored.page_cache : DEFAULT_STATE.page_cache,
      enable_sftp: stored.enable_sftp === true,
    };
  } catch {
    return { ...DEFAULT_STATE };
  }
}

function save(state) {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function domainError(value) {
  const domain = value.trim().toLowerCase();
  if (!domain) return "Enter a domain.";
  if (!domain.includes(".") || /[\s/:]/.test(domain)) return "Enter a domain without a scheme, path, or spaces.";
  if (!domain.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    return "Each domain label must use letters, numbers, or hyphens without starting or ending with a hyphen.";
  }
  return "";
}

function emailError(value) {
  return value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? "Enter a valid admin email address." : "";
}

function inputField(label, input, errorNode = null) {
  return el("div", { class: "col-md-6" }, el("label", { class: "form-label", for: input.id, text: label }), input, errorNode);
}

function selectOptions(values, selected) {
  return values.map(([value, label]) => el("option", { value, selected: value === selected, text: label }));
}

function summaryValue(value, fallback = "Server default") {
  return value || fallback;
}

/* Runtime payloads carry `ok`, `exit_code`, `ran` and `skipped` alongside the
   message. Printing the lot buries the one line an operator reads in four
   internals, so only the message and a failure marker surface. */
function resultDetails(label, value) {
  if (!value || typeof value !== "object" || !value.message) return null;
  return el("div", { class: "mb-2" },
    el("strong", { text: `${label}: ` }),
    el("span", { class: value.ok === false ? "text-danger" : "", text: value.message }));
}

registerPage("site-create", (ctx) => {
  ctx.header({ icon: "plus",
    title: "Create site",
    subtitle: "Configure a new isolated site",
    breadcrumb: [["/dashboard", "Dashboard"], ["/sites", "Sites"], [null, "Create site"]],
  });

  let state = restoredState();
  let step = 1;
  let errors = {};
  const card = el("div", { class: "card" });
  ctx.mount.append(card);

  function update(key, value) {
    state[key] = value;
    save(state);
  }

  function validate(target) {
    const next = {};
    if (target >= 1) {
      const message = domainError(state.domain);
      if (message) next.domain = message;
    }
    if (target >= 2 && isWordPress(state)) {
      const message = emailError(state.admin_email.trim());
      if (message) next.admin_email = message;
    }
    errors = next;
    return Object.keys(errors).length === 0;
  }

  /* Correcting a field re-renders nothing: a full re-render rebuilds the input
     and drops the caret, so the message and the invalid class are swapped in
     place. The key stays present once a field has failed validation, so the
     error keeps tracking the value in both directions. */
  function liveError(key, message, input, node) {
    if (errors[key] === undefined) return;
    errors[key] = message;
    input.classList.toggle("is-invalid", Boolean(message));
    node.textContent = message;
  }

  function stepIndicator() {
    return el("div", { class: "steps steps-counter mb-4", role: "list", "aria-live": "polite", "aria-label": `Site creation step ${step} of 3` },
      ["Site", "Options", "Review"].map((label, index) => el("div", {
        class: `step-item${index + 1 === step ? " active" : ""}${index + 1 < step ? " done" : ""}`,
        role: "listitem",
      }, el("div", { class: "step-item-title", text: label }))));
  }

  function footer(...children) {
    return el("div", { class: "card-footer d-flex justify-content-between gap-2" }, children);
  }

  function renderSite() {
    const domain = el("input", {
      id: "site-create-domain", class: `form-control${errors.domain ? " is-invalid" : ""}`, type: "text", autocomplete: "off",
      spellcheck: false, value: state.domain, "aria-describedby": "site-create-domain-error", placeholder: "example.com",
    });
    const domainMessage = el("div", { id: "site-create-domain-error", class: "invalid-feedback d-block", text: errors.domain || "" });
    const flavor = el("select", { id: "site-create-flavor", class: "form-select" }, selectOptions(FLAVORS, state.flavor));
    const php = el("select", { id: "site-create-php", class: "form-select" }, PHP_VERSIONS.map((value) =>
      el("option", { value, selected: value === state.php_version, text: value || "Server default" })));
    domain.addEventListener("input", () => {
      update("domain", domain.value);
      liveError("domain", domainError(domain.value), domain, domainMessage);
    });
    flavor.addEventListener("change", () => update("flavor", flavor.value));
    php.addEventListener("change", () => update("php_version", php.value));
    const next = el("button", { class: "btn btn-primary", type: "button", text: "Next" });
    next.addEventListener("click", () => {
      if (!validate(1)) return render();
      step = 2;
      render();
    });
    card.replaceChildren(
      el("div", { class: "card-body" }, stepIndicator(),
        el("h3", { class: "card-title", text: "Site" }),
        el("p", { class: "text-secondary", text: "Choose the domain and runtime for this site." }),
        el("div", { class: "row g-3" },
          inputField("Domain", domain, domainMessage),
          inputField("Flavor", flavor),
          inputField("PHP version", php))),
      footer(el("span"), next));
  }

  function renderOptions() {
    const ssl = el("select", { id: "site-create-ssl", class: "form-select" }, selectOptions([
      ["default", "Let's Encrypt"], ["wildcard", "Let's Encrypt wildcard"], ["off", "Off"],
    ], state.letsencrypt));
    const sftp = el("input", { id: "site-create-sftp", class: "form-check-input", type: "checkbox", checked: state.enable_sftp });
    ssl.addEventListener("change", () => { update("letsencrypt", ssl.value); render(); });
    sftp.addEventListener("change", () => update("enable_sftp", sftp.checked));
    const fields = [
      inputField("SSL", ssl),
      el("div", { class: "col-md-6 d-flex align-items-end" }, el("label", { class: "form-check" }, sftp,
        el("span", { class: "form-check-label", text: "Enable SFTP access" }))),
    ];
    if (state.letsencrypt === "wildcard") {
      const dns = el("select", { id: "site-create-dns-provider", class: "form-select" }, selectOptions([["cloudflare", "Cloudflare"]], state.dns_provider));
      dns.addEventListener("change", () => update("dns_provider", dns.value));
      fields.push(inputField("DNS provider", dns));
      fields.push(el("div", { class: "col-md-6 align-self-end" }, el("p", { class: "text-secondary small mb-0", text: "DNS is checked when the certificate is issued during creation. If it fails, the site is created without SSL and you can retry from Settings." })));
    }
    if (isWordPress(state)) {
      const objectCache = el("select", { id: "site-create-object-cache", class: "form-select" }, selectOptions([["none", "None"], ["redis", "Redis"]], state.object_cache));
      const pageCache = el("select", { id: "site-create-page-cache", class: "form-select" }, selectOptions(PAGE_CACHES, state.page_cache));
      const adminUser = el("input", { id: "site-create-admin-user", class: "form-control", type: "text", autocomplete: "username", value: state.admin_user });
      const adminEmail = el("input", {
        id: "site-create-admin-email", class: `form-control${errors.admin_email ? " is-invalid" : ""}`, type: "email", autocomplete: "email",
        value: state.admin_email, "aria-describedby": "site-create-admin-email-error",
      });
      const adminEmailMessage = el("div", { id: "site-create-admin-email-error", class: "invalid-feedback d-block", text: errors.admin_email || "" });
      objectCache.addEventListener("change", () => update("object_cache", objectCache.value));
      pageCache.addEventListener("change", () => update("page_cache", pageCache.value));
      adminUser.addEventListener("input", () => update("admin_user", adminUser.value));
      adminEmail.addEventListener("input", () => {
        update("admin_email", adminEmail.value);
        liveError("admin_email", emailError(adminEmail.value.trim()), adminEmail, adminEmailMessage);
      });
      fields.push(inputField("Object cache", objectCache), inputField("Page cache", pageCache), inputField("Admin username", adminUser), inputField("Admin email", adminEmail, adminEmailMessage));
    }
    const back = el("button", { class: "btn", type: "button", text: "Back" });
    const next = el("button", { class: "btn btn-primary", type: "button", text: "Review" });
    back.addEventListener("click", () => { step = 1; errors = {}; render(); });
    next.addEventListener("click", () => {
      if (!validate(2)) return render();
      step = 3;
      render();
    });
    card.replaceChildren(
      el("div", { class: "card-body" }, stepIndicator(),
        el("h3", { class: "card-title", text: "Options" }),
        el("p", { class: "text-secondary", text: "Set the integrations to configure during creation." }),
        el("div", { class: "row g-3" }, fields)),
      footer(back, next));
  }

  function requestBody(dryRun = false) {
    const body = {
      domain: state.domain.trim().toLowerCase(),
      flavor: state.flavor,
      letsencrypt: state.letsencrypt,
      enable_sftp: state.enable_sftp,
      ...(state.php_version ? { php_version: state.php_version } : {}),
      ...(state.letsencrypt === "wildcard" ? { dns_provider: state.dns_provider } : {}),
      ...(isWordPress(state) ? {
        // "none" is the server's own default, and sending it is not inert:
        // the create job treats *any* cache key as "configure caching", which
        // rebuilds the scaffold, restarts the runtime, and wires the Redis
        // backend for a site that asked for neither.
        ...(state.object_cache !== "none" ? { object_cache: state.object_cache } : {}),
        ...(state.page_cache !== "none" ? { page_cache: state.page_cache } : {}),
        ...(state.admin_user.trim() ? { admin_user: state.admin_user.trim() } : {}),
        ...(state.admin_email.trim() ? { admin_email: state.admin_email.trim() } : {}),
      } : {}),
    };
    return dryRun ? { ...body, dry_run: true } : body;
  }

  function reviewRows() {
    const entries = [
      ["Domain", summaryValue(state.domain)], ["Flavor", FLAVORS.find(([value]) => value === state.flavor)?.[1] || state.flavor],
      ["PHP version", summaryValue(state.php_version)], ["SSL", state.letsencrypt === "default" ? "Let's Encrypt" : state.letsencrypt === "wildcard" ? "Let's Encrypt wildcard" : "Off"],
      ["SFTP", state.enable_sftp ? "Enabled" : "Off"],
    ];
    if (state.letsencrypt === "wildcard") entries.push(["DNS provider", state.dns_provider]);
    if (isWordPress(state)) entries.push(
      ["Object cache", state.object_cache], ["Page cache", state.page_cache], ["Admin username", summaryValue(state.admin_user)], ["Admin email", summaryValue(state.admin_email)],
    );
    return entries.flatMap(([label, value]) => [el("dt", { class: "col-sm-4 text-secondary", text: label }), el("dd", { class: "col-sm-8", text: value })]);
  }

  function renderPlan(plan) {
    const changes = Array.isArray(plan.changes) ? plan.changes : [];
    const restarts = Array.isArray(plan.restarts) ? plan.restarts : [];
    return el("div", { class: "alert alert-info mb-0", role: "status" },
      el("strong", { text: "Preview only. " }),
      el("span", { text: "This plan does not create a site and does not validate cache or SFTP work." }),
      el("div", { class: "mt-2" }, el("strong", { text: "Changes" }),
        changes.length ? el("ul", { class: "mb-0" }, changes.map((change) => el("li", { text: String(change) }))) : el("span", { class: "ms-2", text: "None reported." })),
      restarts.length ? el("div", { class: "mt-2" }, el("strong", { text: "Restarts" }), el("ul", { class: "mb-0" }, restarts.map((restart) => el("li", { text: String(restart) })))) : null);
  }

  function renderReview(message = null) {
    const previewResult = el("div", { class: "mt-3" });
    const preview = el("button", { class: "btn btn-outline-primary", type: "button", text: "Preview plan" });
    const create = el("button", { class: "btn btn-primary", type: "button", icon: "plus", text: "Create site" });
    const back = el("button", { class: "btn", type: "button", text: "Back" });
    back.addEventListener("click", () => { step = 2; errors = {}; render(); });
    preview.addEventListener("click", async () => {
      try {
        await withBusy(preview, async () => {
          const plan = await api("/api/sites", { method: "POST", body: requestBody(true), signal: ctx.signal });
          if (ctx.signal.aborted) return;
          previewResult.replaceChildren(renderPlan(plan));
        });
        if (ctx.signal.aborted) return;
      } catch (error) {
        if (ctx.signal.aborted) return;
        previewResult.replaceChildren(el("div", { class: "alert alert-danger mb-0", role: "alert", text: error.message }));
      }
    });
    create.addEventListener("click", async () => {
      if (!validate(2)) return render();
      let polling = false;
      try {
        await withBusy(create, async () => {
          const response = await api("/api/sites", { method: "POST", body: requestBody(), signal: ctx.signal });
          if (ctx.signal.aborted) return;
          if (!response.job_id) throw new Error("The server did not return a site creation job.");
          polling = true;
          const progress = renderProgress();
          const job = await pollJob(response.job_id, {
            signal: ctx.signal,
            onStep: (steps) => {
              if (!ctx.signal.aborted) progress.replaceChildren(...steps.map((item) => el("li", { class: "list-group-item", text: stepText(item) })));
            },
          });
          if (ctx.signal.aborted) return;
          if (job.state === "succeeded") renderSuccess(job);
          // `fail_job` puts the reason in `result.error`; the job payload has no
          // top-level error field, so reading one discards every real message.
          else renderFailure(job.result?.error || "Site creation failed.");
        });
        if (ctx.signal.aborted) return;
      } catch (error) {
        if (ctx.signal.aborted) return;
        if (polling) renderPollFailure(error.message);
        else renderReview(error.message);
      }
    });
    card.replaceChildren(
      el("div", { class: "card-body" }, stepIndicator(),
        el("h3", { class: "card-title", text: "Review" }),
        el("p", { class: "text-secondary", text: "Confirm the values that will be sent to the server." }),
        message ? el("div", { class: "alert alert-danger", role: "alert", text: message }) : null,
        el("dl", { class: "row mb-0" }, reviewRows()),
        previewResult),
      footer(back, el("div", { class: "d-flex gap-2" }, preview, create)));
  }

  function renderProgress() {
    const progress = el("ul", { class: "list-group list-group-flush mt-3", "aria-live": "polite" });
    card.replaceChildren(el("div", { class: "card-body text-center py-5" },
      el("div", { class: "spinner-border text-primary", role: "status" }, el("span", { class: "visually-hidden", text: "Creating site" })),
      el("h3", { class: "mt-3 mb-1", text: `Creating ${state.domain.trim().toLowerCase()}` }),
      el("p", { class: "text-secondary", text: "The site is being created. Keep this page open while the job runs." }),
      progress));
    return progress;
  }

  function renderSuccess(job) {
    sessionStorage.removeItem(STORAGE_KEY);
    const result = job.result || {};
    const domain = state.domain.trim().toLowerCase();
    const touched = Array.isArray(result.touched) ? result.touched : [];
    const facts = [
      // Twenty-odd absolute paths inline drown everything else on the page, so
      // the list is available but folded. <details> needs no script.
      touched.length ? el("details", { class: "mb-2" },
        el("summary", { text: `${touched.length} path${touched.length === 1 ? "" : "s"} written` }),
        el("ul", { class: "mt-2 mb-0 font-monospace small text-break" }, touched.map((path) => el("li", { text: String(path) })))) : null,
      result.runtime ? resultDetails("Runtime", result.runtime) : null,
      result.cache ? el("div", { class: "mb-2" }, el("strong", { text: "Cache: " }),
        el("span", { text: `page ${result.cache.page_cache}, object ${result.cache.object_cache}` })) : null,
      result.sftp ? resultDetails("SFTP", result.sftp) : null,
    ].filter(Boolean);
    const again = el("button", { class: "btn btn-outline-primary", type: "button", text: "Create another site" });
    again.addEventListener("click", () => { state = { ...DEFAULT_STATE }; errors = {}; step = 1; render(); });
    card.replaceChildren(el("div", { class: "card-body" },
      el("div", { class: "alert alert-success", role: "status" }, el("strong", { text: "Site created. " }), el("span", { text: `${domain} is ready to manage.` })),
      el("h3", { class: "card-title", text: domain }),
      facts.length ? el("div", { class: "text-secondary mb-3" }, facts) : null,
      el("div", { class: "d-flex flex-wrap gap-2" },
        el("a", { class: "btn btn-primary", href: `/site/${encodeURIComponent(domain)}/overview`, dataset: { route: "true" }, text: "Manage site" }), again)));
    if (job.one_time) renderOneTime("Save these credentials now", job.one_time);
  }

  function renderFailure(message) {
    card.replaceChildren(el("div", { class: "card-body" },
      el("div", { class: "alert alert-danger", role: "alert", text: message }),
      el("button", { class: "btn btn-primary", type: "button", text: "Back to the form", onclick: () => renderReview() })));
  }

  function renderPollFailure(message) {
    card.replaceChildren(el("div", { class: "card-body" },
      el("div", { class: "alert alert-danger", role: "alert", text: message }),
      el("a", { class: "btn btn-primary", href: "/events", dataset: { route: "true" }, text: "Open Events" })));
  }

  function render() {
    if (step === 1) renderSite();
    else if (step === 2) renderOptions();
    else renderReview();
  }

  render();
});
