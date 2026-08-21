import { el, api, confirmAction, withBusy, pollJob, toast, navigate } from "./panel.js";

const PHP_FIELDS = [
  ["php_memory_limit", "Memory limit"],
  ["php_max_execution_time", "Max execution time"],
  ["php_max_input_time", "Max input time"],
  ["php_max_input_vars", "Max input vars"],
  ["php_upload_max_size", "Upload max size"],
];

function card(title, body, className = "") {
  return el("div", { class: `card mb-3 ${className}`.trim() },
    el("div", { class: "card-header" }, el("h3", { class: "card-title", text: title })),
    el("div", { class: "card-body" }, body));
}

function error(message) {
  return el("div", { class: "alert alert-danger mb-0", role: "alert", text: message });
}

function lines(value) {
  return Array.isArray(value) ? value.join("\n") : "";
}

function values(text) {
  return text.split("\n").map((value) => value.trim()).filter(Boolean);
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function changeList(payload) {
  const changes = Array.isArray(payload?.changes) ? payload.changes : [];
  if (!changes.length) return el("p", { class: "text-secondary mb-0", text: "No changes planned." });
  return el("ul", { class: "list-group list-group-flush" }, changes.map((change) => el("li", { class: "list-group-item px-0 d-flex gap-2" },
    el("span", { class: "badge bg-azure-lt check-plan", text: "plan" }),
    el("span", { text: String(change) }))));
}

function isIpOrCidr(value) {
  const [address, prefix] = value.split("/");
  if (!address || value.split("/").length > 2) return false;
  const ipv4 = address.split(".");
  if (ipv4.length === 4 && ipv4.every((part) => /^\d+$/.test(part) && Number(part) <= 255)) {
    return prefix === undefined || (/^\d+$/.test(prefix) && Number(prefix) <= 32);
  }
  if (!address.includes(":")) return false;
  return prefix === undefined || (/^\d+$/.test(prefix) && Number(prefix) <= 128);
}

function progressList() {
  return el("ul", { class: "list-group list-group-flush mt-3" });
}

export async function render(ctx, domain, site) {
  const encodedDomain = encodeURIComponent(domain);
  const sections = new Map();
  const plans = el("div", { class: "mb-3" });
  const actionStatus = el("div", { class: "text-secondary small" });
  const preview = el("button", { class: "btn btn-outline-primary", type: "button", text: "Preview changes" });
  const apply = el("button", { class: "btn btn-primary", type: "button", text: "Apply", disabled: true });
  const reset = el("button", { class: "btn btn-link", type: "button", text: "Reset" });
  const acknowledge = el("input", { class: "form-check-input", type: "checkbox", id: "settings-acknowledge" });
  const warningAcknowledgement = el("div", { class: "form-check d-none" }, acknowledge,
    el("label", { class: "form-check-label", for: "settings-acknowledge", text: "I understand and accept the preview warnings." }));
  let previewValid = false;
  let previewWarnings = [];

  function dirtyEntries() {
    return [...sections.entries()].filter(([, section]) => section.dirty());
  }

  function syncActions() {
    const dirty = dirtyEntries().length > 0;
    preview.disabled = !dirty;
    apply.disabled = !previewValid || !dirty || (previewWarnings.length > 0 && !acknowledge.checked);
    warningAcknowledgement.classList.toggle("d-none", previewWarnings.length === 0);
  }

  function invalidatePreview() {
    previewValid = false;
    previewWarnings = [];
    acknowledge.checked = false;
    plans.replaceChildren();
    actionStatus.textContent = "";
    syncActions();
  }

  function register(name, section) {
    sections.set(name, section);
    section.inputs.forEach((input) => input.addEventListener("input", invalidatePreview));
    section.inputs.forEach((input) => input.addEventListener("change", invalidatePreview));
  }

  acknowledge.addEventListener("change", syncActions);

  const configPhp = el("input", { class: "form-control", value: site.php_version || "", "aria-label": "PHP version" });
  const configFlavor = el("input", { class: "form-control", value: site.flavor || "", "aria-label": "Flavor" });
  const configSsl = el("input", { class: "form-check-input", type: "checkbox", checked: site.ssl_enabled || site.letsencrypt === "default" || site.letsencrypt === "wildcard" });
  const sslStatus = el("div", { class: "mt-3" });
  const preflight = el("button", { class: "btn btn-outline-secondary btn-sm", type: "button", text: "Check SSL preflight" });
  const configCard = card("Config", el("div", {},
    el("div", { class: "row g-3" },
      el("div", { class: "col-md-4" }, el("label", { class: "form-label", text: "PHP version" }), configPhp),
      el("div", { class: "col-md-4" }, el("label", { class: "form-label", text: "Flavor" }), configFlavor),
      el("div", { class: "col-md-4 d-flex align-items-end" }, el("label", { class: "form-check" }, configSsl,
        el("span", { class: "form-check-label", text: "Enable Let's Encrypt" })))),
    el("div", { class: "mt-3" }, preflight), sslStatus));
  const initialConfig = {
    php_version: configPhp.value,
    flavor: configFlavor.value,
    letsencrypt: configSsl.checked,
  };
  register("config", {
    inputs: [configPhp, configFlavor, configSsl],
    dirty: () => !same(initialConfig, { php_version: configPhp.value, flavor: configFlavor.value, letsencrypt: configSsl.checked }),
    body: () => ({
      ...(configPhp.value !== initialConfig.php_version ? { php_version: configPhp.value } : {}),
      ...(configFlavor.value !== initialConfig.flavor ? { flavor: configFlavor.value } : {}),
      ...(configSsl.checked !== initialConfig.letsencrypt ? { letsencrypt: configSsl.checked ? "default" : "off" } : {}),
    }),
    path: `/api/sites/${encodedDomain}/config`, method: "POST",
  });

  preflight.addEventListener("click", async (event) => {
    try {
      await withBusy(event.currentTarget, async () => {
        const result = await api(`/api/sites/${encodedDomain}/ssl/preflight`, { method: "POST", body: {}, signal: ctx.signal });
        if (ctx.signal.aborted) return;
        sslStatus.replaceChildren(el("div", { class: `alert ${result.passed ? "alert-success" : "alert-warning"} mb-0` },
          el("strong", { text: result.passed ? "Preflight passed. " : "Preflight needs attention. " }),
          el("span", { text: result.message || "No preflight message." }),
          el("div", { class: "small mt-2", text: [result.mode, ...(result.a_records || []), ...(result.aaaa_records || [])].filter(Boolean).join(" · ") })));
      });
    } catch (failed) {
      if (!ctx.signal.aborted) sslStatus.replaceChildren(error(`Unable to check SSL preflight: ${failed.message}`));
    }
  });

  configSsl.addEventListener("change", async () => {
    if (configSsl.checked) return;
    const confirmed = await confirmAction({
      title: "Disable Let's Encrypt?", message: "The site will stop renewing its certificate.", confirmLabel: "Disable SSL",
    });
    if (ctx.signal.aborted) return;
    if (!confirmed) configSsl.checked = true;
    invalidatePreview();
  });

  const phpBody = el("div", { class: "text-secondary", text: "Loading PHP settings…" });
  const phpCard = card("PHP", phpBody);
  const cacheBody = el("div", { class: "text-secondary", text: "Loading cache settings…" });
  const cacheCard = card("Cache", cacheBody);
  const nginxBody = el("div", { class: "text-secondary", text: "Loading nginx snippet…" });
  const nginxCard = card("Vhost", nginxBody);
  const securityBody = el("div", { class: "text-secondary", text: "Loading security settings…" });
  const securityCard = card("Security", securityBody);
  const dangerProgress = progressList();
  const deleteButton = el("button", { class: "btn btn-danger", type: "button", text: "Delete site" });
  const dangerCard = card("Danger zone", el("div", {},
    el("p", { class: "text-secondary", text: "Deletes the site and its managed resources after a backup attempt." }), deleteButton, dangerProgress), "border-danger");
  const bar = el("div", { class: "card sticky-bottom mb-3" }, el("div", { class: "card-body d-flex flex-wrap align-items-center gap-2" },
    preview, apply, reset, warningAcknowledgement, actionStatus));
  ctx.mount.append(configCard, phpCard, cacheCard, nginxCard, securityCard, plans, bar, dangerCard);

  async function load(path) {
    try {
      const payload = await api(path, { signal: ctx.signal });
      if (ctx.signal.aborted) return { aborted: true };
      return { payload };
    } catch (failed) {
      if (ctx.signal.aborted) return { aborted: true };
      return { error: failed };
    }
  }

  const [phpLoad, cacheLoad, nginxLoad, securityLoad] = await Promise.all([
    load(`/api/sites/${encodedDomain}/php-settings`), load(`/api/sites/${encodedDomain}/cache`),
    load(`/api/sites/${encodedDomain}/nginx-custom`), load(`/api/sites/${encodedDomain}/security`),
  ]);
  if (ctx.signal.aborted) return;

  if (phpLoad.error) phpBody.replaceChildren(error(`Unable to load PHP settings: ${phpLoad.error.message}`));
  else if (!phpLoad.aborted) {
    const current = phpLoad.payload.settings || {};
    const inputs = Object.fromEntries(PHP_FIELDS.map(([key, label]) => [key, el("input", { class: "form-control", value: current[key] || "", "aria-label": label })]));
    const resetPhp = el("input", { class: "form-check-input", type: "checkbox", id: "reset-php" });
    phpBody.replaceChildren(el("div", { class: "row g-3" },
      PHP_FIELDS.map(([key, label]) => el("div", { class: "col-md-4" }, el("label", { class: "form-label", text: label }), inputs[key])),
      el("div", { class: "col-12" }, el("label", { class: "form-check" }, resetPhp,
        el("span", { class: "form-check-label", text: "Reset PHP settings to defaults" })) )));
    register("php", {
      inputs: [...Object.values(inputs), resetPhp],
      dirty: () => resetPhp.checked || PHP_FIELDS.some(([key]) => inputs[key].value !== (current[key] || "")),
      body: () => ({ ...Object.fromEntries(PHP_FIELDS.filter(([key]) => inputs[key].value !== (current[key] || "")).map(([key]) => [key, inputs[key].value])), ...(resetPhp.checked ? { reset_php: true } : {}) }),
      path: `/api/sites/${encodedDomain}/php-settings`, method: "POST",
    });
  }

  if (cacheLoad.error) cacheBody.replaceChildren(error(`Unable to load cache settings: ${cacheLoad.error.message}`));
  else if (!cacheLoad.aborted) {
    const current = cacheLoad.payload;
    const pageCache = el("select", { class: "form-select", "aria-label": "Page cache" }, (current.page_cache_options || []).map((option) => el("option", { value: option.value, selected: option.value === current.page_cache, text: option.label })));
    const objectCache = el("select", { class: "form-select", "aria-label": "Object cache" }, (current.object_cache_options || []).map((option) => el("option", { value: option.value, selected: option.value === current.object_cache, text: option.label })));
    const byoNote = el("div", { class: "form-text" });
    const purgeResult = el("div", { class: "mt-3" });
    const purge = el("button", { class: "btn btn-outline-secondary btn-sm", type: "button", text: "Purge cache" });
    function showByo() {
      const option = (current.page_cache_options || []).find((item) => item.value === pageCache.value);
      byoNote.textContent = option?.source === "byo" ? "Bring your own plugin: install and maintain this plugin yourself before enabling it." : "";
    }
    showByo();
    pageCache.addEventListener("change", showByo);
    cacheBody.replaceChildren(el("div", { class: "row g-3" },
      el("div", { class: "col-md-6" }, el("label", { class: "form-label", text: "Page cache" }), pageCache, byoNote),
      el("div", { class: "col-md-6" }, el("label", { class: "form-label", text: "Object cache" }), objectCache)),
    el("div", { class: "mt-3" }, purge), purgeResult);
    register("cache", {
      inputs: [pageCache, objectCache],
      dirty: () => pageCache.value !== current.page_cache || objectCache.value !== current.object_cache,
      body: () => ({ ...(pageCache.value !== current.page_cache ? { page_cache: pageCache.value } : {}), ...(objectCache.value !== current.object_cache ? { object_cache: objectCache.value } : {}) }),
      path: `/api/sites/${encodedDomain}/cache`, method: "PUT",
    });
    purge.addEventListener("click", async (event) => {
      try {
        await withBusy(event.currentTarget, async () => {
          const result = await api(`/api/sites/${encodedDomain}/cache/purge`, { method: "POST", body: {}, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          renderPurge(result, false);
        });
      } catch (failed) {
        if (!ctx.signal.aborted) renderPurge(failed.payload || { message: failed.message }, true);
      }
    });
    function renderPurge(result, failed) {
      purgeResult.replaceChildren(el("div", { class: `alert ${failed ? "alert-warning" : "alert-success"} mb-0` },
        el("div", { text: result.message || (failed ? "Cache purge did not complete." : "Cache purge completed.") }),
        el("ul", { class: "mb-0 mt-2" }, (result.outcomes || []).map((outcome) => el("li", { text: `${outcome.cache}: ${outcome.status} — ${outcome.message}` })) )));
    }
  }

  if (nginxLoad.error) nginxBody.replaceChildren(error(`Unable to load nginx snippet: ${nginxLoad.error.message}`));
  else if (!nginxLoad.aborted) {
    const current = nginxLoad.payload.content || "";
    const content = el("textarea", { class: "form-control font-monospace", rows: 12, "aria-label": "Nginx custom snippet", value: current });
    const result = el("div", { class: "mt-3" });
    nginxBody.replaceChildren(content, result);
    register("nginx", {
      inputs: [content], dirty: () => content.value !== current, body: () => ({ content: content.value }),
      path: `/api/sites/${encodedDomain}/nginx-custom`, method: "PUT", result,
    });
  }

  if (securityLoad.error) securityBody.replaceChildren(error(`Unable to load security settings: ${securityLoad.error.message}`));
  else if (!securityLoad.aborted) {
    const current = securityLoad.payload;
    const denyIps = el("textarea", { class: "form-control font-monospace", rows: 5, "aria-label": "Denied IPs or CIDRs (one per line)", value: lines(current.deny_ips) });
    const denyError = el("div", { class: "invalid-feedback d-block d-none" });
    const uaBlocks = el("textarea", { class: "form-control", rows: 5, "aria-label": "Blocked user agents (one per line)", value: lines(current.ua_blocks) });
    const authEnabled = el("input", { class: "form-check-input", type: "checkbox", checked: current.basic_auth?.enabled });
    // The server sends `username: null` when basic auth was never configured,
    // and an empty input reads as "". Comparing those two directly marks the
    // whole security section dirty on every load, which sends an untouched
    // security PUT alongside any unrelated edit -- i.e. a PHP change would
    // rewrite the site's security config from whatever the form happens to hold.
    const currentUsername = current.basic_auth?.username || "";
    const authUsername = el("input", { class: "form-control", value: currentUsername, "aria-label": "Basic auth username" });
    const authPassword = el("input", { class: "form-control", type: "password", autocomplete: "new-password", "aria-label": "New basic auth password" });
    const cloudflareOnly = el("input", { class: "form-check-input", type: "checkbox", checked: current.cloudflare_only });
    const loginRate = el("input", { class: "form-check-input", type: "checkbox", checked: current.login_rate_limit });
    const fail2ban = el("input", { class: "form-check-input", type: "checkbox", checked: current.fail2ban });
    const note = current.trusted_edge_error ? el("div", { class: "alert alert-info", text: current.trusted_edge_error }) : null;
    securityBody.replaceChildren(note, el("div", { class: "row g-3" },
      el("div", { class: "col-md-6" }, el("label", { class: "form-label", text: "Denied IPs or CIDRs (one per line)" }), denyIps, denyError),
      el("div", { class: "col-md-6" }, el("label", { class: "form-label", text: "Blocked user agents (one per line)" }), uaBlocks),
      el("div", { class: "col-md-4" }, el("label", { class: "form-check" }, authEnabled, el("span", { class: "form-check-label", text: "Enable basic auth" }))),
      el("div", { class: "col-md-4" }, el("label", { class: "form-label", text: "Basic auth username" }), authUsername),
      el("div", { class: "col-md-4" }, el("label", { class: "form-label", text: "New basic auth password" }), authPassword),
      el("div", { class: "col-12 d-flex flex-wrap gap-3" },
        el("label", { class: "form-check" }, cloudflareOnly, el("span", { class: "form-check-label", text: "Cloudflare-only access" })),
        el("label", { class: "form-check" }, loginRate, el("span", { class: "form-check-label", text: "Limit WordPress login attempts" })),
        el("label", { class: "form-check" }, fail2ban, el("span", { class: "form-check-label", text: "Enable fail2ban login shield" })))));
    function securityBodyPayload() {
      const denied = values(denyIps.value);
      const invalid = denied.map((value, index) => [value, index + 1]).filter(([value]) => !isIpOrCidr(value));
      denyIps.classList.toggle("is-invalid", invalid.length > 0);
      denyError.classList.toggle("d-none", invalid.length === 0);
      denyError.textContent = invalid.length ? `Invalid IP or CIDR on line${invalid.length === 1 ? "" : "s"} ${invalid.map(([, line]) => line).join(", ")}.` : "";
      if (invalid.length) throw new Error("Correct invalid denied IP entries before previewing.");
      const basic = { enabled: authEnabled.checked, username: authUsername.value };
      if (authPassword.value) basic.password = authPassword.value;
      return {
        ...(same(denied, current.deny_ips) ? {} : { deny_ips: denied }),
        ...(same(values(uaBlocks.value), current.ua_blocks) ? {} : { ua_blocks: values(uaBlocks.value) }),
        ...(!same({ enabled: authEnabled.checked, username: authUsername.value }, { enabled: Boolean(current.basic_auth?.enabled), username: currentUsername }) || authPassword.value ? { basic_auth: basic } : {}),
        ...(cloudflareOnly.checked !== current.cloudflare_only ? { cloudflare_only: cloudflareOnly.checked } : {}),
        ...(loginRate.checked !== current.login_rate_limit ? { login_rate_limit: loginRate.checked } : {}),
        ...(fail2ban.checked !== current.fail2ban ? { fail2ban: fail2ban.checked } : {}),
      };
    }
    register("security", {
      inputs: [denyIps, uaBlocks, authEnabled, authUsername, authPassword, cloudflareOnly, loginRate, fail2ban],
      dirty: () => !same(values(denyIps.value), current.deny_ips)
        || !same(values(uaBlocks.value), current.ua_blocks)
        || !same({ enabled: authEnabled.checked, username: authUsername.value }, { enabled: Boolean(current.basic_auth?.enabled), username: currentUsername })
        || Boolean(authPassword.value)
        || cloudflareOnly.checked !== current.cloudflare_only
        || loginRate.checked !== current.login_rate_limit
        || fail2ban.checked !== current.fail2ban,
      body: securityBodyPayload, path: `/api/sites/${encodedDomain}/security`, method: "PUT",
    });
  }

  async function requestSection(name, section, dryRun) {
    const body = section.body();
    if (dryRun) body.dry_run = true;
    if (!dryRun && name === "security" && previewWarnings.length) body.acknowledge_warnings = acknowledge.checked;
    const result = await api(section.path, { method: section.method, body, signal: ctx.signal });
    if (ctx.signal.aborted) return null;
    return result;
  }

  preview.addEventListener("click", async (event) => {
    try {
      await withBusy(event.currentTarget, async () => {
        const dirty = dirtyEntries();
        const rendered = [];
        let warnings = [];
        for (const [name, section] of dirty) {
          const result = await requestSection(name, section, true);
          if (ctx.signal.aborted) return;
          warnings = warnings.concat(result.warnings || []);
          rendered.push(card(`${name[0].toUpperCase() + name.slice(1)} plan`, changeList(result)));
        }
        previewWarnings = warnings;
        warningAcknowledgement.classList.toggle("d-none", warnings.length === 0);
        if (warnings.length) rendered.push(el("div", { class: "alert alert-warning" }, el("strong", { text: "Warnings require acknowledgement before applying." }),
          el("ul", { class: "mb-0 mt-2" }, warnings.map((warning) => el("li", { text: String(warning) })) )));
        plans.replaceChildren(...rendered);
        previewValid = true;
        actionStatus.textContent = "Preview is current.";
        syncActions();
      });
    } catch (failed) {
      if (!ctx.signal.aborted) {
        plans.replaceChildren(error(`Unable to preview changes: ${failed.message}`));
        previewValid = false;
        syncActions();
      }
    }
  });

  apply.addEventListener("click", async (event) => {
    try {
      await withBusy(event.currentTarget, async () => {
        const dirty = dirtyEntries();
        for (const [name, section] of dirty) {
          const result = await requestSection(name, section, false);
          if (ctx.signal.aborted) return;
          if (result.job_id) {
            const progress = progressList();
            plans.append(card(`${name[0].toUpperCase() + name.slice(1)} progress`, progress));
            const job = await pollJob(result.job_id, { signal: ctx.signal, onStep: (steps) => {
              if (!ctx.signal.aborted) progress.replaceChildren(...steps.map((step) => el("li", { class: "list-group-item", text: step.message || step.name || step.action || String(step) })));
            } });
            if (ctx.signal.aborted) return;
            if (job.state !== "succeeded") throw new Error(job.error || `${name} update failed`);
          }
          if (section.result && result.nginx_test_output) section.result.replaceChildren(el("pre", { class: "log-output mb-0", text: result.nginx_test_output }));
        }
        actionStatus.textContent = "Changes applied.";
        previewValid = false;
        syncActions();
        toast("Settings changes applied.");
      });
    } catch (failed) {
      if (!ctx.signal.aborted) {
        const nginx = sections.get("nginx");
        if (nginx?.result && failed.payload?.nginx_test_output) nginx.result.replaceChildren(el("pre", { class: "log-output mb-0", text: failed.payload.nginx_test_output }));
        actionStatus.textContent = `Apply failed: ${failed.message}`;
        toast(`Unable to apply settings: ${failed.message}`, true);
      }
    }
  });

  reset.addEventListener("click", () => {
    if (!ctx.signal.aborted) navigate(`/site/${encodedDomain}/settings`, { replace: true });
  });

  deleteButton.addEventListener("click", async (event) => {
    // confirmAction hands back exactly what the operator typed, and the server
    // gates on it matching the domain. Forward that string; never rebuild it
    // from the domain we already have.
    const typed = await confirmAction({
      title: `Delete ${domain}?`, message: "This permanently deletes the managed site.", confirmLabel: "Delete site", keyword: domain,
    });
    if (ctx.signal.aborted || typed !== domain) return;
    try {
      await withBusy(event.currentTarget, async () => {
        const result = await api(`/api/sites/${encodedDomain}`, { method: "DELETE", body: { confirm: typed }, signal: ctx.signal });
        if (ctx.signal.aborted) return;
        const job = await pollJob(result.job_id, { signal: ctx.signal, onStep: (steps) => {
          if (!ctx.signal.aborted) dangerProgress.replaceChildren(...steps.map((step) => el("li", { class: "list-group-item", text: step.message || step.name || step.action || String(step) })));
        } });
        if (ctx.signal.aborted) return;
        if (job.state !== "succeeded") throw new Error(job.error || "Site deletion failed.");
        await navigate("/sites");
      });
    } catch (failed) {
      if (!ctx.signal.aborted) {
        dangerProgress.replaceChildren(error(`Unable to delete site: ${failed.message}`));
        toast(`Unable to delete site: ${failed.message}`, true);
      }
    }
  });

  syncActions();
}
