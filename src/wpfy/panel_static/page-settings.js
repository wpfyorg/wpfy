/* Panel settings: who can reach this panel, and what it reports home.
 *
 * Exposure publishes the control panel for this whole host to the public
 * internet, so it sits in its own card with its preconditions written out. The
 * server enforces all of them -- a passing DNS preflight and a typed domain
 * confirmation -- and refuses with a message rather than a code. Those messages
 * are rendered verbatim: the server knows why it said no, and paraphrasing it
 * here would only ever be wrong.
 *
 * The panel-access card configures HTTP basic auth on the published route. It
 * renders regardless of exposure state: the credential can be staged before
 * publishing, and whether it is in force is a server answer, never a guess
 * read off the exposure flag. Only the username comes back from the server;
 * the password is write-only and no hash is ever displayed.
 */

import { registerPage, el, api, toast, confirmAction, withBusy, formatTime } from "./panel.js";
import { panelAccessViewModel, panelAccessSaveToast } from "./panel-access-state.js";

function card(title, subtitle, ...body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header d-block" },
      el("h3", { class: "card-title mb-0", text: title }),
      subtitle ? el("p", { class: "text-secondary mb-0 small", text: subtitle }) : null),
    el("div", { class: "card-body" }, body));
}

function factRow(label, value) {
  return [
    el("dt", { class: "col-sm-4 text-secondary", text: label }),
    el("dd", { class: "col-sm-8 font-monospace text-break", text: value === null || value === undefined || value === "" ? "–" : String(value) }),
  ];
}

registerPage("settings", async (ctx) => {
  ctx.header({ icon: "settings",
    title: "Settings",
    subtitle: "Panel exposure, access, and telemetry",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "Settings"]],
  });

  const exposureMount = el("div", {});
  const panelAccessMount = el("div", {});
  const telemetryMount = el("div", {});
  ctx.mount.append(exposureMount, panelAccessMount, telemetryMount);

  async function refresh() {
    try {
      const payload = await api("/api/settings", { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      renderExposure(payload.exposure || {});
      renderTelemetry(payload.telemetry || {});
    } catch (error) {
      if (ctx.signal.aborted) return;
      exposureMount.replaceChildren(card("Settings", "",
        el("div", { class: "alert alert-danger mb-0", role: "alert", text: `Unable to read settings: ${error.message}` })));
    }
  }

  function renderExposure(exposure) {
    const exposed = Boolean(exposure.exposed);
    const domain = el("input", {
      id: "settings-exposure-domain", class: "form-control", type: "text",
      placeholder: "panel.example.com", autocomplete: "off", value: exposure.domain || "",
    });

    const apply = el("button", { class: "btn btn-primary", type: "button", text: exposed ? "Change domain" : "Publish the panel" });
    apply.addEventListener("click", async () => {
      const value = domain.value.trim().toLowerCase();
      if (!value || !value.includes(".") || /[\s/:]/.test(value)) {
        toast("Enter a domain without a scheme, path, or spaces.", true);
        return;
      }
      const typed = await confirmAction({
        title: exposed ? "Change the panel's public domain?" : "Publish this panel to the internet?",
        message: `The panel becomes reachable at https://${value}. Anyone who can resolve that name can reach the login form, and this host's whole control surface sits behind it.`,
        detail: "The server refuses unless DNS for this domain already points here.",
        confirmLabel: exposed ? "Change it" : "Publish it",
        keyword: value,
      });
      if (ctx.signal.aborted || typed !== value) return;
      try {
        await withBusy(apply, async () => {
          // The server gates on `confirm === domain` so the operator has to type
          // the destination they are publishing. Forwarding the value we already
          // hold would satisfy that check for them and reduce it to a click.
          const payload = await api("/api/settings/exposure", {
            method: "POST", body: { domain: value, confirm: typed }, signal: ctx.signal,
          });
          if (ctx.signal.aborted) return;
          toast(payload.message || "Panel exposure updated.");
          await refresh();
        });
      } catch (error) {
        if (!ctx.signal.aborted) toast(error.message, true);
      }
    });

    const disable = el("button", { class: "btn btn-outline-danger", type: "button", icon: "trash", text: "Unpublish" });
    disable.addEventListener("click", async () => {
      const typed = await confirmAction({
        title: "Unpublish the panel?",
        message: "The public Traefik route is removed. The panel stays reachable through its direct bind (loopback, or the host's public address over plain HTTP).",
        confirmLabel: "Unpublish",
        keyword: "unpublish",
      });
      if (ctx.signal.aborted || typed !== "unpublish") return;
      try {
        await withBusy(disable, async () => {
          const payload = await api("/api/settings/exposure", { method: "DELETE", body: {}, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast(payload.message || "Panel unpublished.");
          await refresh();
        });
      } catch (error) {
        if (!ctx.signal.aborted) toast(error.message, true);
      }
    });

    exposureMount.replaceChildren(card(
      "Panel exposure",
      exposed
        ? "This panel is published through Traefik with a TLS certificate"
        : "No Traefik route: the panel answers on its direct bind (HTTP unless self-signed TLS)",
      el("div", { class: "d-flex flex-wrap align-items-center gap-2 mb-3" },
        el("span", {
          class: `badge ${exposed ? "bg-yellow-lt text-yellow" : "bg-green-lt text-green"}`,
          text: exposed ? "Published (TLS)" : "Direct bind",
        }),
        exposed && !exposure.recognised
          ? el("span", { class: "badge bg-red-lt text-red", text: "router not recognised" })
          : null),
      exposed && !exposure.recognised
        ? el("div", { class: "alert alert-warning", role: "status", text: "A router file exists but was not written by this panel. Inspect it before changing anything here." })
        : null,
      el("dl", { class: "row mb-3" },
        ...factRow("Domain", exposure.domain),
        ...factRow("Target", exposure.target_host ? `${exposure.target_host}:${exposure.target_port}` : null),
        ...factRow("Router file", exposure.router_path),
        ...factRow("Systemd service", exposure.service_installed ? "installed" : "not installed")),
      el("p", { class: "text-secondary small", text: "Publishing gives the panel domain a TLS certificate from Let's Encrypt. An optional basic-auth credential can guard the public route on top (see the Basic auth page). DNS for the domain must already resolve to this host; the panel checks and refuses with the reason if it does not." }),
      el("div", { class: "row g-2 align-items-end" },
        el("div", { class: "col-md-6" },
          el("label", { class: "form-label", for: "settings-exposure-domain", text: "Public domain" }), domain),
        el("div", { class: "col-md-auto" }, el("div", { class: "d-flex gap-2" }, apply, exposed ? disable : null)))));
  }

  function renderTelemetry(telemetry) {
    const toggle = el("input", {
      id: "settings-telemetry", class: "form-check-input", type: "checkbox",
      checked: Boolean(telemetry.stored_enabled), disabled: Boolean(telemetry.environment_override),
    });
    toggle.addEventListener("change", async () => {
      try {
        await api("/api/settings/telemetry", { method: "PUT", body: { enabled: toggle.checked }, signal: ctx.signal });
        if (ctx.signal.aborted) return;
        toast(toggle.checked ? "Telemetry enabled." : "Telemetry disabled.");
        await refresh();
      } catch (error) {
        if (ctx.signal.aborted) return;
        // Put the control back where the server says it is, not where the click
        // left it, or the page shows a setting that was never saved.
        toggle.checked = Boolean(telemetry.stored_enabled);
        toast(error.message, true);
      }
    });

    const payload = telemetry.payload && typeof telemetry.payload === "object" ? telemetry.payload : null;

    telemetryMount.replaceChildren(card("Telemetry", "Anonymous usage statistics",
      telemetry.environment_override
        ? el("div", { class: "alert alert-info", role: "status", text: "Telemetry is disabled by an environment variable on this host, which overrides this setting." })
        : null,
      el("label", { class: "form-check form-switch mb-3" }, toggle,
        el("span", { class: "form-check-label", text: "Send anonymous usage statistics" })),
      el("dl", { class: "row mb-3" },
        ...factRow("Effective", telemetry.effective_enabled ? "enabled" : "disabled"),
        ...factRow("Endpoint configured", telemetry.endpoint_configured ? "yes" : "no"),
        ...factRow("Last sent", telemetry.last_sent_at ? formatTime(telemetry.last_sent_at) : "never")),
      payload
        ? el("details", {}, el("summary", { class: "text-secondary", text: "What gets sent" }),
          el("pre", { class: "log-output mt-2 mb-0", text: JSON.stringify(payload, null, 2) }))
        : null));
  }

  function renderPanelAccess(basic) {
    // All state mapping lives in panel-access-state.js (pure, test-covered):
    // badge, subtitle, footer, disable availability and its dialog copy are
    // derived from the server's auth_state answer, never guessed here.
    const vm = panelAccessViewModel(basic);
    const enabled = vm.enabled;
    const fail = (message) => el("div", { class: "text-danger", role: "alert", text: message });
    const username = el("input", {
      id: "settings-panel-access-username", class: "form-control", type: "text",
      autocomplete: "off", value: basic.username || "",
    });
    // Write-only by contract: the server never echoes a password or its hash,
    // so the field starts empty every render.
    const password = el("input", {
      id: "settings-panel-access-password", class: "form-control", type: "password",
      autocomplete: "new-password", placeholder: "Leave blank when disabling",
    });
    const feedback = el("div", { class: "mt-3", "aria-live": "polite" });
    const save = el("button", { class: "btn btn-primary", type: "button", text: enabled ? "Save" : "Enable" });

    save.addEventListener("click", async () => {
      feedback.replaceChildren();
      const name = username.value.trim();
      if (!name) {
        feedback.replaceChildren(fail("A username is required."));
        username.focus();
        return;
      }
      if (!password.value) {
        feedback.replaceChildren(fail(enabled
          ? "Enter the password to set, or use Disable to turn basic auth off."
          : "Enter a password to enable basic auth."));
        password.focus();
        return;
      }
      try {
        await withBusy(save, async () => {
          const payload = await api("/api/settings/basic-auth", {
            method: "PUT", body: { username: name, password: password.value }, signal: ctx.signal,
          });
          if (ctx.signal.aborted) return;
          password.value = "";
          toast(payload.enabled === false
            ? "Panel basic auth is off."
            : panelAccessSaveToast(payload));
          await refreshPanelAccess();
        });
      } catch (failed) {
        if (!ctx.signal.aborted) feedback.replaceChildren(fail(failed.message));
      }
    });

    const disable = el("button", { class: "btn btn-outline-danger", type: "button", text: "Disable" });
    disable.addEventListener("click", async () => {
      const confirmed = await confirmAction({
        title: "Disable panel basic auth?",
        message: vm.disableMessage,
        confirmLabel: "Disable",
      });
      if (ctx.signal.aborted || !confirmed) return;
      try {
        await withBusy(disable, async () => {
          await api("/api/settings/basic-auth", { method: "DELETE", signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast("Panel basic auth disabled.");
          await refreshPanelAccess();
        });
      } catch (failed) {
        if (!ctx.signal.aborted) feedback.replaceChildren(fail(failed.message));
      }
    });

    // Unknown + stored: the backend guarantees a 409 for disable while the
    // router is unattributable, so the action is hidden and the operator is
    // pointed at the actual remedy instead.
    const unknownHint = vm.gated && !vm.disableAvailable
      ? el("p", { class: "text-warning small mb-0", text: "Disable is unavailable until the router is recognizable again. Repair or remove the unrecognized router, then retry." })
      : null;

    panelAccessMount.replaceChildren(card(
      "Panel access",
      vm.subtitle,
      el("div", { class: "d-flex flex-wrap align-items-center gap-2 mb-3" },
        el("span", { class: `badge ${vm.badge.class}`, text: vm.badge.text }),
        vm.gated && basic.username ? el("span", { class: "text-secondary small", text: `User: ${basic.username}` }) : null),
      el("div", { class: "row g-2 align-items-end" },
        el("div", { class: "col-md-5" },
          el("label", { class: "form-label", for: "settings-panel-access-username", text: "Username" }), username),
        el("div", { class: "col-md-5" },
          el("label", { class: "form-label", for: "settings-panel-access-password", text: "Password" }), password),
        el("div", { class: "col-md-auto" }, el("div", { class: "d-flex gap-2" }, save, vm.disableAvailable ? disable : null))),
      feedback,
      unknownHint,
      el("p", { class: "text-secondary small mt-3 mb-0", text: vm.footer })));
  }

  async function refreshPanelAccess() {
    try {
      const payload = await api("/api/settings/basic-auth", { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      renderPanelAccess(payload);
    } catch (error) {
      if (ctx.signal.aborted) return;
      panelAccessMount.replaceChildren(card("Panel access", "",
        el("div", { class: "alert alert-danger mb-0", role: "alert", text: `Unable to read panel access: ${error.message}` })));
    }
  }

  await refresh();
  await refreshPanelAccess();
});
