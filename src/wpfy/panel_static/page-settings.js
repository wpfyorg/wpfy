/* Panel settings: who can reach this panel, and what it reports home.
 *
 * Exposure publishes the control panel for this whole host to the public
 * internet, so it sits in its own card with its preconditions written out. The
 * server enforces all of them -- named-user login, a TOTP-enabled user, a
 * passing DNS preflight, a typed domain confirmation -- and refuses with a
 * message rather than a code. Those messages are rendered verbatim: the server
 * knows why it said no, and paraphrasing it here would only ever be wrong.
 */

import { registerPage, el, api, toast, confirmAction, withBusy, formatTime } from "./panel.js";

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
    subtitle: "Panel exposure and telemetry",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "Settings"]],
  });

  const exposureMount = el("div", {});
  const telemetryMount = el("div", {});
  ctx.mount.append(exposureMount, telemetryMount);

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
        detail: "The server refuses unless a named user is signed in, a TOTP-enabled user exists, and DNS for this domain already points here.",
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
        message: "The public route is removed. The panel stays reachable on loopback and over an SSH tunnel.",
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
      exposed ? "This panel is reachable from the internet" : "This panel is reachable on loopback only",
      el("div", { class: "d-flex flex-wrap align-items-center gap-2 mb-3" },
        el("span", {
          class: `badge ${exposed ? "bg-yellow-lt text-yellow" : "bg-green-lt text-green"}`,
          text: exposed ? "Published" : "Loopback only",
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
      el("p", { class: "text-secondary small", text: "Publishing requires all of: a named user signed in (not the run token), at least one user with TOTP enabled, and DNS for the domain already resolving to this host. The panel checks each one and refuses with the reason if any fails." }),
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

  await refresh();
});
