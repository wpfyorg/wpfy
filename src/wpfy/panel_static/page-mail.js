/* SMTP: the mail transport this host sends through.
 *
 * Deliberately named SMTP rather than Mail or Notifications. Nothing in wpfy
 * sends mail on its own today -- `smtp.send_test_message` has exactly one
 * caller, the explicit test below -- so a page promising alerts would be
 * describing software that does not exist. It says what it is, and what it
 * will be used for once there is something to send.
 *
 * The password is write-only. A blank field on a configured transport keeps the
 * stored one; only a typed value replaces it.
 */

import { registerPage, el, api, toast, confirmAction, withBusy } from "./panel.js";

const TLS_MODES = [
  ["starttls", "STARTTLS (usually port 587)"],
  ["ssl", "Implicit TLS (usually port 465)"],
  ["none", "No encryption"],
];

function card(title, subtitle, ...body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header d-block" },
      el("h3", { class: "card-title mb-0", text: title }),
      subtitle ? el("p", { class: "text-secondary mb-0 small", text: subtitle }) : null),
    el("div", { class: "card-body" }, body));
}

function field(label, control, hint = "") {
  return el("div", { class: "col-md-6" },
    el("label", { class: "form-label", for: control.id, text: label }),
    control,
    hint ? el("small", { class: "form-hint", text: hint }) : null);
}

registerPage("notifications", async (ctx) => {
  ctx.header({ icon: "mail",
    title: "SMTP",
    subtitle: "The SMTP transport for this host",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "SMTP"]],
  });

  const configMount = el("div", {});
  ctx.mount.append(configMount);

  async function refresh() {
    try {
      const payload = await api("/api/notifications/smtp", { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      render(payload);
    } catch (error) {
      if (ctx.signal.aborted) return;
      configMount.replaceChildren(card("SMTP", "",
        el("div", { class: "alert alert-danger mb-0", role: "alert", text: `Unable to read the SMTP configuration: ${error.message}` })));
    }
  }

  function render(payload) {
    const configured = Boolean(payload.configured);
    const config = payload.config || {};
    const host = el("input", { id: "mail-host", class: "form-control", type: "text", autocomplete: "off", value: config.host || "" });
    const port = el("input", { id: "mail-port", class: "form-control", type: "number", min: 1, max: 65535, value: config.port || 587 });
    const sender = el("input", { id: "mail-sender", class: "form-control", type: "email", autocomplete: "off", value: config.sender || "" });
    const username = el("input", { id: "mail-username", class: "form-control", type: "text", autocomplete: "off", value: config.username || "" });
    const password = el("input", {
      id: "mail-password", class: "form-control", type: "password", autocomplete: "new-password",
      placeholder: configured ? "Leave blank to keep the stored password" : "",
    });
    const tls = el("select", { id: "mail-tls", class: "form-select" },
      TLS_MODES.map(([value, label]) => el("option", { value, selected: value === (config.tls || "starttls"), text: label })));

    const save = el("button", { class: "btn btn-primary", type: "button", text: configured ? "Save changes" : "Save transport" });
    save.addEventListener("click", async () => {
      const portValue = Number.parseInt(port.value, 10);
      if (!Number.isFinite(portValue) || portValue < 1 || portValue > 65535) {
        toast("Enter a port between 1 and 65535.", true);
        return;
      }
      for (const [label, value] of [["a host", host.value.trim()], ["a sender address", sender.value.trim()]]) {
        if (!value) {
          toast(`Enter ${label}.`, true);
          return;
        }
      }
      const body = {
        host: host.value.trim(), port: portValue, sender: sender.value.trim(),
        username: username.value.trim(), tls: tls.value,
      };
      if (password.value) body.password = password.value;
      else if (!configured) {
        toast("Enter the SMTP password.", true);
        return;
      }
      if (body.tls === "none") {
        const confirmed = await confirmAction({
          title: "Send mail unencrypted?",
          message: "With no encryption the SMTP password and every message body cross the network in the clear.",
          confirmLabel: "Save anyway",
        });
        if (ctx.signal.aborted || !confirmed) return;
      }
      try {
        await withBusy(save, async () => {
          await api("/api/notifications/smtp", { method: "PUT", body, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast("SMTP transport saved.");
          password.value = "";
          await refresh();
        });
      } catch (error) {
        if (!ctx.signal.aborted) toast(error.message, true);
      }
    });

    const recipient = el("input", { id: "mail-test-recipient", class: "form-control", type: "email", placeholder: "you@example.com", autocomplete: "off" });
    const testResult = el("div", { class: "mt-2" });
    const test = el("button", { class: "btn btn-outline-primary", type: "button", text: "Send test message" });
    test.addEventListener("click", async () => {
      const value = recipient.value.trim();
      if (!value) {
        toast("Enter a recipient address.", true);
        return;
      }
      try {
        await withBusy(test, async () => {
          const payloadOut = await api("/api/notifications/smtp/test", {
            method: "POST", body: { recipient: value }, signal: ctx.signal,
          });
          if (ctx.signal.aborted) return;
          testResult.replaceChildren(el("div", {
            class: "alert alert-success mb-0", role: "status",
            text: payloadOut.message || `Test message sent to ${value}.`,
          }));
        });
      } catch (error) {
        if (!ctx.signal.aborted) {
          testResult.replaceChildren(el("div", { class: "alert alert-danger mb-0", role: "alert", text: error.message }));
        }
      }
    });

    const clear = el("button", { class: "btn btn-outline-danger", type: "button", icon: "trash", text: "Remove transport" });
    clear.addEventListener("click", async () => {
      const typed = await confirmAction({
        title: "Remove the SMTP transport?",
        message: "The stored host, credentials and sender are deleted. Anything configured to send through them stops.",
        confirmLabel: "Remove it",
        keyword: "remove",
      });
      if (ctx.signal.aborted || typed !== "remove") return;
      try {
        await withBusy(clear, async () => {
          await api("/api/notifications/smtp", { method: "DELETE", body: {}, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast("SMTP transport removed.");
          await refresh();
        });
      } catch (error) {
        if (!ctx.signal.aborted) toast(error.message, true);
      }
    });

    const statusLines = Array.isArray(payload.status) ? payload.status : [];

    configMount.replaceChildren(
      card("Transport", configured ? "Configured" : "Not configured",
        el("div", { class: "alert alert-info", role: "status" },
          el("strong", { text: "wpfy does not send mail on its own yet. " }),
          el("span", { text: "This transport is here so a test send can prove the credentials work, and so alerting has something to send through once it exists." })),
        el("div", { class: "row g-3" },
          field("Host", host),
          field("Port", port),
          field("Sender address", sender, "The From: address on messages this host sends."),
          field("Username", username),
          field("Password", password, configured
            ? "Stored and never shown again. Leave blank to keep it; enter a value to replace it."
            : "Stored and never shown again."),
          field("Encryption", tls)),
        el("div", { class: "d-flex flex-wrap gap-2 mt-3" }, save, configured ? clear : null)),
      configured
        ? card("Test send", "Proves the credentials and the route, end to end",
          el("div", { class: "row g-2 align-items-end" },
            el("div", { class: "col-md-6" },
              el("label", { class: "form-label", for: "mail-test-recipient", text: "Recipient" }), recipient),
            el("div", { class: "col-md-auto" }, test)),
          testResult)
        : null,
      statusLines.length
        ? card("Reported status", "", el("pre", { class: "log-output mb-0", text: statusLines.join("\n") }))
        : null);
  }

  await refresh();
});
