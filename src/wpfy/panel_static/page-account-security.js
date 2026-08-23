/* Account security: password, second factor, and signed-in sessions.
 *
 * Everything on this page acts on the caller's own account and nothing else —
 * there is no cross-account power here to gate behind a confirm keyword, so
 * the guards are proof-of-knowledge instead: the current password for a
 * change, password plus a live code for un-enrolling the second factor.
 */

import { registerPage, el, api, toast, withBusy, copyText, formatTime, emptyRow, confirmAction } from "./panel.js";

const MIN_PASSWORD_LENGTH = 12;

function card(title, subtitle, ...body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header d-block" },
      el("h3", { class: "card-title mb-0", text: title }),
      subtitle ? el("p", { class: "text-secondary mb-0 small", text: subtitle }) : null),
    el("div", { class: "card-body" }, body));
}

function field(labelText, control, hint = "") {
  return el("div", { class: "mb-3" },
    el("label", { class: "form-label", for: control.id, text: labelText }), control,
    hint ? el("div", { class: "form-hint", text: hint }) : null);
}

function danger(message) {
  return el("div", { class: "text-danger", role: "alert", text: message });
}

registerPage("account-security", async (ctx) => {
  ctx.header({ icon: "shield-lock",
    title: "Security",
    subtitle: "Password, two-factor authentication, and signed-in sessions",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "Security"]],
  });

  const passwordMount = el("div", {});
  const totpMount = el("div", {});
  const sessionsMount = el("div", {});
  ctx.mount.append(passwordMount, totpMount, sessionsMount);

  /* ---- change password ---- */

  function renderPasswordCard() {
    const current = el("input", {
      id: "acctsec-current-password", class: "form-control", type: "password",
      autocomplete: "current-password",
    });
    const next = el("input", {
      id: "acctsec-new-password", class: "form-control", type: "password",
      autocomplete: "new-password",
    });
    const confirm = el("input", {
      id: "acctsec-confirm-password", class: "form-control", type: "password",
      autocomplete: "new-password",
    });
    const change = el("button", { class: "btn btn-primary", type: "button", text: "Change password" });
    const feedback = el("div", { class: "mt-3", "aria-live": "polite" });

    change.addEventListener("click", async () => {
      feedback.replaceChildren();
      if (next.value.length < MIN_PASSWORD_LENGTH) {
        feedback.replaceChildren(danger("The new password must be at least 12 characters."));
        next.focus();
        return;
      }
      if (next.value !== confirm.value) {
        feedback.replaceChildren(danger("The two new passwords do not match."));
        confirm.focus();
        return;
      }
      try {
        await withBusy(change, async () => {
          await api("/api/auth/password", {
            method: "POST",
            body: { current_password: current.value, new_password: next.value },
            signal: ctx.signal,
          });
          if (ctx.signal.aborted) return;
          current.value = "";
          next.value = "";
          confirm.value = "";
          toast("Password changed.");
        });
      } catch (failed) {
        if (ctx.signal.aborted) return;
        // The contract reserves 401 for "current password did not match". The
        // shared transport cannot yet tell that apart from a dead session and
        // answers both itself, so this branch records the intended wording for
        // the moment the distinction reaches the client.
        feedback.replaceChildren(danger(failed.status === 401 ? "Current password is incorrect." : failed.message));
      }
    });

    passwordMount.replaceChildren(card("Change password", "Prove the current one, then pick a new one",
      el("div", { class: "row g-2" },
        el("div", { class: "col-md-4" }, field("Current password", current)),
        el("div", { class: "col-md-4" }, field("New password", next, "At least 12 characters.")),
        el("div", { class: "col-md-4" }, field("Confirm new password", confirm))),
      el("div", { class: "btn-list" }, change),
      feedback));
  }

  renderPasswordCard();

  /* ---- two-factor authentication ---- */

  async function refreshTotp() {
    try {
      const me = await api("/api/auth/me", { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      if (Boolean(me.totp_enabled)) renderTotpDisable();
      else renderTotpIdle();
    } catch (error) {
      if (!ctx.signal.aborted) {
        totpMount.replaceChildren(card("Two-factor authentication", "",
          el("div", { class: "alert alert-danger mb-0", role: "alert", text: `Unable to load your second-factor status: ${error.message}` })));
      }
    }
  }

  function renderTotpIdle() {
    const begin = el("button", { class: "btn btn-primary", type: "button", text: "Begin enrollment" });
    begin.addEventListener("click", async () => {
      try {
        await withBusy(begin, async () => {
          const payload = await api("/api/auth/totp", { method: "POST", body: {}, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          renderEnrollment(payload.secret || "", payload.uri || "");
        });
      } catch (failed) {
        if (!ctx.signal.aborted) toast(failed.message, true);
      }
    });
    totpMount.replaceChildren(card("Two-factor authentication",
      "Off — a second factor is required before this panel can be published to the internet",
      el("p", { class: "text-secondary", text: "Add a time-based one-time password from any authenticator app. Sign-in will ask for a code from it after your password." }),
      begin));
  }

  function renderEnrollment(secret, uri) {
    const qrBox = el("div", { class: "setup-qr mb-3", role: "img", "aria-label": "Second-factor QR code" });
    if (uri && typeof QRCode !== "undefined") {
      // The same vendored renderer the setup flow uses; it draws an image or
      // canvas into the container at a size .setup-qr reserves.
      new QRCode(qrBox, { text: uri, width: 220, height: 220, correctLevel: QRCode.CorrectLevel.M });
    } else {
      qrBox.append(el("p", { class: "text-secondary small text-center px-2", text: "QR unavailable — enter the secret below by hand." }));
    }

    const secretInput = el("input", {
      id: "acctsec-totp-secret", class: "form-control font-monospace", type: "text",
      readonly: true, value: secret, "aria-label": "Secret",
    });
    const copy = el("button", { class: "btn btn-sm btn-link", type: "button", text: "Copy secret" });
    copy.addEventListener("click", async () => {
      try {
        await copyText(secret);
        copy.textContent = "Copied";
      } catch {
        copy.textContent = "Copy failed";
      }
      setTimeout(() => { copy.textContent = "Copy secret"; }, 2000);
    });

    const code = el("input", {
      id: "acctsec-totp-code", class: "form-control", type: "text",
      inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6",
    });
    const verify = el("button", { class: "btn btn-primary", type: "button", text: "Verify and enable" });
    const cancel = el("button", { class: "btn btn-link", type: "button", text: "Cancel" });
    const feedback = el("div", { class: "mt-3", "aria-live": "polite" });

    cancel.addEventListener("click", async () => {
      // Dropping the displayed secret client-side is not enough: the server
      // keeps the pending enrollment until its TTL expires, and a later Begin
      // would fail with "the setup TOTP secret has already been disclosed".
      // Wait for the cancellation to land -- if it fails, keep the enroll
      // view so the operator can retry instead of hitting a dead secret.
      try {
        await withBusy(cancel, async () => {
          await api("/api/auth/totp/pending", { method: "DELETE", signal: ctx.signal });
        });
      } catch (failed) {
        if (!ctx.signal.aborted) feedback.replaceChildren(danger(`Cancel failed: ${failed.message}`));
        return;
      }
      if (ctx.signal.aborted) return;
      renderTotpIdle();
    });
    verify.addEventListener("click", async () => {
      feedback.replaceChildren();
      const value = code.value.trim();
      if (!/^[0-9]{6}$/.test(value)) {
        feedback.replaceChildren(danger("Enter the six-digit code from your authenticator."));
        code.focus();
        return;
      }
      try {
        await withBusy(verify, async () => {
          await api("/api/auth/totp", { method: "POST", body: { code: value }, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast("Two-factor authentication enabled.");
          await refreshTotp();
        });
      } catch (failed) {
        if (!ctx.signal.aborted) feedback.replaceChildren(danger(failed.message));
      }
    });

    totpMount.replaceChildren(card("Two-factor authentication",
      "Scan, store, verify — the factor activates only after one valid code",
      qrBox,
      el("div", { class: "mb-3" },
        el("label", { class: "form-label", for: "acctsec-totp-secret", text: "Secret" }), secretInput,
        el("div", {}, copy),
        el("small", { class: "text-secondary d-block", text: "Can't scan the code? Enter this key into your authenticator by hand." })),
      el("div", { class: "mb-3" }, field("Authenticator code", code)),
      el("div", { class: "btn-list" }, verify, cancel),
      feedback));
  }

  function renderTotpDisable() {
    const password = el("input", {
      id: "acctsec-totp-password", class: "form-control", type: "password",
      autocomplete: "current-password",
    });
    const code = el("input", {
      id: "acctsec-totp-disable-code", class: "form-control", type: "text",
      inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6",
    });
    const disable = el("button", { class: "btn btn-danger", type: "button", text: "Disable two-factor" });
    const feedback = el("div", { class: "mt-3", "aria-live": "polite" });

    disable.addEventListener("click", async () => {
      feedback.replaceChildren();
      if (!password.value) {
        feedback.replaceChildren(danger("Enter your password to confirm."));
        password.focus();
        return;
      }
      if (!/^[0-9]{6}$/.test(code.value.trim())) {
        feedback.replaceChildren(danger("Enter the six-digit code from your authenticator."));
        code.focus();
        return;
      }
      try {
        await withBusy(disable, async () => {
          await api("/api/auth/totp", {
            method: "DELETE",
            body: { password: password.value, current_totp: code.value.trim() },
            signal: ctx.signal,
          });
          if (ctx.signal.aborted) return;
          toast("Two-factor authentication disabled.");
          await refreshTotp();
        });
      } catch (failed) {
        if (!ctx.signal.aborted) feedback.replaceChildren(danger(failed.message));
      }
    });

    totpMount.replaceChildren(card("Two-factor authentication", "On — sign-in asks for a code after your password",
      el("p", { class: "text-secondary", text: "Disabling removes the second factor. You can enrol again later, but publishing this panel to the internet requires one." }),
      el("div", { class: "row g-2" },
        el("div", { class: "col-md-6" }, field("Password", password)),
        el("div", { class: "col-md-6" }, field("Current code", code))),
      el("div", { class: "btn-list" }, disable),
      feedback));
  }

  /* ---- active sessions ---- */

  async function refreshSessions() {
    try {
      const payload = await api("/api/auth/sessions", { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      renderSessions(Array.isArray(payload.sessions) ? payload.sessions : []);
    } catch (failed) {
      if (!ctx.signal.aborted) {
        sessionsMount.replaceChildren(card("Active sessions", "",
          el("div", { class: "alert alert-danger mb-0", role: "alert", text: `Unable to load sessions: ${failed.message}` })));
      }
    }
  }

  function renderSessions(sessions) {
    const rows = sessions.map((entry) => {
      const id = String(entry.id ?? "");
      const revoke = el("button", { class: "btn btn-sm btn-outline-danger", type: "button", text: "Revoke" });
      revoke.addEventListener("click", async () => {
        // Revoking is mild — the browser can sign back in — but it ends live
        // access, so it gets the panel's standard confirm rather than a bare
        // click, and the message differs for the session being used right now.
        const confirmed = await confirmAction({
          title: "Revoke this session?",
          message: entry.current
            ? "This is the browser you are using. Revoking it signs you out."
            : "That browser is signed out on its next request.",
          confirmLabel: "Revoke",
        });
        if (ctx.signal.aborted || !confirmed) return;
        try {
          await withBusy(revoke, async () => {
            await api(`/api/auth/sessions/${encodeURIComponent(id)}`, { method: "DELETE", signal: ctx.signal });
            if (ctx.signal.aborted) return;
            toast("Session revoked.");
            if (entry.current) {
              // Revoking this browser's own session is a sign-out. The server
              // has already dropped it, so the next authorised call walks the
              // shell's single 401 path — state cleared, sign-in gate shown —
              // exactly what an expired session does.
              await api("/api/auth/me").catch(() => {});
              return;
            }
            await refreshSessions();
          });
        } catch (failed) {
          if (!ctx.signal.aborted) toast(failed.message, true);
        }
      });
      return el("tr", {},
        el("td", { text: formatTime(entry.created) }),
        el("td", { text: formatTime(entry.last_seen) }),
        el("td", {}, entry.current ? el("span", { class: "badge bg-green-lt text-green", text: "Current" }) : null),
        el("td", { class: "text-end" }, revoke));
    });

    sessionsMount.replaceChildren(card("Active sessions", "Every browser signed in as this account",
      el("div", { class: "table-responsive" },
        el("table", { class: "table table-vcenter card-table mb-0" },
          el("thead", {}, el("tr", {},
            el("th", { scope: "col", text: "Created" }),
            el("th", { scope: "col", text: "Last seen" }),
            el("th", { scope: "col", text: "" }),
            el("th", { scope: "col", class: "text-end", text: "" }))),
          el("tbody", {}, sessions.length ? rows : [emptyRow(4, "clock", "No active sessions.")])))));
  }

  await refreshTotp();
  await refreshSessions();
});
