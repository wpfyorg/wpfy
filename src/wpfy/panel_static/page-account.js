/* Account settings: the signed-in operator's own profile and this browser's
 * appearance preference.
 *
 * Deliberately small. The profile fields mirror what first-run setup collects
 * minus the credentials — username and password changes live on the Security
 * page, because changing who you are and proving who you are are different
 * acts. Appearance is browser-local by design: this panel serves one host's
 * operators through one account at a time in front of the screen, and a theme
 * is a property of the eyeball, not of the server.
 */

import { registerPage, el, api, toast, withBusy } from "./panel.js";

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

registerPage("account", async (ctx) => {
  ctx.header({ icon: "users",
    title: "Account settings",
    subtitle: "Your profile and this browser's appearance",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "Account settings"]],
  });

  const profileMount = el("div", {});
  const appearanceMount = el("div", {});
  ctx.mount.append(profileMount, appearanceMount);

  /* ---- profile ---- */

  function renderProfile(me) {
    const firstName = el("input", {
      id: "acct-first-name", class: "form-control", type: "text",
      autocomplete: "given-name", value: me.first_name || "",
    });
    const lastName = el("input", {
      id: "acct-last-name", class: "form-control", type: "text",
      autocomplete: "family-name", value: me.last_name || "",
    });
    const email = el("input", {
      id: "acct-email", class: "form-control", type: "email",
      autocomplete: "email", value: me.email || "",
    });
    const feedback = el("div", { class: "mt-3", "aria-live": "polite" });
    const save = el("button", { class: "btn btn-primary", type: "button", text: "Save profile" });

    save.addEventListener("click", async () => {
      feedback.replaceChildren();
      const body = {
        first_name: firstName.value.trim(),
        last_name: lastName.value.trim(),
        email: email.value.trim(),
      };
      if (!body.email) {
        feedback.replaceChildren(danger("An email address is required."));
        email.focus();
        return;
      }
      try {
        await withBusy(save, async () => {
          // Echo the stored record back into the fields: the server may
          // normalise what was typed, and the form should show what was
          // saved rather than what was sent.
          const payload = await api("/api/auth/profile", { method: "PUT", body, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          const user = payload.user || {};
          firstName.value = user.first_name ?? body.first_name;
          lastName.value = user.last_name ?? body.last_name;
          email.value = user.email ?? body.email;
          toast("Profile saved.");
        });
      } catch (failed) {
        if (!ctx.signal.aborted) feedback.replaceChildren(danger(failed.message));
      }
    });

    profileMount.replaceChildren(card("Profile", "The name and address recorded for your account",
      el("div", { class: "row g-2" },
        el("div", { class: "col-md-4" }, field("First name", firstName)),
        el("div", { class: "col-md-4" }, field("Last name", lastName)),
        el("div", { class: "col-md-4" }, field("Email", email))),
      el("div", { class: "btn-list" }, save),
      feedback));
  }

  try {
    const me = await api("/api/auth/me", { signal: ctx.signal });
    if (!ctx.signal.aborted) renderProfile(me);
  } catch (error) {
    if (!ctx.signal.aborted) {
      profileMount.replaceChildren(card("Profile", "",
        el("div", { class: "alert alert-danger mb-0", role: "alert", text: `Unable to load your profile: ${error.message}` })));
    }
  }

  /* ---- appearance ---- */

  // The shell owns theming: #theme-control's buttons persist the choice under
  // "wpfy-panel-theme" and flip data-theme/data-bs-theme on <html>. Clicking
  // the matching button reuses that wiring instead of duplicating it, and
  // keeps the header menu's radio group in step with this select. The button
  // is part of the static shell, so it exists wherever this page renders; the
  // localStorage write is only a fallback that defers to the next boot.
  const stored = localStorage.getItem("wpfy-panel-theme") || "auto";
  const theme = el("select", { id: "acct-theme", class: "form-select" },
    el("option", { value: "auto", selected: stored === "auto", text: "System" }),
    el("option", { value: "light", selected: stored === "light", text: "Light" }),
    el("option", { value: "dark", selected: stored === "dark", text: "Dark" }));
  theme.addEventListener("change", () => {
    const button = document.querySelector(`#theme-control button[data-theme="${theme.value}"]`);
    if (button) button.click();
    else localStorage.setItem("wpfy-panel-theme", theme.value);
  });

  appearanceMount.replaceChildren(card("Appearance", "Saved in this browser only — it is not an account setting",
    el("div", { class: "row" },
      el("div", { class: "col-md-4" },
        field("Theme", theme, "System follows your device's light or dark setting.")))));
});
