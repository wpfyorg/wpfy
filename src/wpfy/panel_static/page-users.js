import { registerPage, el, api, confirmAction, withBusy, toast, onPanelEvent, session, emptyRow } from "./panel.js";

function badge(value, good = true) {
  return el("span", { class: `badge ${good ? "bg-green-lt text-green" : "bg-yellow-lt text-yellow"}`, text: value });
}

/* 56 characters do not divide 256, so `byte % 56` hands the first 32 letters a
   higher probability than the rest. The bias is small, but this generates panel
   admin passwords, and rejection sampling costs one loop. */
function passwordValue(length = 24) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const limit = Math.floor(256 / alphabet.length) * alphabet.length;
  const out = [];
  while (out.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length))) {
      if (byte < limit && out.length < length) out.push(alphabet[byte % alphabet.length]);
    }
  }
  return out.join("");
}

function field(label, control, hint = "") {
  const id = control.id;
  return el("div", { class: "mb-3" },
    el("label", { class: "form-label", for: id, text: label }), control,
    hint ? el("div", { class: "form-hint", text: hint }) : null);
}

function selectedSites(select) {
  return [...select.selectedOptions].map((option) => option.value);
}

registerPage("users", async (ctx) => {
  const tableBody = el("tbody", {});
  const error = el("div", { class: "mt-3" });
  const editor = el("div", { class: "mt-3" });
  const card = el("div", { class: "card" },
    el("div", { class: "card-header" }, el("h3", { class: "card-title", text: "Users" })),
    el("div", { class: "table-responsive" }, el("table", { class: "table table-vcenter mb-0" },
      el("thead", {}, el("tr", {},
        el("th", { scope: "col", text: "User" }), el("th", { scope: "col", text: "Role" }),
        el("th", { scope: "col", text: "2FA" }), el("th", { scope: "col", text: "Assigned sites" }),
        el("th", { scope: "col", class: "text-end", text: "Actions" }))), tableBody)),
    el("div", { class: "card-body border-top" }, editor, error));
  const add = el("button", { class: "btn btn-primary", type: "button", icon: "plus", text: "Add user" });
  let users = [];
  let sites = [];

  ctx.header({ icon: "users",
    title: "Users",
    subtitle: "Panel access and site assignments",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "Users"]],
    actions: [add],
  });
  ctx.mount.append(card);

  function showError(message) {
    error.replaceChildren(el("div", { class: "alert alert-danger mb-0", role: "alert", text: message }));
  }

  function userEditor(user = null) {
    const creating = !user;
    const username = el("input", { id: "user-username", class: "form-control", autocomplete: "username", value: user?.username || "", disabled: !creating });
    const password = el("input", { id: "user-password", class: "form-control", type: "text", autocomplete: "new-password", "aria-describedby": "user-password-error" });
    const generate = el("button", { class: "btn btn-outline-secondary", type: "button", text: "Generate" });
    const role = el("select", { id: "user-role", class: "form-select" },
      el("option", { value: "admin", selected: user?.role === "admin", text: "Admin" }),
      el("option", { value: "site-manager", selected: user?.role === "site-manager", text: "Site manager" }));
    const siteSelect = el("select", { id: "user-sites", class: "form-select", multiple: true, size: Math.min(6, Math.max(2, sites.length)), "aria-label": "Assigned sites" },
      sites.map((site) => el("option", { value: site.domain, selected: (user?.sites || []).includes(site.domain), text: site.domain })));
    const sitesField = field("Assigned sites", siteSelect, "Required for a site manager. Hold Command or Control to select more than one.");
    const submit = el("button", { class: "btn btn-primary", type: "button", text: creating ? "Create user" : "Save changes" });
    const cancel = el("button", { class: "btn btn-outline-secondary", type: "button", text: "Cancel" });
    const formError = el("div", { id: "user-password-error", class: "mt-3", "aria-live": "polite" });

    function syncRole() {
      sitesField.classList.toggle("d-none", role.value === "admin");
    }
    syncRole();
    role.addEventListener("change", syncRole);
    generate.addEventListener("click", () => { password.value = passwordValue(); password.focus(); });
    cancel.addEventListener("click", () => { editor.replaceChildren(); error.replaceChildren(); });
    submit.addEventListener("click", async () => {
      const value = password.value;
      if (creating && value.length < 12) {
        formError.replaceChildren(el("div", { class: "text-danger", role: "alert", text: "Passwords must be at least 12 characters." }));
        password.setAttribute("aria-describedby", "user-password-error");
        password.focus();
        return;
      }
      if (!creating && value && value.length < 12) {
        formError.replaceChildren(el("div", { class: "text-danger", role: "alert", text: "Passwords must be at least 12 characters." }));
        password.focus();
        return;
      }
      const body = { role: role.value };
      if (role.value === "site-manager") body.sites = selectedSites(siteSelect);
      if (value) body.password = value;
      if (creating) body.username = username.value.trim();
      if (creating && !body.username) {
        formError.replaceChildren(el("div", { class: "text-danger", role: "alert", text: "A username is required." }));
        username.focus();
        return;
      }
      try {
        await withBusy(submit, async () => {
          await api(creating ? "/api/users" : `/api/users/${encodeURIComponent(user.username)}`, {
            method: creating ? "POST" : "PUT", body, signal: ctx.signal,
          });
          if (ctx.signal.aborted) return;
          toast(creating ? "User created." : "User updated.");
          editor.replaceChildren();
          await refresh();
          if (ctx.signal.aborted) return;
        });
      } catch (failed) {
        if (ctx.signal.aborted) return;
        formError.replaceChildren(el("div", { class: "text-danger", role: "alert", text: failed.message }));
      }
    });

    return el("div", { class: "card card-sm" },
      el("div", { class: "card-body" },
        el("h4", { class: "card-title", text: creating ? "Add user" : `Edit ${user.username}` }),
        field("Username", username),
        field("Password", el("div", { class: "input-group" }, password, generate), creating ? "Minimum 12 characters. Generate reveals the password so you can hand it over." : "Leave blank to keep the current password."),
        field("Role", role), sitesField,
        el("div", { class: "btn-list" }, submit, cancel), formError));
  }

  function row(user) {
    const edit = el("button", { class: "btn btn-sm btn-outline-primary", type: "button", text: "Edit" });
    const resetTotp = user.totp_enabled ? el("button", { class: "btn btn-sm btn-outline-warning", type: "button", text: "Reset 2FA" }) : null;
    const remove = user.username === session.principal?.username ? null : el("button", { class: "btn btn-sm btn-outline-danger", type: "button", icon: "trash", text: "Delete" });
    edit.addEventListener("click", () => { error.replaceChildren(); editor.replaceChildren(userEditor(user)); editor.scrollIntoView({ behavior: "smooth", block: "nearest" }); });
    resetTotp?.addEventListener("click", async () => {
      const confirmed = await confirmAction({
        title: `Reset 2FA for ${user.username}?`, message: "This disables their current second factor. They must enrol again at next login.", confirmLabel: "Reset 2FA",
      });
      if (ctx.signal.aborted || !confirmed) return;
      try {
        await withBusy(resetTotp, async () => {
          await api(`/api/users/${encodeURIComponent(user.username)}/totp`, { method: "DELETE", signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast("2FA reset.");
          await refresh();
          if (ctx.signal.aborted) return;
        });
      } catch (failed) {
        if (!ctx.signal.aborted) showError(failed.message);
      }
    });
    remove?.addEventListener("click", async () => {
      const typed = await confirmAction({
        title: `Delete ${user.username}?`, message: "This permanently removes their panel access.", confirmLabel: "Delete user", keyword: user.username,
      });
      if (ctx.signal.aborted || typed !== user.username) return;
      try {
        await withBusy(remove, async () => {
          await api(`/api/users/${encodeURIComponent(user.username)}`, { method: "DELETE", signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast("User deleted.");
          await refresh();
          if (ctx.signal.aborted) return;
        });
      } catch (failed) {
        if (!ctx.signal.aborted) showError(failed.message);
      }
    });
    return el("tr", {},
      el("td", {}, el("div", { class: "fw-medium", text: user.username }),
        user.first_name || user.last_name ? el("div", { class: "text-secondary small", text: [user.first_name, user.last_name].filter(Boolean).join(" ") }) : null,
        user.username === session.principal?.username ? el("span", { class: "badge bg-blue-lt text-blue mt-1", text: "you" }) : null),
      el("td", {}, badge(user.role || "unknown")),
      el("td", {}, user.totp_enabled ? badge("Enabled") : badge("Not enrolled", false)),
      // "All sites" is true for an admin and false for a site-manager with an
      // empty list, who can reach none. Printing the same words for both states
      // the exact opposite of the truth for the account that is restricted.
      el("td", { class: "text-break" }, (user.sites || []).length
        ? el("span", { text: user.sites.join(", ") })
        : user.role === "admin"
          ? el("span", { class: "text-secondary", text: "All sites" })
          : el("span", { class: "text-danger", text: "No sites assigned" })),
      el("td", { class: "text-end" }, el("div", { class: "btn-list justify-content-end" }, edit, resetTotp, remove)));
  }

  function render() {
    tableBody.replaceChildren(...(users.length ? users.map(row) : [emptyRow(5, "users", "No users found.")]));
  }

  async function refresh() {
    try {
      const [usersPayload, sitesPayload] = await Promise.all([api("/api/users", { signal: ctx.signal }), api("/api/sites", { signal: ctx.signal })]);
      if (ctx.signal.aborted) return;
      users = Array.isArray(usersPayload.users) ? usersPayload.users : [];
      sites = Array.isArray(sitesPayload.sites) ? sitesPayload.sites : [];
      render();
    } catch (failed) {
      if (ctx.signal.aborted) return;
      tableBody.replaceChildren(el("tr", {}, el("td", { colspan: 5, class: "text-danger", text: `Unable to load users: ${failed.message}` })));
    }
  }

  add.addEventListener("click", () => { error.replaceChildren(); editor.replaceChildren(userEditor()); editor.scrollIntoView({ behavior: "smooth", block: "nearest" }); });
  await refresh();
  if (ctx.signal.aborted) return;
  ctx.onLeave(onPanelEvent((event) => { if (!ctx.signal.aborted && String(event.action || "").startsWith("user.")) refresh(); }));
});
