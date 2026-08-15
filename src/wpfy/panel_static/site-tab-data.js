import { el, api, confirmAction, withBusy, pollJob, renderOneTime, toast, onPanelEvent, formatBytes, formatTime, session, emptyRow } from "./panel.js";

function card(title, body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header" }, el("h3", { class: "card-title", text: title })),
    el("div", { class: "card-body" }, body));
}

function errorCard(message) {
  return el("div", { class: "alert alert-danger mb-0", role: "alert", text: message });
}

function progressList() {
  return el("ul", { class: "list-group list-group-flush mt-3" });
}

function stepsInto(target, steps) {
  target.replaceChildren(...steps.map((step) => el("li", {
    class: "list-group-item",
    text: step.message || step.name || step.action || String(step),
  })));
}

function message(payload, fallback) {
  return payload?.message || payload?.error || fallback;
}

export async function render(ctx, domain, site) {
  const encodedDomain = encodeURIComponent(domain);
  const databasesBody = el("div", { class: "text-secondary", text: "Loading databases…" });
  const usersBody = el("div", { class: "text-secondary", text: "Loading database users…" });
  const databasesCard = card("Databases", databasesBody);
  const usersCard = card("Database users", usersBody);
  ctx.mount.append(databasesCard, usersCard);

  async function refreshDatabases() {
    try {
      const payload = await api(`/api/sites/${encodedDomain}/databases`, { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      if (payload.ok === false) {
        databasesBody.replaceChildren(errorCard(message(payload, "Unable to load databases.")));
        return;
      }
      const name = el("input", { class: "form-control", "aria-label": "Database name", placeholder: "Database name" });
      const create = el("button", { class: "btn btn-primary", type: "button", text: "Create database" });
      const rows = Array.isArray(payload.databases) ? payload.databases : [];
      const table = el("div", { class: "table-responsive mt-3" }, el("table", { class: "table table-vcenter mb-0" },
        el("thead", {}, el("tr", {}, el("th", { text: "Database" }), el("th", { class: "w-1", text: "" }))),
        el("tbody", {}, rows.length ? rows.map((database) => {
          const drop = el("button", { class: "btn btn-outline-danger btn-sm", type: "button", text: "Drop" });
          drop.addEventListener("click", async () => {
            const typed = await confirmAction({
              title: `Drop ${database}?`,
              message: "This permanently deletes the database and its contents.",
              confirmLabel: "Drop database",
              keyword: database,
            });
            if (ctx.signal.aborted || typed !== database) return;
            try {
              await withBusy(drop, async () => {
                await api(`/api/sites/${encodedDomain}/databases/${encodeURIComponent(database)}`, {
                  method: "DELETE", body: { confirm: typed }, signal: ctx.signal,
                });
                if (ctx.signal.aborted) return;
                await refreshDatabases();
                if (ctx.signal.aborted) return;
                toast(`Database ${database} dropped.`);
              });
              if (ctx.signal.aborted) return;
            } catch (failed) {
              if (ctx.signal.aborted) return;
              databasesBody.replaceChildren(errorCard(`Unable to drop database: ${failed.message}`));
            }
          });
          return el("tr", {}, el("td", { class: "font-monospace", text: database }), el("td", {}, drop));
        }) : emptyRow(2, "database", "No databases found.") )));
      databasesBody.replaceChildren(el("div", { class: "row g-2" },
        el("div", { class: "col-md" }, name),
        el("div", { class: "col-md-auto" }, create)), table);
      create.addEventListener("click", async () => {
        if (!name.value.trim()) {
          toast("Enter a database name.", true);
          return;
        }
        try {
          await withBusy(create, async () => {
            const result = await api(`/api/sites/${encodedDomain}/databases`, {
              method: "POST", body: { name: name.value.trim() }, signal: ctx.signal,
            });
            if (ctx.signal.aborted) return;
            if (result.ok === false) throw new Error(message(result, "Database creation failed."));
            await refreshDatabases();
            if (ctx.signal.aborted) return;
            toast(message(result, "Database created."));
          });
          if (ctx.signal.aborted) return;
        } catch (failed) {
          if (ctx.signal.aborted) return;
          databasesBody.replaceChildren(errorCard(`Unable to create database: ${failed.message}`));
        }
      });
    } catch (failed) {
      if (ctx.signal.aborted) return;
      databasesBody.replaceChildren(errorCard(message(failed.payload, `Unable to load databases: ${failed.message}`)));
    }
  }

  async function runUserJob(result, progress, title) {
    const job = await pollJob(result.job_id, { signal: ctx.signal, onStep: (steps) => {
      if (!ctx.signal.aborted) stepsInto(progress, steps);
    } });
    if (ctx.signal.aborted) return null;
    if (job.state !== "succeeded") throw new Error(job.error || "Database user operation failed.");
    if (job.one_time) renderOneTime(title, job.one_time);
    return job;
  }

  async function refreshUsers() {
    try {
      const payload = await api(`/api/sites/${encodedDomain}/db-users`, { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      if (payload.ok === false) {
        usersBody.replaceChildren(errorCard(message(payload, "Unable to load database users.")));
        return;
      }
      const user = el("input", { class: "form-control", "aria-label": "Database username", placeholder: "Username" });
      const password = el("input", { class: "form-control", type: "password", autocomplete: "new-password", "aria-label": "Database password", placeholder: "Password (generated if blank)" });
      const database = el("input", { class: "form-control", "aria-label": "Database grant", placeholder: "Database grant (optional)" });
      const create = el("button", { class: "btn btn-primary", type: "button", text: "Create user" });
      const progress = progressList();
      const rows = Array.isArray(payload.users) ? payload.users : [];
      const table = el("div", { class: "table-responsive mt-3" }, el("table", { class: "table table-vcenter mb-0" },
        el("thead", {}, el("tr", {}, el("th", { text: "User" }), el("th", { text: "New password (optional)" }), el("th", { class: "w-1", text: "" }))),
        el("tbody", {}, rows.length ? rows.map((name) => {
          const replacement = el("input", { class: "form-control form-control-sm", type: "password", autocomplete: "new-password", "aria-label": `New password for ${name}`, placeholder: "Generate if blank" });
          const rotate = el("button", { class: "btn btn-outline-danger btn-sm", type: "button", text: "Rotate password" });
          const drop = el("button", { class: "btn btn-outline-danger btn-sm", type: "button", text: "Drop" });
          rotate.addEventListener("click", async () => {
            const confirmed = await confirmAction({
              title: `Rotate ${name}'s password?`,
              message: "The current database password will stop working.",
              confirmLabel: "Rotate password",
            });
            if (ctx.signal.aborted || !confirmed) return;
            try {
              await withBusy(rotate, async () => {
                const result = await api(`/api/sites/${encodedDomain}/db-users/${encodeURIComponent(name)}/password`, {
                  method: "POST", body: replacement.value ? { password: replacement.value } : {}, signal: ctx.signal,
                });
                if (ctx.signal.aborted) return;
                const job = await runUserJob(result, progress, `One-time credentials for ${name}`);
                if (ctx.signal.aborted || !job) return;
                replacement.value = "";
                toast(`Password rotated for ${name}.`);
              });
              if (ctx.signal.aborted) return;
            } catch (failed) {
              if (ctx.signal.aborted) return;
              usersBody.replaceChildren(errorCard(`Unable to rotate password: ${failed.message}`));
            }
          });
          drop.addEventListener("click", async () => {
            const typed = await confirmAction({
              title: `Drop ${name}?`,
              message: "This permanently removes the database user.",
              confirmLabel: "Drop user",
              keyword: name,
            });
            if (ctx.signal.aborted || typed !== name) return;
            try {
              await withBusy(drop, async () => {
                await api(`/api/sites/${encodedDomain}/db-users/${encodeURIComponent(name)}`, {
                  method: "DELETE", body: { confirm: typed }, signal: ctx.signal,
                });
                if (ctx.signal.aborted) return;
                await refreshUsers();
                if (ctx.signal.aborted) return;
                toast(`Database user ${name} dropped.`);
              });
              if (ctx.signal.aborted) return;
            } catch (failed) {
              if (ctx.signal.aborted) return;
              usersBody.replaceChildren(errorCard(`Unable to drop database user: ${failed.message}`));
            }
          });
          return el("tr", {}, el("td", { class: "font-monospace", text: name }), el("td", {}, replacement),
            el("td", { class: "text-nowrap" }, el("div", { class: "btn-list" }, rotate, drop)));
        }) : emptyRow(3, "users", "No database users found.") )));
      usersBody.replaceChildren(el("div", { class: "row g-2" },
        el("div", { class: "col-md-3" }, user),
        el("div", { class: "col-md-3" }, password),
        el("div", { class: "col-md-3" }, database),
        el("div", { class: "col-md-auto" }, create)), table, progress);
      create.addEventListener("click", async () => {
        if (!user.value.trim()) {
          toast("Enter a database username.", true);
          return;
        }
        try {
          await withBusy(create, async () => {
            const result = await api(`/api/sites/${encodedDomain}/db-users`, {
              method: "POST",
              body: {
                user: user.value.trim(),
                ...(password.value ? { password: password.value } : {}),
                ...(database.value.trim() ? { database: database.value.trim() } : {}),
              },
              signal: ctx.signal,
            });
            if (ctx.signal.aborted) return;
            const job = await runUserJob(result, progress, `One-time credentials for ${user.value.trim()}`);
            if (ctx.signal.aborted || !job) return;
            await refreshUsers();
            if (ctx.signal.aborted) return;
            toast("Database user created.");
          });
          if (ctx.signal.aborted) return;
        } catch (failed) {
          if (ctx.signal.aborted) return;
          usersBody.replaceChildren(errorCard(`Unable to create database user: ${failed.message}`));
        }
      });
    } catch (failed) {
      if (ctx.signal.aborted) return;
      usersBody.replaceChildren(errorCard(message(failed.payload, `Unable to load database users: ${failed.message}`)));
    }
  }

  const adminerEnabled = Boolean(site.adminer_enabled || site.adminer_port);
  const adminerToggle = el("input", { class: "form-check-input", type: "checkbox", checked: adminerEnabled, id: "adminer-enabled" });
  const adminerPort = el("input", {
    class: "form-control", type: "number", min: 1, max: 65535, value: site.adminer_port || "",
    "aria-label": "Adminer port", placeholder: "Optional port",
  });
  const adminerStatus = el("div", { class: "mt-3" });
  const adminerCard = card("Adminer", el("div", {},
    el("p", { class: "text-secondary", text: "Adminer exposes this site's database over HTTP. Enable it only when needed." }),
    el("div", { class: "row g-2 align-items-center" },
      el("div", { class: "col-md-auto" }, el("label", { class: "form-check" }, adminerToggle,
        el("span", { class: "form-check-label", text: "Enable Adminer" }))),
      el("div", { class: "col-md-4" }, adminerPort)),
    adminerStatus));

  adminerToggle.addEventListener("change", async () => {
    const action = adminerToggle.checked ? "on" : "off";
    if (action === "on") {
      const confirmed = await confirmAction({
        title: "Enable Adminer?",
        message: "Adminer exposes this site's database over HTTP.",
        confirmLabel: "Enable Adminer",
      });
      if (ctx.signal.aborted) return;
      if (!confirmed) {
        adminerToggle.checked = false;
        return;
      }
    }
    try {
      await withBusy(adminerToggle, async () => {
        const result = await api(`/api/sites/${encodedDomain}/adminer`, {
          method: "POST",
          body: { action, ...(action === "on" && adminerPort.value.trim() ? { port: adminerPort.value.trim() } : {}) },
          signal: ctx.signal,
        });
        if (ctx.signal.aborted) return;
        if (result.ok === false) throw new Error(message(result, "Adminer update failed."));
        adminerStatus.replaceChildren(el("div", { class: "alert alert-success mb-0", text: message(result, `Adminer turned ${action}.`) }));
      });
      if (ctx.signal.aborted) return;
    } catch (failed) {
      if (ctx.signal.aborted) return;
      adminerToggle.checked = action !== "on";
      adminerStatus.replaceChildren(errorCard(`Unable to update Adminer: ${failed.message}`));
    }
  });

  const backupsBody = el("div", { class: "text-secondary", text: "Loading backups…" });
  const backupsCard = card("Backups", backupsBody);

  async function refreshBackups() {
    try {
      const payload = await api(`/api/sites/${encodedDomain}/backups`, { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      const create = el("button", { class: "btn btn-primary", type: "button", text: "Create backup" });
      const progress = progressList();
      // Backups written here stay on this host until a remote destination is
      // configured, which is a host-wide setting, not a per-site one. A host
      // that loses its disk loses these with it. The banner only appears when
      // there is genuinely no destination, and only for an admin -- a
      // site-manager cannot read or set one, so telling them would be noise.
      const destination = el("div", {});
      if (session.isAdmin) {
        api("/api/backup/remote", { signal: ctx.signal }).then((remote) => {
          if (ctx.signal.aborted || remote.config) return;
          destination.replaceChildren(el("div", { class: "alert alert-warning d-flex flex-wrap align-items-center gap-2 mb-0 mt-3", role: "status" },
            el("span", { class: "flex-fill", text: "These archives stay on this host. Set a remote destination so a disk failure does not take the backups with it." }),
            el("a", { class: "btn btn-sm", href: "/admin/backup", dataset: { route: "true" }, text: "Set a destination" })));
        }).catch(() => {});
      }
      const backups = Array.isArray(payload.backups) ? payload.backups.slice().sort((left, right) =>
        Number(right.modified_at || 0) - Number(left.modified_at || 0)) : [];
      const table = el("div", { class: "table-responsive mt-3" }, el("table", { class: "table table-vcenter mb-0" },
        el("thead", {}, el("tr", {}, el("th", { text: "Archive" }), el("th", { text: "Size" }),
          el("th", { text: "Created" }), el("th", { class: "w-1", text: "" }))),
        el("tbody", {}, backups.length ? backups.map((backup) => {
          const restore = el("button", { class: "btn btn-outline-danger btn-sm", type: "button", text: "Restore" });
          restore.addEventListener("click", async () => {
            const typed = await confirmAction({
              title: `Restore ${backup.name}?`,
              message: "The current site content will be replaced with this archive.",
              confirmLabel: "Restore backup",
              danger: true,
              keyword: domain,
            });
            if (ctx.signal.aborted || typed !== domain) return;
            try {
              await withBusy(restore, async () => {
                const result = await api(`/api/sites/${encodedDomain}/restore`, {
                  method: "POST", body: { archive: backup.name }, signal: ctx.signal,
                });
                if (ctx.signal.aborted) return;
                const job = await pollJob(result.job_id, { signal: ctx.signal, onStep: (steps) => {
                  if (!ctx.signal.aborted) stepsInto(progress, steps);
                } });
                if (ctx.signal.aborted) return;
                if (job.state !== "succeeded") throw new Error(job.error || "Restore failed.");
                toast("Backup restored.");
              });
              if (ctx.signal.aborted) return;
            } catch (failed) {
              if (ctx.signal.aborted) return;
              backupsBody.replaceChildren(errorCard(`Unable to restore backup: ${failed.message}`));
            }
          });
          return el("tr", {}, el("td", { class: "font-monospace", text: backup.name || "–" }),
            el("td", { text: formatBytes(backup.size_bytes) }),
            el("td", { text: formatTime(Number(backup.modified_at) * 1000) }), el("td", {}, restore));
        }) : emptyRow(4, "cloud-upload", "No backups found.") )));
      backupsBody.replaceChildren(create, destination, table, progress);
      create.addEventListener("click", async () => {
        try {
          await withBusy(create, async () => {
            const result = await api(`/api/sites/${encodedDomain}/backups`, {
              method: "POST", body: {}, signal: ctx.signal,
            });
            if (ctx.signal.aborted) return;
            const job = await pollJob(result.job_id, { signal: ctx.signal, onStep: (steps) => {
              if (!ctx.signal.aborted) stepsInto(progress, steps);
            } });
            if (ctx.signal.aborted) return;
            if (job.state !== "succeeded") throw new Error(job.error || "Backup failed.");
            await refreshBackups();
            if (ctx.signal.aborted) return;
            toast("Backup created.");
          });
          if (ctx.signal.aborted) return;
        } catch (failed) {
          if (ctx.signal.aborted) return;
          backupsBody.replaceChildren(errorCard(`Unable to create backup: ${failed.message}`));
        }
      });
    } catch (failed) {
      if (ctx.signal.aborted) return;
      backupsBody.replaceChildren(errorCard(`Unable to load backups: ${failed.message}`));
    }
  }

  ctx.mount.append(adminerCard, backupsCard);
  await Promise.all([refreshDatabases(), refreshUsers(), refreshBackups()]);
  if (ctx.signal.aborted) return;
  ctx.onLeave(onPanelEvent((event) => {
    if (event.domain !== domain || ctx.signal.aborted) return;
    refreshDatabases();
    refreshUsers();
    refreshBackups();
  }));
}
