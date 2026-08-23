import { el, api, confirmAction, withBusy, toast, formatTime, onPanelEvent, emptyRow } from "./panel.js";

function card(title, body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header" }, el("h3", { class: "card-title", text: title })),
    el("div", { class: "card-body" }, body));
}

function errorCard(message) {
  return el("div", { class: "alert alert-danger mb-0", role: "alert", text: message });
}

function message(payload, fallback) {
  return payload?.message || payload?.error || fallback;
}

function scheduleError(schedule) {
  const fields = schedule.trim().split(/\s+/).filter(Boolean);
  if (fields.length !== 5) {
    return `A cron schedule needs five whitespace-separated fields; this one has ${fields.length}.`;
  }
  return "";
}

export async function render(ctx, domain) {
  const encodedDomain = encodeURIComponent(domain);
  const body = el("div", { class: "text-secondary", text: "Loading scheduled jobs…" });
  ctx.mount.append(card("Scheduled jobs", body));

  async function refresh() {
    try {
      const payload = await api(`/api/sites/${encodedDomain}/cron`, { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      if (payload.ok === false) {
        body.replaceChildren(errorCard(message(payload, "Unable to load scheduled jobs.")));
        return;
      }

      const schedule = el("input", { class: "form-control", "aria-label": "Cron schedule", placeholder: "* * * * *" });
      const command = el("input", { class: "form-control", "aria-label": "Cron command", placeholder: "Command" });
      const services = Array.isArray(payload.services) ? payload.services : [];
      const service = el("select", { class: "form-select", "aria-label": "Service", disabled: services.length === 0 },
        services.length ? services.map((name) => el("option", { value: name, text: name })) : el("option", { value: "", text: "No services available" }));
      const timeout = el("input", { class: "form-control", type: "number", min: 1, "aria-label": "Timeout in seconds", placeholder: "Timeout (seconds)" });
      const add = el("button", { class: "btn btn-primary", type: "button", text: "Add job" });
      const result = el("div", { class: "mt-3" });
      const jobs = Array.isArray(payload.jobs) ? payload.jobs : [];

      const table = el("div", { class: "table-responsive mt-3" }, el("table", { class: "table table-vcenter mb-0" },
        el("thead", {}, el("tr", {},
          el("th", { text: "Schedule" }), el("th", { text: "Command" }), el("th", { text: "Service" }),
          el("th", { text: "Enabled" }), el("th", { text: "Last run" }), el("th", { class: "w-1", text: "Actions" }))),
        el("tbody", {}, jobs.length ? jobs.map((job) => {
          const toggle = el("button", {
            class: "btn btn-outline-secondary btn-sm", type: "button",
            text: job.enabled ? "Disable" : "Enable",
          });
          const run = el("button", { class: "btn btn-outline-primary btn-sm", type: "button", text: "Run now" });
          const remove = el("button", { class: "btn btn-outline-danger btn-sm", type: "button", text: "Delete" });

          toggle.addEventListener("click", async () => {
            try {
              await withBusy(toggle, async () => {
                await api(`/api/sites/${encodedDomain}/cron/${encodeURIComponent(job.id)}`, {
                  method: "PUT", body: { enabled: !job.enabled }, signal: ctx.signal,
                });
                if (ctx.signal.aborted) return;
                await refresh();
                if (ctx.signal.aborted) return;
                toast(`Scheduled job ${job.enabled ? "disabled" : "enabled"}.`);
              });
              if (ctx.signal.aborted) return;
            } catch (failed) {
              if (ctx.signal.aborted) return;
              result.replaceChildren(errorCard(`Unable to update scheduled job: ${failed.message}`));
            }
          });

          run.addEventListener("click", async () => {
            const confirmed = await confirmAction({
              title: "Run scheduled job now?",
              message: `This executes the stored command ahead of schedule (${job.schedule || "unscheduled"}).`,
              confirmLabel: "Run now",
            });
            if (ctx.signal.aborted || !confirmed) return;
            try {
              await withBusy(run, async () => {
                const response = await api(`/api/sites/${encodedDomain}/cron/${encodeURIComponent(job.id)}/run`, {
                  method: "POST", signal: ctx.signal,
                });
                if (ctx.signal.aborted) return;
                const outcome = response.outcome || "ok";
                const text = message(response, outcome === "ok" ? "Scheduled job completed." : `Scheduled job ${outcome}.`);
                result.replaceChildren(el("div", {
                  class: `alert alert-${outcome === "ok" ? "success" : "warning"} mb-0`, role: "status",
                  text: `Run ${outcome}: ${text}`,
                }));
                toast(`Scheduled job run ${outcome}.`, outcome !== "ok" && outcome !== "skipped");
                if (outcome === "ok" || outcome === "skipped") await refresh();
                if (ctx.signal.aborted) return;
              });
              if (ctx.signal.aborted) return;
            } catch (failed) {
              if (ctx.signal.aborted) return;
              const outcome = failed.payload?.outcome;
              if (outcome) {
                result.replaceChildren(el("div", {
                  class: `alert alert-${outcome === "skipped" ? "warning" : "danger"} mb-0`, role: "status",
                  text: `Run ${outcome}: ${message(failed.payload, failed.message)}`,
                }));
                toast(`Scheduled job run ${outcome}.`, outcome !== "skipped");
                return;
              }
              result.replaceChildren(errorCard(`Scheduled job run failed: ${failed.message}`));
            }
          });

          remove.addEventListener("click", async () => {
            const confirmed = await confirmAction({
              title: "Delete scheduled job?",
              message: "This permanently removes the scheduled job.",
              confirmLabel: "Delete job",
            });
            if (ctx.signal.aborted || !confirmed) return;
            try {
              await withBusy(remove, async () => {
                await api(`/api/sites/${encodedDomain}/cron/${encodeURIComponent(job.id)}`, {
                  method: "DELETE", signal: ctx.signal,
                });
                if (ctx.signal.aborted) return;
                await refresh();
                if (ctx.signal.aborted) return;
                toast("Scheduled job deleted.");
              });
              if (ctx.signal.aborted) return;
            } catch (failed) {
              if (ctx.signal.aborted) return;
              result.replaceChildren(errorCard(`Unable to delete scheduled job: ${failed.message}`));
            }
          });

          return el("tr", {},
            el("td", { class: "font-monospace", text: job.schedule || "–" }),
            el("td", { class: "font-monospace text-break", text: job.command || "–" }),
            el("td", { text: job.service || "–" }),
            el("td", { text: job.enabled ? "Yes" : "No" }),
            el("td", { text: job.last_run === null ? "never" : formatTime(job.last_run) }),
            el("td", { class: "text-nowrap" }, el("div", { class: "btn-list" }, toggle, run, remove)));
        }) : emptyRow(6, "clock", "No scheduled jobs found.") )));

      body.replaceChildren(
        el("div", { class: "row g-2" },
          el("div", { class: "col-md-2" }, schedule),
          el("div", { class: "col-md" }, command),
          el("div", { class: "col-md-2" }, service),
          el("div", { class: "col-md-2" }, timeout),
          el("div", { class: "col-md-auto" }, add)),
        table, result);

      add.addEventListener("click", async () => {
        const invalidSchedule = scheduleError(schedule.value);
        if (invalidSchedule) {
          result.replaceChildren(errorCard(invalidSchedule));
          return;
        }
        if (!command.value.trim()) {
          result.replaceChildren(errorCard("A cron command is required."));
          return;
        }
        try {
          await withBusy(add, async () => {
            const response = await api(`/api/sites/${encodedDomain}/cron`, {
              method: "POST",
              body: {
                schedule: schedule.value.trim(), command: command.value.trim(), service: service.value,
                ...(timeout.value ? { timeout: Number(timeout.value) } : {}),
              },
              signal: ctx.signal,
            });
            if (ctx.signal.aborted) return;
            if (response.ok === false) throw new Error(message(response, "Unable to add scheduled job."));
            await refresh();
            if (ctx.signal.aborted) return;
            toast("Scheduled job added.");
          });
          if (ctx.signal.aborted) return;
        } catch (failed) {
          if (ctx.signal.aborted) return;
          result.replaceChildren(errorCard(`Unable to add scheduled job: ${failed.message}`));
        }
      });
    } catch (failed) {
      if (ctx.signal.aborted) return;
      body.replaceChildren(errorCard(message(failed.payload, `Unable to load scheduled jobs: ${failed.message}`)));
    }
  }

  await refresh();
  if (ctx.signal.aborted) return;
  ctx.onLeave(onPanelEvent((event) => {
    if (event.domain !== domain || ctx.signal.aborted) return;
    refresh();
  }));
}
