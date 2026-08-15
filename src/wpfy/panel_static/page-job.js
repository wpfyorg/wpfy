import { registerPage, el, api, pollJob, renderOneTime, stepText } from "./panel.js";

function stateBadge(state) {
  const classes = {
    running: "bg-blue-lt text-blue", pending: "bg-blue-lt text-blue",
    succeeded: "bg-green-lt text-green", failed: "bg-red-lt text-red",
  };
  return el("span", { class: `badge ${classes[state] || "bg-secondary-lt text-secondary"}`, text: state || "unknown" });
}

function stepsList(steps) {
  return el("div", { class: "list-group list-group-flush" },
    steps.length ? steps.map((step) => el("div", { class: "list-group-item", text: stepText(step) }))
      : el("div", { class: "list-group-item text-secondary", text: "No steps reported yet." }));
}

function resultCard(job) {
  if (job.state === "failed") {
    return el("div", { class: "alert alert-danger", role: "alert", text: job.result?.error || "This operation failed." });
  }
  if (job.state === "succeeded") {
    const result = job.result && typeof job.result === "object" ? job.result : {};
    const entries = Object.entries(result).filter(([, value]) => value !== null && value !== undefined);
    return el("div", {},
      el("div", { class: "alert alert-success", role: "status", text: "Completed successfully." }),
      // A raw JSON.stringify of the payload is technically the truth and
      // practically unreadable -- site.create alone returns twenty absolute
      // paths on one line. Scalars become rows; the rest folds away.
      entries.length ? el("dl", { class: "row mb-0" }, entries.flatMap(([key, value]) => [
        el("dt", { class: "col-sm-3 text-secondary", text: key.replaceAll("_", " ") }),
        el("dd", { class: "col-sm-9" }, typeof value === "object"
          ? el("details", {}, el("summary", { class: "text-secondary", text: Array.isArray(value) ? `${value.length} item${value.length === 1 ? "" : "s"}` : "details" }),
            el("pre", { class: "log-output mt-2 mb-0", text: JSON.stringify(value, null, 2) }))
          : el("span", { class: "font-monospace text-break", text: String(value) })),
      ])) : null);
  }
  return null;
}

registerPage("job-detail", async (ctx) => {
  const jobId = ctx.params.jobId;
  const detail = el("div", { class: "card-body text-secondary", text: "Loading operation…" });
  const stepsMount = el("div", {});
  const resultMount = el("div", { class: "mt-3" });
  const progress = el("div", { class: "progress progress-sm mb-3" }, el("div", { class: "progress-bar progress-bar-indeterminate" }));
  const card = el("div", { class: "card" }, detail, el("div", { class: "card-body pt-0" }, progress, stepsMount, resultMount));
  ctx.mount.append(card);

  function render(job) {
    const label = job.domain ? `${job.action} · ${job.domain}` : job.action || "Operation";
    ctx.header({ icon: "list-check",
      title: label,
      subtitle: "Operation details",
      breadcrumb: [["/dashboard", "Dashboard"], ["/events", "Events"], [null, job.action || "Operation"]],
    });
    detail.replaceChildren(el("div", { class: "d-flex align-items-center gap-2" },
      el("h3", { class: "card-title mb-0", text: label }), stateBadge(job.state)));
    const steps = Array.isArray(job.steps) ? job.steps : [];
    stepsMount.replaceChildren(stepsList(steps));
    const active = job.state === "running" || job.state === "pending";
    progress.classList.toggle("d-none", !active);
    resultMount.replaceChildren(resultCard(job));
    if (job.state === "succeeded" && job.one_time) renderOneTime("Save these credentials now", job.one_time);
  }

  let job;
  try {
    job = await api(`/api/jobs/${encodeURIComponent(jobId)}`, { signal: ctx.signal });
    if (ctx.signal.aborted) return;
    render(job);
  } catch (error) {
    if (ctx.signal.aborted) return;
    ctx.header({ icon: "list-check", title: "Operation unavailable", breadcrumb: [["/dashboard", "Dashboard"], ["/events", "Events"], [null, "Operation"]] });
    detail.replaceChildren(el("div", { class: "alert alert-danger mb-0", role: "alert" },
      el("span", { text: error.message }),
      error.status === 404 ? el("a", { class: "alert-link ms-2", href: "/events", dataset: { route: "true" }, text: "Open Events" }) : null));
    progress.remove();
    return;
  }

  if (job.state !== "running" && job.state !== "pending") return;
  try {
    const completed = await pollJob(jobId, {
      signal: ctx.signal,
      onStep: (steps, current) => {
        if (ctx.signal.aborted) return;
        render({ ...current, steps });
      },
    });
    if (ctx.signal.aborted) return;
    render(completed);
  } catch (error) {
    if (ctx.signal.aborted) return;
    progress.remove();
    resultMount.replaceChildren(el("div", { class: "alert alert-danger", role: "alert" },
      el("span", { text: error.message }),
      el("a", { class: "alert-link ms-2", href: "/events", dataset: { route: "true" }, text: "Open Events" })));
  }
});
