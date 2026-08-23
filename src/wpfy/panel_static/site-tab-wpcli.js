import { el, api, confirmAction, withBusy, pollJob, toast } from "./panel.js";

function card(title, body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header" }, el("h3", { class: "card-title", text: title })),
    el("div", { class: "card-body" }, body));
}

function errorCard(message) {
  return el("div", { class: "alert alert-danger mb-0", role: "alert", text: message });
}

export async function render(ctx, domain) {
  const encodedDomain = encodeURIComponent(domain);
  const command = el("input", { class: "form-control", "aria-label": "WP-CLI command", placeholder: "core version" });
  const run = el("button", { class: "btn btn-danger", type: "button", text: "Run against live site" });
  const wpResult = el("div", { class: "mt-3" });
  ctx.mount.append(card("WP-CLI", el("div", {},
    el("p", {
      class: "text-secondary", text: "Commands execute against the live site. Check the command carefully before running it.",
    }), el("div", { class: "input-group" }, command, run), wpResult)));

  function output(job) {
    const result = job.result || {};
    const text = [result.stdout, result.stderr].filter(Boolean).join(result.stdout && result.stderr ? "\n" : "");
    return text ? el("pre", { class: "log-output mb-0", text }) : null;
  }

  run.addEventListener("click", async () => {
    const args = command.value.trim().split(/\s+/).filter(Boolean);
    if (args.length === 0) {
      wpResult.replaceChildren(errorCard("Enter a WP-CLI command."));
      return;
    }
    const confirmed = await confirmAction({
      title: "Run WP-CLI command?",
      message: "This executes against the live site.",
      detail: `wp ${args.join(" ")}`,
      confirmLabel: "Run command",
    });
    if (ctx.signal.aborted || !confirmed) return;
    try {
      await withBusy(run, async () => {
        const response = await api(`/api/sites/${encodedDomain}/wp`, {
          method: "POST", body: { args }, signal: ctx.signal,
        });
        if (ctx.signal.aborted) return;
        const job = await pollJob(response.job_id, { signal: ctx.signal });
        if (ctx.signal.aborted) return;
        const resultOutput = output(job);
        if (job.state !== "succeeded") {
          wpResult.replaceChildren(errorCard(job.error || "WP-CLI command failed."), resultOutput);
          return;
        }
        wpResult.replaceChildren(el("div", { class: "alert alert-success mb-3", role: "status", text: "WP-CLI command completed." }), resultOutput);
        toast("WP-CLI command completed.");
      });
      if (ctx.signal.aborted) return;
    } catch (failed) {
      if (ctx.signal.aborted) return;
      wpResult.replaceChildren(errorCard(`Unable to run WP-CLI command: ${failed.message}`));
    }
  });
}
