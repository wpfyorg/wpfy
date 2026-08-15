import { el, api, confirmAction, withBusy, pollJob, renderOneTime, toast, onPanelEvent } from "./panel.js";
import { renderFileBrowser } from "./site-file-browser.js";

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

function output(job) {
  const result = job.result || {};
  const text = [result.stdout, result.stderr].filter(Boolean).join(result.stdout && result.stderr ? "\n" : "");
  return text ? el("pre", { class: "log-output mb-0", text }) : null;
}

export async function render(ctx, domain) {
  const encodedDomain = encodeURIComponent(domain);
  const sftpBody = el("div", { class: "text-secondary", text: "Loading SFTP status…" });
  const wpBody = el("div", {});
  const filesMount = el("div", {});
  ctx.mount.append(card("SFTP", sftpBody), card("WP-CLI", wpBody), filesMount);
  renderFileBrowser(ctx, domain, filesMount);

  async function refreshSftp() {
    try {
      const payload = await api(`/api/sites/${encodedDomain}/sftp`, { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      renderSftp(payload);
    } catch (failed) {
      if (ctx.signal.aborted) return;
      renderSftp(failed.payload || { message: failed.message, ok: false });
    }
  }

  function renderSftp(payload) {
    const status = el("div", {
      class: `alert alert-${payload.ok === false ? "warning" : "secondary"} mb-3`, role: "status",
      text: message(payload, "SFTP status is unavailable."),
    });
    const enable = el("button", { class: "btn btn-primary", type: "button", text: "Enable" });
    const rotate = el("button", { class: "btn btn-outline-danger", type: "button", text: "Rotate password" });
    const disable = el("button", { class: "btn btn-outline-danger", type: "button", text: "Disable" });
    const actionResult = el("div", { class: "mt-3" });

    async function action(name, button) {
      try {
        await withBusy(button, async () => {
          const response = await api(`/api/sites/${encodedDomain}/sftp`, {
            method: "POST", body: { action: name }, signal: ctx.signal,
          });
          if (ctx.signal.aborted) return;
          if (response.ok === false) throw new Error(message(response, `Unable to ${name} SFTP.`));
          if (name === "rotate" && response.one_time) renderOneTime(`One-time SFTP credentials for ${domain}`, response.one_time);
          actionResult.replaceChildren(el("div", { class: "alert alert-success mb-0", role: "status", text: message(response, `SFTP ${name}d.`) }));
          await refreshSftp();
          if (ctx.signal.aborted) return;
          toast(`SFTP ${name}d.`);
        });
        if (ctx.signal.aborted) return;
      } catch (failed) {
        if (ctx.signal.aborted) return;
        actionResult.replaceChildren(errorCard(`Unable to ${name} SFTP: ${failed.message}`));
      }
    }

    enable.addEventListener("click", () => action("enable", enable));
    rotate.addEventListener("click", async () => {
      const confirmed = await confirmAction({
        title: "Rotate SFTP password?",
        message: "The existing SFTP password will stop working.",
        confirmLabel: "Rotate password",
      });
      if (ctx.signal.aborted || !confirmed) return;
      action("rotate", rotate);
    });
    disable.addEventListener("click", async () => {
      const confirmed = await confirmAction({
        title: "Disable SFTP?",
        message: "Existing SFTP access will stop working.",
        confirmLabel: "Disable SFTP",
      });
      if (ctx.signal.aborted || !confirmed) return;
      action("disable", disable);
    });

    sftpBody.replaceChildren(status, el("div", { class: "btn-list" }, enable, rotate, disable), actionResult);
  }

  const command = el("input", { class: "form-control", "aria-label": "WP-CLI command", placeholder: "core version" });
  const run = el("button", { class: "btn btn-danger", type: "button", text: "Run against live site" });
  const wpResult = el("div", { class: "mt-3" });
  wpBody.append(el("p", {
    class: "text-secondary", text: "Commands execute against the live site. Check the command carefully before running it.",
  }), el("div", { class: "input-group" }, command, run), wpResult);

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

  await refreshSftp();
  if (ctx.signal.aborted) return;
  ctx.onLeave(onPanelEvent((event) => {
    if (event.domain !== domain || ctx.signal.aborted) return;
    refreshSftp();
  }));
}
