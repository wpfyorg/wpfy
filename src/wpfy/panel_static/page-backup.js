/* Remote backup: one destination for the whole host, plus the schedule.
 *
 * The backend is a hand-rolled SigV4 client (`s3_backup.py`, zero dependencies),
 * so anything speaking the S3 API works. The provider list below is therefore
 * a set of endpoint/region templates over one real capability -- not a set of
 * integrations. Providers that need a different protocol entirely (Dropbox,
 * Google Drive, plain SFTP, rclone remotes) have no code behind them at all and
 * are listed as unavailable rather than shown as controls that do nothing.
 *
 * The secret key is write-only: no read path returns it. A blank secret field on
 * an existing destination means "keep the stored one", which is what stops an
 * edit to the prefix from wiping a working credential.
 */

import { registerPage, el, api, toast, confirmAction, withBusy, formatTime } from "./panel.js";

/** `endpoint` may carry `{region}`, substituted when the operator picks a region. */
const PROVIDERS = [
  {
    id: "s3", label: "Amazon S3", endpoint: "https://s3.{region}.amazonaws.com", region: "us-east-1",
    hint: "Region must match the bucket's region, or uploads are redirected and fail.",
  },
  {
    id: "wasabi", label: "Wasabi", endpoint: "https://s3.{region}.wasabisys.com", region: "us-east-1",
    hint: "Wasabi bills a 90-day minimum retention per object.",
  },
  {
    id: "spaces", label: "DigitalOcean Spaces", endpoint: "https://{region}.digitaloceanspaces.com", region: "nyc3",
    hint: "The region is the datacentre code, for example nyc3 or fra1.",
  },
  {
    id: "b2", label: "Backblaze B2", endpoint: "https://s3.{region}.backblazeb2.com", region: "us-west-004",
    hint: "Use the S3-compatible application key, not the native B2 key.",
  },
  {
    id: "r2", label: "Cloudflare R2", endpoint: "https://{account}.r2.cloudflarestorage.com", region: "auto",
    hint: "Replace {account} with your Cloudflare account ID. R2 always uses the region 'auto'.",
  },
  {
    id: "minio", label: "MinIO or other S3-compatible", endpoint: "", region: "us-east-1",
    hint: "Any endpoint that speaks the S3 API. HTTPS unless you explicitly allow plaintext.",
  },
];

/* Listed so the absence is explicit rather than mysterious. None of these have
   a line of code behind them; each needs a different transport, and two need an
   OAuth consent flow the panel has no pattern for. */
const UNAVAILABLE = [
  ["Dropbox", "Needs OAuth and the Dropbox content API."],
  ["Google Drive", "Needs OAuth and the Drive API."],
  ["SFTP", "Needs an SSH transport; wpfy's SFTP support is inbound, per site."],
  ["Custom rclone remote", "Needs rclone installed on the host, which wpfy does not ship."],
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

registerPage("remote-backup", async (ctx) => {
  ctx.header({ icon: "cloud-upload",
    title: "Remote backup",
    subtitle: "Where site backups are uploaded, and when",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "Remote backup"]],
  });

  const destinationMount = el("div", {});
  const scheduleMount = el("div", {});
  ctx.mount.append(destinationMount, scheduleMount, card(
    "Other providers",
    "Not available — listed so the absence is explicit",
    el("ul", { class: "list-unstyled mb-0" }, UNAVAILABLE.map(([name, why]) => el("li", { class: "mb-2" },
      el("span", { class: "fw-bold", text: `${name}: ` }),
      el("span", { class: "text-secondary", text: why })))),
    el("p", { class: "text-secondary small mb-0 mt-2", text: "Any S3-compatible endpoint works today, including self-hosted MinIO." }),
  ));

  async function refresh() {
    try {
      const payload = await api("/api/backup/remote", { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      renderDestination(payload.config);
      renderSchedule(payload.schedule || {});
    } catch (error) {
      if (ctx.signal.aborted) return;
      destinationMount.replaceChildren(card("Destination", "",
        el("div", { class: "alert alert-danger mb-0", role: "alert", text: `Unable to read the backup configuration: ${error.message}` })));
    }
  }

  function renderDestination(config) {
    const configured = Boolean(config);
    const endpoint = el("input", { id: "bk-endpoint", class: "form-control", type: "url", autocomplete: "off", value: config?.endpoint || "" });
    const bucket = el("input", { id: "bk-bucket", class: "form-control", type: "text", autocomplete: "off", value: config?.bucket || "" });
    const region = el("input", { id: "bk-region", class: "form-control", type: "text", autocomplete: "off", value: config?.region || "" });
    const prefix = el("input", { id: "bk-prefix", class: "form-control", type: "text", autocomplete: "off", value: config?.prefix || "" });
    const accessKey = el("input", { id: "bk-access", class: "form-control", type: "text", autocomplete: "off", value: config?.access_key || "" });
    const secretKey = el("input", {
      id: "bk-secret", class: "form-control", type: "password", autocomplete: "new-password",
      placeholder: configured ? "Leave blank to keep the stored key" : "",
    });
    const insecure = el("input", { id: "bk-insecure", class: "form-check-input", type: "checkbox", checked: Boolean(config?.allow_insecure) });
    const providerHint = el("div", { class: "text-secondary small mt-1" });

    const provider = el("select", { id: "bk-provider", class: "form-select" },
      el("option", { value: "", text: "Choose a provider…" }),
      PROVIDERS.map((entry) => el("option", { value: entry.id, text: entry.label })));
    provider.addEventListener("change", () => {
      const entry = PROVIDERS.find((item) => item.id === provider.value);
      if (!entry) {
        providerHint.replaceChildren();
        return;
      }
      // Only the transport-shaped fields are filled. Bucket, prefix and the
      // credentials are the operator's; overwriting those on a provider change
      // would silently discard what they already typed.
      region.value = entry.region;
      endpoint.value = entry.endpoint.replace("{region}", entry.region);
      providerHint.replaceChildren(el("span", { text: entry.hint }));
    });

    const save = el("button", { class: "btn btn-primary", type: "button", text: configured ? "Save changes" : "Save destination" });
    save.addEventListener("click", async () => {
      const body = {
        endpoint: endpoint.value.trim(), bucket: bucket.value.trim(), region: region.value.trim(),
        prefix: prefix.value.trim(), access_key: accessKey.value.trim(), allow_insecure: insecure.checked,
      };
      for (const [label, value] of [["an endpoint", body.endpoint], ["a bucket", body.bucket], ["a region", body.region], ["an access key", body.access_key]]) {
        if (!value) {
          toast(`Enter ${label}.`, true);
          return;
        }
      }
      // Absent, not empty: the server reads a missing key as "keep the stored
      // secret" and an empty string the same way, but sending nothing is the
      // clearer statement of intent.
      if (secretKey.value) body.secret_key = secretKey.value;
      else if (!configured) {
        toast("Enter the secret key for this destination.", true);
        return;
      }
      if (body.endpoint.startsWith("http://") && !body.allow_insecure) {
        toast("A plaintext endpoint needs “allow insecure” ticked, or use HTTPS.", true);
        return;
      }
      try {
        await withBusy(save, async () => {
          await api("/api/backup/remote", { method: "PUT", body, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast("Destination saved.");
          secretKey.value = "";
          await refresh();
        });
      } catch (error) {
        if (!ctx.signal.aborted) toast(error.message, true);
      }
    });

    const clear = el("button", { class: "btn btn-outline-danger", type: "button", icon: "trash", text: "Remove destination" });
    clear.addEventListener("click", async () => {
      const typed = await confirmAction({
        title: "Remove the backup destination?",
        message: "Scheduled uploads stop immediately. Archives already uploaded are not touched, and local backups keep running.",
        confirmLabel: "Remove it",
        keyword: "remove",
      });
      if (ctx.signal.aborted || typed !== "remove") return;
      try {
        await withBusy(clear, async () => {
          await api("/api/backup/remote", { method: "DELETE", body: {}, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast("Destination removed.");
          await refresh();
        });
      } catch (error) {
        if (!ctx.signal.aborted) toast(error.message, true);
      }
    });

    destinationMount.replaceChildren(card(
      "Destination",
      configured ? "Every site's backups upload here" : "No destination configured",
      !configured
        ? el("div", { class: "alert alert-warning", role: "status", text: "Backups stay on this host until a destination is set. A host that loses its disk loses its backups with it." })
        : null,
      el("div", { class: "row g-2 mb-3" }, el("div", { class: "col-md-6" }, provider, providerHint)),
      el("div", { class: "row g-3" },
        field("Endpoint", endpoint, "The S3 API endpoint, including https://"),
        field("Bucket", bucket),
        field("Region", region),
        field("Prefix", prefix, "Key prefix inside the bucket, for example wpfy"),
        field("Access key", accessKey),
        field("Secret key", secretKey, configured
          ? "Stored and never shown again. Leave blank to keep it; enter a value to replace it."
          : "Stored and never shown again."),
        el("div", { class: "col-12" }, el("label", { class: "form-check" }, insecure,
          el("span", { class: "form-check-label", text: "Allow a plaintext (http://) endpoint" })))),
      el("div", { class: "d-flex flex-wrap gap-2 mt-3" }, save, configured ? clear : null)));
  }

  function renderSchedule(schedule) {
    const cadence = el("select", { id: "bk-cadence", class: "form-select" },
      el("option", { value: "daily", text: "Daily" }), el("option", { value: "weekly", text: "Weekly" }));
    const time = el("input", { id: "bk-time", class: "form-control", type: "time", value: "02:30" });
    const weekday = el("select", { id: "bk-weekday", class: "form-select" },
      ["mon", "tue", "wed", "thu", "fri", "sat", "sun"].map((value) => el("option", { value, text: value })));
    const upload = el("input", { id: "bk-upload", class: "form-check-input", type: "checkbox", checked: true });
    const weekdayWrap = el("div", { class: "col-md-3 d-none" },
      el("label", { class: "form-label", for: "bk-weekday", text: "Weekday" }), weekday);
    cadence.addEventListener("change", () => weekdayWrap.classList.toggle("d-none", cadence.value !== "weekly"));

    const save = el("button", { class: "btn btn-primary", type: "button", icon: "device-floppy", text: "Save schedule" });
    save.addEventListener("click", async () => {
      const body = { cadence: cadence.value, time: time.value, upload_s3: upload.checked };
      if (cadence.value === "weekly") body.weekday = weekday.value;
      if (!/^\d{2}:\d{2}$/.test(body.time)) {
        toast("Enter a time as HH:MM.", true);
        return;
      }
      try {
        await withBusy(save, async () => {
          await api("/api/backup/schedule", { method: "PUT", body, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast("Schedule saved.");
          await refresh();
        });
      } catch (error) {
        if (!ctx.signal.aborted) toast(error.message, true);
      }
    });

    const disable = el("button", { class: "btn btn-outline-danger", type: "button", icon: "trash", text: "Disable schedule" });
    disable.addEventListener("click", async () => {
      const confirmed = await confirmAction({
        title: "Disable scheduled backups?",
        message: "No backup runs automatically after this. Manual backups from each site still work.",
        confirmLabel: "Disable",
      });
      if (ctx.signal.aborted || !confirmed) return;
      try {
        await withBusy(disable, async () => {
          await api("/api/backup/schedule", { method: "DELETE", body: {}, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast("Schedule disabled.");
          await refresh();
        });
      } catch (error) {
        if (!ctx.signal.aborted) toast(error.message, true);
      }
    });

    scheduleMount.replaceChildren(card("Schedule", "Systemd timer on this host",
      el("p", { class: "text-secondary", text: schedule.message || "No schedule reported." }),
      el("div", { class: "row g-3 align-items-end" },
        el("div", { class: "col-md-3" }, el("label", { class: "form-label", for: "bk-cadence", text: "Cadence" }), cadence),
        el("div", { class: "col-md-3" }, el("label", { class: "form-label", for: "bk-time", text: "Time" }), time),
        weekdayWrap,
        el("div", { class: "col-md-3" }, el("label", { class: "form-check mt-4" }, upload,
          el("span", { class: "form-check-label", text: "Upload to the destination" })))),
      el("div", { class: "d-flex flex-wrap gap-2 mt-3" }, save, disable)));
  }

  await refresh();
});
