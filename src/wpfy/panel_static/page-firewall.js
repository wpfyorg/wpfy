/* Firewall: which ports accept a connection, and what happens to whoever gets in.
 *
 * Two halves that are genuinely different subsystems and are kept visually
 * separate rather than blended into one "security" mush:
 *
 *   Ports (ufw)      — refuses the connection at all.
 *   Intrusion (f2b)  — lets it in, then bans the address that misbehaves.
 *
 * The lockout copy here is not decoration. Denying or removing the SSH port
 * severs the connection this panel is reached over, and no button on this page
 * can undo it afterwards. The server refuses those two operations unless the
 * request carries the SSH port as a typed confirmation; this page is where the
 * operator types it, having been told exactly what it costs.
 */

import { registerPage, el, api, toast, confirmAction, withBusy, pollJob, stepText } from "./panel.js";

const PROTOCOLS = ["tcp", "udp"];

function card(title, subtitle, ...body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header d-block" },
      el("h3", { class: "card-title mb-0", text: title }),
      subtitle ? el("p", { class: "text-secondary mb-0 small", text: subtitle }) : null),
    el("div", { class: "card-body" }, body));
}

function alert(message, kind = "danger") {
  return el("div", { class: `alert alert-${kind} mb-0`, role: kind === "danger" ? "alert" : "status", text: message });
}

function stateBadge(ok, onText, offText) {
  return el("span", { class: `badge ${ok ? "bg-green-lt text-green" : "bg-red-lt text-red"}`, text: ok ? onText : offText });
}

function field(label, control, hint = "") {
  return el("div", { class: "col-md" },
    el("label", { class: "form-label", for: control.id, text: label }),
    control,
    hint ? el("small", { class: "form-hint", text: hint }) : null);
}

registerPage("firewall", async (ctx) => {
  ctx.header({ icon: "flame",
    title: "Firewall",
    subtitle: "Open ports and intrusion prevention",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "Firewall"]],
  });

  const portsMount = el("div", {});
  const f2bMount = el("div", {});
  ctx.mount.append(portsMount, f2bMount);

  let state = null;

  async function refresh() {
    try {
      const payload = await api("/api/firewall", { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      state = payload;
      renderPorts(payload.ports || {});
      renderEnforcement(payload);
    } catch (error) {
      if (ctx.signal.aborted) return;
      portsMount.replaceChildren(card("Firewall", "", alert(`Unable to read firewall state: ${error.message}`)));
      f2bMount.replaceChildren();
    }
  }

  /** One mutation path for every port change, so the confirm rules live once. */
  async function mutate(button, { method, body, success }) {
    try {
      await withBusy(button, async () => {
        const payload = await api("/api/firewall/ports", { method, body, signal: ctx.signal });
        if (ctx.signal.aborted) return;
        toast(payload.message || success);
        state = { ...state, ports: payload.ports };
        renderPorts(payload.ports || {});
      });
    } catch (error) {
      if (!ctx.signal.aborted) toast(error.message, true);
    }
  }

  /* ---- ports ---- */

  /** True when a rule covers the SSH port, range included — `20:30` is the
   *  quiet way to lose a shell, because nobody reads it as "22". */
  function carriesSsh(port, protocol, sshPort) {
    const [low, high] = String(port).split(":");
    return protocol !== "udp" && Number(low) <= sshPort && sshPort <= Number(high || low);
  }

  function ruleRow(rule, ports) {
    const guarded = rule.action === "allow" && carriesSsh(rule.port, rule.protocol, ports.ssh_port);
    const remove = el("button", { class: "btn btn-sm btn-outline-danger", type: "button", icon: "trash", text: "Remove" });
    remove.addEventListener("click", async () => {
      const typed = await confirmAction(guarded ? {
        title: "Remove the rule carrying SSH?",
        message: `Port ${rule.port}/${rule.protocol} carries SSH on port ${ports.ssh_port}. Removing this rule ends remote shell access to this host, including the connection this panel is reached over.`,
        detail: "Only continue if you have console access to this machine by another route.",
        confirmLabel: "Remove the rule",
        keyword: String(ports.ssh_port),
      } : {
        title: "Remove this rule?",
        message: `Traffic to ${rule.port}/${rule.protocol} will fall back to the default policy (${ports.default_incoming || "unknown"}).`,
        confirmLabel: "Remove",
      });
      if (ctx.signal.aborted || !typed) return;
      const body = { port: rule.port, protocol: rule.protocol, action: rule.action };
      if (rule.source && rule.source !== "Anywhere") body.source = rule.source;
      if (guarded) body.confirm = String(ports.ssh_port);
      await mutate(remove, { method: "DELETE", body, success: "Rule removed." });
    });

    return el("tr", {},
      el("td", { class: "font-monospace" }, el("span", { text: `${rule.port}/${rule.protocol}` }),
        rule.v6 ? el("span", { class: "badge bg-secondary-lt text-secondary ms-2", text: "IPv6 only" }) : null,
        guarded ? el("span", { class: "badge bg-yellow-lt text-yellow ms-2", text: "carries SSH" }) : null,
        rule.comment ? el("div", { class: "text-secondary small", text: rule.comment }) : null),
      el("td", {}, el("span", {
        class: `badge ${rule.action === "allow" ? "bg-green-lt text-green" : "bg-red-lt text-red"}`, text: rule.action,
      })),
      el("td", { class: "font-monospace text-break", text: rule.source || "Anywhere" }),
      el("td", { class: "text-end" }, remove));
  }

  function addForm(ports) {
    const port = el("input", { id: "fw-port", class: "form-control", type: "text", placeholder: "443 or 2200:2210", autocomplete: "off" });
    const protocol = el("select", { id: "fw-protocol", class: "form-select" },
      PROTOCOLS.map((value) => el("option", { value, text: value })));
    const source = el("input", { id: "fw-source", class: "form-control", type: "text", placeholder: "Anywhere", autocomplete: "off" });
    const comment = el("input", { id: "fw-comment", class: "form-control", type: "text", placeholder: "Optional label", autocomplete: "off" });
    const action = el("select", { id: "fw-action", class: "form-select" },
      el("option", { value: "allow", text: "Allow" }), el("option", { value: "deny", text: "Deny" }));
    const submit = el("button", { class: "btn btn-primary", type: "button", icon: "plus", text: "Add rule" });

    const preset = el("select", { id: "fw-preset", class: "form-select", "aria-label": "Common ports" },
      el("option", { value: "", text: "Common ports…" }),
      (ports.presets || []).map((entry, index) => el("option", { value: String(index), text: `${entry.label} (${entry.port}/${entry.protocol})` })));
    const presetNote = el("div", { class: "text-secondary small mt-1" });
    preset.addEventListener("change", () => {
      const entry = (ports.presets || [])[Number(preset.value)];
      if (!entry) {
        presetNote.replaceChildren();
        return;
      }
      port.value = entry.port;
      protocol.value = entry.protocol;
      // A caution preset says why it is a bad idea in the same breath as
      // filling the field. A list that presents 3306 as neutral is worse than
      // no list at all.
      presetNote.replaceChildren(el("span", {
        class: entry.caution ? "text-danger" : "text-secondary", text: entry.note || "",
      }));
    });

    submit.addEventListener("click", async () => {
      const value = port.value.trim();
      if (!value) {
        toast("Enter a port or a low:high range.", true);
        return;
      }
      const body = { port: value, protocol: protocol.value, action: action.value };
      if (source.value.trim()) body.source = source.value.trim();
      if (comment.value.trim()) body.comment = comment.value.trim();

      // The server guards this too; asking here means the operator reads the
      // consequence before the request, not as a 400 afterwards.
      const hitsSsh = action.value === "deny" && carriesSsh(value, protocol.value, ports.ssh_port);
      if (hitsSsh) {
        const typed = await confirmAction({
          title: "Deny the port carrying SSH?",
          message: `This denies port ${value}/tcp, which carries SSH on port ${ports.ssh_port}. Remote shell access to this host ends, including the connection this panel is reached over.`,
          detail: "Only continue if you have console access to this machine by another route.",
          confirmLabel: "Deny it",
          keyword: String(ports.ssh_port),
        });
        if (ctx.signal.aborted || typed !== String(ports.ssh_port)) return;
        body.confirm = String(ports.ssh_port);
      }
      await mutate(submit, { method: "POST", body, success: "Rule added." });
      if (!ctx.signal.aborted) port.value = "";
    });

    return el("div", {},
      el("div", { class: "row g-2 mb-2" }, el("div", { class: "col-md-6" }, preset, presetNote)),
      el("div", { class: "row g-2 align-items-end" },
        field("Port", port, "A number, or low:high for a range."),
        field("Protocol", protocol),
        field("Action", action),
        field("Source", source, "Leave blank for anywhere. An address or CIDR restricts it."),
        field("Label", comment),
        el("div", { class: "col-md-auto" }, submit)));
  }

  function powerControls(ports) {
    const enable = el("button", { class: "btn btn-primary", type: "button", icon: "flame", text: "Enable firewall" });
    const disable = el("button", { class: "btn btn-outline-danger", type: "button", icon: "flame", text: "Disable firewall" });

    enable.addEventListener("click", async () => {
      const confirmed = await confirmAction({
        title: "Enable the firewall?",
        message: `Incoming traffic will be denied by default. SSH on port ${ports.ssh_port} is allowed automatically before the firewall comes up, so this connection survives.`,
        detail: "Any service on a port with no allow rule stops being reachable immediately.",
        confirmLabel: "Enable",
        danger: false,
      });
      if (ctx.signal.aborted || !confirmed) return;
      try {
        await withBusy(enable, async () => {
          const payload = await api("/api/firewall/enable", { method: "POST", body: {}, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast(payload.message || "Firewall enabled.");
          renderPorts(payload.ports || {});
        });
      } catch (error) {
        if (!ctx.signal.aborted) toast(error.message, true);
      }
    });

    disable.addEventListener("click", async () => {
      const typed = await confirmAction({
        title: "Disable the firewall?",
        message: "Every port on this host becomes reachable from the internet again, including anything bound to 0.0.0.0 that you have not thought about lately.",
        confirmLabel: "Disable it",
        keyword: "disable",
      });
      if (ctx.signal.aborted || typed !== "disable") return;
      try {
        await withBusy(disable, async () => {
          const payload = await api("/api/firewall/disable", { method: "POST", body: { confirm: "disable" }, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          toast(payload.message || "Firewall disabled.");
          renderPorts(payload.ports || {});
        });
      } catch (error) {
        if (!ctx.signal.aborted) toast(error.message, true);
      }
    });

    return el("div", { class: "d-flex flex-wrap gap-2" }, ports.active ? disable : enable);
  }

  function renderPorts(ports) {
    if (!ports.installed) {
      portsMount.replaceChildren(card("Ports", "Host firewall (ufw)",
        alert(ports.message || "ufw is not installed on this host.", "warning"),
        el("p", { class: "text-secondary mt-3 mb-1", text: "wpfy does not install it for you. To add it:" }),
        el("pre", { class: "log-output mb-0", text: "apt-get install -y ufw" })));
      return;
    }

    // `active: false` from an unchecked probe means "not known". Printing it as
    // "Not enabled" would state something the panel never looked at.
    if (ports.checked === false) {
      portsMount.replaceChildren(card("Ports", "Host firewall (ufw)",
        alert(`Firewall state could not be read: ${ports.message || "no reason reported"}`, "warning"),
        el("p", { class: "text-secondary mb-0 mt-3", text: "Rules are not shown because none were read — this is not a claim that there are none." })));
      return;
    }

    const rules = ports.rules || [];
    const table = rules.length
      ? el("div", { class: "table-responsive" }, el("table", { class: "table table-vcenter" },
        el("thead", {}, el("tr", {},
          el("th", { text: "Port" }), el("th", { text: "Action" }),
          el("th", { text: "Source" }), el("th", { class: "text-end", text: "" }))),
        el("tbody", {}, rules.map((rule) => ruleRow(rule, ports)))))
      : el("p", { class: "text-secondary", text: ports.active ? "No rules. Only the default policy applies." : "No rules configured yet." });

    portsMount.replaceChildren(card("Ports", "Host firewall (ufw)",
      el("div", { class: "d-flex flex-wrap align-items-center gap-2 mb-3" },
        stateBadge(ports.active, "Active", "Not enabled"),
        el("span", { class: "badge bg-secondary-lt text-secondary", text: `incoming: ${ports.default_incoming}` }),
        el("span", { class: "badge bg-secondary-lt text-secondary", text: `outgoing: ${ports.default_outgoing}` }),
        el("span", { class: "badge bg-blue-lt text-blue", text: `SSH: ${ports.ssh_port}` }),
        el("div", { class: "ms-auto" }, powerControls(ports))),
      !ports.active ? alert("The firewall is installed but not enabled, so none of these rules are being applied.", "warning") : null,
      table,
      el("hr"),
      el("h4", { text: "Add a rule" }),
      addForm(ports)));
  }

  /* ---- intrusion prevention ---- */

  function renderEnforcement(payload) {
    const enforcement = payload.enforcement || {};
    const install = el("button", { class: "btn btn-primary", type: "button", icon: "device-floppy", text: "Install and repair" });
    install.addEventListener("click", async () => {
      const steps = el("ul", { class: "list-group list-group-flush mt-3" });
      try {
        await withBusy(install, async () => {
          const started = await api("/api/firewall/install", { method: "POST", body: {}, signal: ctx.signal });
          if (ctx.signal.aborted) return;
          f2bMount.append(steps);
          const job = await pollJob(started.job_id, {
            signal: ctx.signal,
            onStep: (list) => {
              if (!ctx.signal.aborted) steps.replaceChildren(...list.map((item) => el("li", { class: "list-group-item", text: stepText(item) })));
            },
          });
          if (ctx.signal.aborted) return;
          if (job.state === "succeeded") toast("Intrusion prevention installed.");
          else toast(job.result?.error || "The install failed.", true);
          await refresh();
        });
      } catch (error) {
        if (!ctx.signal.aborted) toast(error.message, true);
      }
    });

    const rows = [
      ["IPv4 enforcement", enforcement.ipv4_active],
      ...(enforcement.ipv6_applicable ? [["IPv6 enforcement", enforcement.ipv6_active]] : []),
      ["DOCKER-USER chain present", enforcement.docker_user_present],
      ["wpfy chain attached", enforcement.wpfy_chain_attached],
    ];

    f2bMount.replaceChildren(card("Intrusion prevention", "fail2ban — bans addresses that fail authentication repeatedly",
      payload.action_stale
        ? alert("The installed ban action is out of date. Reinstall to pick up the current one.", "warning")
        : null,
      enforcement.degraded_reason ? alert(enforcement.degraded_reason, "warning") : null,
      el("ul", { class: "list-unstyled mb-3" }, rows.map(([label, ok]) => el("li", { class: "d-flex align-items-center gap-2 mb-1" },
        el("span", { class: `status-dot ${ok ? "bg-green" : "bg-red"}` }),
        el("span", { text: label }),
        el("span", { class: `ms-auto small ${ok ? "text-green" : "text-danger"}`, text: ok ? "active" : "inactive" })))),
      enforcement.chain_name
        ? el("p", { class: "text-secondary small" }, el("span", { text: "Chain: " }), el("span", { class: "font-monospace", text: enforcement.chain_name }))
        : null,
      !payload.ipv6_capable
        ? el("p", { class: "text-secondary small mb-3", text: "This host reports no usable IPv6 stack, so IPv6 bans are not applied." })
        : null,
      install));
  }

  await refresh();
});
