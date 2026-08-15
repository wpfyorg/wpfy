/* Instance: what this installation is, and where it keeps things.
 *
 * The page you open to answer "which version is this, where does it write, and
 * is the edge actually up" without an SSH session. Two independent reads, each
 * degrading on its own -- diagnostics shelling out to Docker is exactly the call
 * that fails on a host in trouble, and losing the version and paths with it
 * would take the page down at the moment it is most worth having.
 */

import { registerPage, el, api, withBusy } from "./panel.js";

function card(title, subtitle, ...body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header d-block" },
      el("h3", { class: "card-title mb-0", text: title }),
      subtitle ? el("p", { class: "text-secondary mb-0 small", text: subtitle }) : null),
    el("div", { class: "card-body" }, body));
}

function facts(pairs) {
  return el("dl", { class: "row mb-0" }, pairs.flatMap(([label, value]) => [
    el("dt", { class: "col-sm-4 text-secondary", text: label }),
    el("dd", { class: "col-sm-8 font-monospace text-break", text: value === null || value === undefined || value === "" ? "–" : String(value) }),
  ]));
}

registerPage("instance", async (ctx) => {
  ctx.header({ icon: "info-circle",
    title: "Instance",
    subtitle: "This wpfy installation",
    breadcrumb: [["/dashboard", "Dashboard"], [null, "Instance"]],
  });

  const aboutMount = el("div", {});
  const pathsMount = el("div", {});
  const diagnosticsMount = el("div", {});
  ctx.mount.append(aboutMount, pathsMount, diagnosticsMount);

  async function loadInstance() {
    try {
      const payload = await api("/api/instance", { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      aboutMount.replaceChildren(card("About", "", facts([
        ["Version", payload.version],
        ["Docker", payload.docker_version],
        ["Edge proxy", payload.traefik],
        ["Sites", payload.site_count],
      ])));
      const paths = payload.paths || {};
      pathsMount.replaceChildren(card("Paths", "Where this installation reads and writes", facts([
        ["Install root", paths.install_root],
        ["Config", paths.config_dir],
        ["State", paths.state_dir],
        ["Logs", paths.log_dir],
      ])));
    } catch (error) {
      if (ctx.signal.aborted) return;
      aboutMount.replaceChildren(card("About", "",
        el("div", { class: "alert alert-danger mb-0", role: "alert", text: `Unable to read instance facts: ${error.message}` })));
    }
  }

  async function loadDiagnostics(button = null) {
    const body = el("div", { class: "text-secondary", text: "Running diagnostics…" });
    diagnosticsMount.replaceChildren(card("Diagnostics", "Host-level checks", body, refreshButton()));
    try {
      const run = async () => {
        const payload = await api("/api/system/diagnostics", { signal: ctx.signal });
        if (ctx.signal.aborted) return;
        const checks = payload.checks || [];
        body.replaceChildren(checks.length
          ? el("div", { class: "table-responsive" }, el("table", { class: "table table-vcenter mb-0" },
            el("thead", {}, el("tr", {}, el("th", { text: "Status" }), el("th", { text: "Check" }), el("th", { text: "Message" }))),
            el("tbody", {}, checks.map((check) => el("tr", {},
              el("td", { class: check.ok ? "text-green" : "text-danger", text: check.ok ? "Pass" : "Fail" }),
              el("td", { text: check.name || "–" }),
              el("td", { text: check.message || "–" }))))))
          : el("p", { class: "text-secondary mb-0", text: "No diagnostics were reported." }));
      };
      await (button ? withBusy(button, run) : run());
    } catch (error) {
      if (ctx.signal.aborted) return;
      body.replaceChildren(el("div", { class: "alert alert-danger mb-0", role: "alert", text: `Diagnostics failed: ${error.message}` }));
    }
  }

  function refreshButton() {
    const button = el("button", { class: "btn mt-3", type: "button", text: "Run again" });
    button.addEventListener("click", () => loadDiagnostics(button));
    return button;
  }

  await Promise.all([loadInstance(), loadDiagnostics()]);
});
