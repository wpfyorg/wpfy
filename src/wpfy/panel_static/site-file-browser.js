import {
  el, api, apiUpload, apiDownload, confirmAction, withBusy, toast,
  formatBytes, formatTime, onPanelEvent,
} from "./panel.js";

const MAX_EDIT_BYTES = 1024 * 1024;
const MAX_UPLOAD_BYTES = 256 * 1024 * 1024;
const CHMOD_MODES = ["0600", "0640", "0644", "0700", "0750", "0755"];

function card(title, body) {
  return el("div", { class: "card mb-3" },
    el("div", { class: "card-header" }, el("h3", { class: "card-title", text: title })),
    el("div", { class: "card-body" }, body));
}

function errorCard(message) {
  return el("div", { class: "alert alert-danger mb-0", role: "alert", text: message });
}

function joinPath(path, name) {
  return [path, name].filter(Boolean).join("/");
}

function filePath(domain, path = "", action = "") {
  const query = new URLSearchParams();
  if (path) query.set("path", path);
  return `/api/sites/${encodeURIComponent(domain)}/files${action}${query.size ? `?${query}` : ""}`;
}

export function renderFileBrowser(ctx, domain, mount) {
  const body = el("div", { class: "text-secondary", text: "Loading files…" });
  mount.append(card("Files", body));
  const encodedDomain = encodeURIComponent(domain);
  let currentPath = "";

  function renderBreadcrumbs(path, navigate) {
    const crumbs = [el("button", { class: "btn btn-link p-0", type: "button", text: "Site root", onclick: () => navigate("") })];
    const parts = path ? path.split("/") : [];
    parts.forEach((part, index) => {
      const target = parts.slice(0, index + 1).join("/");
      crumbs.push(el("span", { class: "text-secondary px-1", text: "/" }),
        el("button", { class: "btn btn-link p-0", type: "button", text: part, onclick: () => navigate(target) }));
    });
    return el("nav", { class: "mb-3", "aria-label": "File path" }, crumbs);
  }

  async function refresh(path = currentPath) {
    currentPath = path;
    try {
      const payload = await api(filePath(domain, path), { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      renderListing(payload);
    } catch (failed) {
      if (ctx.signal.aborted) return;
      body.replaceChildren(errorCard(`Unable to load files: ${failed.message}`));
    }
  }

  function renderListing(payload) {
    const path = payload.path || "";
    currentPath = path;
    const entries = Array.isArray(payload.entries) ? payload.entries : [];
    const status = el("div", { class: "mt-3" });
    const folder = el("input", { class: "form-control", "aria-label": "New folder name", placeholder: "New folder name" });
    const mkdir = el("button", { class: "btn btn-primary", type: "button", icon: "folder", text: "Create folder" });
    const upload = el("input", { class: "form-control", type: "file", "aria-label": "Upload file" });
    const uploadButton = el("button", { class: "btn btn-outline-primary", type: "button", text: "Upload" });

    async function createFolder() {
      const name = folder.value.trim();
      if (!name) {
        toast("Enter a folder name.", true);
        return;
      }
      try {
        await withBusy(mkdir, async () => {
          await api(`/api/sites/${encodedDomain}/files/mkdir`, {
            method: "POST", body: { path: joinPath(currentPath, name) }, signal: ctx.signal,
          });
          if (ctx.signal.aborted) return;
          folder.value = "";
          await refresh();
          if (ctx.signal.aborted) return;
          toast("Folder created.");
        });
        if (ctx.signal.aborted) return;
      } catch (failed) {
        if (ctx.signal.aborted) return;
        status.replaceChildren(errorCard(`Unable to create folder: ${failed.message}`));
      }
    }

    async function uploadFile() {
      const file = upload.files?.[0];
      if (!file) {
        toast("Choose a file to upload.", true);
        return;
      }
      if (file.size > MAX_UPLOAD_BYTES) {
        status.replaceChildren(errorCard(`Uploads are limited to ${formatBytes(MAX_UPLOAD_BYTES)}.`));
        return;
      }
      try {
        await withBusy(uploadButton, async () => {
          await apiUpload(filePath(domain, joinPath(currentPath, file.name), "/upload"), file, { signal: ctx.signal });
          if (ctx.signal.aborted) return;
          upload.value = "";
          await refresh();
          if (ctx.signal.aborted) return;
          toast("File uploaded.");
        });
        if (ctx.signal.aborted) return;
      } catch (failed) {
        if (ctx.signal.aborted) return;
        status.replaceChildren(errorCard(`Unable to upload file: ${failed.message}`));
      }
    }

    mkdir.addEventListener("click", createFolder);
    uploadButton.addEventListener("click", uploadFile);

    const table = el("div", { class: "table-responsive mt-3" }, el("table", { class: "table table-vcenter mb-0" },
      el("thead", {}, el("tr", {}, el("th", { text: "Name" }), el("th", { text: "Size" }),
        el("th", { text: "Mode" }), el("th", { text: "Modified" }), el("th", { class: "w-1", text: "" }))),
      el("tbody", {}, entries.length ? entries.map((entry) => entryRow(entry, path, status)) :
        el("tr", {}, el("td", { colspan: 5, class: "text-secondary", text: "This folder is empty." }))
    )));

    body.replaceChildren(renderBreadcrumbs(path, refresh),
      el("div", { class: "row g-2" },
        el("div", { class: "col-md" }, folder), el("div", { class: "col-md-auto" }, mkdir)),
      el("div", { class: "row g-2 mt-1" },
        el("div", { class: "col-md" }, upload), el("div", { class: "col-md-auto" }, uploadButton)),
      table, status);
  }

  function entryRow(entry, path, status) {
    const target = joinPath(path, entry.name);
    const isDirectory = entry.type === "dir";
    const open = el("button", { class: "btn btn-link p-0 text-start", type: "button", text: entry.name });
    open.addEventListener("click", () => {
      if (isDirectory) refresh(target);
      else if (entry.type === "file") openEditor(target, entry);
      else status.replaceChildren(errorCard(`${entry.name} is not a regular file and cannot be opened here.`));
    });
    const rename = el("button", { class: "btn btn-outline-secondary btn-sm", type: "button", text: "Rename" });
    const chmod = el("select", { class: "form-select form-select-sm", "aria-label": `Permissions for ${entry.name}` },
      CHMOD_MODES.map((mode) => el("option", { value: mode, selected: mode === entry.mode, text: mode })));
    const remove = el("button", { class: "btn btn-outline-danger btn-sm", type: "button", text: "Delete" });

    rename.addEventListener("click", () => {
      const to = el("input", { class: "form-control", "aria-label": `New name for ${entry.name}`, value: entry.name });
      const submit = el("button", { class: "btn btn-primary", type: "button", text: "Rename" });
      status.replaceChildren(el("div", { class: "input-group" }, to, submit));
      to.focus();
      submit.addEventListener("click", async () => {
        const name = to.value.trim();
        if (!name || name === entry.name) return;
        try {
          await withBusy(submit, async () => {
            await api(`/api/sites/${encodedDomain}/files/rename`, {
              method: "POST", body: { path: target, to: joinPath(path, name) }, signal: ctx.signal,
            });
            if (ctx.signal.aborted) return;
            await refresh();
            if (ctx.signal.aborted) return;
            toast("File renamed.");
          });
          if (ctx.signal.aborted) return;
        } catch (failed) {
          if (ctx.signal.aborted) return;
          status.replaceChildren(errorCard(`Unable to rename ${entry.name}: ${failed.message}`));
        }
      });
    });

    chmod.addEventListener("change", async () => {
      try {
        await withBusy(chmod, async () => {
          const result = await api(`/api/sites/${encodedDomain}/files/chmod`, {
            method: "POST", body: { path: target, mode: chmod.value }, signal: ctx.signal,
          });
          if (ctx.signal.aborted) return;
          entry.mode = result.mode || chmod.value;
          toast(`Permissions changed to ${entry.mode}.`);
        });
        if (ctx.signal.aborted) return;
      } catch (failed) {
        if (ctx.signal.aborted) return;
        chmod.value = entry.mode || "0644";
        status.replaceChildren(errorCard(`Unable to change permissions: ${failed.message}`));
      }
    });

    remove.addEventListener("click", async () => {
      const confirmed = await confirmAction({
        title: `Delete ${entry.name}?`,
        message: "This permanently removes the selected item.",
        detail: target,
        confirmLabel: "Delete",
        keyword: isDirectory ? entry.name : null,
      });
      if (ctx.signal.aborted || !confirmed) return;
      try {
        await withBusy(remove, async () => {
          await api(filePath(domain), {
            method: "DELETE", body: { path: target, ...(isDirectory ? { confirm: confirmed } : {}) }, signal: ctx.signal,
          });
          if (ctx.signal.aborted) return;
          await refresh();
          if (ctx.signal.aborted) return;
          toast(`${entry.name} deleted.`);
        });
        if (ctx.signal.aborted) return;
      } catch (failed) {
        if (ctx.signal.aborted) return;
        status.replaceChildren(errorCard(`Unable to delete ${entry.name}: ${failed.message}`));
      }
    });

    return el("tr", {}, el("td", { class: isDirectory ? "font-monospace" : "" }, open),
      el("td", { text: isDirectory ? "–" : formatBytes(entry.size) }),
      el("td", { class: "font-monospace", text: entry.mode || "–" }),
      el("td", { text: formatTime(Number(entry.modified) * 1000) }),
      el("td", { class: "text-nowrap" }, el("div", { class: "btn-list" }, rename, chmod, remove)));
  }

  function download(target, name, status) {
    return async (button) => {
      try {
        await withBusy(button, async () => {
          await apiDownload(filePath(domain, target, "/download"), name, { signal: ctx.signal });
          if (ctx.signal.aborted) return;
        });
        if (ctx.signal.aborted) return;
      } catch (failed) {
        if (ctx.signal.aborted) return;
        status.replaceChildren(errorCard(`Unable to download ${name}: ${failed.message}`));
      }
    };
  }

  async function openEditor(target, entry) {
    const editorBody = el("div", { class: "text-secondary", text: "Loading file…" });
    body.replaceChildren(card(entry.name, editorBody));
    const status = el("div", { class: "mt-3" });
    const downloadButton = el("button", { class: "btn btn-outline-primary", type: "button", text: "Download" });
    downloadButton.addEventListener("click", () => download(target, entry.name, status)(downloadButton));
    // Built once, before the size and encoding checks: every state that replaces
    // the listing needs a way back to it. A file that cannot be edited is still
    // a file the operator opened by accident, and leaving them with only a
    // Download button makes a page reload the only exit.
    const back = el("button", { class: "btn btn-outline-secondary", type: "button", text: "Back to files" });
    back.addEventListener("click", () => refresh(currentPath));
    if (Number(entry.size) > MAX_EDIT_BYTES) {
      editorBody.replaceChildren(el("p", { class: "text-secondary mb-3", text: `Files over ${formatBytes(MAX_EDIT_BYTES)} cannot be edited in the panel.` }),
        el("div", { class: "btn-list" }, downloadButton, back), status);
      return;
    }
    try {
      const payload = await api(filePath(domain, target, "/content"), { signal: ctx.signal });
      if (ctx.signal.aborted) return;
      const content = el("textarea", { class: "form-control font-monospace", rows: 20, "aria-label": `Contents of ${entry.name}`, value: payload.content || "" });
      const save = el("button", { class: "btn btn-primary", type: "button", icon: "device-floppy", text: "Save" });
      save.addEventListener("click", async () => {
        if (entry.name === "wp-config.php") {
          const confirmed = await confirmAction({
            title: "Save wp-config.php?",
            message: "A broken configuration takes the site down immediately.",
            detail: target,
            confirmLabel: "Save wp-config.php",
            keyword: "wp-config.php",
          });
          if (ctx.signal.aborted || confirmed !== "wp-config.php") return;
        }
        try {
          await withBusy(save, async () => {
            await api(`/api/sites/${encodedDomain}/files/content`, {
              method: "PUT", body: { path: target, content: content.value }, signal: ctx.signal,
            });
            if (ctx.signal.aborted) return;
            toast(`${entry.name} saved.`);
          });
          if (ctx.signal.aborted) return;
        } catch (failed) {
          if (ctx.signal.aborted) return;
          status.replaceChildren(errorCard(`Unable to save ${entry.name}: ${failed.message}`));
        }
      });
      editorBody.replaceChildren(content, el("div", { class: "btn-list mt-3" }, save, downloadButton, back), status);
    } catch (failed) {
      if (ctx.signal.aborted) return;
      if (failed.message === "file is not valid UTF-8 text") {
        editorBody.replaceChildren(el("p", { class: "text-secondary mb-3", text: "This file is not valid UTF-8 text and cannot be edited in the panel." }),
          el("div", { class: "btn-list" }, downloadButton, back), status);
        return;
      }
      editorBody.replaceChildren(errorCard(`Unable to load ${entry.name}: ${failed.message}`),
        el("div", { class: "btn-list mt-3" }, downloadButton, back), status);
    }
  }

  ctx.onLeave(onPanelEvent((event) => {
    if (event.domain === domain && String(event.action || "").startsWith("files.") && !ctx.signal.aborted) refresh();
  }));
  refresh();
}
