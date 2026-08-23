import { renderFileBrowser } from "./site-file-browser.js";

/** File Manager tab: the per-site file browser is the whole tab. The browser
 *  itself (listing, upload, edit, delete) lives in site-file-browser.js and is
 *  shared; this module only adapts it to the tab contract (`render`). */
export async function render(ctx, domain) {
  renderFileBrowser(ctx, domain, ctx.mount);
}
