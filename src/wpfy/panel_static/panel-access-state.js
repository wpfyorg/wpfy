// Pure view-model for the Panel access card. Deliberately import-free so
// tests can exercise the state mapping directly with node, without dragging
// in the shell module graph. page-settings.js renders exactly what this
// returns; copy lives here so the card cannot drift from the contract.

export function panelAccessViewModel(basic) {
  const enabled = Boolean(basic.enabled);
  // Server-derived state from the router's own content, never a guess:
  //   enforced -- recognized router carries exactly the stored credential
  //   staged   -- stored but verifiably nothing enforces it
  //   stale    -- a router enforces a DIFFERENT credential than stored, or
  //               enforces one while nothing is stored: the old prompt is
  //               live either way
  //   unknown  -- exposed but wpfy cannot attribute the router
  //   off      -- nothing stored and verifiably no middleware anywhere
  const authState = basic.auth_state || "unknown";
  const enforced = authState === "enforced";
  const stale = authState === "stale";
  const unknown = authState === "unknown";
  // A prompt may exist whenever a router enforces something -- including
  // stale, where the live credential is not ours -- or when enforcement
  // cannot be verified. Staged is verifiably prompt-free.
  const gated = enforced || stale || unknown;
  // Disable needs something to remove at the router: a stored credential, or
  // a stale middleware wpfy can rewrite away. Unknown is refused server-side
  // (409) until the router is recognizable again.
  const disableAvailable = (enabled || stale) && !unknown;

  const badge = enforced
    ? { class: "bg-green-lt text-green", text: "Enabled" }
    : stale
      ? { class: "bg-warning-lt text-warning", text: "Stale" }
      : unknown
        ? { class: "bg-warning-lt text-warning", text: "Unverified" }
        : authState === "staged"
          ? { class: "bg-warning-lt text-warning", text: "Staged" }
          : { class: "bg-secondary-lt text-secondary", text: "Off" };

  const subtitle = enforced
    ? `HTTP basic auth is configured for public access (user: ${basic.username || "–"})`
    : stale
      ? enabled
        ? "The public router enforces a different credential than the one stored here. Rotate or disable to take over the prompt."
        : "The public router enforces a credential wpfy does not hold. Enable to take over the prompt, or disable to end it."
      : unknown
        ? enabled
          ? "Basic auth is saved, but wpfy cannot verify whether the public router enforces it."
          : "The public domain is exposed through a router wpfy cannot verify. It may or may not prompt for basic auth."
        : authState === "staged"
          ? "Basic auth is saved but nothing currently enforces it on the public domain."
          : "No HTTP basic auth on the public domain";

  // Backend refuses (409) to remove the credential while the router is
  // unattributable -- the operator must resolve the router first, so the
  // action is hidden rather than offered and doomed.
  const disableMessage = enforced
    ? "The public panel domain answers without the HTTP basic-auth prompt until it is enabled again."
    : stale
      ? enabled
        ? "The public router enforces a different credential than the one stored here. Disabling removes the router's basic-auth middleware, ending that prompt."
        : "The public router enforces a credential wpfy does not hold. Disabling removes the router's basic-auth middleware, ending that prompt."
      : "Disabling removes the stored credential. No public router currently enforces it, so the public domain does not change.";

  const footer = enforced
    ? "Guards the public panel domain with HTTP basic auth. Loopback access and the SSH tunnel stay unguarded by design."
    : stale
      ? "The public domain is gated by a credential wpfy does not hold. Loopback access and the SSH tunnel stay unguarded by design."
      : unknown
        ? "Enforcement on the public domain could not be verified; check the router before relying on it. Loopback access and the SSH tunnel stay unguarded by design."
        : authState === "staged"
          ? "The credential is stored but not applied to the public domain. Loopback access and the SSH tunnel stay unguarded by design."
          : "Nothing gates the public panel domain beyond the panel login. Loopback access and the SSH tunnel stay unguarded by design.";

  return {
    authState,
    enabled,
    gated,
    enforceKnown: enforced,
    badge,
    subtitle,
    footer,
    disableAvailable,
    disableMessage,
  };
}

// Save-button toast copy, derived from the server's answer rather than
// assuming success means enforced.
export function panelAccessSaveToast(payload) {
  const who = payload.username ? ` for ${payload.username}` : "";
  if (payload.auth_state === "enforced") return `Panel basic auth enabled${who}.`;
  if (payload.auth_state === "staged") return `Credential${who} saved; nothing currently enforces it on the public domain.`;
  return `Credential${who} saved; wpfy could not verify enforcement on the public domain.`;
}
