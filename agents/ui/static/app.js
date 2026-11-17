// Placeholder: shows the session returned by the server. Replaced by the real front-end.
"use strict";

async function loadSession() {
  const status = document.getElementById("status");
  const out = document.getElementById("session");
  try {
    const resp = await fetch("/api/session", {credentials: "same-origin", cache: "no-store"});
    const data = await resp.json();
    status.textContent = resp.ok ? "Signed in." : "Session request failed: " + resp.status;
    // Never show the CSRF value on screen.
    out.textContent = JSON.stringify({actions: data.actions, operator: data.operator}, null, 2);
  } catch (err) {
    status.textContent = "Session request failed.";
  }
}

document.addEventListener("DOMContentLoaded", loadSession);
