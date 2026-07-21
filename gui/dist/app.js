const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

let entries = [];
let selectedId = null;
let isCreating = false;
let generatorTargetInput = null;
let totpTimer = null;

const $ = (sel) => document.querySelector(sel);

// WKWebView (macOS) auto-capitalizes and auto-corrects plain text inputs by
// default, like iOS Safari — left alone it silently mutates usernames, URLs,
// and TOTP secrets as the user types them. Every text field in this app
// holds literal data, never prose, so disable all of that unconditionally.
function hardenInputs(root = document) {
  root.querySelectorAll("input, textarea").forEach((el) => {
    el.setAttribute("autocapitalize", "off");
    el.setAttribute("autocorrect", "off");
    el.setAttribute("spellcheck", "false");
  });
}
// Forms (entry detail, modals) get rebuilt via innerHTML at runtime, so
// re-apply to any input/textarea that shows up rather than tracking every
// call site by hand.
new MutationObserver(() => hardenInputs()).observe(document.body, { childList: true, subtree: true });
hardenInputs();

function toast(msg) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 2200);
}

function showScreen(name) {
  $("#screen-lock").classList.toggle("hidden", name !== "lock");
  $("#screen-vault").classList.toggle("hidden", name !== "vault");
}

// ---------- Unlock / create ----------
//
// The lock screen is rendered entirely from JS into #lock-card because
// which fields it shows depends on runtime state: whether a vault exists
// yet, and — if so — whether it's protected by a master password or by an
// emailed/texted login code. `unlockedViaOtp` tracks the latter for the
// current session so the vault view can offer "turn off code login"
// instead of "change master password".
let unlockedViaOtp = false;

async function init() {
  unlockedViaOtp = false;
  const exists = await invoke("vault_exists", { path: null });
  isCreating = !exists;

  if (exists) {
    const status = await invoke("otp_status", { path: null });
    if (status.configured) {
      renderOtpUnlockScreen(status);
      showScreen("lock");
      return;
    }
  }
  renderPasswordScreen();
  showScreen("lock");
}

function afterUnlock(fetchedEntries) {
  entries = fetchedEntries;
  renderEntryList();
  $("#btn-change-password").classList.toggle("hidden", unlockedViaOtp);
  $("#btn-disable-otp").classList.toggle("hidden", !unlockedViaOtp);
  showScreen("vault");
}

function lockCardHtml(inner) {
  $("#lock-card").innerHTML = `
    <div class="brand">
      <div class="brand-mark">🔒</div>
      <h1>PassVault</h1>
    </div>
    ${inner}
  `;
}

// ---- master password screen (also the default when creating a vault) ----

function renderPasswordScreen() {
  lockCardHtml(`
    <p class="muted">${isCreating ? "No vault found yet. Choose a master password to create one." : "Enter your master password to unlock your vault."}</p>
    <form id="unlock-form">
      <input id="unlock-password" type="password" placeholder="Master password" autocomplete="current-password" required />
      <div id="create-confirm-wrap" class="${isCreating ? "" : "hidden"}">
        <input id="create-password-confirm" type="password" placeholder="Confirm master password" autocomplete="new-password" />
      </div>
      <button type="submit" id="unlock-submit">${isCreating ? "Create vault" : "Unlock"}</button>
    </form>
    <p id="lock-error" class="error hidden"></p>
    ${isCreating ? `<p class="muted lock-switch"><a href="#" id="switch-to-otp-setup">Use an email code instead →</a></p>` : ""}
  `);

  $("#unlock-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const password = $("#unlock-password").value;
    $("#lock-error").classList.add("hidden");
    try {
      let fetched;
      if (isCreating) {
        const confirmPw = $("#create-password-confirm").value;
        if (password !== confirmPw) throw new Error("Passwords did not match");
        if (password.length < 8) throw new Error("Master password should be at least 8 characters");
        fetched = await invoke("create_vault", { path: null, masterPassword: password });
      } else {
        fetched = await invoke("unlock_vault", { path: null, masterPassword: password });
      }
      afterUnlock(fetched);
    } catch (err) {
      $("#lock-error").textContent = String(err);
      $("#lock-error").classList.remove("hidden");
    }
  });

  if (isCreating) {
    $("#switch-to-otp-setup").addEventListener("click", (e) => {
      e.preventDefault();
      renderOtpSetupChannelScreen();
    });
  }
}

// ---- OTP setup: choose channel + contact (new vault only) ----

function renderOtpSetupChannelScreen() {
  lockCardHtml(`
    <p class="muted">Get a login code by email instead of remembering a master password.</p>
    <form id="otp-setup-form">
      <input id="otp-contact" type="text" placeholder="you@example.com" required />
      <label class="range-row"><input type="checkbox" id="otp-portable" /> Unlockable from any device (advanced)</label>
      <div id="otp-server-wrap" class="hidden">
        <input id="otp-server-url" type="text" placeholder="https://your-key-server.example.com" />
      </div>
      <button type="submit" id="otp-setup-submit">Send code</button>
    </form>
    <p id="lock-error" class="error hidden"></p>
    <p class="muted lock-switch"><a href="#" id="switch-to-password-setup">← Use a master password instead</a></p>
  `);

  const contactInput = $("#otp-contact");

  $("#otp-portable").addEventListener("change", (e) => {
    $("#otp-server-wrap").classList.toggle("hidden", !e.target.checked);
  });

  $("#switch-to-password-setup").addEventListener("click", (e) => {
    e.preventDefault();
    renderPasswordScreen();
  });

  $("#otp-setup-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const contact = contactInput.value.trim();
    const portable = $("#otp-portable").checked;
    const serverUrl = portable ? $("#otp-server-url").value.trim() || null : null;
    const errEl = $("#lock-error");
    errEl.classList.add("hidden");

    try {
      const maskedContact = await invoke("otp_begin_setup", {
        args: { path: null, contact, portable, server_url: serverUrl },
      });
      renderOtpCodeEntryScreen({ mode: "setup", maskedContact });
    } catch (err) {
      errEl.textContent = String(err);
      errEl.classList.remove("hidden");
    }
  });
}

// ---- OTP unlock: existing vault already configured for code login ----

function renderOtpUnlockScreen(status) {
  lockCardHtml(`
    <p class="muted">This vault unlocks with a code sent via email to ${status.contact_masked}.</p>
    <button id="otp-send-unlock-code" class="primary">Send code</button>
    <p id="lock-error" class="error hidden"></p>
  `);

  $("#otp-send-unlock-code").addEventListener("click", async () => {
    const errEl = $("#lock-error");
    errEl.classList.add("hidden");
    try {
      const info = await invoke("otp_begin_unlock", { path: null });
      renderOtpCodeEntryScreen({ mode: "unlock", maskedContact: info.contact_masked });
    } catch (err) {
      errEl.textContent = String(err);
      errEl.classList.remove("hidden");
    }
  });
}

// ---- OTP code entry — shared by setup confirmation and unlock ----

function renderOtpCodeEntryScreen({ mode, maskedContact }) {
  lockCardHtml(`
    <p class="muted">Enter the code sent via email to ${maskedContact}.</p>
    <form id="otp-code-form">
      <input id="otp-code" type="text" inputmode="numeric" placeholder="123456" autocomplete="one-time-code" required />
      <button type="submit" id="otp-code-submit">${mode === "setup" ? "Confirm & create vault" : "Unlock"}</button>
    </form>
    <p id="lock-error" class="error hidden"></p>
    <p class="muted lock-switch"><a href="#" id="otp-code-back">← Start over</a></p>
  `);

  $("#otp-code-back").addEventListener("click", (e) => {
    e.preventDefault();
    init();
  });

  $("#otp-code-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const code = $("#otp-code").value.trim();
    const errEl = $("#lock-error");
    errEl.classList.add("hidden");
    try {
      const fetched = mode === "setup" ? await invoke("otp_confirm_setup", { code }) : await invoke("otp_confirm_unlock", { code });
      unlockedViaOtp = true;
      afterUnlock(fetched);
    } catch (err) {
      errEl.textContent = String(err);
      errEl.classList.remove("hidden");
    }
  });
}

listen("vault-locked", () => {
  selectedId = null;
  entries = [];
  toast("Vault auto-locked after inactivity");
  init();
});

$("#btn-lock").addEventListener("click", async () => {
  await invoke("lock_vault");
  selectedId = null;
  entries = [];
  init();
});

$("#btn-disable-otp").addEventListener("click", () => {
  $("#disable-otp-new").value = "";
  $("#disable-otp-confirm").value = "";
  $("#disable-otp-error").classList.add("hidden");
  $("#modal-disable-otp").classList.remove("hidden");
});
$("#disable-otp-close").addEventListener("click", () => $("#modal-disable-otp").classList.add("hidden"));
$("#disable-otp-submit").addEventListener("click", async () => {
  const newPw = $("#disable-otp-new").value;
  const confirmPw = $("#disable-otp-confirm").value;
  const errEl = $("#disable-otp-error");
  errEl.classList.add("hidden");

  if (newPw !== confirmPw) {
    errEl.textContent = "Passwords did not match";
    errEl.classList.remove("hidden");
    return;
  }
  if (newPw.length < 8) {
    errEl.textContent = "Master password should be at least 8 characters";
    errEl.classList.remove("hidden");
    return;
  }
  try {
    await invoke("otp_disable", { newMasterPassword: newPw });
    unlockedViaOtp = false;
    $("#btn-change-password").classList.remove("hidden");
    $("#btn-disable-otp").classList.add("hidden");
    $("#modal-disable-otp").classList.add("hidden");
    toast("Code login turned off — master password is now active");
  } catch (err) {
    errEl.textContent = String(err);
    errEl.classList.remove("hidden");
  }
});

// ---------- Delete vault — two stages: type DELETE, then re-authenticate ----------

function deleteVaultModalHtml(inner) {
  $("#delete-vault-modal-content").innerHTML = inner;
}

function renderDeleteStageWarning() {
  deleteVaultModalHtml(`
    <h2>Delete vault</h2>
    <p class="muted">This permanently deletes this vault and everything in it. There is no undo — passwords, notes, everything.</p>
    <label>Type <strong>DELETE</strong> to continue</label>
    <input id="delete-confirm-text" type="text" autocomplete="off" />
    <p id="delete-vault-error" class="error hidden"></p>
    <div class="modal-actions">
      <button id="delete-continue" class="danger">Continue</button>
      <button id="delete-cancel" class="ghost">Cancel</button>
    </div>
  `);
  $("#delete-cancel").addEventListener("click", () => $("#modal-delete-vault").classList.add("hidden"));
  $("#delete-continue").addEventListener("click", () => {
    const val = $("#delete-confirm-text").value.trim();
    const errEl = $("#delete-vault-error");
    if (val !== "DELETE") {
      errEl.textContent = 'Type DELETE (all caps) to continue';
      errEl.classList.remove("hidden");
      return;
    }
    if (unlockedViaOtp) {
      renderDeleteStageOtpSend();
    } else {
      renderDeleteStagePassword();
    }
  });
}

function renderDeleteStagePassword() {
  deleteVaultModalHtml(`
    <h2>Delete vault</h2>
    <p class="muted">Enter your master password to permanently delete this vault.</p>
    <input id="delete-password" type="password" placeholder="Master password" autocomplete="current-password" />
    <p id="delete-vault-error" class="error hidden"></p>
    <div class="modal-actions">
      <button id="delete-submit" class="danger">Permanently delete</button>
      <button id="delete-cancel" class="ghost">Cancel</button>
    </div>
  `);
  $("#delete-cancel").addEventListener("click", () => $("#modal-delete-vault").classList.add("hidden"));
  $("#delete-submit").addEventListener("click", async () => {
    const password = $("#delete-password").value;
    const errEl = $("#delete-vault-error");
    errEl.classList.add("hidden");
    try {
      await invoke("delete_vault_password", { password });
      finishVaultDeletion();
    } catch (err) {
      errEl.textContent = String(err);
      errEl.classList.remove("hidden");
    }
  });
}

function renderDeleteStageOtpSend() {
  deleteVaultModalHtml(`
    <h2>Delete vault</h2>
    <p class="muted">We'll send a confirmation code to verify it's really you before permanently deleting this vault.</p>
    <p id="delete-vault-error" class="error hidden"></p>
    <div class="modal-actions">
      <button id="delete-send-code" class="danger">Send code</button>
      <button id="delete-cancel" class="ghost">Cancel</button>
    </div>
  `);
  $("#delete-cancel").addEventListener("click", () => $("#modal-delete-vault").classList.add("hidden"));
  $("#delete-send-code").addEventListener("click", async () => {
    const errEl = $("#delete-vault-error");
    errEl.classList.add("hidden");
    try {
      const info = await invoke("delete_vault_otp_begin");
      renderDeleteStageOtpConfirm(info.contact_masked);
    } catch (err) {
      errEl.textContent = String(err);
      errEl.classList.remove("hidden");
    }
  });
}

function renderDeleteStageOtpConfirm(maskedContact) {
  deleteVaultModalHtml(`
    <h2>Delete vault</h2>
    <p class="muted">Enter the code sent to ${maskedContact} to permanently delete this vault.</p>
    <input id="delete-otp-code" type="text" inputmode="numeric" placeholder="123456" autocomplete="one-time-code" />
    <p id="delete-vault-error" class="error hidden"></p>
    <div class="modal-actions">
      <button id="delete-submit" class="danger">Permanently delete</button>
      <button id="delete-cancel" class="ghost">Cancel</button>
    </div>
  `);
  $("#delete-cancel").addEventListener("click", () => $("#modal-delete-vault").classList.add("hidden"));
  $("#delete-submit").addEventListener("click", async () => {
    const code = $("#delete-otp-code").value.trim();
    const errEl = $("#delete-vault-error");
    errEl.classList.add("hidden");
    try {
      await invoke("delete_vault_otp_confirm", { code });
      finishVaultDeletion();
    } catch (err) {
      errEl.textContent = String(err);
      errEl.classList.remove("hidden");
    }
  });
}

function finishVaultDeletion() {
  $("#modal-delete-vault").classList.add("hidden");
  selectedId = null;
  entries = [];
  unlockedViaOtp = false;
  toast("Vault permanently deleted");
  init();
}

$("#btn-delete-vault").addEventListener("click", () => {
  $("#modal-delete-vault").classList.remove("hidden");
  renderDeleteStageWarning();
});

// ---------- Entry list ----------

function renderEntryList() {
  const filter = $("#search").value.trim().toLowerCase();
  const list = $("#entry-list");
  list.innerHTML = "";

  const visible = entries
    .filter((e) => !filter || e.title.toLowerCase().includes(filter) || e.username.toLowerCase().includes(filter))
    .sort((a, b) => a.title.localeCompare(b.title));

  for (const entry of visible) {
    const row = document.createElement("div");
    row.className = "entry-row" + (entry.id === selectedId ? " active" : "");
    row.innerHTML = `<div class="title"></div><div class="username"></div>`;
    row.querySelector(".title").textContent = entry.title;
    row.querySelector(".username").textContent = entry.username;
    row.addEventListener("click", () => {
      selectedId = entry.id;
      renderEntryList();
      renderDetail();
    });
    list.appendChild(row);
  }
}

$("#search").addEventListener("input", renderEntryList);

$("#btn-new-entry").addEventListener("click", () => {
  selectedId = null;
  renderEntryList();
  renderDetailForm(null);
});

// ---------- Detail / edit form ----------

function renderDetail() {
  const entry = entries.find((e) => e.id === selectedId);
  if (!entry) {
    $("#detail").innerHTML = `<div class="empty-state">Select an entry, or create a new one.</div>`;
    return;
  }
  renderDetailForm(entry);
}

function renderDetailForm(entry) {
  clearInterval(totpTimer);
  const isNew = !entry;
  const e = entry || { title: "", username: "", password: "", url: "", notes: "", tags: [], totp_secret: null, custom_fields: [] };

  const detail = $("#detail");
  detail.innerHTML = `
    <form class="entry-form" id="entry-form">
      <h2>${isNew ? "New entry" : "Edit entry"}</h2>

      <div class="field">
        <label>Title</label>
        <input id="f-title" type="text" required />
      </div>
      <div class="field">
        <label>Username</label>
        <input id="f-username" type="text" />
      </div>
      <div class="field">
        <label>Password</label>
        <div class="field-row">
          <input id="f-password" type="password" />
          <button type="button" id="f-toggle-pw" class="ghost">👁</button>
          <button type="button" id="f-gen-pw" class="ghost">Generate</button>
        </div>
      </div>
      <div class="field">
        <label>URL</label>
        <input id="f-url" type="text" />
      </div>
      <div class="field">
        <label>Tags (comma separated)</label>
        <input id="f-tags" type="text" />
      </div>
      <div class="field">
        <label>TOTP secret (Base32, optional)</label>
        <input id="f-totp" type="text" placeholder="e.g. GEZDGNBVGY3TQOJQ" />
        <div id="totp-display"></div>
      </div>
      <div class="field">
        <label>Notes</label>
        <textarea id="f-notes" rows="3" style="width:100%; padding:10px 12px; border-radius:8px; border:1px solid var(--border); background: var(--panel-2); color: var(--text);"></textarea>
      </div>

      <div class="form-actions">
        <button type="submit" class="primary">${isNew ? "Create entry" : "Save changes"}</button>
        ${!isNew ? `<button type="button" id="f-delete" class="danger">Delete</button>` : ""}
      </div>
    </form>
  `;

  $("#f-title").value = e.title;
  $("#f-username").value = e.username;
  $("#f-password").value = e.password;
  $("#f-url").value = e.url;
  $("#f-tags").value = (e.tags || []).join(", ");
  $("#f-totp").value = e.totp_secret || "";
  $("#f-notes").value = e.notes;

  $("#f-toggle-pw").addEventListener("click", () => {
    const input = $("#f-password");
    input.type = input.type === "password" ? "text" : "password";
  });

  $("#f-gen-pw").addEventListener("click", () => {
    generatorTargetInput = $("#f-password");
    openGenerator();
  });

  if (!isNew) {
    $("#f-delete").addEventListener("click", async () => {
      if (!confirm(`Delete "${e.title}"? This cannot be undone.`)) return;
      await invoke("delete_entry", { id: e.id });
      entries = entries.filter((x) => x.id !== e.id);
      selectedId = null;
      renderEntryList();
      renderDetail();
      toast("Entry deleted");
    });
  }

  document.getElementById("entry-form").addEventListener("submit", async (evt) => {
    evt.preventDefault();
    const input = {
      title: $("#f-title").value.trim(),
      username: $("#f-username").value,
      password: $("#f-password").value,
      url: $("#f-url").value,
      notes: $("#f-notes").value,
      tags: $("#f-tags").value.split(",").map((t) => t.trim()).filter(Boolean),
      custom_fields: e.custom_fields || [],
      totp_secret: $("#f-totp").value.trim() || null,
    };
    if (!input.title) return;

    try {
      let saved;
      if (isNew) {
        saved = await invoke("add_entry", { input });
        entries.push(saved);
      } else {
        saved = await invoke("update_entry", { id: e.id, input });
        entries = entries.map((x) => (x.id === e.id ? saved : x));
      }
      selectedId = saved.id;
      renderEntryList();
      renderDetail();
      toast(isNew ? "Entry created" : "Entry saved");
    } catch (err) {
      toast("Error: " + err);
    }
  });

  if (e.totp_secret) {
    startTotpDisplay(e);
  }
}

function startTotpDisplay(entry) {
  const el = $("#totp-display");
  const refresh = async () => {
    try {
      const { code, seconds_remaining } = await invoke("get_totp", { id: entry.id });
      const pct = Math.round((seconds_remaining / 30) * 100);
      el.innerHTML = `
        <div class="totp-row">
          <span>${code}</span>
          <div class="bar"><div class="bar-fill" style="width:${pct}%"></div></div>
          <span class="muted">${seconds_remaining}s</span>
        </div>`;
    } catch {
      /* entry not saved yet, or secret invalid — ignore until next save */
    }
  };
  refresh();
  totpTimer = setInterval(refresh, 1000);
}

// ---------- Generator modal ----------

function openGenerator() {
  $("#modal-generator").classList.remove("hidden");
  refreshGenerated();
}

async function refreshGenerated() {
  const opts = {
    length: Number($("#gen-length").value),
    lowercase: $("#gen-lowercase").checked,
    uppercase: $("#gen-uppercase").checked,
    digits: $("#gen-digits").checked,
    symbols: $("#gen-symbols").checked,
    exclude_ambiguous: $("#gen-ambiguous").checked,
  };
  try {
    const pw = await invoke("generate_password", { opts });
    $("#gen-output").value = pw;
    const strength = await invoke("estimate_password_strength", { password: pw });
    $("#gen-strength").textContent = `~${Math.round(strength.bits)} bits of entropy (${strength.label})`;
  } catch (err) {
    $("#gen-output").value = "";
    $("#gen-strength").textContent = String(err);
  }
}

$("#gen-length").addEventListener("input", () => {
  $("#gen-length-value").textContent = $("#gen-length").value;
  refreshGenerated();
});
for (const id of ["gen-lowercase", "gen-uppercase", "gen-digits", "gen-symbols", "gen-ambiguous"]) {
  document.getElementById(id).addEventListener("change", refreshGenerated);
}
$("#gen-refresh").addEventListener("click", refreshGenerated);
$("#gen-copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("#gen-output").value);
  toast("Copied to clipboard");
});
$("#gen-use").addEventListener("click", () => {
  if (generatorTargetInput) {
    generatorTargetInput.value = $("#gen-output").value;
    generatorTargetInput.type = "text";
  }
  $("#modal-generator").classList.add("hidden");
});
$("#gen-close").addEventListener("click", () => $("#modal-generator").classList.add("hidden"));
$("#btn-generator").addEventListener("click", () => {
  generatorTargetInput = null;
  openGenerator();
});

// ---------- Change master password modal ----------

$("#btn-change-password").addEventListener("click", () => {
  $("#passwd-old").value = "";
  $("#passwd-new").value = "";
  $("#passwd-confirm").value = "";
  $("#passwd-error").classList.add("hidden");
  $("#modal-passwd").classList.remove("hidden");
});
$("#passwd-close").addEventListener("click", () => $("#modal-passwd").classList.add("hidden"));
$("#passwd-submit").addEventListener("click", async () => {
  const oldP = $("#passwd-old").value;
  const newP = $("#passwd-new").value;
  const confirm = $("#passwd-confirm").value;
  const errEl = $("#passwd-error");
  errEl.classList.add("hidden");

  if (newP !== confirm) {
    errEl.textContent = "New passwords did not match";
    errEl.classList.remove("hidden");
    return;
  }
  if (newP.length < 8) {
    errEl.textContent = "New master password should be at least 8 characters";
    errEl.classList.remove("hidden");
    return;
  }
  try {
    await invoke("change_master_password", { oldPassword: oldP, newPassword: newP });
    $("#modal-passwd").classList.add("hidden");
    toast("Master password changed");
  } catch (err) {
    errEl.textContent = String(err);
    errEl.classList.remove("hidden");
  }
});

// ---------- Import passwords from another manager's CSV export ----------

let importCsvText = null;

function importModalHtml(inner) {
  $("#import-modal-content").innerHTML = inner;
}

function renderImportPickFile() {
  importCsvText = null;
  importModalHtml(`
    <h2>Import passwords</h2>
    <p class="muted">Import a CSV export from Chrome, Firefox, Safari, Bitwarden, LastPass, or 1Password — the format is detected automatically.</p>
    <input id="import-file" type="file" accept=".csv,text/csv" />
    <p id="import-error" class="error hidden"></p>
    <div class="modal-actions">
      <button id="import-cancel" class="ghost">Cancel</button>
    </div>
  `);
  $("#import-cancel").addEventListener("click", () => $("#modal-import").classList.add("hidden"));

  $("#import-file").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    const errEl = $("#import-error");
    errEl.classList.add("hidden");
    if (!file) return;

    try {
      const text = await file.text();
      const preview = await invoke("import_preview", { csvText: text });
      if (preview.length === 0) {
        errEl.textContent = "No importable entries found — is this a password export CSV?";
        errEl.classList.remove("hidden");
        return;
      }
      importCsvText = text;
      renderImportPreview(preview);
    } catch (err) {
      errEl.textContent = String(err);
      errEl.classList.remove("hidden");
    }
  });
}

function renderImportPreview(preview) {
  const rows = preview
    .slice(0, 10)
    .map((p) => `<div class="import-row">${p.title || "(untitled)"} — ${p.username || "(no username)"}</div>`)
    .join("");
  const more = preview.length > 10 ? `<div class="muted">...and ${preview.length - 10} more</div>` : "";

  importModalHtml(`
    <h2>Import passwords</h2>
    <p class="muted">Found ${preview.length} ${preview.length === 1 ? "entry" : "entries"} to import (passwords not shown here):</p>
    <div class="import-preview-list">${rows}${more}</div>
    <p id="import-error" class="error hidden"></p>
    <div class="modal-actions">
      <button id="import-confirm" class="primary">Import ${preview.length} ${preview.length === 1 ? "entry" : "entries"}</button>
      <button id="import-cancel" class="ghost">Cancel</button>
    </div>
  `);
  $("#import-cancel").addEventListener("click", () => $("#modal-import").classList.add("hidden"));
  $("#import-confirm").addEventListener("click", async () => {
    const errEl = $("#import-error");
    errEl.classList.add("hidden");
    try {
      entries = await invoke("import_confirm", { csvText: importCsvText });
      renderEntryList();
      $("#modal-import").classList.add("hidden");
      toast(`Imported ${preview.length} ${preview.length === 1 ? "entry" : "entries"} — delete the CSV file now, it has plaintext passwords in it`);
    } catch (err) {
      errEl.textContent = String(err);
      errEl.classList.remove("hidden");
    }
  });
}

$("#btn-import").addEventListener("click", () => {
  $("#modal-import").classList.remove("hidden");
  renderImportPickFile();
});

init();
