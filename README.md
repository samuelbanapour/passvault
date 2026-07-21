# PassVault

A portable, cross-platform encrypted password manager. Rust workspace with a
shared crypto core, a CLI, and a native desktop GUI (Tauri) — no cloud
sync, no telemetry, no runtime dependencies once built.

## Security design

- **Vault encryption:** XChaCha20-Poly1305 (AEAD) over the entire entry list.
- **Key derivation:** Argon2id (64 MiB, 3 iterations, 4 lanes) from your
  master password.
- **Key wrapping:** the master password only ever unwraps a random
  256-bit data encryption key (DEK) — changing your master password
  re-wraps the DEK instead of re-encrypting all your data, and rotates the
  Argon2 salt.
- Sensitive key material is zeroized on drop (`zeroize`).
- TOTP (RFC 6238) codes for 2FA-enabled entries, a configurable password
  generator, and arbitrary custom fields/secure notes per entry.

See [`core/src/vault.rs`](core/src/vault.rs) for the on-disk format.

### Email login as an alternative to a master password

For users who'd rather not manage a master password, a vault can instead be
unlocked with a one-time code sent by email (`passvault otp-init`, or the
"Use an email code instead" link in the GUI). Under the hood the code
never *is* the encryption key — a random 256-bit recovery key is generated
at setup and does the actual encrypting, exactly like a master password
would. Two ways to hold that key:

- **This device only (default):** the recovery key lives in the OS
  keychain (macOS Keychain / Windows Credential Manager / Linux Secret
  Service). Fully offline, no server, no ongoing cost — but the vault can
  only be OTP-unlocked on the device that created it.
- **Portable (`--portable`):** the recovery key is held by a small
  key-custody server (`server/`, see below) and released only after OTP
  verification, so the same vault file can be OTP-unlocked from any
  device. This is a real trust shift — it turns an offline, zero-knowledge
  tool into one where a server can (if compromised) unlock your vault.

Turn it off any time with `passvault otp-disable` (or the GUI's "Turn off
code login"), which prompts for a real master password to replace it.

(SMS was deliberately left out: there's no SMS provider that's genuinely
free — every one bills per message or gates you behind a trial with
content restrictions — and the old free workaround, carrier email-to-SMS
gateways, is now dead for AT&T/T-Mobile/Cricket/Boost and dying for
Verizon. Email has none of these problems.)

## Layout

- `core/` — `passvault-core`: crypto, vault file format, generator, TOTP.
  Framework-agnostic; both the CLI and GUI depend on it.
- `otp/` — `passvault-otp`: OTP code generation/verification, recovery-key
  generation, OS keychain access, an SMTP (`lettre`) sender, and the HTTP
  client for the key-custody server. Shared by the CLI and GUI.
- `server/` — `passvault-keyserver`: the optional key-custody server for
  portable OTP login (axum + SQLite). Self-hosted; see below.
- `cli/` — `passvault`: command-line interface (`init`, `add`, `get`,
  `list`, `edit`, `rm`, `totp`, `gen`, `passwd`, `otp-init`, `otp-status`,
  `otp-disable`, `delete-vault`).
- `gui/` — `passvault-gui`: Tauri desktop app (plain HTML/CSS/JS frontend,
  no Node/npm build step) with the same feature set plus auto-lock after
  5 minutes idle.

## Building

Requires the Rust toolchain (`rustup.rs`) and, for the GUI, `cargo install
tauri-cli --version "^2"` plus your OS's native webview (WKWebView on
macOS, WebView2 on Windows, webkit2gtk on Linux — all pre-installed on
current OS versions except Linux, where you'll need `webkit2gtk` from your
package manager).

```sh
# CLI — produces a single portable binary at target/release/passvault
cargo build --release -p passvault

# GUI — produces a proper installer, not a bare executable:
#   macOS:   target/release/bundle/macos/PassVault.app + a .dmg
#   Windows: an NSIS installer (.exe) under target/release/bundle/nsis
#   Linux:   .deb / .AppImage under target/release/bundle
cd gui/src-tauri && cargo tauri build
```

Cross-platform installers require running the build on each target OS (or
via CI, e.g. GitHub Actions with a matrix of macos/windows/ubuntu
runners) — Tauri does not cross-compile GUI bundles from a single machine.

A prebuilt macOS `PassVault.app` and `PassVault_0.1.0_aarch64.dmg` are in
`gui/release/` (apple silicon; unsigned, so first launch needs
right-click → Open, or `xattr -dr com.apple.quarantine PassVault.app`).

## CLI quick reference

```sh
passvault init                                  # create a new vault
passvault add "GitHub" -u octocat --generate     # add an entry with a generated password
passvault list                                   # list entries (no secrets)
passvault get GitHub --show                      # show a password
passvault get GitHub --copy                      # copy to clipboard, auto-clears in 20s
passvault totp GitHub                            # current 2FA code
passvault gen 24 --no-symbols                    # one-off password, nothing stored
passvault passwd                                 # change master password
```

Vault location defaults to the OS app-data directory; override with
`--vault <path>` or `$PASSVAULT_PATH`.

```sh
passvault otp-init --email you@example.com              # OTP login, this device only
passvault otp-init --email you@example.com --portable \
  --server https://your-key-server.example.com           # OTP login, any device
passvault otp-status                                      # show current login method
passvault otp-disable                                     # switch back to a master password
passvault delete-vault                                     # permanently delete this vault
passvault import exported.csv                             # import from another password manager
passvault import exported.csv --delete-after               # ...then delete the source file
```

`delete-vault` requires typing `DELETE` to continue, then re-authenticating
(master password, or a fresh OTP code) as the actual destructive step —
typing the confirmation alone is never enough. For portable (server
custody) vaults it also purges the key from the key-custody server, not
just the local file. The GUI has the same flow behind a "Delete vault…"
button in the sidebar.

`import` reads a CSV export and auto-detects the source format — Chrome,
Firefox, Safari, Bitwarden, LastPass, and 1Password are all supported, each
with their own column names and quirks (Bitwarden mixes non-login rows in
the same file; Firefox omits a title column and gets one derived from the
URL; Safari/Bitwarden may embed a TOTP secret as an `otpauth://` URI rather
than a bare secret — all handled automatically). It shows a preview
(title/username only, no passwords) and asks for confirmation before
touching the vault. The GUI has the same flow behind an "Import
passwords…" button in the sidebar, with the same password-free preview.

## Email credentials

Sending real codes needs SMTP credentials, read from environment
variables or a `KEY=VALUE` file at `<app data dir>/notify.env` (never
committed, never hardcoded):

```
SMTP_HOST=...
SMTP_PORT=587
SMTP_USER=...
SMTP_PASS=...
SMTP_FROM=passvault@yourdomain.com

PASSVAULT_KEY_SERVER_URL=https://your-key-server.example.com
```

`SMTP_INSECURE=1` skips TLS/auth entirely for pointing at a local test
catcher (Mailpit, MailHog) during development — never set it against a
real mail server.

## Running the key-custody server

Only needed for portable (`--portable`) OTP login.

```sh
export SERVER_MASTER_KEY=$(openssl rand -base64 32)   # encrypts stored keys at rest
export DATABASE_PATH=passvault-keyserver.sqlite
# plus the SMTP vars above — the server sends its own OTP codes
cargo run --release -p passvault-keyserver
```

Rate-limited to one code per account per 60s and 10/day; each OTP session
is single-use for exactly one key store/fetch/delete operation. See
[`server/src/handlers.rs`](server/src/handlers.rs) for the full design —
worth reading before trusting it with real vaults, since server custody is
a meaningfully different security model than the default local-keychain
mode (see "Email login" above).
