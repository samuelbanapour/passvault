mod vault_path;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use comfy_table::Table;
use passvault_core::{estimate_strength, generate, Entry, GeneratorOptions, Vault};
use passvault_otp::{mask_contact, KeyCustody};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "passvault", version, about = "A portable, encrypted password manager")]
struct Cli {
    /// Path to the vault file. Defaults to the OS-appropriate app data
    /// directory, or $PASSVAULT_PATH if set.
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new, empty vault.
    Init,
    /// Add a new entry.
    Add {
        title: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(short = 'U', long)]
        url: Option<String>,
        #[arg(short, long)]
        notes: Option<String>,
        /// Generate a random password instead of being prompted for one.
        #[arg(short, long)]
        generate: bool,
        #[arg(long, default_value_t = 20)]
        length: usize,
        /// Base32 TOTP secret, if this account has 2FA enabled.
        #[arg(long)]
        totp_secret: Option<String>,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
    },
    /// List all entries (titles/usernames only — no secrets shown).
    List {
        /// Only show entries whose title contains this text.
        filter: Option<String>,
    },
    /// Show a single entry.
    Get {
        query: String,
        /// Copy the password to the clipboard instead of printing it.
        #[arg(short, long)]
        copy: bool,
        /// Print the password in plaintext (default hides it).
        #[arg(short, long)]
        show: bool,
    },
    /// Print the current TOTP code for an entry.
    Totp { query: String },
    /// Edit fields of an existing entry.
    Edit {
        query: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(short = 'U', long)]
        url: Option<String>,
        #[arg(short, long)]
        notes: Option<String>,
        #[arg(long)]
        totp_secret: Option<String>,
        /// Prompt for a new password.
        #[arg(short, long)]
        password: bool,
    },
    /// Delete an entry.
    Rm { query: String },
    /// Generate a random password without storing it anywhere.
    Gen {
        #[arg(default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
        #[arg(long)]
        no_digits: bool,
        #[arg(long)]
        no_uppercase: bool,
        #[arg(long)]
        no_lowercase: bool,
        #[arg(long)]
        exclude_ambiguous: bool,
    },
    /// Change the master password.
    Passwd,
    /// Create a new vault unlocked by an emailed code instead of a master
    /// password — meant for users who'd rather not manage one.
    OtpInit {
        /// Send login codes to this email address.
        #[arg(long)]
        email: String,
        /// Store the vault's real key on a key-custody server instead of
        /// this device's keychain, so the vault can be unlocked from any
        /// device. Requires --server and trusting that server with your
        /// vault's key material.
        #[arg(long)]
        portable: bool,
        #[arg(long)]
        server: Option<String>,
    },
    /// Show whether this vault uses OTP login, and how.
    OtpStatus,
    /// Turn off OTP login and switch back to a master password.
    OtpDisable,
    /// Permanently delete this vault and everything in it. Cannot be
    /// undone. Requires re-authenticating (master password, or a fresh
    /// OTP code) as the actual destructive step.
    DeleteVault,
    /// Import entries from another password manager's CSV export (Chrome,
    /// Firefox, Safari, Bitwarden, LastPass, 1Password all work — the
    /// column format is auto-detected).
    Import {
        path: PathBuf,
        /// Delete the source CSV file after a successful import. It
        /// contains your passwords in plain text, so leaving it around
        /// defeats a lot of the point.
        #[arg(long)]
        delete_after: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let vault_path = cli.vault.clone().unwrap_or_else(vault_path::default_vault_path);

    match cli.command {
        Command::Init => cmd_init(&vault_path),
        Command::Add {
            title,
            username,
            url,
            notes,
            generate: gen_pw,
            length,
            totp_secret,
            tags,
        } => cmd_add(&vault_path, title, username, url, notes, gen_pw, length, totp_secret, tags),
        Command::List { filter } => cmd_list(&vault_path, filter),
        Command::Get { query, copy, show } => cmd_get(&vault_path, &query, copy, show),
        Command::Totp { query } => cmd_totp(&vault_path, &query),
        Command::Edit {
            query,
            username,
            url,
            notes,
            totp_secret,
            password,
        } => cmd_edit(&vault_path, &query, username, url, notes, totp_secret, password),
        Command::Rm { query } => cmd_rm(&vault_path, &query),
        Command::Gen {
            length,
            no_symbols,
            no_digits,
            no_uppercase,
            no_lowercase,
            exclude_ambiguous,
        } => cmd_gen(length, no_symbols, no_digits, no_uppercase, no_lowercase, exclude_ambiguous),
        Command::Passwd => cmd_passwd(&vault_path),
        Command::OtpInit { email, portable, server } => cmd_otp_init(&vault_path, email, portable, server),
        Command::OtpStatus => cmd_otp_status(&vault_path),
        Command::OtpDisable => cmd_otp_disable(&vault_path),
        Command::DeleteVault => cmd_delete_vault(&vault_path),
        Command::Import { path, delete_after } => cmd_import(&vault_path, &path, delete_after),
    }
}

/// Reads a password hidden from the terminal. Falls back to a plain stdin
/// line (with a visible warning) when there's no controlling TTY to hide
/// input on — e.g. CI pipelines or piped scripting, where rpassword's
/// /dev/tty access simply isn't available.
fn read_password(prompt: &str) -> Result<String> {
    match rpassword::prompt_password(prompt) {
        Ok(p) => Ok(p),
        Err(_) => {
            eprint!("{prompt}");
            std::io::stderr().flush().ok();
            eprintln!("(no TTY available — input will not be hidden)");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            Ok(line.trim_end_matches(['\r', '\n']).to_string())
        }
    }
}

/// Reads a plain (non-hidden) line — used for OTP codes, where masking
/// input just makes it error-prone to type and buys no real secrecy (the
/// code is already single-use and about to expire).
fn read_line_visible(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn unlock_via_otp(vault_path: &Path) -> Result<String> {
    let pending = passvault_otp::begin_unlock(vault_path).context("failed to start OTP login")?;
    println!("A login code was sent via email to {}", mask_contact(pending.contact()));
    let code = read_line_visible("Enter the code: ")?;
    pending.confirm(&code).context("OTP verification failed")
}

fn prompt_master_password(prompt: &str) -> Result<String> {
    if let Ok(p) = std::env::var("PASSVAULT_MASTER_PASSWORD") {
        return Ok(p);
    }
    read_password(prompt)
}

/// Prompts for (and confirms) a new master password. `env_var` names the
/// environment variable checked for non-interactive use — callers pick a
/// distinct variable for `init` vs `passwd` so the latter can't collide
/// with the "current password" variable used to unlock the vault first.
fn prompt_new_master_password(env_var: &str) -> Result<String> {
    if let Ok(p) = std::env::var(env_var) {
        return Ok(p);
    }
    let p1 = read_password("New master password: ")?;
    let p2 = read_password("Confirm master password: ")?;
    if p1 != p2 {
        bail!("passwords did not match");
    }
    if p1.len() < 8 {
        bail!("master password should be at least 8 characters");
    }
    Ok(p1)
}

fn cmd_init(vault_path: &PathBuf) -> Result<()> {
    if let Some(parent) = vault_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let password = prompt_new_master_password("PASSVAULT_MASTER_PASSWORD")?;
    Vault::create(vault_path, &password).context("failed to create vault")?;
    println!("Vault created at {}", vault_path.display());
    Ok(())
}

fn open_vault(vault_path: &PathBuf) -> Result<(Vault, String)> {
    if !vault_path.exists() {
        bail!(
            "no vault found at {} — run `passvault init` (or `passvault otp-init`) first",
            vault_path.display()
        );
    }
    let password = if passvault_otp::is_configured(vault_path) {
        unlock_via_otp(vault_path)?
    } else {
        prompt_master_password("Master password: ")?
    };
    let vault = Vault::unlock(vault_path, &password).context("failed to unlock vault")?;
    Ok((vault, password))
}

fn resolve_one<'a>(vault: &'a Vault, query: &str) -> Result<&'a Entry> {
    if let Ok(id) = Uuid::parse_str(query) {
        if let Some(e) = vault.find(id) {
            return Ok(e);
        }
    }
    let matches = vault.find_by_title(query);
    match matches.len() {
        0 => bail!("no entry matching '{query}'"),
        1 => Ok(matches[0]),
        _ => {
            let mut msg = format!("multiple entries match '{query}':\n");
            for e in &matches {
                msg.push_str(&format!("  {} — {}\n", e.id, e.title));
            }
            msg.push_str("re-run with the full UUID to disambiguate");
            bail!(msg)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_add(
    vault_path: &PathBuf,
    title: String,
    username: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    gen_pw: bool,
    length: usize,
    totp_secret: Option<String>,
    tags: Vec<String>,
) -> Result<()> {
    let (mut vault, _) = open_vault(vault_path)?;

    let mut entry = Entry::new(title);
    entry.username = username.unwrap_or_default();
    entry.url = url.unwrap_or_default();
    entry.notes = notes.unwrap_or_default();
    entry.tags = tags;
    entry.totp_secret = totp_secret;

    entry.password = if gen_pw {
        let opts = GeneratorOptions {
            length,
            ..Default::default()
        };
        let pw = generate(&opts)?;
        println!("Generated password: {pw}");
        pw
    } else {
        let p1 = read_password("Entry password: ")?;
        let p2 = read_password("Confirm password: ")?;
        if p1 != p2 {
            bail!("passwords did not match");
        }
        p1
    };

    let id = entry.id;
    vault.add_entry(entry);
    vault.save()?;
    println!("Added entry {id}");
    Ok(())
}

fn cmd_list(vault_path: &PathBuf, filter: Option<String>) -> Result<()> {
    let (vault, _) = open_vault(vault_path)?;
    let entries: Vec<&Entry> = match &filter {
        Some(f) => vault.find_by_title(f),
        None => vault.entries().iter().collect(),
    };

    if entries.is_empty() {
        println!("(no entries)");
        return Ok(());
    }

    let mut table = Table::new();
    table.set_header(vec!["Title", "Username", "URL", "TOTP", "Tags", "ID"]);
    for e in entries {
        table.add_row(vec![
            e.title.clone(),
            e.username.clone(),
            e.url.clone(),
            if e.totp_secret.is_some() { "yes".into() } else { "".into() },
            e.tags.join(", "),
            e.id.to_string(),
        ]);
    }
    println!("{table}");
    Ok(())
}

fn cmd_get(vault_path: &PathBuf, query: &str, copy: bool, show: bool) -> Result<()> {
    let (vault, _) = open_vault(vault_path)?;
    let entry = resolve_one(&vault, query)?;

    println!("Title:    {}", entry.title);
    println!("Username: {}", entry.username);
    println!("URL:      {}", entry.url);
    if !entry.notes.is_empty() {
        println!("Notes:    {}", entry.notes);
    }
    for f in &entry.custom_fields {
        if f.hidden {
            println!("{}: (hidden — use --show or copy to reveal)", f.key);
        } else {
            println!("{}: {}", f.key, f.value);
        }
    }

    if copy {
        copy_to_clipboard_temporarily(&entry.password, 20)?;
    } else if show {
        println!("Password: {}", entry.password);
    } else {
        println!("Password: (use --show to reveal or --copy to copy to clipboard)");
    }

    if let Some(secret) = &entry.totp_secret {
        let code = passvault_core::totp_now(secret)?;
        let remaining = passvault_core::totp_seconds_remaining(30);
        println!("TOTP:     {code} (expires in {remaining}s)");
    }
    Ok(())
}

fn cmd_totp(vault_path: &PathBuf, query: &str) -> Result<()> {
    let (vault, _) = open_vault(vault_path)?;
    let entry = resolve_one(&vault, query)?;
    let secret = entry
        .totp_secret
        .as_ref()
        .context("this entry has no TOTP secret configured")?;
    let code = passvault_core::totp_now(secret)?;
    let remaining = passvault_core::totp_seconds_remaining(30);
    println!("{code} (expires in {remaining}s)");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_edit(
    vault_path: &PathBuf,
    query: &str,
    username: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    totp_secret: Option<String>,
    change_password: bool,
) -> Result<()> {
    let (mut vault, _) = open_vault(vault_path)?;
    let id = resolve_one(&vault, query)?.id;

    let new_password = if change_password {
        let p1 = read_password("New entry password: ")?;
        let p2 = read_password("Confirm password: ")?;
        if p1 != p2 {
            bail!("passwords did not match");
        }
        Some(p1)
    } else {
        None
    };

    vault.update_entry(id, |e| {
        if let Some(u) = username {
            e.username = u;
        }
        if let Some(u) = url {
            e.url = u;
        }
        if let Some(n) = notes {
            e.notes = n;
        }
        if let Some(t) = totp_secret {
            e.totp_secret = Some(t);
        }
        if let Some(p) = new_password {
            e.password = p;
        }
    })?;

    vault.save()?;
    println!("Updated entry {id}");
    Ok(())
}

fn cmd_rm(vault_path: &PathBuf, query: &str) -> Result<()> {
    let (mut vault, _) = open_vault(vault_path)?;
    let id = resolve_one(&vault, query)?.id;
    let title = vault.delete_entry(id)?.title;
    vault.save()?;
    println!("Deleted '{title}' ({id})");
    Ok(())
}

fn cmd_gen(
    length: usize,
    no_symbols: bool,
    no_digits: bool,
    no_uppercase: bool,
    no_lowercase: bool,
    exclude_ambiguous: bool,
) -> Result<()> {
    let opts = GeneratorOptions {
        length,
        lowercase: !no_lowercase,
        uppercase: !no_uppercase,
        digits: !no_digits,
        symbols: !no_symbols,
        exclude_ambiguous,
    };
    let pw = generate(&opts)?;
    let (bits, label) = estimate_strength(&pw);
    println!("{pw}");
    eprintln!("~{:.0} bits of entropy ({})", bits, label.as_str());
    Ok(())
}

fn cmd_passwd(vault_path: &PathBuf) -> Result<()> {
    let (mut vault, old_password) = open_vault(vault_path)?;
    let new_password = prompt_new_master_password("PASSVAULT_NEW_MASTER_PASSWORD")?;
    vault.change_master_password(&old_password, &new_password)?;
    println!("Master password changed.");
    Ok(())
}

fn cmd_otp_init(vault_path: &PathBuf, email: String, portable: bool, server: Option<String>) -> Result<()> {
    if vault_path.exists() {
        bail!("a vault already exists at {}", vault_path.display());
    }
    let custody = if portable { KeyCustody::Server } else { KeyCustody::Local };
    let server_url = if portable {
        Some(
            server
                .or_else(|| std::env::var("PASSVAULT_KEY_SERVER_URL").ok())
                .context("--portable requires --server <url> (or $PASSVAULT_KEY_SERVER_URL)")?,
        )
    } else {
        None
    };

    let pending = passvault_otp::begin_setup(email.clone(), custody, server_url)
        .context("failed to start OTP setup — check your email provider configuration")?;
    println!("A verification code was sent to {}", mask_contact(&email));
    let code = read_line_visible("Enter the code to confirm: ")?;

    let recovery_key = pending.recovery_key.clone();
    if let Some(parent) = vault_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    pending.confirm(vault_path, &code).context("verification failed")?;
    Vault::create(vault_path, &recovery_key).context("failed to create vault")?;

    println!("Vault created at {} — protected by email login, no master password needed.", vault_path.display());
    match custody {
        KeyCustody::Local => println!("Your recovery key lives in this device's keychain — this vault can only be OTP-unlocked here."),
        KeyCustody::Server => println!("Your recovery key is held by the key-custody server, so this vault can be OTP-unlocked from any device."),
    }
    Ok(())
}

fn cmd_otp_status(vault_path: &Path) -> Result<()> {
    match passvault_otp::config_for(vault_path)? {
        None => println!("OTP login is not configured for this vault — it uses a master password."),
        Some(cfg) => {
            println!("OTP login: email");
            println!("Contact:   {}", mask_contact(&cfg.contact));
            println!(
                "Custody:   {}",
                match cfg.custody {
                    KeyCustody::Local => "this device's keychain only",
                    KeyCustody::Server => "portable (key-custody server)",
                }
            );
        }
    }
    Ok(())
}

fn cmd_otp_disable(vault_path: &PathBuf) -> Result<()> {
    if !passvault_otp::is_configured(vault_path) {
        bail!("OTP login is not configured for this vault");
    }
    let recovery_key = unlock_via_otp(vault_path)?;
    let mut vault = Vault::unlock(vault_path, &recovery_key).context("OTP verified but the recovered key didn't unlock the vault")?;

    let new_password = prompt_new_master_password("PASSVAULT_NEW_MASTER_PASSWORD")?;
    vault.change_master_password(&recovery_key, &new_password)?;

    passvault_otp::disable(vault_path)?;
    println!("OTP login disabled. This vault now uses the master password you just set.");
    Ok(())
}

fn cmd_delete_vault(vault_path: &PathBuf) -> Result<()> {
    if !vault_path.exists() {
        bail!("no vault found at {}", vault_path.display());
    }

    println!("This will PERMANENTLY delete the vault at {} and everything in it.", vault_path.display());
    println!("This cannot be undone.");

    let is_otp = passvault_otp::is_configured(vault_path);
    if is_otp {
        if let Some(cfg) = passvault_otp::config_for(vault_path)? {
            if cfg.custody == KeyCustody::Server {
                println!("This also permanently deletes the vault's key from the key-custody server.");
            }
        }
    }

    let confirm = read_line_visible("Type DELETE to continue: ")?;
    if confirm.trim() != "DELETE" {
        bail!("confirmation did not match — nothing was deleted");
    }

    // Re-authenticate as the actual destructive step, so typing "DELETE"
    // alone is never enough — you still have to prove you can currently
    // unlock the vault.
    if is_otp {
        let pending = passvault_otp::begin_unlock(vault_path).context("failed to start OTP login")?;
        println!("A confirmation code was sent via email to {}", mask_contact(pending.contact()));
        let code = read_line_visible("Enter the code to permanently delete this vault: ")?;
        pending.confirm_and_delete(&code).context("OTP verification failed — vault was not deleted")?;
        passvault_otp::disable(vault_path)?;
    } else {
        let password = prompt_master_password("Master password: ")?;
        Vault::unlock(vault_path, &password).context("incorrect master password — vault was not deleted")?;
    }

    std::fs::remove_file(vault_path).context("failed to delete vault file")?;
    println!("Vault permanently deleted.");
    Ok(())
}

fn cmd_import(vault_path: &PathBuf, csv_path: &PathBuf, delete_after: bool) -> Result<()> {
    let contents = std::fs::read_to_string(csv_path)
        .with_context(|| format!("failed to read {}", csv_path.display()))?;
    let imported = passvault_core::parse_csv(&contents).context("failed to parse CSV file")?;

    if imported.is_empty() {
        bail!("no importable entries found in {} — check it's a password export CSV", csv_path.display());
    }

    println!("Found {} entries to import:", imported.len());
    for e in imported.iter().take(10) {
        let user = if e.username.is_empty() { "(no username)" } else { &e.username };
        println!("  {} — {}", e.title, user);
    }
    if imported.len() > 10 {
        println!("  ...and {} more", imported.len() - 10);
    }

    let confirm = read_line_visible("Import these into the vault? [y/N]: ")?;
    if !confirm.trim().eq_ignore_ascii_case("y") {
        bail!("import cancelled — nothing was changed");
    }

    let (mut vault, _) = open_vault(vault_path)?;
    let count = imported.len();
    for entry in imported {
        vault.add_entry(entry);
    }
    vault.save()?;
    println!("Imported {count} entries.");

    if delete_after {
        std::fs::remove_file(csv_path).context("failed to delete source CSV file")?;
        println!("Deleted {} (it contained plaintext passwords).", csv_path.display());
    } else {
        println!(
            "Reminder: {} still contains plaintext passwords — delete it now that the import is confirmed working.",
            csv_path.display()
        );
    }
    Ok(())
}

fn copy_to_clipboard_temporarily(text: &str, seconds: u64) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new().context("could not access system clipboard")?;
    clipboard.set_text(text.to_string())?;
    println!("Password copied to clipboard. Clearing in {seconds}s (Ctrl+C to leave it)...");

    for remaining in (1..=seconds).rev() {
        print!("\r{remaining:>3}s remaining ");
        std::io::stdout().flush().ok();
        thread::sleep(Duration::from_secs(1));
    }
    println!();

    // Only clear if the clipboard still holds what we put there — avoid
    // clobbering something the user copied in the meantime.
    if clipboard.get_text().unwrap_or_default() == text {
        clipboard.set_text(String::new()).ok();
        println!("Clipboard cleared.");
    }
    Ok(())
}
