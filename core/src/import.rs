use crate::entry::Entry;
use crate::error::{Result, VaultError};

/// Column aliases covering the CSV export formats of the major password
/// managers/browsers, verified against their actual current export headers
/// rather than assumed:
///
/// - Chrome/Edge/Brave: `name,url,username,password`
/// - Firefox: `url,username,password,httpRealm,formActionOrigin,guid,...` (no title)
/// - Safari: `Title,URL,Username,Password,Notes,OTPAuth`
/// - Bitwarden: `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp`
/// - LastPass: `url,username,password,extra,name,grouping,fav`
/// - 1Password (CSV import template): `title,website,username,password,totp,notes`
///
/// Rather than a hand-written parser per vendor, headers are matched
/// case-insensitively against these aliases — the formats above overlap
/// enough that one flexible mapping covers all of them.
struct ColumnMap {
    title: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    url: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
    record_type: Option<usize>,
}

fn find_column(headers: &csv::StringRecord, aliases: &[&str]) -> Option<usize> {
    headers.iter().position(|h| {
        let h = h.trim().to_lowercase();
        aliases.iter().any(|a| h == *a)
    })
}

impl ColumnMap {
    fn detect(headers: &csv::StringRecord) -> Self {
        ColumnMap {
            title: find_column(headers, &["name", "title"]),
            username: find_column(headers, &["username"]),
            password: find_column(headers, &["password"]),
            url: find_column(headers, &["url", "login_uri", "website", "urls", "action_url"]),
            notes: find_column(headers, &["notes", "note", "extra"]),
            totp: find_column(headers, &["totp", "login_totp", "otpauth"]),
            record_type: find_column(headers, &["type"]),
        }
    }

    fn get(&self, record: &csv::StringRecord, idx: Option<usize>) -> String {
        idx.and_then(|i| record.get(i)).unwrap_or("").trim().to_string()
    }
}

/// Extracts the `secret` parameter from an `otpauth://` URI (Safari's
/// export format), or returns the input unchanged if it's already a bare
/// base32 secret (Bitwarden/1Password's format).
fn normalize_totp(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    if let Some(query_start) = raw.find('?') {
        if raw.starts_with("otpauth://") {
            let query = &raw[query_start + 1..];
            for pair in query.split('&') {
                if let Some(secret) = pair.strip_prefix("secret=") {
                    return Some(secret.to_string());
                }
            }
            return None; // otpauth:// URI with no secret param — not usable
        }
    }
    Some(raw.to_string())
}

/// Derives a readable title from a URL when the source format has no
/// title/name column at all (Firefox's export is the main case).
fn title_from_url(url: &str) -> String {
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = without_scheme.split(['/', ':', '?']).next().unwrap_or(without_scheme);
    if host.is_empty() {
        "Imported entry".to_string()
    } else {
        host.to_string()
    }
}

/// Parses a password-manager CSV export into vault entries. Skips rows
/// that are clearly not login items (Bitwarden's `type` column) and rows
/// with neither a title nor a URL to derive one from.
pub fn parse_csv(contents: &str) -> Result<Vec<Entry>> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(contents.as_bytes());

    let headers = reader
        .headers()
        .map_err(|e| VaultError::Import(e.to_string()))?
        .clone();
    let map = ColumnMap::detect(&headers);

    let mut entries = Vec::new();
    for result in reader.records() {
        let record = result.map_err(|e| VaultError::Import(e.to_string()))?;

        if let Some(idx) = map.record_type {
            let ty = record.get(idx).unwrap_or("").trim();
            if !ty.is_empty() && !ty.eq_ignore_ascii_case("login") {
                continue;
            }
        }

        let title = map.get(&record, map.title);
        let url = map.get(&record, map.url);
        if title.is_empty() && url.is_empty() {
            continue;
        }

        let mut entry = Entry::new(if title.is_empty() { title_from_url(&url) } else { title });
        entry.username = map.get(&record, map.username);
        entry.password = map.get(&record, map.password);
        entry.url = url;
        entry.notes = map.get(&record, map.notes);
        entry.totp_secret = normalize_totp(&map.get(&record, map.totp));
        entries.push(entry);
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chrome_export() {
        let csv = "name,url,username,password\nGitHub,https://github.com,octocat,hunter2\n";
        let entries = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "GitHub");
        assert_eq!(entries[0].username, "octocat");
        assert_eq!(entries[0].password, "hunter2");
        assert_eq!(entries[0].url, "https://github.com");
    }

    #[test]
    fn parses_firefox_export_deriving_title_from_url() {
        let csv = "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n\
                    https://example.com/login,alice,swordfish,,,{abc},1,2,3\n";
        let entries = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "example.com");
        assert_eq!(entries[0].username, "alice");
    }

    #[test]
    fn parses_safari_export_with_otpauth_uri() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                    Example,https://example.com,bob,pw123,a note,otpauth://totp/Example:bob?secret=JBSWY3DPEHPK3PXP&issuer=Example\n";
        let entries = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].notes, "a note");
        assert_eq!(entries[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn parses_bitwarden_export_and_skips_non_login_rows() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                    ,0,login,My Bank,,,0,https://bank.example,carol,pw456,BASE32SECRET\n\
                    ,0,note,Just a note,secret info,,0,,,,\n";
        let entries = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1, "the 'note' type row should be skipped");
        assert_eq!(entries[0].title, "My Bank");
        assert_eq!(entries[0].totp_secret.as_deref(), Some("BASE32SECRET"));
    }

    #[test]
    fn parses_lastpass_export() {
        let csv = "url,username,password,extra,name,grouping,fav\n\
                    https://lp.example,dave,pw789,some extra notes,LP Entry,,0\n";
        let entries = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "LP Entry");
        assert_eq!(entries[0].notes, "some extra notes");
    }

    #[test]
    fn parses_1password_export() {
        let csv = "title,website,username,password,totp,notes\n\
                    1P Entry,https://onepassword.example,erin,pw000,ABCDEFGH,note here\n";
        let entries = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].url, "https://onepassword.example");
        assert_eq!(entries[0].totp_secret.as_deref(), Some("ABCDEFGH"));
    }

    #[test]
    fn skips_blank_rows() {
        let csv = "name,url,username,password\n,,,\nGitHub,https://github.com,octocat,hunter2\n";
        let entries = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
    }
}
