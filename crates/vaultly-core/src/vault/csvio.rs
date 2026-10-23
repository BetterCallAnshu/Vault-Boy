//! CSV import/export.
//!
//! Import is header-driven, so Chrome/Edge, Firefox, Bitwarden, 1Password and
//! LastPass exports all work without per-vendor parsers: each known column name
//! is mapped through an alias table and unknown columns are ignored.
//!
//! Export is **plaintext** and exists only behind the UI's re-authentication
//! and warning flow.

use serde::{Deserialize, Serialize};

use super::model::{EntryMeta, EntrySecrets};
use super::VaultError;

const MAX_IMPORT_ROWS: usize = 20_000;

#[derive(Debug, Clone, Default)]
pub struct ImportedEntry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp: String,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ImportSummary {
    pub imported: usize,
    pub skipped: usize,
}

const TITLE_ALIASES: &[&str] = &["name", "title", "account", "item name"];
const USERNAME_ALIASES: &[&str] = &[
    "username",
    "login_username",
    "user",
    "login",
    "email",
    "login name",
];
const PASSWORD_ALIASES: &[&str] = &["password", "login_password", "pass", "pwd"];
const URL_ALIASES: &[&str] = &[
    "url",
    "login_uri",
    "website",
    "web site",
    "uri",
    "web address",
];
const NOTES_ALIASES: &[&str] = &["notes", "note", "extra", "comments", "comment"];
const TOTP_ALIASES: &[&str] = &[
    "otp",
    "totp",
    "login_totp",
    "otpauth",
    "one-time password",
    "totp secret",
];
const FOLDER_ALIASES: &[&str] = &["folder", "grouping", "group", "collection"];
const TAGS_ALIASES: &[&str] = &["tags", "tag", "labels"];
const FAVORITE_ALIASES: &[&str] = &["favorite", "fav", "favourite"];

struct Columns {
    title: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    url: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
    folder: Option<usize>,
    tags: Option<usize>,
    favorite: Option<usize>,
}

impl Columns {
    fn detect(headers: &csv::StringRecord) -> Self {
        let find = |aliases: &[&str]| {
            headers.iter().position(|header| {
                let normalized = header.trim().to_ascii_lowercase().replace(' ', "_");
                aliases
                    .iter()
                    .any(|alias| normalized == alias.replace(' ', "_"))
            })
        };
        Columns {
            title: find(TITLE_ALIASES),
            username: find(USERNAME_ALIASES),
            password: find(PASSWORD_ALIASES),
            url: find(URL_ALIASES),
            notes: find(NOTES_ALIASES),
            totp: find(TOTP_ALIASES),
            folder: find(FOLDER_ALIASES),
            tags: find(TAGS_ALIASES),
            favorite: find(FAVORITE_ALIASES),
        }
    }
}

fn value(record: &csv::StringRecord, index: Option<usize>) -> String {
    index
        .and_then(|i| record.get(i))
        .unwrap_or("")
        .trim()
        .to_string()
}

fn parse_bool(text: &str) -> bool {
    matches!(
        text.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "y"
    )
}

fn split_tags(text: &str) -> Vec<String> {
    text.split([',', ';'])
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .take(64)
        .map(str::to_string)
        .collect()
}

/// Parse a CSV export into entries without touching the vault.
pub fn parse(text: &str) -> Result<Vec<ImportedEntry>, VaultError> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_reader(text.as_bytes());

    let headers = reader.headers().map_err(|_| VaultError::Csv)?.clone();
    if headers.is_empty() {
        return Err(VaultError::Csv);
    }
    let columns = Columns::detect(&headers);
    if columns.password.is_none() && columns.username.is_none() {
        return Err(VaultError::Csv);
    }

    let mut entries = Vec::new();
    for record in reader.records() {
        if entries.len() >= MAX_IMPORT_ROWS {
            break;
        }
        let record = record.map_err(|_| VaultError::Csv)?;
        if record.iter().all(|field| field.trim().is_empty()) {
            continue;
        }

        let username = value(&record, columns.username);
        let url = value(&record, columns.url);
        let title = {
            let raw = value(&record, columns.title);
            if raw.is_empty() {
                if !url.is_empty() {
                    url.clone()
                } else if !username.is_empty() {
                    username.clone()
                } else {
                    "Imported entry".to_string()
                }
            } else {
                raw
            }
        };

        entries.push(ImportedEntry {
            title,
            username,
            password: value(&record, columns.password),
            url,
            notes: value(&record, columns.notes),
            totp: value(&record, columns.totp),
            folder: Some(value(&record, columns.folder)).filter(|f| !f.is_empty()),
            tags: split_tags(&value(&record, columns.tags)),
            favorite: parse_bool(&value(&record, columns.favorite)),
        });
    }
    Ok(entries)
}

/// Plaintext CSV export. Callers must re-authenticate the user first.
pub fn export(rows: &[(EntryMeta, EntrySecrets)]) -> Result<String, VaultError> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record([
            "title",
            "url",
            "username",
            "password",
            "notes",
            "totp",
            "folder",
            "tags",
            "favorite",
            "kind",
        ])
        .map_err(|_| VaultError::Csv)?;

    for (meta, secrets) in rows {
        writer
            .write_record([
                meta.title.as_str(),
                meta.url.as_str(),
                meta.username.as_str(),
                secrets.password.as_str(),
                secrets.notes.as_str(),
                secrets.totp_secret.as_str(),
                meta.folder.as_deref().unwrap_or(""),
                &meta.tags.join(","),
                if meta.favorite { "1" } else { "0" },
                meta.kind.as_str(),
            ])
            .map_err(|_| VaultError::Csv)?;
    }

    let bytes = writer.into_inner().map_err(|_| VaultError::Csv)?;
    String::from_utf8(bytes).map_err(|_| VaultError::Csv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_chrome_export() {
        let csv = "name,url,username,password,note\n\
                   GitHub,https://github.com,octocat,gh-pass,work account\n\
                   ,https://example.com,someone@example.com,pass2,\n";
        let entries = parse(csv).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].title, "GitHub");
        assert_eq!(entries[0].notes, "work account");
        assert_eq!(entries[1].title, "https://example.com");
    }

    #[test]
    fn imports_bitwarden_export() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Work,1,login,GitHub,notes,,0,https://github.com,octocat,gh-pass,JBSWY3DPEHPK3PXP\n";
        let entries = parse(csv).unwrap();
        let entry = &entries[0];
        assert_eq!(entry.folder.as_deref(), Some("Work"));
        assert!(entry.favorite);
        assert_eq!(entry.url, "https://github.com");
        assert_eq!(entry.totp, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn imports_lastpass_export() {
        let csv = "url,username,password,extra,name,grouping,fav\n\
                   https://mail.example,me@example.com,secret,\"multi\nline note\",Mail,Personal,0\n";
        let entries = parse(csv).unwrap();
        assert_eq!(entries[0].title, "Mail");
        assert_eq!(entries[0].notes, "multi\nline note");
        assert_eq!(entries[0].folder.as_deref(), Some("Personal"));
        assert!(!entries[0].favorite);
    }

    #[test]
    fn imports_1password_export() {
        let csv = "Title,Url,Username,Password,OTPAuth,Favorite,Tags,Notes\n\
                   Bank,https://bank.example,alice,pw,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP,true,\"finance,important\",note\n";
        let entries = parse(csv).unwrap();
        assert_eq!(entries[0].tags, vec!["finance", "important"]);
        assert!(entries[0].favorite);
        assert!(entries[0].totp.starts_with("otpauth://"));
    }

    #[test]
    fn rejects_files_without_credential_columns() {
        assert_eq!(
            parse("foo,bar\n1,2\n").unwrap_err(),
            VaultError::Csv
        );
    }

    #[test]
    fn export_round_trips_through_import() {
        use crate::vault::model::EntryKind;
        use uuid::Uuid;

        let meta = EntryMeta {
            id: Uuid::new_v4(),
            kind: EntryKind::Login,
            title: "GitHub".into(),
            username: "octocat".into(),
            url: "https://github.com".into(),
            tags: vec!["work".into(), "code".into()],
            folder: Some("Dev".into()),
            favorite: true,
            created_at: 0,
            updated_at: 0,
            password_updated_at: Some(0),
            deleted_at: None,
            has_totp: false,
            has_notes: true,
            has_card: false,
            has_identity: false,
            custom_labels: vec![],
            history_len: 0,
        };
        let mut secrets = EntrySecrets::default();
        secrets.password = "gh-pass".into();
        secrets.notes = "line one\nline two".into();

        let exported = export(&[(meta, secrets)]).unwrap();
        let parsed = parse(&exported).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].title, "GitHub");
        assert_eq!(parsed[0].password, "gh-pass");
        assert_eq!(parsed[0].notes, "line one\nline two");
        assert_eq!(parsed[0].tags, vec!["work", "code"]);
        assert!(parsed[0].favorite);
    }
}
