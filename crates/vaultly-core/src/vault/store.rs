//! Vault lifecycle and entry operations.
//!
//! The store is IO-free: it turns bytes into a `Vault` and back. Atomic writes,
//! backups and ACLs belong to the Windows layer.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{self, Sealed};
use crate::crypto::derive::{derive_entry_key, derive_subkey, INFO_INDEX};
use crate::crypto::encoding::{decode_recovery_key, generate_recovery_key};
use crate::crypto::kdf::{derive_key, random_salt, KdfParams};
use crate::crypto::{ct_eq, Key32};

use super::csvio::{self, ImportSummary, ImportedEntry};
use super::format::{
    aad_entry, aad_labeled, Header, HelloWrap, RawVault, Record, RecoveryWrap, Wrap, LABEL_INDEX,
    LABEL_PASSWORD, LABEL_RECOVERY,
};
use super::health::{self, HealthReport};
use super::index::{Index, INDEX_SCHEMA};
use super::model::{
    CardSecrets, CustomField, EntryKind, EntryMeta, EntrySecrets, IdentitySecrets, Revision,
};
use super::search;
use super::totp::{self, TotpCode};
use super::VaultError;

/// Minimum master password length, enforced in addition to the UI strength
/// meter. A 12-character passphrase is the smallest we accept.
pub const MIN_MASTER_PASSWORD_LEN: usize = 12;
/// Previous versions retained per entry.
pub const HISTORY_LIMIT: usize = 20;
/// Deleted entries are purged automatically after 30 days.
pub const TRASH_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// An entry is reported as "old" after a year without a password change.
pub const OLD_PASSWORD_MS: i64 = 365 * 24 * 60 * 60 * 1000;

const MAX_TITLE: usize = 512;
const MAX_USERNAME: usize = 512;
const MAX_URL: usize = 4096;
const MAX_TAGS: usize = 64;
const MAX_TAG: usize = 64;
const MAX_PASSWORD: usize = 4096;
const MAX_NOTES: usize = 100_000;
const MAX_CUSTOM_FIELDS: usize = 64;
const MAX_CUSTOM_LABEL: usize = 256;
const MAX_CUSTOM_VALUE: usize = 8192;
const MAX_FOLDERS: usize = 512;

/// Options for creating a vault.
#[derive(Debug, Clone, Copy)]
pub struct CreateOptions {
    pub kdf: KdfParams,
    pub recovery: bool,
    pub now: i64,
}

/// A freshly created vault plus the one-time recovery key, if requested.
pub struct CreatedVault {
    pub vault: Vault,
    /// Display exactly once; never persisted in plaintext.
    pub recovery_key: Option<Zeroizing<String>>,
}

/// New entry supplied by the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryDraft {
    pub kind: EntryKind,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub secrets: EntrySecrets,
}

/// Partial update. `folder: Some("")` clears the folder; `secrets: None` keeps
/// the existing secret payload untouched.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EntryPatch {
    #[serde(default)]
    pub kind: Option<EntryKind>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub favorite: Option<bool>,
    #[serde(default)]
    pub secrets: Option<EntrySecrets>,
}

/// Decrypted record payload: current secrets plus capped history.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RecordPayload {
    #[serde(default)]
    secrets: EntrySecrets,
    #[serde(default)]
    history: Vec<Revision>,
}

/// An unlocked vault. Dropping it wipes the root key and all metadata.
pub struct Vault {
    header: Header,
    vrk: Key32,
    index: Index,
    records: Vec<Record>,
}

impl Vault {
    /// Create a new empty vault.
    pub fn create(password: &[u8], options: CreateOptions) -> Result<CreatedVault, VaultError> {
        if password.len() < MIN_MASTER_PASSWORD_LEN {
            return Err(VaultError::InvalidInput);
        }
        options
            .kdf
            .validate()
            .map_err(|_| VaultError::InvalidInput)?;

        let mut vault_id = [0u8; 16];
        getrandom::fill(&mut vault_id).map_err(|_| VaultError::Crypto)?;
        let salt = random_salt()?;
        let vrk = Key32::random()?;
        let kek = derive_key(password, &salt, &options.kdf)?;
        let wrap = vrk.with_secret(|bytes| {
            aead::seal(&kek, &aad_labeled(&vault_id, LABEL_PASSWORD), bytes)
        })?;

        let mut recovery_wrap = None;
        let mut recovery_key = None;
        if options.recovery {
            let display = generate_recovery_key()?;
            let recovery = decode_recovery_key(&display)?;
            let recovery_salt = random_salt()?;
            let recovery_kek =
                recovery.with_secret(|bytes| derive_key(bytes, &recovery_salt, &options.kdf))?;
            let wrapped = vrk.with_secret(|bytes| {
                aead::seal(
                    &recovery_kek,
                    &aad_labeled(&vault_id, LABEL_RECOVERY),
                    bytes,
                )
            })?;
            recovery_wrap = Some(RecoveryWrap {
                kdf: options.kdf,
                salt: recovery_salt,
                wrap: Wrap::from_sealed(&wrapped),
            });
            recovery_key = Some(display);
        }

        let header = Header {
            vault_id,
            created_at: options.now,
            kdf: options.kdf,
            salt,
            wrap: Wrap::from_sealed(&wrap),
            recovery: recovery_wrap,
            hello: None,
        };

        Ok(CreatedVault {
            vault: Vault {
                header,
                vrk,
                index: Index::new(),
                records: Vec::new(),
            },
            recovery_key,
        })
    }

    /// Unlock with the master password.
    pub fn unlock(bytes: &[u8], password: &[u8]) -> Result<Vault, VaultError> {
        let raw = RawVault::parse(bytes)?;
        let kek = derive_key(password, &raw.header.salt, &raw.header.kdf)
            .map_err(|_| VaultError::Corrupt)?;
        let opened = aead::open(
            &kek,
            &aad_labeled(&raw.header.vault_id, LABEL_PASSWORD),
            &raw.header.wrap.to_sealed(),
        )
        .map_err(|_| VaultError::InvalidPassword)?;
        let vrk = key_from_opened(&opened)?;
        Self::assemble(raw, vrk)
    }

    /// Unlock with the one-time recovery key.
    pub fn unlock_with_recovery(bytes: &[u8], recovery_phrase: &str) -> Result<Vault, VaultError> {
        let raw = RawVault::parse(bytes)?;
        let recovery = raw
            .header
            .recovery
            .as_ref()
            .ok_or(VaultError::Unsupported)?;
        let recovery_key = decode_recovery_key(recovery_phrase).map_err(|_| VaultError::InvalidInput)?;
        let kek = recovery_key
            .with_secret(|bytes| derive_key(bytes, &recovery.salt, &recovery.kdf))
            .map_err(|_| VaultError::Corrupt)?;
        let opened = aead::open(
            &kek,
            &aad_labeled(&raw.header.vault_id, LABEL_RECOVERY),
            &recovery.wrap.to_sealed(),
        )
        .map_err(|_| VaultError::InvalidPassword)?;
        let vrk = key_from_opened(&opened)?;
        Self::assemble(raw, vrk)
    }

    fn assemble(raw: RawVault, vrk: Key32) -> Result<Vault, VaultError> {
        let index = open_index(&vrk, &raw.header, &raw.index_nonce, &raw.index)?;
        if index.schema != INDEX_SCHEMA {
            return Err(VaultError::Corrupt);
        }

        let mut index_ids = HashSet::with_capacity(index.entries.len());
        for meta in &index.entries {
            if !index_ids.insert(meta.id) {
                return Err(VaultError::Corrupt);
            }
        }
        if index_ids.len() != raw.records.len() {
            return Err(VaultError::Corrupt);
        }
        for record in &raw.records {
            if !index_ids.contains(&record.id) {
                return Err(VaultError::Corrupt);
            }
        }

        Ok(Vault {
            header: raw.header,
            vrk,
            index,
            records: raw.records,
        })
    }

    /// Serialize back to the v1 container. Every record keeps its ciphertext
    /// unless it changed; the index is always re-encrypted with a fresh nonce.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        let index_plain =
            Zeroizing::new(serde_json::to_vec(&self.index).map_err(|_| VaultError::Corrupt)?);
        let key = derive_subkey(&self.vrk, &self.header.vault_id, INFO_INDEX)?;
        let mut sealed = aead::seal(
            &key,
            &aad_labeled(&self.header.vault_id, LABEL_INDEX),
            &index_plain,
        )?;
        let index_nonce = sealed.nonce;
        let index = std::mem::take(&mut sealed.ciphertext);

        RawVault {
            header: self.header.clone(),
            index_nonce,
            index,
            records: self.records.clone(),
        }
        .encode()
    }

    // ---- metadata -------------------------------------------------------

    pub fn list(&self) -> &[EntryMeta] {
        &self.index.entries
    }

    pub fn active_entries(&self) -> impl Iterator<Item = &EntryMeta> {
        self.index.entries.iter().filter(|meta| !meta.is_deleted())
    }

    pub fn folders(&self) -> &[String] {
        &self.index.folders
    }

    pub fn meta(&self, id: Uuid) -> Result<&EntryMeta, VaultError> {
        self.index
            .entries
            .iter()
            .find(|meta| meta.id == id)
            .ok_or(VaultError::NotFound)
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    // ---- secrets --------------------------------------------------------

    /// Decrypt one entry's secrets. The value zeroizes when dropped.
    pub fn secrets(&self, id: Uuid) -> Result<EntrySecrets, VaultError> {
        Ok(self.payload(id)?.secrets)
    }

    fn payload(&self, id: Uuid) -> Result<RecordPayload, VaultError> {
        let record = self
            .records
            .iter()
            .find(|record| record.id == id)
            .ok_or(VaultError::NotFound)?;
        let key = derive_entry_key(&self.vrk, &self.header.vault_id, id.as_bytes())?;
        let sealed = Sealed {
            nonce: record.nonce,
            ciphertext: record.ciphertext.clone(),
        };
        let opened = aead::open(
            &key,
            &aad_entry(&self.header.vault_id, id.as_bytes()),
            &sealed,
        )?;
        serde_json::from_slice(&opened).map_err(|_| VaultError::Corrupt)
    }

    // ---- mutations ------------------------------------------------------

    pub fn create_entry(&mut self, draft: EntryDraft, now: i64) -> Result<Uuid, VaultError> {
        validate_meta_fields(&draft.title, &draft.username, &draft.url, &draft.tags)?;
        validate_secrets(&draft.secrets)?;
        if draft.secrets.is_empty() {
            return Err(VaultError::InvalidInput);
        }

        let id = Uuid::new_v4();
        let flags = flags_for(&draft.secrets);
        let meta = EntryMeta {
            id,
            kind: draft.kind,
            title: draft.title.trim().to_string(),
            username: draft.username.trim().to_string(),
            url: draft.url.trim().to_string(),
            tags: normalized_tags(&draft.tags),
            folder: normalize_folder(draft.folder),
            favorite: draft.favorite,
            created_at: now,
            updated_at: now,
            password_updated_at: if draft.secrets.password.is_empty() {
                None
            } else {
                Some(now)
            },
            deleted_at: None,
            has_totp: flags.0,
            has_notes: flags.1,
            has_card: flags.2,
            has_identity: flags.3,
            custom_labels: draft
                .secrets
                .custom
                .iter()
                .map(|field| field.label.trim().to_string())
                .collect(),
            history_len: 0,
        };

        let payload = RecordPayload {
            secrets: draft.secrets,
            history: Vec::new(),
        };
        self.insert_record(id, &payload)?;

        if let Some(folder) = &meta.folder {
            self.ensure_folder(folder);
        }
        self.index.entries.push(meta);
        Ok(id)
    }

    /// Apply a partial update. Metadata is updated first, then secrets.
    pub fn update_entry(&mut self, id: Uuid, patch: EntryPatch, now: i64) -> Result<(), VaultError> {
        if let Some(title) = &patch.title {
            if title.trim().is_empty() || title.chars().count() > MAX_TITLE {
                return Err(VaultError::InvalidInput);
            }
        }
        if let Some(username) = &patch.username {
            if username.chars().count() > MAX_USERNAME {
                return Err(VaultError::InvalidInput);
            }
        }
        if let Some(url) = &patch.url {
            if url.chars().count() > MAX_URL {
                return Err(VaultError::InvalidInput);
            }
        }
        if let Some(tags) = &patch.tags {
            validate_tags(tags)?;
        }
        if let Some(secrets) = &patch.secrets {
            validate_secrets(secrets)?;
        }

        let mut folder_to_ensure = None;
        {
            let meta = self
                .index
                .entries
                .iter_mut()
                .find(|meta| meta.id == id)
                .ok_or(VaultError::NotFound)?;

            if let Some(kind) = patch.kind {
                meta.kind = kind;
            }
            if let Some(title) = patch.title {
                meta.title = title.trim().to_string();
            }
            if let Some(username) = patch.username {
                meta.username = username.trim().to_string();
            }
            if let Some(url) = patch.url {
                meta.url = url.trim().to_string();
            }
            if let Some(tags) = patch.tags {
                meta.tags = normalized_tags(&tags);
            }
            if let Some(folder) = patch.folder {
                meta.folder = normalize_folder(Some(folder));
                folder_to_ensure = meta.folder.clone();
            }
            if let Some(favorite) = patch.favorite {
                meta.favorite = favorite;
            }
            meta.updated_at = now;
        }
        if let Some(folder) = folder_to_ensure {
            self.ensure_folder(&folder);
        }

        if let Some(secrets) = patch.secrets {
            self.set_secrets(id, secrets, now)?;
        }
        Ok(())
    }

    /// Replace an entry's secret payload, appending the previous version to
    /// history (capped at [`HISTORY_LIMIT`]).
    pub fn set_secrets(
        &mut self,
        id: Uuid,
        secrets: EntrySecrets,
        now: i64,
    ) -> Result<(), VaultError> {
        validate_secrets(&secrets)?;
        let previous_updated_at = self.meta(id)?.updated_at;
        let mut payload = self.payload(id)?;
        let password_changed = !ct_eq(
            payload.secrets.password.as_bytes(),
            secrets.password.as_bytes(),
        );
        let old = std::mem::replace(&mut payload.secrets, secrets);
        if !old.is_empty() {
            payload.history.insert(
                0,
                Revision {
                    at: previous_updated_at,
                    secrets: old,
                },
            );
            payload.history.truncate(HISTORY_LIMIT);
        }

        let flags = flags_for(&payload.secrets);
        let history_len = payload.history.len();
        let labels: Vec<String> = payload
            .secrets
            .custom
            .iter()
            .map(|field| field.label.trim().to_string())
            .collect();
        self.store_payload(id, &payload)?;

        let meta = self
            .index
            .entries
            .iter_mut()
            .find(|meta| meta.id == id)
            .ok_or(VaultError::NotFound)?;
        meta.updated_at = now;
        if password_changed {
            meta.password_updated_at = Some(now);
        }
        meta.has_totp = flags.0;
        meta.has_notes = flags.1;
        meta.has_card = flags.2;
        meta.has_identity = flags.3;
        meta.custom_labels = labels;
        meta.history_len = history_len;
        Ok(())
    }

    pub fn delete_entry(&mut self, id: Uuid, now: i64) -> Result<(), VaultError> {
        let meta = self
            .index
            .entries
            .iter_mut()
            .find(|meta| meta.id == id)
            .ok_or(VaultError::NotFound)?;
        meta.deleted_at = Some(now);
        meta.updated_at = now;
        Ok(())
    }

    pub fn restore_entry(&mut self, id: Uuid, now: i64) -> Result<(), VaultError> {
        let meta = self
            .index
            .entries
            .iter_mut()
            .find(|meta| meta.id == id)
            .ok_or(VaultError::NotFound)?;
        meta.deleted_at = None;
        meta.updated_at = now;
        Ok(())
    }

    /// Permanently remove entries deleted more than 30 days ago.
    pub fn purge_expired(&mut self, now: i64) -> usize {
        let cutoff = now.saturating_sub(TRASH_RETENTION_MS);
        let expired: Vec<Uuid> = self
            .index
            .entries
            .iter()
            .filter(|meta| meta.deleted_at.is_some_and(|at| at <= cutoff))
            .map(|meta| meta.id)
            .collect();
        for id in &expired {
            self.remove_entry(*id);
        }
        expired.len()
    }

    pub fn empty_trash(&mut self) -> usize {
        let deleted: Vec<Uuid> = self
            .index
            .entries
            .iter()
            .filter(|meta| meta.is_deleted())
            .map(|meta| meta.id)
            .collect();
        for id in &deleted {
            self.remove_entry(*id);
        }
        deleted.len()
    }

    fn remove_entry(&mut self, id: Uuid) {
        self.index.entries.retain(|meta| meta.id != id);
        self.records.retain(|record| record.id != id);
    }

    // ---- history --------------------------------------------------------

    pub fn history_timestamps(&self, id: Uuid) -> Result<Vec<i64>, VaultError> {
        Ok(self
            .payload(id)?
            .history
            .iter()
            .map(|revision| revision.at)
            .collect())
    }

    pub fn restore_revision(
        &mut self,
        id: Uuid,
        revision_index: usize,
        now: i64,
    ) -> Result<(), VaultError> {
        let secrets = {
            let payload = self.payload(id)?;
            payload
                .history
                .get(revision_index)
                .ok_or(VaultError::NotFound)?
                .secrets
                .clone()
        };
        self.set_secrets(id, secrets, now)
    }

    // ---- key wrapping ---------------------------------------------------

    /// Run a closure with the vault root key. Used only by the Windows Hello
    /// layer to wrap/unwrap the key with a Hello-protected CNG key.
    pub fn with_vrk<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        self.vrk.with_secret(f)
    }

    pub fn hello_wrap(&self) -> Option<&HelloWrap> {
        self.header.hello.as_ref()
    }

    pub fn set_hello_wrap(&mut self, credential: String, wrap: Wrap, created_at: i64) {
        self.header.hello = Some(HelloWrap {
            credential,
            wrap,
            created_at,
        });
    }

    pub fn remove_hello_wrap(&mut self) {
        self.header.hello = None;
    }

    /// Re-derive the password key and try to open the wrapped root key.
    ///
    /// Used for re-authentication before plaintext export and password change.
    /// AEAD tag verification is constant time.
    pub fn verify_password(&self, password: &[u8]) -> bool {
        match derive_key(password, &self.header.salt, &self.header.kdf) {
            Ok(kek) => aead::open(
                &kek,
                &aad_labeled(&self.header.vault_id, LABEL_PASSWORD),
                &self.header.wrap.to_sealed(),
            )
            .is_ok(),
            Err(_) => false,
        }
    }

    /// Re-wrap the same root key under a new master password and KDF salt.
    /// No entry ciphertext is touched, so no plaintext is written twice.
    pub fn change_password(
        &mut self,
        new_password: &[u8],
        kdf: KdfParams,
    ) -> Result<(), VaultError> {
        if new_password.len() < MIN_MASTER_PASSWORD_LEN {
            return Err(VaultError::InvalidInput);
        }
        kdf.validate().map_err(|_| VaultError::InvalidInput)?;

        let salt = random_salt()?;
        let kek = derive_key(new_password, &salt, &kdf)?;
        let wrap = self.vrk.with_secret(|bytes| {
            aead::seal(&kek, &aad_labeled(&self.header.vault_id, LABEL_PASSWORD), bytes)
        })?;

        self.header.kdf = kdf;
        self.header.salt = salt;
        self.header.wrap = Wrap::from_sealed(&wrap);
        Ok(())
    }

    // ---- derived features ----------------------------------------------

    pub fn search(&self, query: &str) -> Vec<Uuid> {
        search::rank(&self.index, query)
    }

    pub fn health_report(&self, now: i64) -> Result<HealthReport, VaultError> {
        health::analyze(self, now)
    }

    pub fn totp_code(&self, id: Uuid, now_ms: i64) -> Result<TotpCode, VaultError> {
        totp::code(self, id, now_ms)
    }

    /// Encrypted backup bytes are byte-identical in meaning to the vault file;
    /// this exists to make the intent explicit at the command layer.
    pub fn export_backup(&self) -> Result<Vec<u8>, VaultError> {
        self.to_bytes()
    }

    pub fn export_csv(&self) -> Result<Zeroizing<String>, VaultError> {
        let mut rows = Vec::new();
        for meta in self.active_entries() {
            let secrets = self.secrets(meta.id)?;
            rows.push((meta.clone(), secrets));
        }
        csvio::export(&rows).map(Zeroizing::new)
    }

    pub fn import_entries(
        &mut self,
        entries: Vec<ImportedEntry>,
        now: i64,
    ) -> Result<ImportSummary, VaultError> {
        let mut imported = 0usize;
        let mut skipped = 0usize;
        for entry in entries {
            let draft = EntryDraft {
                kind: EntryKind::Login,
                title: entry.title.clone(),
                username: entry.username.clone(),
                url: entry.url.clone(),
                tags: entry.tags.clone(),
                folder: entry.folder.clone(),
                favorite: entry.favorite,
                secrets: EntrySecrets {
                    password: entry.password.clone(),
                    notes: entry.notes.clone(),
                    totp_secret: entry.totp.clone(),
                    card: None,
                    identity: None,
                    custom: Vec::new(),
                },
            };
            match self.create_entry(draft, now) {
                Ok(_) => imported += 1,
                Err(VaultError::InvalidInput) => skipped += 1,
                Err(error) => return Err(error),
            }
        }
        Ok(ImportSummary { imported, skipped })
    }

    // ---- internals ------------------------------------------------------

    fn insert_record(&mut self, id: Uuid, payload: &RecordPayload) -> Result<(), VaultError> {
        let (nonce, ciphertext) = self.seal_payload(id, payload)?;
        self.records.push(Record {
            id,
            nonce,
            ciphertext,
        });
        Ok(())
    }

    fn store_payload(&mut self, id: Uuid, payload: &RecordPayload) -> Result<(), VaultError> {
        let (nonce, ciphertext) = self.seal_payload(id, payload)?;
        match self.records.iter_mut().find(|record| record.id == id) {
            Some(record) => {
                record.nonce = nonce;
                record.ciphertext = ciphertext;
            }
            None => self.records.push(Record {
                id,
                nonce,
                ciphertext,
            }),
        }
        Ok(())
    }

    fn seal_payload(
        &self,
        id: Uuid,
        payload: &RecordPayload,
    ) -> Result<([u8; 24], Vec<u8>), VaultError> {
        let key = derive_entry_key(&self.vrk, &self.header.vault_id, id.as_bytes())?;
        let plaintext =
            Zeroizing::new(serde_json::to_vec(payload).map_err(|_| VaultError::Corrupt)?);
        let mut sealed = aead::seal(
            &key,
            &aad_entry(&self.header.vault_id, id.as_bytes()),
            &plaintext,
        )?;
        Ok((sealed.nonce, std::mem::take(&mut sealed.ciphertext)))
    }

    fn ensure_folder(&mut self, folder: &str) {
        if folder.is_empty() {
            return;
        }
        if self.index.folders.len() >= MAX_FOLDERS
            || self.index.folders.iter().any(|existing| existing == folder)
        {
            return;
        }
        self.index.folders.push(folder.to_string());
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("entries", &self.index.entries.len())
            .field("key", &self.vrk)
            .finish_non_exhaustive()
    }
}

fn key_from_opened(opened: &Zeroizing<Vec<u8>>) -> Result<Key32, VaultError> {
    if opened.len() != 32 {
        return Err(VaultError::Corrupt);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(opened);
    let key = Key32::from_bytes(bytes);
    bytes.zeroize();
    Ok(key)
}

fn open_index(
    vrk: &Key32,
    header: &Header,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Index, VaultError> {
    let key = derive_subkey(vrk, &header.vault_id, INFO_INDEX)?;
    let sealed = Sealed {
        nonce: *nonce,
        ciphertext: ciphertext.to_vec(),
    };
    let plaintext = aead::open(&key, &aad_labeled(&header.vault_id, LABEL_INDEX), &sealed)?;
    serde_json::from_slice(&plaintext).map_err(|_| VaultError::Corrupt)
}

fn flags_for(secrets: &EntrySecrets) -> (bool, bool, bool, bool) {
    (
        !secrets.totp_secret.trim().is_empty(),
        !secrets.notes.trim().is_empty(),
        secrets.card.is_some(),
        secrets.identity.is_some(),
    )
}

fn normalize_folder(folder: Option<String>) -> Option<String> {
    folder
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalized_tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tag in tags {
        let trimmed = tag.trim();
        if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    out
}

fn validate_meta_fields(
    title: &str,
    username: &str,
    url: &str,
    tags: &[String],
) -> Result<(), VaultError> {
    if title.trim().is_empty() || title.chars().count() > MAX_TITLE {
        return Err(VaultError::InvalidInput);
    }
    if username.chars().count() > MAX_USERNAME || url.chars().count() > MAX_URL {
        return Err(VaultError::InvalidInput);
    }
    validate_tags(tags)
}

fn validate_tags(tags: &[String]) -> Result<(), VaultError> {
    if tags.len() > MAX_TAGS || tags.iter().any(|tag| tag.chars().count() > MAX_TAG) {
        return Err(VaultError::InvalidInput);
    }
    Ok(())
}

fn validate_secrets(secrets: &EntrySecrets) -> Result<(), VaultError> {
    if secrets.password.chars().count() > MAX_PASSWORD
        || secrets.notes.chars().count() > MAX_NOTES
        || secrets.totp_secret.chars().count() > 512
        || secrets.custom.len() > MAX_CUSTOM_FIELDS
    {
        return Err(VaultError::InvalidInput);
    }
    for field in &secrets.custom {
        if field.label.chars().count() > MAX_CUSTOM_LABEL
            || field.value.chars().count() > MAX_CUSTOM_VALUE
        {
            return Err(VaultError::InvalidInput);
        }
    }
    if let Some(card) = &secrets.card {
        let max = |value: &str| value.chars().count() <= 64;
        if !max(&card.number)
            || !max(&card.holder)
            || !max(&card.expiry)
            || !max(&card.cvv)
            || !max(&card.pin)
        {
            return Err(VaultError::InvalidInput);
        }
    }
    if let Some(identity) = &secrets.identity {
        let fields = [
            &identity.full_name,
            &identity.email,
            &identity.phone,
            &identity.address,
            &identity.passport,
            &identity.national_id,
            &identity.date_of_birth,
        ];
        if fields
            .iter()
            .any(|value| value.chars().count() > MAX_NOTES)
        {
            return Err(VaultError::InvalidInput);
        }
    }
    Ok(())
}

/// Convenience for the UI: an empty secret payload for a given kind.
impl EntrySecrets {
    pub fn for_kind(kind: EntryKind) -> Self {
        let mut secrets = EntrySecrets::default();
        match kind {
            EntryKind::Card => {
                secrets.card = Some(CardSecrets::default());
            }
            EntryKind::Identity => {
                secrets.identity = Some(IdentitySecrets::default());
            }
            EntryKind::Login | EntryKind::Note => {}
        }
        secrets
    }

    /// Add a custom field, used by importers.
    pub fn push_custom(&mut self, label: &str, value: &str, secret: bool) {
        self.custom.push(CustomField {
            label: label.to_string(),
            value: value.to_string(),
            secret,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;

    fn fast_kdf() -> KdfParams {
        KdfParams::new(64 * 1024, 1, 1)
    }

    fn new_vault() -> Vault {
        Vault::create(
            b"correct horse battery",
            CreateOptions {
                kdf: fast_kdf(),
                recovery: false,
                now: 1_000,
            },
        )
        .unwrap()
        .vault
    }

    fn draft(title: &str, password: &str) -> EntryDraft {
        let mut secrets = EntrySecrets::default();
        secrets.password = password.into();
        EntryDraft {
            kind: EntryKind::Login,
            title: title.into(),
            username: "user".into(),
            url: "https://example.com".into(),
            tags: vec!["work".into()],
            folder: Some("Mail".into()),
            favorite: false,
            secrets,
        }
    }

    #[test]
    fn create_and_unlock_round_trip() {
        let mut vault = new_vault();
        let id = vault.create_entry(draft("GitHub", "hunter2hunter2"), 2_000).unwrap();
        let bytes = vault.to_bytes().unwrap();
        drop(vault);

        let unlocked = Vault::unlock(&bytes, b"correct horse battery").unwrap();
        assert_eq!(unlocked.list().len(), 1);
        assert_eq!(unlocked.secrets(id).unwrap().password, "hunter2hunter2");
    }

    #[test]
    fn wrong_password_cannot_open_vault() {
        let vault = new_vault();
        let bytes = vault.to_bytes().unwrap();
        assert_eq!(
            Vault::unlock(&bytes, b"wrong password here").unwrap_err(),
            VaultError::InvalidPassword
        );
    }

    #[test]
    fn short_master_password_is_rejected() {
        let result = Vault::create(
            b"short",
            CreateOptions {
                kdf: fast_kdf(),
                recovery: false,
                now: 1_000,
            },
        );
        assert!(matches!(result, Err(VaultError::InvalidInput)));
    }

    #[test]
    fn tampering_with_ciphertext_is_detected() {
        let mut vault = new_vault();
        let id = vault.create_entry(draft("Bank", "s3cret-passphrase"), 2_000).unwrap();
        let mut bytes = vault.to_bytes().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;

        match Vault::unlock(&bytes, b"correct horse battery") {
            Err(VaultError::Corrupt) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(vault) => {
                // If the record parses, decryption of the touched record must fail.
                assert!(vault.secrets(id).is_err());
            }
        }
    }

    #[test]
    fn tampering_with_header_kdf_is_detected() {
        let vault = new_vault();
        let bytes = vault.to_bytes().unwrap();
        let text = String::from_utf8_lossy(&bytes);
        let tampered = text.replace("\"t_cost\":1", "\"t_cost\":2");
        assert_ne!(text, tampered);
        let result = Vault::unlock(tampered.as_bytes(), b"correct horse battery");
        assert!(result.is_err());
    }

    #[test]
    fn entry_records_cannot_be_swapped_between_entries() {
        let mut vault = new_vault();
        let first = vault.create_entry(draft("One", "password-one-1"), 2_000).unwrap();
        let second = vault.create_entry(draft("Two", "password-two-2"), 2_001).unwrap();

        // Swap ciphertexts while keeping ids: AAD binds record id, so opening
        // either record must fail.
        let first_index = vault.records.iter().position(|r| r.id == first).unwrap();
        let second_index = vault.records.iter().position(|r| r.id == second).unwrap();
        let first_ct = vault.records[first_index].ciphertext.clone();
        let second_ct = vault.records[second_index].ciphertext.clone();
        vault.records[first_index].ciphertext = second_ct;
        vault.records[second_index].ciphertext = first_ct;

        assert!(vault.secrets(first).is_err());
        assert!(vault.secrets(second).is_err());
    }

    #[test]
    fn history_is_recorded_and_restorable() {
        let mut vault = new_vault();
        let id = vault.create_entry(draft("Mail", "first-password"), 2_000).unwrap();
        let mut secrets = vault.secrets(id).unwrap();
        secrets.password = "second-password".into();
        vault.set_secrets(id, secrets, 3_000).unwrap();

        assert_eq!(vault.history_timestamps(id).unwrap().len(), 1);
        vault.restore_revision(id, 0, 4_000).unwrap();
        assert_eq!(vault.secrets(id).unwrap().password, "first-password");
    }

    #[test]
    fn history_is_capped() {
        let mut vault = new_vault();
        let id = vault.create_entry(draft("Mail", "start"), 2_000).unwrap();
        for i in 0..(HISTORY_LIMIT + 5) {
            let mut secrets = vault.secrets(id).unwrap();
            secrets.password = format!("password-{i}");
            vault.set_secrets(id, secrets, 3_000 + i as i64).unwrap();
        }
        assert_eq!(vault.history_timestamps(id).unwrap().len(), HISTORY_LIMIT);
    }

    #[test]
    fn trash_retention_and_purge() {
        let mut vault = new_vault();
        let id = vault.create_entry(draft("Old", "password-old-1"), 0).unwrap();
        vault.delete_entry(id, 0).unwrap();
        assert!(vault.list()[0].is_deleted());

        assert_eq!(vault.purge_expired(TRASH_RETENTION_MS - 1), 0);
        assert_eq!(vault.purge_expired(TRASH_RETENTION_MS + 1), 1);
        assert!(vault.list().is_empty());
    }

    #[test]
    fn verify_password_matches_unlock() {
        let vault = new_vault();
        assert!(vault.verify_password(b"correct horse battery"));
        assert!(!vault.verify_password(b"wrong password here"));
    }

    #[test]
    fn change_password_preserves_entries_and_invalidates_old_password() {
        let mut vault = new_vault();
        let id = vault.create_entry(draft("Router", "admin-password-1"), 2_000).unwrap();
        vault
            .change_password(b"an entirely new passphrase", fast_kdf())
            .unwrap();
        let bytes = vault.to_bytes().unwrap();

        assert_eq!(
            Vault::unlock(&bytes, b"correct horse battery").unwrap_err(),
            VaultError::InvalidPassword
        );
        let unlocked = Vault::unlock(&bytes, b"an entirely new passphrase").unwrap();
        assert_eq!(unlocked.secrets(id).unwrap().password, "admin-password-1");
    }

    #[test]
    fn recovery_key_opens_vault() {
        let created = Vault::create(
            b"correct horse battery",
            CreateOptions {
                kdf: fast_kdf(),
                recovery: true,
                now: 1_000,
            },
        )
        .unwrap();
        let recovery = created.recovery_key.clone().unwrap();
        let mut vault = created.vault;
        let id = vault.create_entry(draft("Mail", "pw"), 2_000).unwrap();
        let bytes = vault.to_bytes().unwrap();

        let unlocked = Vault::unlock_with_recovery(&bytes, &recovery).unwrap();
        assert_eq!(unlocked.secrets(id).unwrap().password, "pw");
        assert_eq!(
            Vault::unlock_with_recovery(&bytes, "AAAA-BBBB").unwrap_err(),
            VaultError::InvalidInput
        );
    }

    #[test]
    fn search_finds_by_title_and_excludes_trash() {
        let mut vault = new_vault();
        let id = vault.create_entry(draft("GitHub Account", "pw"), 2_000).unwrap();
        assert_eq!(vault.search("github"), vec![id]);
        vault.delete_entry(id, 3_000).unwrap();
        assert!(vault.search("github").is_empty());
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        let mut vault = new_vault();
        let mut bad = draft("   ", "pw");
        assert!(matches!(
            vault.create_entry(bad.clone(), 2_000),
            Err(VaultError::InvalidInput)
        ));
        bad.title = "ok".into();
        bad.secrets.password = "x".repeat(MAX_PASSWORD + 1);
        assert!(matches!(
            vault.create_entry(bad, 2_000),
            Err(VaultError::InvalidInput)
        ));
    }

    #[test]
    fn duplicate_tags_are_deduplicated() {
        let mut vault = new_vault();
        let mut entry = draft("Title", "pw");
        entry.tags = vec!["a".into(), "a".into(), " ".into(), "b".into()];
        let id = vault.create_entry(entry, 2_000).unwrap();
        assert_eq!(vault.meta(id).unwrap().tags, vec!["a", "b"]);
    }
}
