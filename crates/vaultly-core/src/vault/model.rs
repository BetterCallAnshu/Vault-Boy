//! Data model for vault entries.
//!
//! Split into [`EntryMeta`] (small, searchable, kept decrypted in the encrypted
//! index while unlocked) and [`EntrySecrets`] (encrypted in a per-entry record
//! and only decrypted on demand). Every type here zeroizes on drop.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

/// The four entry shapes the UI offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    #[default]
    Login,
    Note,
    Card,
    Identity,
}

impl EntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::Login => "login",
            EntryKind::Note => "note",
            EntryKind::Card => "card",
            EntryKind::Identity => "identity",
        }
    }
}

/// A user-defined field. Values are always treated as secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CustomField {
    pub label: String,
    pub value: String,
    /// Whether the UI masks the value by default.
    pub secret: bool,
}

impl CustomField {
    fn wipe(&mut self) {
        self.label.zeroize();
        self.value.zeroize();
    }
}

impl Zeroize for CustomField {
    fn zeroize(&mut self) {
        self.wipe();
    }
}

impl Drop for CustomField {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Payment card details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CardSecrets {
    pub number: String,
    pub holder: String,
    pub expiry: String,
    pub cvv: String,
    pub pin: String,
}

impl Drop for CardSecrets {
    fn drop(&mut self) {
        self.number.zeroize();
        self.holder.zeroize();
        self.expiry.zeroize();
        self.cvv.zeroize();
        self.pin.zeroize();
    }
}

/// Identity document details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IdentitySecrets {
    pub full_name: String,
    pub email: String,
    pub phone: String,
    pub address: String,
    pub passport: String,
    pub national_id: String,
    pub date_of_birth: String,
}

impl Drop for IdentitySecrets {
    fn drop(&mut self) {
        self.full_name.zeroize();
        self.email.zeroize();
        self.phone.zeroize();
        self.address.zeroize();
        self.passport.zeroize();
        self.national_id.zeroize();
        self.date_of_birth.zeroize();
    }
}

/// Secret payload of an entry, encrypted in its own record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EntrySecrets {
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub notes: String,
    /// Base32 TOTP secret or `otpauth://` URI. Never sent to the frontend by
    /// default; the UI receives only generated codes.
    #[serde(default)]
    pub totp_secret: String,
    #[serde(default)]
    pub card: Option<CardSecrets>,
    #[serde(default)]
    pub identity: Option<IdentitySecrets>,
    #[serde(default)]
    pub custom: Vec<CustomField>,
}

impl EntrySecrets {
    /// Whether this payload carries any secret at all.
    pub fn is_empty(&self) -> bool {
        self.password.is_empty()
            && self.notes.is_empty()
            && self.totp_secret.is_empty()
            && self.card.as_ref().is_none_or(|c| {
                c.number.is_empty() && c.holder.is_empty() && c.cvv.is_empty()
            })
            && self.identity.as_ref().is_none_or(|i| {
                i.full_name.is_empty() && i.email.is_empty() && i.phone.is_empty()
            })
            && self.custom.iter().all(|f| f.value.is_empty())
    }

    /// Read a single named field. Used by the reveal/copy IPC path.
    pub fn field(&self, field: SecretField) -> Option<&str> {
        let value = match field {
            SecretField::Password => &self.password,
            SecretField::Notes => &self.notes,
            SecretField::TotpSecret => &self.totp_secret,
            SecretField::CardNumber => &self.card.as_ref()?.number,
            SecretField::CardHolder => &self.card.as_ref()?.holder,
            SecretField::CardExpiry => &self.card.as_ref()?.expiry,
            SecretField::CardCvv => &self.card.as_ref()?.cvv,
            SecretField::CardPin => &self.card.as_ref()?.pin,
            SecretField::IdentityFullName => &self.identity.as_ref()?.full_name,
            SecretField::IdentityEmail => &self.identity.as_ref()?.email,
            SecretField::IdentityPhone => &self.identity.as_ref()?.phone,
            SecretField::IdentityAddress => &self.identity.as_ref()?.address,
            SecretField::IdentityPassport => &self.identity.as_ref()?.passport,
            SecretField::IdentityNationalId => &self.identity.as_ref()?.national_id,
            SecretField::IdentityDateOfBirth => &self.identity.as_ref()?.date_of_birth,
        };
        Some(value).filter(|v| !v.is_empty()).map(String::as_str)
    }

    /// Value of a custom field by position.
    pub fn custom_field(&self, index: usize) -> Option<&str> {
        self.custom
            .get(index)
            .map(|f| f.value.as_str())
            .filter(|v| !v.is_empty())
    }
}

impl Drop for EntrySecrets {
    fn drop(&mut self) {
        self.password.zeroize();
        self.notes.zeroize();
        self.totp_secret.zeroize();
        // Option<CardSecrets>/IdentitySecrets and Vec<CustomField> zeroize on
        // their own drops.
    }
}

/// A named secret the UI may ask the backend to reveal or copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretField {
    Password,
    Notes,
    TotpSecret,
    CardNumber,
    CardHolder,
    CardExpiry,
    CardCvv,
    CardPin,
    IdentityFullName,
    IdentityEmail,
    IdentityPhone,
    IdentityAddress,
    IdentityPassport,
    IdentityNationalId,
    IdentityDateOfBirth,
}

/// One previous version of an entry's secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Revision {
    pub at: i64,
    pub secrets: EntrySecrets,
}

impl Drop for Revision {
    fn drop(&mut self) {
        // EntrySecrets zeroizes on drop; nothing else here is secret.
        let _ = &self.at;
    }
}

/// Searchable metadata. Held decrypted only while the vault is unlocked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntryMeta {
    pub id: Uuid,
    pub kind: EntryKind,
    pub title: String,
    pub username: String,
    pub url: String,
    pub tags: Vec<String>,
    pub folder: Option<String>,
    pub favorite: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub password_updated_at: Option<i64>,
    pub deleted_at: Option<i64>,
    /// Presence flags so the UI never needs to decrypt an entry to render it.
    pub has_totp: bool,
    pub has_notes: bool,
    pub has_card: bool,
    pub has_identity: bool,
    /// Custom field labels only; values stay encrypted.
    pub custom_labels: Vec<String>,
    pub history_len: usize,
}

impl EntryMeta {
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    fn wipe(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.url.zeroize();
        for tag in &mut self.tags {
            tag.zeroize();
        }
        if let Some(folder) = &mut self.folder {
            folder.zeroize();
        }
        for label in &mut self.custom_labels {
            label.zeroize();
        }
    }
}

impl Drop for EntryMeta {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_lookup_covers_every_kind() {
        let mut identity = IdentitySecrets::default();
        identity.full_name = "A B".into();
        let secrets = EntrySecrets {
            password: "pw".into(),
            notes: "note".into(),
            totp_secret: "JBSWY3DPEHPK3PXP".into(),
            card: Some(CardSecrets {
                number: "4111".into(),
                holder: "A".into(),
                expiry: "01/30".into(),
                cvv: "123".into(),
                pin: "9999".into(),
            }),
            identity: Some(identity),
            custom: vec![CustomField {
                label: "API key".into(),
                value: "k".into(),
                secret: true,
            }],
        };
        assert_eq!(secrets.field(SecretField::Password), Some("pw"));
        assert_eq!(secrets.field(SecretField::CardNumber), Some("4111"));
        assert_eq!(secrets.field(SecretField::IdentityFullName), Some("A B"));
        assert_eq!(secrets.field(SecretField::IdentityEmail), None);
        assert_eq!(secrets.custom_field(0), Some("k"));
        assert_eq!(secrets.custom_field(5), None);
    }
}
