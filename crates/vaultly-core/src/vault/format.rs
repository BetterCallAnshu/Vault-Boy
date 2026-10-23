//! Vault file format v1.
//!
//! ```text
//! magic       "VLTY"                      4 bytes
//! version     u16 LE                      2 bytes
//! header_len  u32 LE                      4 bytes
//! header      JSON (see [Header])         header_len bytes
//! index_len   u32 LE                      4 bytes
//! index_nonce 24 bytes
//! index_ct    index_len bytes             AEAD(index key, aad = base || "index")
//! record_cnt  u32 LE                      4 bytes
//! records     repeated:
//!               id        16 bytes
//!               ct_len    u32 LE
//!               nonce     24 bytes
//!               ct        ct_len bytes    AEAD(entry key, aad = base || "entry" || id)
//! ```
//!
//! `base` is `magic || version || vault_id`, so a wrapped key, index or entry
//! cannot be moved to another vault, another entry, or a different version.
//! See `docs/VAULT_FORMAT.md`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::VaultError;
use crate::crypto::aead::{Sealed, NONCE_LEN, TAG_LEN};
use crate::crypto::kdf::{KdfParams, SALT_LEN};

pub const MAGIC: [u8; 4] = *b"VLTY";
pub const VERSION: u16 = 1;

pub const MAX_HEADER_LEN: u32 = 64 * 1024;
pub const MAX_INDEX_LEN: u32 = 64 * 1024 * 1024;
pub const MAX_RECORD_LEN: u32 = 16 * 1024 * 1024;
pub const MAX_ENTRIES: u32 = 100_000;
/// 32-byte wrapped key plus a 16-byte Poly1305 tag.
pub const WRAP_LEN: usize = 32 + TAG_LEN;

pub const LABEL_PASSWORD: &[u8] = b"wrap:password";
pub const LABEL_RECOVERY: &[u8] = b"wrap:recovery";
pub const LABEL_HELLO: &[u8] = b"wrap:hello";
pub const LABEL_INDEX: &[u8] = b"index";
pub const LABEL_ENTRY: &[u8] = b"entry";

/// AEAD wrapper stored in the header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wrap {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Wrap {
    pub fn from_sealed(sealed: &Sealed) -> Self {
        Wrap {
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext.clone(),
        }
    }

    pub fn to_sealed(&self) -> Sealed {
        Sealed {
            nonce: self.nonce,
            ciphertext: self.ciphertext.clone(),
        }
    }
}

/// The recovery key wraps the same vault root key, under its own Argon2id salt
/// and parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryWrap {
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub wrap: Wrap,
}

/// Windows Hello wrap. The ciphertext is produced by a Hello-protected CNG
/// key held by the platform layer; the core only stores and returns it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloWrap {
    pub credential: String,
    pub wrap: Wrap,
    pub created_at: i64,
}

/// Plaintext, authenticated header.
///
/// The KDF parameters and salt feed key derivation, so tampering with them
/// makes the wrapped vault key fail authentication. The vault id is in every
/// AAD, so the header cannot be spliced between vaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub vault_id: [u8; 16],
    pub created_at: i64,
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub wrap: Wrap,
    #[serde(default)]
    pub recovery: Option<RecoveryWrap>,
    #[serde(default)]
    pub hello: Option<HelloWrap>,
}

impl Header {
    pub fn validate(&self) -> Result<(), VaultError> {
        self.kdf.validate().map_err(|_| VaultError::Corrupt)?;
        if self.wrap.ciphertext.len() != WRAP_LEN {
            return Err(VaultError::Corrupt);
        }
        if let Some(recovery) = &self.recovery {
            recovery.kdf.validate().map_err(|_| VaultError::Corrupt)?;
            if recovery.wrap.ciphertext.len() != WRAP_LEN {
                return Err(VaultError::Corrupt);
            }
        }
        if let Some(hello) = &self.hello {
            if hello.wrap.ciphertext.len() != WRAP_LEN || hello.credential.len() > 256 {
                return Err(VaultError::Corrupt);
            }
        }
        Ok(())
    }
}

/// One encrypted entry record.
#[derive(Debug, Clone)]
pub struct Record {
    pub id: Uuid,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Parsed vault bytes, still encrypted.
#[derive(Debug, Clone)]
pub struct RawVault {
    pub header: Header,
    pub index_nonce: [u8; NONCE_LEN],
    pub index: Vec<u8>,
    pub records: Vec<Record>,
}

/// Base associated data shared by every AEAD operation in a vault.
pub fn aad_base(vault_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + 2 + 16);
    aad.extend_from_slice(&MAGIC);
    aad.extend_from_slice(&VERSION.to_le_bytes());
    aad.extend_from_slice(vault_id);
    aad
}

/// `base || label`.
pub fn aad_labeled(vault_id: &[u8; 16], label: &[u8]) -> Vec<u8> {
    let mut aad = aad_base(vault_id);
    aad.extend_from_slice(label);
    aad
}

/// `base || "entry" || entry_id`.
pub fn aad_entry(vault_id: &[u8; 16], entry_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = aad_labeled(vault_id, LABEL_ENTRY);
    aad.extend_from_slice(entry_id);
    aad
}

impl RawVault {
    pub fn encode(&self) -> Result<Vec<u8>, VaultError> {
        let header = serde_json::to_vec(&self.header).map_err(|_| VaultError::Corrupt)?;
        if header.len() > MAX_HEADER_LEN as usize
            || self.index.len() > MAX_INDEX_LEN as usize
            || self.records.len() > MAX_ENTRIES as usize
        {
            return Err(VaultError::InvalidInput);
        }

        let capacity = 4
            + 2
            + 4
            + header.len()
            + 4
            + NONCE_LEN
            + self.index.len()
            + 4
            + self
                .records
                .iter()
                .map(|record| 16 + 4 + NONCE_LEN + record.ciphertext.len())
                .sum::<usize>();
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(header.len() as u32).to_le_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&(self.index.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.index_nonce);
        out.extend_from_slice(&self.index);

        out.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        for record in &self.records {
            if record.ciphertext.len() > MAX_RECORD_LEN as usize {
                return Err(VaultError::InvalidInput);
            }
            out.extend_from_slice(record.id.as_bytes());
            out.extend_from_slice(&(record.ciphertext.len() as u32).to_le_bytes());
            out.extend_from_slice(&record.nonce);
            out.extend_from_slice(&record.ciphertext);
        }
        Ok(out)
    }

    pub fn parse(bytes: &[u8]) -> Result<RawVault, VaultError> {
        let mut reader = Reader::new(bytes);

        let magic = reader.take(4)?;
        if magic != MAGIC {
            return Err(VaultError::BadMagic);
        }
        let version = reader.u16()?;
        if version != VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }

        let header_len = reader.u32()?;
        if header_len == 0 || header_len > MAX_HEADER_LEN {
            return Err(VaultError::Corrupt);
        }
        let header_bytes = reader.take(header_len as usize)?;
        let header: Header = serde_json::from_slice(header_bytes).map_err(|_| VaultError::Corrupt)?;
        header.validate()?;

        let index_len = reader.u32()?;
        if index_len < TAG_LEN as u32 || index_len > MAX_INDEX_LEN {
            return Err(VaultError::Corrupt);
        }
        let mut index_nonce = [0u8; NONCE_LEN];
        index_nonce.copy_from_slice(reader.take(NONCE_LEN)?);
        let index = reader.take(index_len as usize)?.to_vec();

        let record_count = reader.u32()?;
        if record_count > MAX_ENTRIES {
            return Err(VaultError::Corrupt);
        }
        let mut records = Vec::with_capacity(record_count as usize);
        let mut seen = std::collections::HashSet::with_capacity(record_count as usize);
        for _ in 0..record_count {
            let mut id_bytes = [0u8; 16];
            id_bytes.copy_from_slice(reader.take(16)?);
            let id = Uuid::from_bytes(id_bytes);

            let ct_len = reader.u32()?;
            if ct_len < TAG_LEN as u32 || ct_len > MAX_RECORD_LEN {
                return Err(VaultError::Corrupt);
            }
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(reader.take(NONCE_LEN)?);
            let ciphertext = reader.take(ct_len as usize)?.to_vec();

            if !seen.insert(id) {
                return Err(VaultError::Corrupt);
            }
            records.push(Record {
                id,
                nonce,
                ciphertext,
            });
        }

        if reader.remaining() != 0 {
            return Err(VaultError::Corrupt);
        }

        Ok(RawVault {
            header,
            index_nonce,
            index,
            records,
        })
    }
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], VaultError> {
        let end = self.offset.checked_add(len).ok_or(VaultError::Corrupt)?;
        if end > self.data.len() {
            return Err(VaultError::Corrupt);
        }
        let slice = &self.data[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16, VaultError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, VaultError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;

    fn header() -> Header {
        Header {
            vault_id: [9u8; 16],
            created_at: 1,
            kdf: KdfParams::default(),
            salt: [1u8; SALT_LEN],
            wrap: Wrap {
                nonce: [2u8; NONCE_LEN],
                ciphertext: vec![3u8; WRAP_LEN],
            },
            recovery: None,
            hello: None,
        }
    }

    fn raw() -> RawVault {
        RawVault {
            header: header(),
            index_nonce: [4u8; NONCE_LEN],
            index: vec![5u8; 48],
            records: vec![Record {
                id: Uuid::from_bytes([6u8; 16]),
                nonce: [7u8; NONCE_LEN],
                ciphertext: vec![8u8; 64],
            }],
        }
    }

    #[test]
    fn round_trips() {
        let bytes = raw().encode().unwrap();
        let parsed = RawVault::parse(&bytes).unwrap();
        assert_eq!(parsed.header.vault_id, [9u8; 16]);
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.index, vec![5u8; 48]);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = raw().encode().unwrap();
        bytes[0] = b'X';
        assert_eq!(RawVault::parse(&bytes).unwrap_err(), VaultError::BadMagic);
    }

    #[test]
    fn rejects_unknown_version() {
        let mut bytes = raw().encode().unwrap();
        bytes[4] = 2;
        assert_eq!(
            RawVault::parse(&bytes).unwrap_err(),
            VaultError::UnsupportedVersion(2)
        );
    }

    #[test]
    fn rejects_truncation_and_trailing_bytes() {
        let mut bytes = raw().encode().unwrap();
        bytes.pop();
        assert_eq!(RawVault::parse(&bytes).unwrap_err(), VaultError::Corrupt);

        let mut bytes = raw().encode().unwrap();
        bytes.push(0);
        assert_eq!(RawVault::parse(&bytes).unwrap_err(), VaultError::Corrupt);
    }

    #[test]
    fn rejects_duplicate_record_ids() {
        let mut vault = raw();
        let duplicate = vault.records[0].clone();
        vault.records.push(duplicate);
        let bytes = vault.encode().unwrap();
        assert_eq!(RawVault::parse(&bytes).unwrap_err(), VaultError::Corrupt);
    }

    #[test]
    fn rejects_downgraded_kdf_parameters() {
        let mut vault = raw();
        vault.header.kdf = KdfParams::new(1024, 1, 1);
        let bytes = vault.encode().unwrap();
        assert_eq!(RawVault::parse(&bytes).unwrap_err(), VaultError::Corrupt);
    }

    #[test]
    fn aad_labels_differ() {
        let id = [1u8; 16];
        assert_ne!(aad_labeled(&id, LABEL_INDEX), aad_labeled(&id, LABEL_ENTRY));
        assert_ne!(
            aad_entry(&id, &[1u8; 16]),
            aad_entry(&id, &[2u8; 16])
        );
    }
}
