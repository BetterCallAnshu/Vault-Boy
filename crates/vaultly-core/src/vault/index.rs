//! The index: small metadata for every entry, encrypted as one AEAD record.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::model::EntryMeta;

pub const INDEX_SCHEMA: u16 = 1;

/// All searchable metadata plus the user's folder list.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Index {
    pub schema: u16,
    pub entries: Vec<EntryMeta>,
    pub folders: Vec<String>,
}

impl Index {
    pub fn new() -> Self {
        Index {
            schema: INDEX_SCHEMA,
            entries: Vec::new(),
            folders: Vec::new(),
        }
    }
}

impl Drop for Index {
    fn drop(&mut self) {
        for entry in &mut self.entries {
            // EntryMeta zeroizes itself.
            let _ = entry;
        }
        for folder in &mut self.folders {
            folder.zeroize();
        }
    }
}
