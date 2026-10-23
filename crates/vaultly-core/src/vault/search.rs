//! Fuzzy search over the metadata index.
//!
//! Search never touches secret payloads: it scores title, username, URL, folder
//! and tags from the index, which is already decrypted while unlocked.

use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use uuid::Uuid;

use super::index::Index;

/// Rank active entries against `query`; an empty query lists everything,
/// favourites first.
pub fn rank(index: &Index, query: &str) -> Vec<Uuid> {
    let needle = query.trim();
    if needle.is_empty() {
        let mut entries: Vec<&super::model::EntryMeta> = index
            .entries
            .iter()
            .filter(|entry| !entry.is_deleted())
            .collect();
        entries.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        return entries.into_iter().map(|entry| entry.id).collect();
    }

    let matcher = SkimMatcherV2::default();
    let mut scored: Vec<(i64, &super::model::EntryMeta)> = Vec::new();

    for entry in &index.entries {
        if entry.is_deleted() {
            continue;
        }
        let mut best: Option<i64> = None;
        let mut consider = |score: Option<i64>| {
            if let Some(score) = score {
                best = Some(best.map_or(score, |current| current.max(score)));
            }
        };

        consider(matcher.fuzzy_match(&entry.title, needle));
        consider(matcher.fuzzy_match(&entry.username, needle));
        consider(matcher.fuzzy_match(&entry.url, needle));
        if let Some(folder) = &entry.folder {
            consider(matcher.fuzzy_match(folder, needle));
        }
        for tag in &entry.tags {
            consider(matcher.fuzzy_match(tag, needle));
        }

        if let Some(score) = best {
            scored.push((score, entry));
        }
    }

    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.title.cmp(&b.1.title)));
    scored.into_iter().map(|(_, entry)| entry.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{EntryKind, EntryMeta};

    fn meta(title: &str, tags: &[&str], favorite: bool) -> EntryMeta {
        EntryMeta {
            id: Uuid::new_v4(),
            kind: EntryKind::Login,
            title: title.into(),
            username: "user".into(),
            url: "https://example.com".into(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            folder: Some("Work".into()),
            favorite,
            created_at: 0,
            updated_at: 0,
            password_updated_at: Some(0),
            deleted_at: None,
            has_totp: false,
            has_notes: false,
            has_card: false,
            has_identity: false,
            custom_labels: vec![],
            history_len: 0,
        }
    }

    fn index(entries: Vec<EntryMeta>) -> Index {
        Index {
            schema: 1,
            entries,
            folders: vec!["Work".into()],
        }
    }

    #[test]
    fn empty_query_returns_favourites_first() {
        let plain = meta("Alpha", &[], false);
        let favourite = meta("Zulu", &[], true);
        let (a, z) = (plain.id, favourite.id);
        let result = rank(&index(vec![plain, favourite]), "  ");
        assert_eq!(result[0], z);
        assert!(result.contains(&a));
    }

    #[test]
    fn matches_title_tags_and_folder() {
        let entry = meta("GitHub", &["dev", "code"], false);
        let id = entry.id;
        let index = index(vec![entry]);
        assert_eq!(rank(&index, "github"), vec![id]);
        assert_eq!(rank(&index, "code"), vec![id]);
        assert_eq!(rank(&index, "work"), vec![id]);
        assert!(rank(&index, "nomatch").is_empty());
    }

    #[test]
    fn deleted_entries_are_hidden() {
        let mut entry = meta("GitHub", &[], false);
        entry.deleted_at = Some(1);
        let index = index(vec![entry]);
        assert!(rank(&index, "").is_empty());
        assert!(rank(&index, "github").is_empty());
    }
}
