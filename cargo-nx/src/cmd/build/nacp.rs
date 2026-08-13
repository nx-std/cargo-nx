//! Assembly of NACP control data from a package's `[package.metadata.nx.nro.nacp]`
//! block.
//!
//! A manifest may leave every field unset, so the defaults applied here are what
//! decides what a title is actually called on the console. Per-language entries
//! override the global name and author; a language the manifest does not mention
//! falls back to them rather than being left blank.

use nx_object::{
    read::nacp::SetLanguage,
    write::{NacpBuilder, nacp},
};

use super::metadata::{NacpLangEntry, NacpMetadata};

/// Assemble NACP control data from a package's manifest metadata.
///
/// A field the manifest leaves unset takes a placeholder default rather than
/// failing, so this always produces usable control data. Per-language entries
/// override the global name and author; a language absent from the table falls back
/// to them.
///
/// `dlc_base_title_id` is accepted by the manifest but not applied here: the builder
/// derives the add-on content base id from the application id itself.
///
/// # Errors
///
/// Returns an error if `title_id` is not hexadecimal, or if a name, author, or
/// version exceeds the fixed width NACP reserves for it.
pub fn build_nacp_from_metadata(metadata: &NacpMetadata) -> Result<Vec<u8>, BuildNacpError> {
    // Use defaults for unset fields
    let default_name = metadata
        .name
        .clone()
        .unwrap_or_else(|| "Unknown Application".to_string());
    let default_author = metadata
        .author
        .clone()
        .unwrap_or_else(|| "Unknown Author".to_string());
    let default_version = metadata
        .version
        .clone()
        .unwrap_or_else(|| "1.0.0".to_string());

    let mut builder = NacpBuilder::new().version(default_version);

    // If per-language entries exist, use them; otherwise use global defaults
    match &metadata.lang {
        Some(lang_entries) => {
            // Set per-language entries, falling back to the global defaults
            let fallback = NacpLangEntry {
                name: default_name.clone(),
                author: default_author.clone(),
            };

            // Helper macro to set language entry with fallback
            macro_rules! set_lang {
                ($lang:expr, $entry:expr) => {
                    if let Some(ref entry) = $entry {
                        builder = builder
                            .name_for_language($lang, &entry.name)
                            .author_for_language($lang, &entry.author);
                    } else {
                        builder = builder
                            .name_for_language($lang, &fallback.name)
                            .author_for_language($lang, &fallback.author);
                    }
                };
            }

            set_lang!(SetLanguage::ENUS, lang_entries.en_us);
            set_lang!(SetLanguage::ENGB, lang_entries.en_gb);
            set_lang!(SetLanguage::JA, lang_entries.ja);
            set_lang!(SetLanguage::FR, lang_entries.fr);
            set_lang!(SetLanguage::DE, lang_entries.de);
            set_lang!(SetLanguage::ES419, lang_entries.es_419);
            set_lang!(SetLanguage::ES, lang_entries.es);
            set_lang!(SetLanguage::IT, lang_entries.it);
            set_lang!(SetLanguage::NL, lang_entries.nl);
            set_lang!(SetLanguage::FRCA, lang_entries.fr_ca);
            set_lang!(SetLanguage::PT, lang_entries.pt);
            set_lang!(SetLanguage::RU, lang_entries.ru);
            set_lang!(SetLanguage::KO, lang_entries.ko);
            set_lang!(SetLanguage::ZHTW, lang_entries.zh_tw);
            set_lang!(SetLanguage::ZHCN, lang_entries.zh_cn);
            set_lang!(SetLanguage::PTBR, lang_entries.pt_br);
        }
        None => {
            // No per-language entries, use global defaults for all languages
            builder = builder.name(default_name).author(default_author);
        }
    }

    // Parse title_id if provided
    if let Some(ref title_id_str) = metadata.title_id {
        let title_id = u64::from_str_radix(title_id_str, 16).map_err(|err| {
            BuildNacpError::InvalidTitleId {
                value: title_id_str.clone(),
                source: err,
            }
        })?;
        builder = builder.application_id(title_id);
    }

    // Note: dlc_base_title_id is not supported by NacpBuilder yet.
    // NacpBuilder already sets add_on_content_base_id to title_id + 0x1000
    // automatically, so we don't need to handle it separately.

    // Build NACP bytes
    builder.build().map_err(BuildNacpError::Build)
}

/// Errors produced while building NACP control data from `Cargo.toml` metadata.
#[derive(Debug, thiserror::Error)]
pub enum BuildNacpError {
    /// `title_id` is not a hexadecimal integer.
    ///
    /// The manifest writes it as a bare hex string, so a `0x` prefix is rejected
    /// here too. Holds the offending value.
    #[error("invalid title_id '{value}'")]
    InvalidTitleId {
        /// The value that failed to parse.
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },

    /// A field does not fit the fixed width NACP reserves for it.
    #[error("failed to assemble the NACP control data")]
    Build(#[source] nacp::BuildError),
}

#[cfg(test)]
mod tests {
    use super::{BuildNacpError, NacpMetadata, build_nacp_from_metadata};

    #[test]
    fn build_nacp_from_metadata_with_a_non_hexadecimal_title_id_fails() {
        //* Given
        let metadata = NacpMetadata {
            title_id: Some("not-hex".to_string()),
            ..Default::default()
        };

        //* When
        let result = build_nacp_from_metadata(&metadata);

        //* Then
        assert!(
            matches!(result, Err(BuildNacpError::InvalidTitleId { ref value, .. }) if value == "not-hex"),
            "the offending value should be carried on the error, got {result:?}"
        );
    }

    #[test]
    fn build_nacp_from_metadata_with_a_prefixed_title_id_fails() {
        //* Given
        // Unlike the NPDM fields, this one is read as bare hex digits.
        let metadata = NacpMetadata {
            title_id: Some("0x0100000000010000".to_string()),
            ..Default::default()
        };

        //* When
        let result = build_nacp_from_metadata(&metadata);

        //* Then
        assert!(
            matches!(result, Err(BuildNacpError::InvalidTitleId { .. })),
            "a `0x` prefix should be rejected rather than stripped, got {result:?}"
        );
    }

    #[test]
    fn build_nacp_from_metadata_without_a_title_id_succeeds() {
        //* Given
        // Every other field is optional and falls back to a default.
        let metadata = NacpMetadata::default();

        //* When
        let result = build_nacp_from_metadata(&metadata);

        //* Then
        assert!(
            result.is_ok(),
            "a bare metadata block should still produce NACP data, got {result:?}"
        );
    }
}
