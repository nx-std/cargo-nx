//! The console keys an NCA is encrypted with, loaded from a keyset file.
//!
//! A keyset file is a flat list of `name = hex` lines. Every tool in this ecosystem reads the same
//! file, so it holds far more than any one of them needs; this module keeps the two keys an NCA
//! needs and ignores the rest rather than modelling a keyset in full.
//!
//! Those two are the header key, which encrypts an NCA header, and the application key area key for
//! the generation the archive is built for, which wraps its key area. Either may be listed
//! directly or derived from a master key and the seeds beside it, so parsing is followed by a
//! derivation pass — a keyset that lists a key wins over one that could produce it, which is the
//! same answer in practice and the one that does not silently override what the file said.
//!
//! Derivation stops at the master keys. The chain below them runs on the secure boot key and the
//! TSEC key, which are unique to one console and are not what a keyset distributed for packing
//! homebrew carries; a file that supplies neither a master key nor a derived key for the generation
//! asked for is reported as missing it.
//!
//! Parsing here takes text and nothing else: a keyset arrives already read, so this file has no
//! opinion on where one lives. Finding and reading it is [`file`]'s job, which is what keeps the
//! derivation below testable from a string literal.

use std::collections::HashMap;

use nx_object::write::nca::KeyGeneration;

pub mod file;

use crate::crypto::aes_ecb_decrypt;

/// Number of key generations a keyset file can name.
const KEY_GENERATION_COUNT: usize = 32;

/// The keys needed to encrypt an NCA, indexed by the generation they belong to.
pub struct Keyset {
    header_key: Option<[u8; 0x20]>,
    key_area_key_application: [Option<[u8; 0x10]>; KEY_GENERATION_COUNT],
}

impl Keyset {
    /// The key an NCA header is encrypted with, if the keyset carries or can derive it.
    pub fn header_key(&self) -> Option<&[u8; 0x20]> {
        self.header_key.as_ref()
    }

    /// The key that wraps an application's key area at `generation`, if the keyset has it.
    pub fn key_area_key_application(&self, generation: KeyGeneration) -> Option<&[u8; 0x10]> {
        // A generation is 1-based and bounded by its own constructor, so the slot always exists.
        self.key_area_key_application
            .get(usize::from(generation.to_u8()) - 1)
            .and_then(Option::as_ref)
    }
}

impl std::str::FromStr for Keyset {
    type Err = ParseKeysetError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let entries = parse_entries(text)?;
        Ok(derive(&entries))
    }
}

/// The `name = hex` pairs of a keyset file, with names lowercased.
type Entries = HashMap<String, Vec<u8>>;

/// Split `text` into its named hex values.
///
/// Blank lines and comments are skipped, and a name this crate has no use for is kept rather than
/// rejected: a keyset file is shared with other tools and listing an unknown key is not an error.
fn parse_entries(text: &str) -> Result<Entries, ParseKeysetError> {
    let mut entries = Entries::new();

    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        let Some((name, value)) = line.split_once(['=', ',']) else {
            return Err(ParseKeysetError::MalformedLine { line: index + 1 });
        };

        let value = decode_hex(value.trim()).ok_or(ParseKeysetError::MalformedValue {
            line: index + 1,
            name: name.trim().to_lowercase(),
        })?;

        entries.insert(name.trim().to_lowercase(), value);
    }

    Ok(entries)
}

/// Decode a hex string into bytes, or `None` if it is not one of even length.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }

    (0..text.len())
        .step_by(2)
        .map(|start| u8::from_str_radix(&text[start..start + 2], 16).ok())
        .collect()
}

/// Take the keys the entries list, then fill in whatever the master keys can produce.
fn derive(entries: &Entries) -> Keyset {
    let mut header_key = fixed_size(entries, "header_key");
    let mut key_area_key_application = [None; KEY_GENERATION_COUNT];
    for (generation, slot) in key_area_key_application.iter_mut().enumerate() {
        *slot = fixed_size(
            entries,
            &format!("key_area_key_application_{generation:02x}"),
        );
    }

    let kek_generation_source: Option<[u8; 0x10]> =
        fixed_size(entries, "aes_kek_generation_source");
    let key_generation_source: Option<[u8; 0x10]> =
        fixed_size(entries, "aes_key_generation_source");
    let application_source: Option<[u8; 0x10]> =
        fixed_size(entries, "key_area_key_application_source");
    let header_kek_source: Option<[u8; 0x10]> = fixed_size(entries, "header_kek_source");
    let header_key_source: Option<[u8; 0x20]> = fixed_size(entries, "header_key_source");

    let (Some(kek_generation_source), Some(key_generation_source)) =
        (kek_generation_source, key_generation_source)
    else {
        // Without both seeds nothing below the master keys can be produced, so whatever the file
        // listed directly is all there is.
        return Keyset {
            header_key,
            key_area_key_application,
        };
    };

    for (generation, key_area_key) in key_area_key_application.iter_mut().enumerate() {
        let Some(master_key) = fixed_size::<0x10>(entries, &format!("master_key_{generation:02x}"))
        else {
            continue;
        };

        if key_area_key.is_none()
            && let Some(source) = application_source
        {
            *key_area_key = Some(generate_kek(
                &source,
                &master_key,
                &kek_generation_source,
                &key_generation_source,
            ));
        }

        // The header key belongs to the first generation alone: an NCA header is encrypted with the
        // same key whatever generation its key area was wrapped with.
        if generation == 0
            && header_key.is_none()
            && let (Some(kek_source), Some(key_source)) = (header_kek_source, header_key_source)
        {
            let header_kek = generate_kek(
                &kek_source,
                &master_key,
                &kek_generation_source,
                &key_generation_source,
            );
            let mut key = key_source;
            aes_ecb_decrypt(&header_kek, &mut key);
            header_key = Some(key);
        }
    }

    Keyset {
        header_key,
        key_area_key_application,
    }
}

/// Read the entry named `name`, if it is present and exactly `N` bytes long.
///
/// A key of the wrong length is treated as absent rather than as an error: keyset files in the wild
/// carry entries whose names collide with these at other sizes, and refusing the whole file over one
/// would make it unusable for the keys that are fine.
fn fixed_size<const N: usize>(entries: &Entries, name: &str) -> Option<[u8; N]> {
    entries.get(name)?.as_slice().try_into().ok()
}

/// Unwrap one key from another, the way the console's key generation does.
///
/// Three chained ECB decryptions: the master key unwraps the generation seed into a KEK, the KEK
/// unwraps `source` into a key-specific KEK, and that unwraps the final seed into the key.
fn generate_kek(
    source: &[u8; 0x10],
    master_key: &[u8; 0x10],
    kek_generation_source: &[u8; 0x10],
    key_generation_source: &[u8; 0x10],
) -> [u8; 0x10] {
    let mut kek = *kek_generation_source;
    aes_ecb_decrypt(master_key, &mut kek);

    let mut source_kek = *source;
    aes_ecb_decrypt(&kek, &mut source_kek);

    let mut key = *key_generation_source;
    aes_ecb_decrypt(&source_kek, &mut key);
    key
}

/// Error returned when a keyset file cannot be parsed.
#[derive(Debug, thiserror::Error)]
pub enum ParseKeysetError {
    /// A line carries neither `=` nor `,` and so names nothing.
    ///
    /// Holds the 1-based line number.
    #[error("line {line} is not a `name = value` pair")]
    MalformedLine {
        /// The 1-based line number.
        line: usize,
    },
    /// A value is not an even-length run of hex digits.
    ///
    /// Holds the 1-based line number and the name whose value was rejected.
    #[error("the value of '{name}' on line {line} is not hexadecimal")]
    MalformedValue {
        /// The 1-based line number.
        line: usize,
        /// The name whose value was rejected.
        name: String,
    },
}

#[cfg(test)]
mod tests {
    use nx_object::write::nca::KeyGeneration;

    use super::Keyset;

    #[test]
    fn from_str_takes_a_listed_header_key_as_given() {
        //* Given
        let text = format!("header_key = {}\n", "ab".repeat(0x20));

        //* When
        let keyset: Keyset = text.parse().expect("a well-formed keyset should parse");

        //* Then
        assert_eq!(
            keyset.header_key(),
            Some(&[0xABu8; 0x20]),
            "the file's own value should be used"
        );
    }

    #[test]
    fn key_area_key_application_finds_a_listed_key_at_its_generation() {
        //* Given
        let text = format!("key_area_key_application_02 = {}\n", "cd".repeat(0x10));

        //* When
        let keyset: Keyset = text.parse().expect("a well-formed keyset should parse");

        //* Then
        let generation = KeyGeneration::try_from(3).expect("3 is a valid generation");
        assert_eq!(
            keyset.key_area_key_application(generation),
            Some(&[0xCDu8; 0x10]),
            "generation 3 is named `_02`, since the file numbers from zero"
        );
    }

    #[test]
    fn key_area_key_application_reports_a_generation_the_file_omits_as_absent() {
        //* Given
        let text = format!("key_area_key_application_00 = {}\n", "11".repeat(0x10));
        let keyset: Keyset = text.parse().expect("a well-formed keyset should parse");

        //* When
        let generation = KeyGeneration::try_from(9).expect("9 is a valid generation");
        let key = keyset.key_area_key_application(generation);

        //* Then
        assert!(key.is_none(), "nothing in the file names generation 9");
    }

    #[test]
    fn from_str_derives_a_key_area_key_from_a_master_key_and_the_seeds() {
        //* Given
        // Only the seeds and a master key: nothing lists the key area key itself.
        let text = format!(
            "master_key_00 = {}\n\
             aes_kek_generation_source = {}\n\
             aes_key_generation_source = {}\n\
             key_area_key_application_source = {}\n",
            "01".repeat(0x10),
            "02".repeat(0x10),
            "03".repeat(0x10),
            "04".repeat(0x10),
        );

        //* When
        let keyset: Keyset = text.parse().expect("a well-formed keyset should parse");

        //* Then
        assert!(
            keyset
                .key_area_key_application(KeyGeneration::FIRST)
                .is_some(),
            "the master key and the seeds are enough to produce it"
        );
    }

    #[test]
    fn from_str_ignores_comments_blank_lines_and_unknown_names() {
        //* Given
        let text = format!(
            "# a comment\n\
             \n\
             titlekek_00 = {}\n\
             header_key = {}\n",
            "ff".repeat(0x10),
            "ab".repeat(0x20),
        );

        //* When
        let keyset: Keyset = text.parse().expect("unknown names are not an error");

        //* Then
        assert_eq!(keyset.header_key(), Some(&[0xABu8; 0x20]));
    }

    #[test]
    fn from_str_refuses_a_line_without_a_separator() {
        //* Given
        let text = "header_key\n";

        //* When
        let result = text.parse::<Keyset>();

        //* Then
        assert!(result.is_err(), "a line naming nothing cannot be read");
    }

    #[test]
    fn from_str_refuses_a_value_that_is_not_hexadecimal() {
        //* Given
        let text = "header_key = not-hex\n";

        //* When
        let result = text.parse::<Keyset>();

        //* Then
        assert!(
            result.is_err(),
            "a key that cannot be decoded would silently become the wrong key"
        );
    }
}
