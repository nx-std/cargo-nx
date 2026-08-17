//! Decrypting an NCA into the plaintext container it was built from.
//!
//! This inverts what packing seals, and the steps run in the reverse order for the same reason the
//! forward ones run in theirs:
//!
//! 1. Decrypt the header, which is what makes every other field in the archive readable.
//! 2. Unwrap the key area, using the generation the header itself names.
//! 3. Decrypt the sections the header marks as CTR-encrypted, with the key the area holds.
//!
//! The generation is discovered rather than chosen — it is stored in the archive, so a caller
//! supplies a whole keyset here instead of the single key area key that packing takes.
//!
//! The header's key area field is left as it was found, wrapped. The unwrapped copy is returned
//! beside the image rather than written back into it, so the bytes stay the ones whose hashes and
//! signature were computed and [`crate::unpack::verify`] can still check them.

use nx_object::{
    raw::nca::{NCA_HEADER_SIZE, NcaCryptType},
    read::nca::{FromBytesError, Nca},
    write::nca::{KeyGeneration, SECTION_KEY_INDEX},
};

use crate::{
    crypto::{aes_ctr_apply, aes_ecb_decrypt, aes_xts_decrypt},
    keyset::Keyset,
};

/// Sector size the header is encrypted in.
const HEADER_SECTOR_SIZE: usize = 0x200;

/// A decrypted archive: the plaintext bytes and the key area they were sealed with.
pub struct PlainNca {
    /// The whole archive with its header and CTR sections decrypted.
    pub bytes: Vec<u8>,
    /// The key area, unwrapped.
    ///
    /// The copy inside `bytes` is still wrapped, because unwrapping it there would change the range
    /// the header signature covers.
    pub key_area: [[u8; 0x10]; 4],
}

/// Decrypt `image` with the keys `keyset` holds for the generation it names.
///
/// # Errors
///
/// Returns an error if the image is shorter than a header, if the keyset lacks the header key or a
/// key area key for the generation the archive names, if the decrypted header is not a valid NCA —
/// which is what a wrong header key produces — or if a section is encrypted with a scheme this tool
/// does not implement.
pub fn decrypt(image: &[u8], keyset: &Keyset) -> Result<PlainNca, DecryptError> {
    if image.len() < NCA_HEADER_SIZE as usize {
        return Err(DecryptError::TooSmall {
            available: image.len(),
        });
    }

    let header_key = keyset.header_key().ok_or(DecryptError::MissingHeaderKey)?;

    let mut bytes = image.to_vec();
    aes_xts_decrypt(
        header_key,
        &mut bytes[..NCA_HEADER_SIZE as usize],
        HEADER_SECTOR_SIZE,
    );

    // Parsed while the sections are still ciphertext, which is sound because the reader only ever
    // looks at the header: it proves the section bounds without reading what is inside them.
    let plan = plan_sections(&bytes)?;

    let generation = KeyGeneration::try_from(plan.key_generation).map_err(|_| {
        DecryptError::UnknownKeyGeneration {
            generation: plan.key_generation,
        }
    })?;
    let key_area_key =
        keyset
            .key_area_key_application(generation)
            .ok_or(DecryptError::MissingKeyAreaKey {
                generation: plan.key_generation,
            })?;

    let mut key_area = plan.key_area;
    aes_ecb_decrypt(key_area_key, key_area.as_flattened_mut());
    let section_key = key_area[SECTION_KEY_INDEX];

    for section in plan.ctr_sections {
        aes_ctr_apply(&section_key, &section.counter, &mut bytes[section.range]);
    }

    Ok(PlainNca { bytes, key_area })
}

/// Error returned by [`decrypt`].
#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    /// The image is shorter than the header an NCA opens with.
    ///
    /// Holds what the file actually contained.
    #[error("an NCA is at least {NCA_HEADER_SIZE} bytes; this one is {available}")]
    TooSmall {
        /// Number of bytes the image holds.
        available: usize,
    },
    /// The keyset carries no header key, and none can be derived from it.
    ///
    /// Without it nothing in the archive can be read, so this fails before any other check.
    #[error("the keyset has no header key")]
    MissingHeaderKey,
    /// The archive names a key generation outside the range a keyset can express.
    ///
    /// Holds the generation the header carried. This means the header decrypted to something that
    /// is not a generation, which in practice means the header key was the wrong one.
    #[error("the archive names key generation {generation}, which no keyset can hold")]
    UnknownKeyGeneration {
        /// The generation the header carried.
        generation: u8,
    },
    /// The keyset has no application key area key for the generation the archive names.
    ///
    /// Holds the generation that was looked up. The keyset is for an older console than the archive
    /// was built for, or it stops at a master key that does not reach this generation.
    #[error("the keyset has no application key area key for generation {generation}")]
    MissingKeyAreaKey {
        /// The generation that was looked up.
        generation: u8,
    },
    /// The decrypted header is not a valid NCA.
    ///
    /// Almost always means the header key was wrong: a header decrypted with the wrong key is
    /// indistinguishable from noise, so it fails at the magic rather than at a field.
    #[error("the decrypted header is not a valid NCA")]
    Parse(#[source] FromBytesError),
    /// A CTR-encrypted section produced no counter.
    ///
    /// Holds the section that was being planned. The reader derives a counter for every section it
    /// reports as CTR-encrypted, so this indicates a defect here rather than a malformed archive.
    #[error("section {section_index} is CTR-encrypted but produced no counter")]
    MissingCounter {
        /// Index of the section in the header.
        section_index: usize,
    },
    /// A section is encrypted with a scheme this tool does not implement.
    ///
    /// Holds the section and the scheme it named. AES-XTS sections and the relocating BKTR scheme
    /// belong to update partitions and to archives this tool does not produce.
    #[error("section {section_index} uses encryption scheme {scheme}, which is not supported")]
    UnsupportedEncryption {
        /// Index of the section in the header.
        section_index: usize,
        /// The scheme the FS header named.
        scheme: u8,
    },
}

/// What the decrypted header says still has to be decrypted.
///
/// Collected in one pass so that the borrow of the image ends before it is written to.
struct Plan {
    key_generation: u8,
    key_area: [[u8; 0x10]; 4],
    ctr_sections: Vec<CtrSection>,
}

/// One section awaiting AES-CTR decryption.
struct CtrSection {
    range: std::ops::Range<usize>,
    counter: [u8; 0x10],
}

/// Read the decrypted header and list the work its sections imply.
fn plan_sections(bytes: &[u8]) -> Result<Plan, DecryptError> {
    let nca = Nca::try_from_bytes(bytes).map_err(DecryptError::Parse)?;

    let mut ctr_sections = Vec::new();
    for section in nca.sections() {
        match section.encryption() {
            NcaCryptType::None => {}
            NcaCryptType::Ctr => {
                let counter = section.counter().ok_or(DecryptError::MissingCounter {
                    section_index: section.index(),
                })?;
                ctr_sections.push(CtrSection {
                    range: section.range(),
                    counter,
                });
            }
            scheme @ (NcaCryptType::Xts | NcaCryptType::Bktr) => {
                return Err(DecryptError::UnsupportedEncryption {
                    section_index: section.index(),
                    scheme: scheme as u8,
                });
            }
        }
    }

    Ok(Plan {
        key_generation: nca.key_generation(),
        key_area: nca.header().encrypted_keys,
        ctr_sections,
    })
}

#[cfg(test)]
mod tests {
    use nx_object::{
        raw::nca::NcaContentType,
        write::{
            NcaBuilder,
            nca::{KeyGeneration, SECTION_KEY_INDEX, Section, SectionData, SectionEncryption},
        },
    };

    use super::{DecryptError, decrypt};
    use crate::{
        crypto::{aes_ctr_apply, aes_ecb_encrypt, aes_xts_encrypt},
        keyset::Keyset,
    };

    /// The header key and generation-1 key area key a test keyset carries.
    const HEADER_KEY: [u8; 0x20] = [0x11; 0x20];
    const KEY_AREA_KEY: [u8; 0x10] = [0x22; 0x10];
    const SECTION_KEY: [u8; 0x10] = [0x33; 0x10];

    /// A keyset naming both keys directly, so no derivation is involved.
    fn keyset() -> Keyset {
        let header_key: String = HEADER_KEY.iter().map(|b| format!("{b:02x}")).collect();
        let key_area_key: String = KEY_AREA_KEY.iter().map(|b| format!("{b:02x}")).collect();
        format!("header_key = {header_key}\nkey_area_key_application_00 = {key_area_key}\n")
            .parse()
            .expect("the test keyset should parse")
    }

    /// Pack an archive the way the packing path does: encrypt sections, wrap the key area,
    /// then encrypt the header.
    fn sealed_archive(payload: &[u8], encryption: SectionEncryption) -> Vec<u8> {
        let plain = NcaBuilder::new(NcaContentType::Program, 0x0100_0000_0000_1000)
            .key_generation(KeyGeneration::FIRST)
            .key_area_key(SECTION_KEY_INDEX, SECTION_KEY)
            .expect("the section key slot should accept a key")
            .section(
                0,
                Section {
                    data: SectionData::Partition {
                        archive: payload.to_vec(),
                        hash_block_size: 0x1000,
                    },
                    encryption,
                },
            )
            .expect("placing a section at index 0 should succeed")
            .build()
            .expect("a small archive should build");

        let ctr_sections = plain.ctr_sections();
        let mut header = plain.header;
        let mut body = plain.body;

        for section in ctr_sections {
            aes_ctr_apply(&SECTION_KEY, &section.counter, &mut body[section.range]);
        }

        aes_ecb_encrypt(&KEY_AREA_KEY, header.encrypted_keys.as_flattened_mut());

        let mut bytes = zerocopy::IntoBytes::as_bytes(&header).to_vec();
        aes_xts_encrypt(&HEADER_KEY, &mut bytes, 0x200);
        bytes.append(&mut body);
        bytes
    }

    #[test]
    fn decrypt_with_a_sealed_archive_recovers_the_payload() {
        //* Given
        let payload = vec![0xABu8; 0x400];
        let image = sealed_archive(&payload, SectionEncryption::Ctr);

        //* When
        let plain = decrypt(&image, &keyset()).expect("the archive should decrypt");

        //* Then
        let nca = nx_object::read::nca::Nca::try_from_bytes(&plain.bytes)
            .expect("the decrypted archive should parse");
        assert_eq!(
            nca.section(0).expect("index 0 holds a section").data(),
            &payload[..],
            "the round trip should return the bytes that were packed"
        );
    }

    #[test]
    fn decrypt_with_a_sealed_archive_unwraps_the_section_key() {
        //* Given
        let image = sealed_archive(&vec![0xABu8; 0x400], SectionEncryption::Ctr);

        //* When
        let plain = decrypt(&image, &keyset()).expect("the archive should decrypt");

        //* Then
        assert_eq!(plain.key_area[SECTION_KEY_INDEX], SECTION_KEY);
    }

    #[test]
    fn decrypt_with_a_plaintext_section_leaves_it_untouched() {
        //* Given
        let payload = vec![0xCDu8; 0x400];
        let image = sealed_archive(&payload, SectionEncryption::None);

        //* When
        let plain = decrypt(&image, &keyset()).expect("the archive should decrypt");

        //* Then
        let nca = nx_object::read::nca::Nca::try_from_bytes(&plain.bytes)
            .expect("the decrypted archive should parse");
        assert_eq!(
            nca.section(0).expect("index 0 holds a section").data(),
            &payload[..]
        );
    }

    #[test]
    fn decrypt_with_the_wrong_header_key_fails_to_parse() {
        //* Given
        let image = sealed_archive(&vec![0xABu8; 0x400], SectionEncryption::Ctr);
        let wrong: Keyset = "header_key = 99999999999999999999999999999999\
                             99999999999999999999999999999999\n\
                             key_area_key_application_00 = 22222222222222222222222222222222\n"
            .parse()
            .expect("the test keyset should parse");

        //* When
        let result = decrypt(&image, &wrong);

        //* Then
        assert!(matches!(result, Err(DecryptError::Parse(_))));
    }

    #[test]
    fn decrypt_with_a_keyset_missing_the_header_key_fails() {
        //* Given
        let image = sealed_archive(&vec![0xABu8; 0x400], SectionEncryption::Ctr);
        let empty: Keyset = "key_area_key_application_00 = 22222222222222222222222222222222\n"
            .parse()
            .expect("the test keyset should parse");

        //* When
        let result = decrypt(&image, &empty);

        //* Then
        assert!(matches!(result, Err(DecryptError::MissingHeaderKey)));
    }

    #[test]
    fn decrypt_with_a_buffer_shorter_than_a_header_fails() {
        //* Given
        let image = vec![0u8; 0x100];

        //* When
        let result = decrypt(&image, &keyset());

        //* Then
        assert!(matches!(result, Err(DecryptError::TooSmall { .. })));
    }
}
