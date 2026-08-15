//! Turning a plaintext container into the encrypted archive the console loads.
//!
//! The builder hands over a container whose every field and hash is correct and whose bytes are all
//! in the clear. Four steps finish it, and their order is fixed by what each one covers:
//!
//! 1. Encrypt the sections the container names, with the key area's section key taken while it is
//!    still readable.
//! 2. Wrap the key area, which sits inside the range the header signature covers.
//! 3. Sign the header, now that the wrapped key area is in place.
//! 4. Encrypt the header, which is what the signature was computed over.
//!
//! The archive's name follows from the result rather than being chosen: an NCA is named by the first
//! sixteen bytes of its own hash, so it cannot be known until the bytes are final.

use nx_object::write::nca::{PlainNca, SECTION_KEY_INDEX};
use sha2::{Digest as _, Sha256};
use zerocopy::IntoBytes as _;

use super::signing;
use crate::crypto::{aes_ctr_apply, aes_ecb_encrypt, aes_xts_encrypt};

/// The `0x200` bytes of the header that both signatures cover, starting at the magic.
const SIGNED_RANGE: std::ops::Range<usize> = 0x200..0x400;

/// Sector size the header is encrypted in.
const HEADER_SECTOR_SIZE: usize = 0x200;

/// The keys one archive is finished with.
pub struct ArchiveKeys<'a> {
    /// Encrypts the header.
    pub header_key: &'a [u8; 0x20],
    /// Wraps the key area, which in turn holds the key the sections are encrypted with.
    pub key_area_key: &'a [u8; 0x10],
}

/// A finished archive: the bytes to write and the identity they give it.
pub struct Archive {
    /// The encrypted archive, header first.
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`, which is what the content meta records.
    pub hash: [u8; 0x20],
}

impl Archive {
    /// The name the archive is stored under, which is the head of its own hash.
    pub fn nca_id(&self) -> [u8; 0x10] {
        let mut id = [0u8; 0x10];
        id.copy_from_slice(&self.hash[..0x10]);
        id
    }

    /// The file name the archive is written as, with `suffix` appended before `.nca`.
    ///
    /// The metadata archive carries `cnmt` as its suffix, which is how a reader tells it apart from
    /// the contents it describes; every other archive passes an empty suffix.
    pub fn file_name(&self, suffix: &str) -> String {
        let id = self
            .nca_id()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        if suffix.is_empty() {
            format!("{id}.nca")
        } else {
            format!("{id}.{suffix}.nca")
        }
    }
}

/// Encrypt, sign, and seal `plain` into the archive the console loads.
///
/// # Errors
///
/// Returns an error if the header signature cannot be produced, which does not depend on the
/// container and so means the build is broken rather than the title.
pub fn finish(
    plain: PlainNca,
    keys: &ArchiveKeys<'_>,
    sign_header: bool,
) -> Result<Archive, FinishError> {
    let ctr_sections = plain.ctr_sections();
    let PlainNca {
        mut header,
        mut body,
    } = plain;

    // Taken before the key area is wrapped, which is the last moment it can be read.
    let section_key = header.encrypted_keys[SECTION_KEY_INDEX];
    for section in ctr_sections {
        aes_ctr_apply(&section_key, &section.counter, &mut body[section.range]);
    }

    aes_ecb_encrypt(keys.key_area_key, header.encrypted_keys.as_flattened_mut());

    if sign_header {
        let signed = &header.as_bytes()[SIGNED_RANGE];
        header.npdm_key_sig = signing::sign_header(signed).map_err(FinishError)?;
    }

    let mut bytes = header.as_bytes().to_vec();
    aes_xts_encrypt(keys.header_key, &mut bytes, HEADER_SECTOR_SIZE);
    bytes.append(&mut body);

    let hash: [u8; 0x20] = Sha256::digest(&bytes).into();

    Ok(Archive { bytes, hash })
}

/// The header signature could not be produced.
///
/// Returned by [`finish`], which fails in no other way: the ciphers it runs are total over the bytes
/// the builder produced.
#[derive(Debug, thiserror::Error)]
#[error("the program NCA header could not be signed")]
pub struct FinishError(#[source] pub signing::SignError);
