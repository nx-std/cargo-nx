//! Checking that a decrypted archive is internally consistent.
//!
//! Three independent checks, each answering a different question, and each usable on its own so a
//! caller can report them separately rather than being told only that "something" failed:
//!
//! - [`header_signature`] — was the header altered after it was signed?
//! - [`fs_header_hash`] — does a section's description still match what the header recorded of it?
//! - [`section_hashes`] — do the section's contents still match the table or tree covering them?
//!
//! Only the second of an NCA's two signatures is checkable here. The first is verified against a
//! modulus that lives in the console, so this module has nothing to check it with and does not
//! pretend otherwise.
//!
//! Every check takes bytes that are already decrypted. Run against ciphertext they would all fail,
//! and for the wrong reason.

use nx_object::{
    raw::nca::{IvfcHeader, NCA_SECTION_COUNT, Pfs0Superblock},
    read::nca::{Nca, NcaSection, Superblock},
};
use sha2::{Digest as _, Sha256};
use zerocopy::IntoBytes as _;

use crate::signing::{self, SIGNATURE_SIZE, SIGNED_RANGE};

/// Bytes in a SHA-256 digest.
const HASH_SIZE: usize = 0x20;

/// Check the header's second signature against the key this tool signs with.
///
/// `image` is the decrypted archive. Only a header this tool signed can pass: an archive packed by
/// another toolchain carries a signature this key did not produce.
///
/// An archive that was never signed is [`SignatureCheck::Absent`] rather than an error. Only the
/// program archive of a title is signed — the control, manual, and metadata archives leave the field
/// zeroed by design — so reporting those as failures would call a correctly packed title broken.
///
/// # Errors
///
/// Returns an error if the image is too short to hold a signed header, or if a signature is present
/// and does not verify — meaning the header was altered after signing, or signed by a different key.
pub fn header_signature(image: &[u8]) -> Result<SignatureCheck, HeaderSignatureError> {
    let signed = image
        .get(SIGNED_RANGE)
        .ok_or(HeaderSignatureError::TooSmall {
            available: image.len(),
        })?;

    let stored: &[u8; SIGNATURE_SIZE] = image
        .get(SIGNATURE_SIZE..SIGNED_RANGE.start)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(HeaderSignatureError::TooSmall {
            available: image.len(),
        })?;

    if stored.iter().all(|byte| *byte == 0) {
        return Ok(SignatureCheck::Absent);
    }

    signing::verify_header(signed, stored).map_err(HeaderSignatureError::Verify)?;

    Ok(SignatureCheck::Verified)
}

/// What checking a header's second signature established.
pub enum SignatureCheck {
    /// The signature is present and verifies against the built-in key.
    Verified,
    /// The header carries no signature, which is how every archive but the program one is packed.
    Absent,
}

/// Error returned by [`header_signature`].
#[derive(Debug, thiserror::Error)]
pub enum HeaderSignatureError {
    /// The image is too short to hold the signature and the range it covers.
    ///
    /// Holds what the image actually contained.
    #[error("a signed header needs {} bytes; the image has {available}", SIGNED_RANGE.end)]
    TooSmall {
        /// Number of bytes the image holds.
        available: usize,
    },
    /// The signature does not verify.
    #[error("the header signature does not verify")]
    Verify(#[source] signing::VerifyError),
}

/// Check that the FS header at `index` still hashes to what the NCA header recorded for it.
///
/// This is the link that ties a section's description — its type, its encryption, its superblock —
/// to the signed part of the header. A field changed in an FS header without rehashing breaks here.
///
/// # Errors
///
/// Returns an error if `index` is not one of the four slots an NCA holds, or if the recorded hash
/// and the computed one differ.
pub fn fs_header_hash(nca: &Nca<'_>, index: usize) -> Result<(), FsHeaderHashError> {
    if index >= NCA_SECTION_COUNT {
        return Err(FsHeaderHashError::NoSuchSection { index });
    }

    let header = nca.header();
    // Both arrays are `NCA_SECTION_COUNT` long, and the bound was just checked.
    let computed: [u8; HASH_SIZE] = Sha256::digest(header.fs_headers[index].as_bytes()).into();
    let recorded = header.section_hashes[index];

    if computed != recorded {
        return Err(FsHeaderHashError::Mismatch { index });
    }

    Ok(())
}

/// Error returned by [`fs_header_hash`].
#[derive(Debug, thiserror::Error)]
pub enum FsHeaderHashError {
    /// The index is not one of the four slots an NCA header holds.
    ///
    /// Holds the rejected index.
    #[error("index {index} is outside the {NCA_SECTION_COUNT} an NCA holds")]
    NoSuchSection {
        /// The rejected index.
        index: usize,
    },
    /// The FS header does not hash to what the NCA header recorded.
    ///
    /// Holds the section. The FS header was edited after the archive was built, or the archive is
    /// corrupt; either way the section's description can no longer be trusted.
    #[error("the FS header for section {index} does not match its recorded hash")]
    Mismatch {
        /// Index of the section in the header.
        index: usize,
    },
}

/// Check a section's contents against the hash table or hash tree covering them.
///
/// Which structure is used follows from the section's hash type, as it does everywhere else: a PFS0
/// section carries one table, a RomFS section a whole IVFC tree.
///
/// # Errors
///
/// Returns an error if the superblock cannot be read, if it locates a region outside the section, if
/// it declares a block size of zero or a level count that names no levels, if a hash table is
/// shorter than the blocks it must cover, or if any recorded hash differs from the computed one.
pub fn section_hashes(section: &NcaSection<'_>) -> Result<(), SectionHashesError> {
    match section.superblock() {
        Superblock::Pfs0(superblock) => partition_hashes(section.bytes(), superblock),
        Superblock::RomFs(superblock) => ivfc_hashes(section.bytes(), &superblock.ivfc_header),
        Superblock::Unreadable => Err(SectionHashesError::SuperblockUnreadable),
    }
}

/// Error returned by [`section_hashes`].
#[derive(Debug, thiserror::Error)]
pub enum SectionHashesError {
    /// The superblock span could not be read as either verification structure.
    ///
    /// Both structures exactly fill the span the FS header reserves, so a section that parsed
    /// cannot reach this; it exists because reading a superblock is infallible by design.
    #[error("the section's superblock could not be read")]
    SuperblockUnreadable,
    /// The superblock declares a block size of zero, which covers nothing.
    #[error("the superblock declares a block size of zero")]
    ZeroBlockSize,
    /// The IVFC header declares a level count that names no stored levels.
    ///
    /// Holds the count the header carried, which counts the master hash as well as the levels.
    #[error("the IVFC header declares {level_count} levels, which names none to check")]
    NoLevels {
        /// The count the IVFC header carried.
        level_count: u32,
    },
    /// A region the superblock locates falls outside the section.
    ///
    /// Holds which region it was and where the superblock put it.
    #[error("{region} lies at {offset} of size {size}, outside the {available}-byte section")]
    RegionOutOfBounds {
        /// Which region was being read.
        region: Region,
        /// Offset the superblock records, from the start of the section.
        offset: u64,
        /// Length the superblock records.
        size: u64,
        /// Number of bytes the section holds.
        available: usize,
    },
    /// The master hash does not cover what the superblock says it covers.
    ///
    /// Holds the level it was taken over. The verification structure was rebuilt without the
    /// superblock being updated, or the section is corrupt.
    #[error("the master hash over level {level} does not match")]
    MasterHashMismatch {
        /// Which level the master hash covers.
        level: usize,
    },
    /// A hash table is shorter than the blocks it has to cover.
    ///
    /// Holds the level and the counts on both sides.
    #[error("level {level} holds {available} hashes but must cover {blocks} blocks")]
    HashTableTooShort {
        /// Which level the table belongs to.
        level: usize,
        /// Number of blocks the level above is cut into.
        blocks: usize,
        /// Number of hashes the table actually holds.
        available: usize,
    },
    /// A recorded block hash differs from the computed one.
    ///
    /// Holds the level and the block within it. This is the check that catches altered contents:
    /// the bytes of that block are not the ones the archive was built from.
    #[error("the hash for block {block} of level {level} does not match")]
    BlockHashMismatch {
        /// Which level the hash was read from.
        level: usize,
        /// Which block of the level above it covers.
        block: usize,
    },
}

/// Check a PFS0 section: the master hash over the table, then the table over the archive.
fn partition_hashes(section: &[u8], superblock: &Pfs0Superblock) -> Result<(), SectionHashesError> {
    let block_size = superblock.block_size.get() as usize;
    if block_size == 0 {
        return Err(SectionHashesError::ZeroBlockSize);
    }

    let table = region(
        section,
        superblock.hash_table_offset.get(),
        superblock.hash_table_size.get(),
        Region::HashTable,
    )?;
    let archive = region(
        section,
        superblock.pfs0_offset.get(),
        superblock.pfs0_size.get(),
        Region::Archive,
    )?;

    let master: [u8; HASH_SIZE] = Sha256::digest(table).into();
    if master != superblock.master_hash {
        return Err(SectionHashesError::MasterHashMismatch { level: 0 });
    }

    check_blocks(table, archive, block_size, 0)
}

/// Check an IVFC tree: the master hash over level 0, then each level over the one above it.
fn ivfc_hashes(section: &[u8], ivfc: &IvfcHeader) -> Result<(), SectionHashesError> {
    // `level_count` counts the master hash as well as the stored levels.
    let stored = (ivfc.level_count.get() as usize)
        .checked_sub(1)
        .filter(|count| *count > 0)
        .ok_or(SectionHashesError::NoLevels {
            level_count: ivfc.level_count.get(),
        })?;

    let mut levels = Vec::with_capacity(stored);
    for index in 0..stored {
        let header = ivfc
            .level_headers
            .get(index)
            .ok_or(SectionHashesError::NoLevels {
                level_count: ivfc.level_count.get(),
            })?;
        levels.push(region(
            section,
            header.logical_offset.get(),
            header.hash_data_size.get(),
            Region::Level { index },
        )?);
    }

    // Proven non-empty by the `stored > 0` filter above.
    let master: [u8; HASH_SIZE] = Sha256::digest(levels[0]).into();
    if master != ivfc.master_hash {
        return Err(SectionHashesError::MasterHashMismatch { level: 0 });
    }

    for index in 0..stored - 1 {
        // A level's own header states the block size its hashes cover, so the hashes in level
        // `index` are taken over blocks of that size cut from the level above it.
        let block_size = 1usize
            .checked_shl(ivfc.level_headers[index].block_size.get())
            .filter(|size| *size > 0)
            .ok_or(SectionHashesError::ZeroBlockSize)?;

        check_blocks(levels[index], levels[index + 1], block_size, index)?;
    }

    Ok(())
}

/// Check that `hashes` holds the SHA-256 of every `block_size` chunk of `data`.
///
/// Hashes past the blocks `data` actually has are padding and are not checked, which is what lets a
/// level padded out to a whole block verify.
fn check_blocks(
    hashes: &[u8],
    data: &[u8],
    block_size: usize,
    level: usize,
) -> Result<(), SectionHashesError> {
    for (index, block) in data.chunks(block_size).enumerate() {
        let start = index * HASH_SIZE;
        let recorded =
            hashes
                .get(start..start + HASH_SIZE)
                .ok_or(SectionHashesError::HashTableTooShort {
                    level,
                    blocks: data.len().div_ceil(block_size),
                    available: hashes.len() / HASH_SIZE,
                })?;

        let computed: [u8; HASH_SIZE] = Sha256::digest(block).into();
        if computed != recorded {
            return Err(SectionHashesError::BlockHashMismatch {
                level,
                block: index,
            });
        }
    }

    Ok(())
}

/// Which region of a section a bounds failure was reading.
#[derive(Debug, Clone, Copy)]
pub enum Region {
    /// The single-level hash table of a PFS0 section.
    HashTable,
    /// The archive of a PFS0 section.
    Archive,
    /// One level of a RomFS section's IVFC tree.
    Level {
        /// Which level, counted from the master hash downwards.
        index: usize,
    },
}

impl std::fmt::Display for Region {
    /// Renders as the region's name, with an IVFC level carrying its index, so a bounds failure
    /// reads as `the hash table lies at …` or `IVFC level 2 lies at …`.
    ///
    /// The rendering is pinned by a unit test rather than a doctest: this module belongs to the
    /// binary target, which rustdoc cannot run examples against.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashTable => write!(f, "the hash table"),
            Self::Archive => write!(f, "the archive"),
            Self::Level { index } => write!(f, "IVFC level {index}"),
        }
    }
}

/// Borrow the region at `offset` of `size` bytes from `section`.
fn region(
    section: &[u8],
    offset: u64,
    size: u64,
    which: Region,
) -> Result<&[u8], SectionHashesError> {
    let start = usize::try_from(offset).map_err(|_| SectionHashesError::RegionOutOfBounds {
        region: which,
        offset,
        size,
        available: section.len(),
    })?;
    let len = usize::try_from(size).map_err(|_| SectionHashesError::RegionOutOfBounds {
        region: which,
        offset,
        size,
        available: section.len(),
    })?;

    start
        .checked_add(len)
        .and_then(|end| section.get(start..end))
        .ok_or(SectionHashesError::RegionOutOfBounds {
            region: which,
            offset,
            size,
            available: section.len(),
        })
}

#[cfg(test)]
mod tests {
    use nx_object::{
        raw::nca::NcaContentType,
        read::nca::Nca,
        write::{
            NcaBuilder,
            nca::{Section, SectionData, SectionEncryption},
        },
    };

    use super::{
        FsHeaderHashError, HeaderSignatureError, Region, SectionHashesError, SignatureCheck,
        fs_header_hash, header_signature, section_hashes,
    };
    use crate::signing::{SIGNATURE_SIZE, SIGNED_RANGE, sign_header};

    /// A plaintext archive holding one section of `data`, built the way the packer builds one.
    fn plain_nca(data: SectionData) -> Vec<u8> {
        NcaBuilder::new(NcaContentType::Program, 0x0100_0000_0000_1000)
            .section(
                0,
                Section {
                    data,
                    encryption: SectionEncryption::None,
                },
            )
            .expect("placing a section at index 0 should succeed")
            .build()
            .expect("a small archive should build")
            .to_bytes()
    }

    /// A partition section carrying `size` bytes of archive.
    fn partition(size: usize) -> SectionData {
        SectionData::Partition {
            archive: vec![0xAB; size],
            hash_block_size: 0x1000,
        }
    }

    #[test]
    fn section_hashes_with_an_untouched_partition_succeeds() {
        //* Given
        let image = plain_nca(partition(0x4000));
        let nca = Nca::try_from_bytes(&image).expect("a built archive should parse");
        let section = nca.section(0).expect("index 0 holds a section");

        //* When
        let result = section_hashes(&section);

        //* Then
        assert!(result.is_ok(), "a freshly built section must verify");
    }

    #[test]
    fn section_hashes_with_an_altered_partition_block_fails() {
        //* Given
        // One byte of the archive is flipped, leaving the hash table describing the original.
        let mut image = plain_nca(partition(0x4000));
        let last = image.len() - 1;
        image[last] ^= 0xFF;
        let nca = Nca::try_from_bytes(&image).expect("a built archive should parse");
        let section = nca.section(0).expect("index 0 holds a section");

        //* When
        let result = section_hashes(&section);

        //* Then
        assert!(matches!(
            result,
            Err(SectionHashesError::BlockHashMismatch { .. })
        ));
    }

    #[test]
    fn section_hashes_with_an_untouched_romfs_succeeds() {
        //* Given
        let image = plain_nca(SectionData::RomFs(vec![0xCD; 0x8000]));
        let nca = Nca::try_from_bytes(&image).expect("a built archive should parse");
        let section = nca.section(0).expect("index 0 holds a section");

        //* When
        let result = section_hashes(&section);

        //* Then
        assert!(result.is_ok(), "a freshly built IVFC tree must verify");
    }

    #[test]
    fn section_hashes_with_an_altered_romfs_block_fails() {
        //* Given
        let mut image = plain_nca(SectionData::RomFs(vec![0xCD; 0x8000]));
        let last = image.len() - 1;
        image[last] ^= 0xFF;
        let nca = Nca::try_from_bytes(&image).expect("a built archive should parse");
        let section = nca.section(0).expect("index 0 holds a section");

        //* When
        let result = section_hashes(&section);

        //* Then
        assert!(matches!(
            result,
            Err(SectionHashesError::BlockHashMismatch { .. })
        ));
    }

    #[test]
    fn fs_header_hash_with_an_untouched_header_succeeds() {
        //* Given
        let image = plain_nca(partition(0x1000));
        let nca = Nca::try_from_bytes(&image).expect("a built archive should parse");

        //* When
        let result = fs_header_hash(&nca, 0);

        //* Then
        assert!(result.is_ok());
    }

    #[test]
    fn fs_header_hash_with_an_altered_fs_header_fails() {
        //* Given
        // The section counter sits in the FS header and outside every other hash, so flipping it
        // isolates this check from the section's own contents.
        let mut image = plain_nca(partition(0x1000));
        image[0x400 + 0x140] ^= 0xFF;
        let nca = Nca::try_from_bytes(&image).expect("a built archive should parse");

        //* When
        let result = fs_header_hash(&nca, 0);

        //* Then
        assert!(matches!(result, Err(FsHeaderHashError::Mismatch { .. })));
    }

    #[test]
    fn fmt_with_each_region_renders_its_name() {
        //* Given
        let regions = [
            Region::HashTable,
            Region::Archive,
            Region::Level { index: 2 },
        ];

        //* When
        let rendered: Vec<String> = regions.iter().map(ToString::to_string).collect();

        //* Then
        assert_eq!(rendered, ["the hash table", "the archive", "IVFC level 2"]);
    }

    #[test]
    fn header_signature_with_an_unsigned_header_reports_absent() {
        //* Given
        // How every archive of a title but the program one is packed.
        let image = plain_nca(partition(0x1000));

        //* When
        let result = header_signature(&image);

        //* Then
        assert!(matches!(
            result.expect("an unsigned header is not an error"),
            SignatureCheck::Absent
        ));
    }

    #[test]
    fn header_signature_with_a_header_this_tool_signed_reports_verified() {
        //* Given
        let mut image = plain_nca(partition(0x1000));
        let signature = sign_header(&image[SIGNED_RANGE]).expect("the built-in key should sign");
        image[SIGNATURE_SIZE..SIGNED_RANGE.start].copy_from_slice(&signature);

        //* When
        let result = header_signature(&image);

        //* Then
        assert!(matches!(
            result.expect("a signed header should verify"),
            SignatureCheck::Verified
        ));
    }

    #[test]
    fn header_signature_with_a_header_altered_after_signing_fails() {
        //* Given
        let mut image = plain_nca(partition(0x1000));
        let signature = sign_header(&image[SIGNED_RANGE]).expect("the built-in key should sign");
        image[SIGNATURE_SIZE..SIGNED_RANGE.start].copy_from_slice(&signature);
        // The title ID sits inside the signed range.
        image[0x210] ^= 0xFF;

        //* When
        let result = header_signature(&image);

        //* Then
        assert!(matches!(result, Err(HeaderSignatureError::Verify(_))));
    }

    #[test]
    fn header_signature_with_a_buffer_shorter_than_a_header_fails() {
        //* Given
        let image = vec![0u8; 0x100];

        //* When
        let result = header_signature(&image);

        //* Then
        assert!(matches!(result, Err(HeaderSignatureError::TooSmall { .. })));
    }

    #[test]
    fn fs_header_hash_with_an_index_past_the_last_section_fails() {
        //* Given
        let image = plain_nca(partition(0x1000));
        let nca = Nca::try_from_bytes(&image).expect("a built archive should parse");

        //* When
        let result = fs_header_hash(&nca, 4);

        //* Then
        assert!(matches!(
            result,
            Err(FsHeaderHashError::NoSuchSection { index: 4 })
        ));
    }
}
