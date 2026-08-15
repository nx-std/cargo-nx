//! Reading the title ID out of `main.npdm` and patching what the archive needs changed.
//!
//! Two things can change in an NPDM on the way into an archive. The title ID is overwritten when the
//! caller names one, so that every archive of the title agrees with it. And the ACID's public key is
//! replaced by the one that will sign the program NCA's header, which is what makes the console's
//! second signature check pass.
//!
//! Both patches are byte edits at offsets the header itself gives, applied to the descriptor already
//! parsed and validated — the layout is proven before anything is written into it.

use nx_object::read::npdm::Npdm;

use super::{signing, title_id::TitleId};

/// Offset of the title ID within the ACI0 section.
const ACI0_PROGRAM_ID_OFFSET: usize = 0x10;

/// Offset of the public key within the ACID section, which follows the signature.
const ACID_PUBLIC_KEY_OFFSET: usize = 0x100;

/// What the caller wants changed in the descriptor.
pub struct Patch {
    /// Title ID to stamp in, or `None` to keep the one the descriptor already carries.
    pub title_id: Option<TitleId>,
    /// Whether to advertise the key that will sign the program NCA's header.
    pub sign_program_header: bool,
}

/// Validate `descriptor`, apply `patch` to it in place, and return the title ID it now names.
///
/// # Errors
///
/// Returns an error if the descriptor is not a well-formed NPDM, if the title ID it carries is
/// outside the application range and no override was given, or if a patch would fall outside the
/// bytes handed in.
pub fn process(descriptor: &mut [u8], patch: &Patch) -> Result<TitleId, ProcessError> {
    let (acid_offset, aci0_offset, program_id) = {
        let npdm = Npdm::try_from_bytes(descriptor).map_err(ProcessError::Malformed)?;
        let header = npdm.header();
        (
            header.acid_offset.get() as usize,
            header.aci_offset.get() as usize,
            npdm.program_id(),
        )
    };

    let title_id = match patch.title_id {
        Some(title_id) => title_id,
        None => TitleId::try_from(program_id).map_err(ProcessError::TitleId)?,
    };

    if patch.title_id.is_some() {
        let start = aci0_offset + ACI0_PROGRAM_ID_OFFSET;
        let slot = descriptor
            .get_mut(start..start + size_of::<u64>())
            .ok_or(ProcessError::PatchOutOfBounds { offset: start })?;
        slot.copy_from_slice(&title_id.to_u64().to_le_bytes());
    }

    if patch.sign_program_header {
        let start = acid_offset + ACID_PUBLIC_KEY_OFFSET;
        let slot = descriptor
            .get_mut(start..start + signing::SIGNATURE_SIZE)
            .ok_or(ProcessError::PatchOutOfBounds { offset: start })?;
        slot.copy_from_slice(signing::acid_public_key());
    }

    Ok(title_id)
}

/// Error returned by [`process`].
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// The bytes are not a well-formed NPDM.
    #[error("`main.npdm` is not a valid program descriptor")]
    Malformed(#[source] nx_object::read::npdm::FromBytesError),
    /// The descriptor's own title ID is not one an application may use.
    #[error("`main.npdm` carries a title ID an application may not use")]
    TitleId(#[source] super::title_id::ParseTitleIdError),
    /// A patch would run past the end of the descriptor.
    ///
    /// Holds the offset the patch would have started at.
    #[error("`main.npdm` is too short for the patch at offset {offset:#x}")]
    PatchOutOfBounds {
        /// The offset the patch would have started at.
        offset: usize,
    },
}
