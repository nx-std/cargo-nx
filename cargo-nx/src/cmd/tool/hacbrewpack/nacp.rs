//! Validating `control.nacp` and applying the overrides an archive is built with.
//!
//! The NACP is what the home screen reads, so a title with no name or no publisher in it is a title
//! the console shows blank. Both are checked here rather than left to be noticed on hardware: a name
//! is present if any language entry carries one, since the console falls back across languages.
//!
//! Overrides are written to every language entry rather than to one, because a caller who renames a
//! title means it renamed, not renamed in English.

use nx_object::raw::nacp::NacpStruct;
use zerocopy::{FromBytes as _, IntoBytes as _};

use super::title_id::TitleId;

/// Language entries the overrides are written to.
///
/// The structure holds sixteen, of which the first twelve are the languages the console ships user
/// interfaces for; the rest are reserved and left as the caller supplied them.
const OVERRIDDEN_LANGUAGES: usize = 12;

/// Longest title name a language entry can hold, leaving room for the terminator.
pub const MAX_NAME_LEN: usize = 0x200 - 1;

/// Longest publisher a language entry can hold, leaving room for the terminator.
pub const MAX_PUBLISHER_LEN: usize = 0x100 - 1;

/// Logo handling that lets the console decide when to show the title's logo.
const LOGO_HANDLING_AUTO: u8 = 0;

/// What the caller wants changed in the control property.
pub struct Patch {
    /// Title name for every language, or `None` to keep what the file carries.
    pub name: Option<String>,
    /// Publisher for every language, or `None` to keep what the file carries.
    pub publisher: Option<String>,
    /// Title ID to stamp into the ID fields, or `None` to leave them alone.
    pub title_id: Option<TitleId>,
    /// Whether to let the console decide when to show the logo.
    pub logo_handling_auto: bool,
}

/// Validate `control`, apply `patch` to it in place, and report whether anything changed.
///
/// # Errors
///
/// Returns an error if the bytes are not the size of a control property, if an override is longer
/// than its field, or if the file names neither a title nor a publisher and no override supplies
/// one.
pub fn process(control: &mut [u8], patch: &Patch) -> Result<(), ProcessError> {
    let mut nacp = NacpStruct::read_from_bytes(control).map_err(|_| ProcessError::WrongSize {
        length: control.len(),
        expected: size_of::<NacpStruct>(),
    })?;

    match &patch.name {
        Some(name) => set_language_field(&mut nacp, name, MAX_NAME_LEN, Field::Name)?,
        None if !has_any(&nacp, Field::Name) => return Err(ProcessError::MissingName),
        None => {}
    }

    match &patch.publisher {
        Some(publisher) => {
            set_language_field(&mut nacp, publisher, MAX_PUBLISHER_LEN, Field::Publisher)?;
        }
        None if !has_any(&nacp, Field::Publisher) => return Err(ProcessError::MissingPublisher),
        None => {}
    }

    if patch.logo_handling_auto {
        nacp.logo_handling = LOGO_HANDLING_AUTO;
    }

    if let Some(title_id) = patch.title_id {
        nacp.presence_group_id = title_id.to_u64().into();
        nacp.save_data_owner_id = title_id.to_u64().into();
        nacp.add_on_content_base_id = title_id.add_on_content_base().into();
        for id in &mut nacp.local_communication_id {
            *id = title_id.to_u64().into();
        }
    }

    control.copy_from_slice(nacp.as_bytes());

    Ok(())
}

/// Which of the two per-language strings an operation applies to.
#[derive(Debug, Clone, Copy)]
enum Field {
    Name,
    Publisher,
}

/// Whether any language entry carries a non-empty `field`.
fn has_any(nacp: &NacpStruct, field: Field) -> bool {
    nacp.lang.iter().any(|entry| {
        let bytes = match field {
            Field::Name => &entry.name[..],
            Field::Publisher => &entry.author[..],
        };
        bytes.first().is_some_and(|byte| *byte != 0)
    })
}

/// Write `value` into `field` for every language the console has an interface for.
fn set_language_field(
    nacp: &mut NacpStruct,
    value: &str,
    max_len: usize,
    field: Field,
) -> Result<(), ProcessError> {
    if value.len() > max_len {
        return Err(ProcessError::OverrideTooLong {
            field: match field {
                Field::Name => "title name",
                Field::Publisher => "title publisher",
            },
            length: value.len(),
            max_len,
        });
    }

    for entry in &mut nacp.lang[..OVERRIDDEN_LANGUAGES] {
        let slot = match field {
            Field::Name => &mut entry.name[..],
            Field::Publisher => &mut entry.author[..],
        };
        slot.fill(0);
        slot[..value.len()].copy_from_slice(value.as_bytes());
    }

    Ok(())
}

/// Error returned by [`process`].
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// The bytes are not the size of a control property.
    ///
    /// Holds the length read and the length the structure requires.
    #[error("`control.nacp` is {length} bytes, expected {expected}")]
    WrongSize {
        /// The length read.
        length: usize,
        /// The length the structure requires.
        expected: usize,
    },
    /// No language entry names the title and no override supplies one.
    #[error("`control.nacp` names no title in any language")]
    MissingName,
    /// No language entry names the publisher and no override supplies one.
    #[error("`control.nacp` names no publisher in any language")]
    MissingPublisher,
    /// An override is longer than the field it is written into.
    ///
    /// Holds which field, the length given, and the length allowed.
    #[error("the {field} is {length} bytes, which exceeds the {max_len} the field holds")]
    OverrideTooLong {
        /// Which field was too long.
        field: &'static str,
        /// The length given.
        length: usize,
        /// The length allowed.
        max_len: usize,
    },
}

#[cfg(test)]
mod tests {
    use nx_object::raw::nacp::NacpStruct;
    use zerocopy::{FromBytes as _, FromZeros as _, IntoBytes as _};

    use super::{MAX_NAME_LEN, Patch, ProcessError, process};
    use crate::cmd::tool::hacbrewpack::title_id::TitleId;

    /// A control property naming a title and publisher in the first language slot.
    fn named_control() -> Vec<u8> {
        let mut nacp = NacpStruct::new_zeroed();
        nacp.lang[0].name[..5].copy_from_slice(b"Title");
        nacp.lang[0].author[..9].copy_from_slice(b"Publisher");
        nacp.as_bytes().to_vec()
    }

    /// A patch that changes nothing.
    fn no_patch() -> Patch {
        Patch {
            name: None,
            publisher: None,
            title_id: None,
            logo_handling_auto: false,
        }
    }

    #[test]
    fn process_accepts_a_control_naming_a_title_and_publisher() {
        //* Given
        let mut control = named_control();

        //* When
        let result = process(&mut control, &no_patch());

        //* Then
        assert!(result.is_ok());
    }

    #[test]
    fn process_refuses_a_control_naming_no_title() {
        //* Given
        // The console would show this title blank on the home screen.
        let mut nacp = NacpStruct::new_zeroed();
        nacp.lang[0].author[..9].copy_from_slice(b"Publisher");
        let mut control = nacp.as_bytes().to_vec();

        //* When
        let result = process(&mut control, &no_patch());

        //* Then
        assert!(matches!(result, Err(ProcessError::MissingName)));
    }

    #[test]
    fn process_replaces_the_name_in_every_interface_language() {
        //* Given
        let mut control = named_control();
        let patch = Patch {
            name: Some("Renamed".to_owned()),
            ..no_patch()
        };

        //* When
        process(&mut control, &patch).expect("the override should apply");

        //* Then
        let nacp = NacpStruct::read_from_bytes(&control).expect("the buffer is the right size");
        assert_eq!(&nacp.lang[0].name[..7], b"Renamed");
        assert_eq!(
            &nacp.lang[11].name[..7],
            b"Renamed",
            "a rename means renamed, not renamed in one language"
        );
    }

    #[test]
    fn process_refuses_an_override_longer_than_its_field() {
        //* Given
        let mut control = named_control();
        let patch = Patch {
            name: Some("x".repeat(MAX_NAME_LEN + 1)),
            ..no_patch()
        };

        //* When
        let result = process(&mut control, &patch);

        //* Then
        assert!(matches!(result, Err(ProcessError::OverrideTooLong { .. })));
    }

    #[test]
    fn process_stamps_a_title_id_override_into_every_id_field() {
        //* Given
        let mut control = named_control();
        let title_id: TitleId = "0100000000001000".parse().expect("a valid application ID");
        let patch = Patch {
            title_id: Some(title_id),
            ..no_patch()
        };

        //* When
        process(&mut control, &patch).expect("the override should apply");

        //* Then
        let nacp = NacpStruct::read_from_bytes(&control).expect("the buffer is the right size");
        assert_eq!(nacp.presence_group_id.get(), title_id.to_u64());
        assert_eq!(nacp.save_data_owner_id.get(), title_id.to_u64());
        assert_eq!(
            nacp.add_on_content_base_id.get(),
            title_id.add_on_content_base(),
            "downloadable content is published above the title itself"
        );
        assert!(
            nacp.local_communication_id
                .iter()
                .all(|id| id.get() == title_id.to_u64())
        );
    }
}
