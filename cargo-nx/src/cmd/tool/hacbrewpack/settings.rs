//! The two hexadecimal settings an archive is stamped with, parsed once at the boundary.

/// The SDK an archive claims to have been built with.
///
/// Stored as one word that unpacks into `major.minor.micro.revision`. The floor is not arbitrary:
/// the loader rejects an archive claiming an SDK older than the one that introduced the container
/// layout this tool writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SdkVersion(u32);

impl SdkVersion {
    /// Oldest SDK the loader accepts for this container layout.
    pub const MIN: u32 = 0x000B0000;

    /// Newest SDK the field can express.
    pub const MAX: u32 = 0x00FFFFFF;

    /// The version as the packed word the header stores.
    pub fn to_u32(self) -> u32 {
        self.0
    }
}

impl Default for SdkVersion {
    fn default() -> Self {
        // 12.17.0.0, which is what a title built by this tool reports unless told otherwise.
        Self(0x000C1100)
    }
}

impl TryFrom<u32> for SdkVersion {
    type Error = ParseSdkVersionError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if !(Self::MIN..=Self::MAX).contains(&value) {
            return Err(ParseSdkVersionError::OutOfRange { value });
        }
        Ok(Self(value))
    }
}

impl std::str::FromStr for SdkVersion {
    type Err = ParseSdkVersionError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let digits = input.strip_prefix("0x").unwrap_or(input);
        let value = u32::from_str_radix(digits, 16).map_err(ParseSdkVersionError::Malformed)?;
        Self::try_from(value)
    }
}

impl std::fmt::Display for SdkVersion {
    /// Renders as the dotted `major.minor.micro.revision` the console reports, so `0x000C1100`
    /// prints as `0.12.17.0`.
    ///
    /// The rendering is pinned by a unit test rather than a doctest: this module belongs to the
    /// binary target, which rustdoc cannot run examples against.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [major, minor, micro, revision] = self.0.to_be_bytes();
        write!(f, "{major}.{minor}.{micro}.{revision}")
    }
}

/// Error returned when an SDK version cannot be built.
#[derive(Debug, thiserror::Error)]
pub enum ParseSdkVersionError {
    /// The input is not a hexadecimal number.
    #[error("an SDK version must be hexadecimal")]
    Malformed(#[source] std::num::ParseIntError),
    /// The version is outside what the loader accepts.
    ///
    /// Holds the rejected value.
    #[error(
        "SDK version {value:08X} is outside the range {:08X}-{:08X}",
        SdkVersion::MIN,
        SdkVersion::MAX
    )]
    OutOfRange {
        /// The rejected value.
        value: u32,
    },
}

/// The AES-128 key an archive's sections are encrypted with, before the key area wraps it.
///
/// Any sixteen bytes work: the key travels inside the archive's own key area, so it is a per-archive
/// value rather than a shared secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyAreaKey([u8; 0x10]);

impl KeyAreaKey {
    /// The key as the bytes that go into the key area.
    pub fn to_bytes(self) -> [u8; 0x10] {
        self.0
    }
}

impl Default for KeyAreaKey {
    fn default() -> Self {
        Self([4; 0x10])
    }
}

impl std::str::FromStr for KeyAreaKey {
    type Err = ParseKeyAreaKeyError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.len() != 0x20 {
            return Err(ParseKeyAreaKeyError::WrongLength {
                length: input.len(),
            });
        }

        let mut key = [0u8; 0x10];
        for (byte, digits) in key.iter_mut().zip(input.as_bytes().chunks_exact(2)) {
            let digits =
                std::str::from_utf8(digits).map_err(|_| ParseKeyAreaKeyError::Malformed)?;
            *byte = u8::from_str_radix(digits, 16).map_err(|_| ParseKeyAreaKeyError::Malformed)?;
        }

        Ok(Self(key))
    }
}

impl std::fmt::LowerHex for KeyAreaKey {
    /// Renders as the thirty-two lowercase hex digits the key is written as, with no separators.
    ///
    /// The rendering is pinned by a unit test rather than a doctest: this module belongs to the
    /// binary target, which rustdoc cannot run examples against.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Error returned when a key area key cannot be parsed.
#[derive(Debug, thiserror::Error)]
pub enum ParseKeyAreaKeyError {
    /// The input is not thirty-two hex digits.
    ///
    /// Holds the length that was given.
    #[error("a key area key is 32 hex digits, not {length}")]
    WrongLength {
        /// The length that was given.
        length: usize,
    },
    /// The input is the right length but is not hexadecimal.
    #[error("a key area key must be hexadecimal")]
    Malformed,
}

#[cfg(test)]
mod tests {
    use super::{KeyAreaKey, SdkVersion};

    #[test]
    fn from_str_accepts_an_sdk_version_at_or_above_the_floor() {
        //* Given
        let input = "000C1100";

        //* When
        let version: SdkVersion = input.parse().expect("an in-range version should parse");

        //* Then
        assert_eq!(version.to_u32(), 0x000C1100);
    }

    #[test]
    fn from_str_refuses_an_sdk_version_below_the_floor() {
        //* Given
        // The loader rejects an archive claiming an SDK older than the container layout.
        let input = "000A0000";

        //* When
        let result = input.parse::<SdkVersion>();

        //* Then
        assert!(result.is_err());
    }

    #[test]
    fn fmt_renders_an_sdk_version_in_the_dotted_form_the_console_reports() {
        //* Given
        let version: SdkVersion = "000C1100"
            .parse()
            .expect("an in-range version should parse");

        //* When
        let rendered = version.to_string();

        //* Then
        assert_eq!(rendered, "0.12.17.0");
    }

    #[test]
    fn from_str_accepts_a_key_area_key_of_thirty_two_hex_digits() {
        //* Given
        let input = "0102030405060708090a0b0c0d0e0f10";

        //* When
        let key: KeyAreaKey = input.parse().expect("32 hex digits should parse");

        //* Then
        assert_eq!(
            key.to_bytes(),
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn from_str_refuses_a_key_area_key_of_the_wrong_length() {
        //* Given
        let input = "0102";

        //* When
        let result = input.parse::<KeyAreaKey>();

        //* Then
        assert!(
            result.is_err(),
            "a short key would be padded into a different key"
        );
    }

    #[test]
    fn fmt_renders_a_key_area_key_as_thirty_two_lowercase_digits() {
        //* Given
        let key = KeyAreaKey::default();

        //* When
        let rendered = format!("{key:x}");

        //* Then
        assert_eq!(rendered, "04040404040404040404040404040404");
    }
}
