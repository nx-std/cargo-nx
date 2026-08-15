//! The title ID every archive of a title is stamped with.

/// A title ID that falls inside the range the console accepts for an application.
///
/// The range is not cosmetic: an ID below it names a system title and one above it names something
/// the loader will not mount as an application, so the value is checked once here and trusted
/// everywhere it is written afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TitleId(u64);

impl TitleId {
    /// Lowest ID the console treats as an application.
    pub const MIN: u64 = 0x0100000000000000;

    /// Highest ID the console treats as an application.
    pub const MAX: u64 = 0x0FFFFFFFFFFFFFFF;

    /// Highest ID that is conventional for a homebrew title.
    ///
    /// Above this the ID is still accepted, but it overlaps the space published titles are assigned
    /// from, so the command warns rather than refusing.
    pub const CONVENTIONAL_MAX: u64 = 0x01FFFFFFFFFFFFFF;

    /// The ID as the plain number every header stores.
    pub fn to_u64(self) -> u64 {
        self.0
    }

    /// The base ID downloadable content for this title is published under.
    pub fn add_on_content_base(self) -> u64 {
        self.to_u64() + 0x1000
    }

    /// Whether the ID sits above the range homebrew conventionally uses.
    pub fn is_above_conventional_range(self) -> bool {
        self.to_u64() > Self::CONVENTIONAL_MAX
    }
}

impl TryFrom<u64> for TitleId {
    type Error = ParseTitleIdError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if !(Self::MIN..=Self::MAX).contains(&value) {
            return Err(ParseTitleIdError::OutOfRange { value });
        }
        Ok(Self(value))
    }
}

impl std::str::FromStr for TitleId {
    type Err = ParseTitleIdError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let digits = input.strip_prefix("0x").unwrap_or(input);
        let value = u64::from_str_radix(digits, 16).map_err(ParseTitleIdError::Malformed)?;
        Self::try_from(value)
    }
}

impl std::fmt::Display for TitleId {
    /// Renders as the sixteen lowercase hex digits every file name and log line uses, so
    /// `0x100000000001000` prints as `0100000000001000`.
    ///
    /// The rendering is pinned by a unit test rather than a doctest: this module belongs to the
    /// binary target, which rustdoc cannot run examples against.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Error returned when a title ID cannot be built.
#[derive(Debug, thiserror::Error)]
pub enum ParseTitleIdError {
    /// The input is not a hexadecimal number.
    #[error("a title ID must be hexadecimal")]
    Malformed(#[source] std::num::ParseIntError),
    /// The ID is outside the range the console accepts for an application.
    ///
    /// Holds the rejected value.
    #[error(
        "title ID {value:016x} is outside the application range {:016x}-{:016x}",
        TitleId::MIN,
        TitleId::MAX
    )]
    OutOfRange {
        /// The rejected value.
        value: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::TitleId;

    #[test]
    fn from_str_accepts_a_hexadecimal_id_inside_the_range() {
        //* Given
        let input = "0100000000001000";

        //* When
        let title_id: TitleId = input.parse().expect("an in-range ID should parse");

        //* Then
        assert_eq!(title_id.to_u64(), 0x0100000000001000);
    }

    #[test]
    fn from_str_accepts_a_leading_0x_prefix() {
        //* Given
        let input = "0x0100000000001000";

        //* When
        let title_id: TitleId = input.parse().expect("a prefixed ID should parse");

        //* Then
        assert_eq!(title_id.to_u64(), 0x0100000000001000);
    }

    #[test]
    fn display_renders_sixteen_lowercase_hex_digits() {
        //* Given
        // File names and the CNMT's own name are built from this rendering, so it is fixed.
        let title_id: TitleId = "0100000000001000"
            .parse()
            .expect("an in-range ID should parse");

        //* When
        let rendered = title_id.to_string();

        //* Then
        assert_eq!(rendered, "0100000000001000");
    }

    #[test]
    fn from_str_refuses_an_id_below_the_application_range() {
        //* Given
        // A system title, which the loader will not mount as an application.
        let input = "0000000000000042";

        //* When
        let result = input.parse::<TitleId>();

        //* Then
        assert!(result.is_err());
    }

    #[test]
    fn from_str_refuses_an_id_above_the_application_range() {
        //* Given
        let input = "1000000000000000";

        //* When
        let result = input.parse::<TitleId>();

        //* Then
        assert!(result.is_err());
    }

    #[test]
    fn is_above_conventional_range_flags_an_id_past_the_homebrew_space() {
        //* Given
        let input = "0200000000000000";

        //* When
        let title_id: TitleId = input
            .parse()
            .expect("it is still inside the accepted range");

        //* Then
        assert!(
            title_id.is_above_conventional_range(),
            "it overlaps the space published titles are assigned from"
        );
    }
}
