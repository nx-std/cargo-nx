//! The `cargo nx tool` subcommand: Switch homebrew toolchain utilities.

mod identifier;

pub mod bin2c;
pub mod bin2s;
pub mod build_pfs0;
pub mod build_romfs;
pub mod elf2kip;
pub mod elf2nro;
pub mod elf2nso;
pub mod hacbrewpack;
pub mod hactool;
pub mod nacptool;
pub mod npdmtool;

use crate::{ToolArgs, ToolSubcommand, ui::CliError};

/// Dispatch a `cargo nx tool <name>` invocation to its handler.
///
/// # Errors
///
/// Wraps whatever the dispatched tool returned in the matching variant, so the
/// failure names the tool that produced it.
pub fn handle_subcommand(args: ToolArgs) -> Result<(), Error> {
    match args.subcommand {
        ToolSubcommand::Elf2nro(args) => elf2nro::handle_subcommand(args).map_err(Error::Elf2nro),
        ToolSubcommand::Elf2nso(args) => elf2nso::handle_subcommand(args).map_err(Error::Elf2nso),
        ToolSubcommand::Elf2kip(args) => elf2kip::handle_subcommand(args).map_err(Error::Elf2kip),
        ToolSubcommand::BuildPfs0(args) => {
            build_pfs0::handle_subcommand(args).map_err(Error::BuildPfs0)
        }
        ToolSubcommand::BuildRomfs(args) => {
            build_romfs::handle_subcommand(args).map_err(Error::BuildRomfs)
        }
        ToolSubcommand::Npdmtool(args) => {
            npdmtool::handle_subcommand(args).map_err(Error::Npdmtool)
        }
        ToolSubcommand::Nacptool(args) => {
            nacptool::handle_subcommand(args).map_err(Error::Nacptool)
        }
        ToolSubcommand::Bin2s(args) => bin2s::handle_subcommand(args).map_err(Error::Bin2s),
        ToolSubcommand::Bin2c(args) => bin2c::handle_subcommand(args).map_err(Error::Bin2c),
        ToolSubcommand::Hacbrewpack(args) => {
            hacbrewpack::handle_subcommand(args).map_err(Error::Hacbrewpack)
        }
        ToolSubcommand::Hactool(args) => hactool::handle_subcommand(args).map_err(Error::Hactool),
    }
}

/// Errors from the `tool` subcommand.
///
/// Each variant wraps the failure of one toolchain utility, naming which tool
/// failed; the utility's own error carries the detail via the source chain.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The `elf2nro` utility failed.
    #[error("`elf2nro` failed")]
    Elf2nro(#[source] elf2nro::Error),

    /// The `elf2nso` utility failed.
    #[error("`elf2nso` failed")]
    Elf2nso(#[source] elf2nso::Error),

    /// The `elf2kip` utility failed.
    #[error("`elf2kip` failed")]
    Elf2kip(#[source] elf2kip::Error),

    /// The `build_pfs0` utility failed.
    #[error("`build_pfs0` failed")]
    BuildPfs0(#[source] build_pfs0::Error),

    /// The `build_romfs` utility failed.
    #[error("`build_romfs` failed")]
    BuildRomfs(#[source] build_romfs::Error),

    /// The `npdmtool` utility failed.
    #[error("`npdmtool` failed")]
    Npdmtool(#[source] npdmtool::Error),

    /// The `nacptool` utility failed.
    #[error("`nacptool` failed")]
    Nacptool(#[source] nacptool::Error),

    /// The `bin2s` utility failed.
    #[error("`bin2s` failed")]
    Bin2s(#[source] bin2s::Error),

    /// The `bin2c` utility failed.
    #[error("`bin2c` failed")]
    Bin2c(#[source] bin2c::Error),

    /// The `hacbrewpack` utility failed.
    #[error("`hacbrewpack` failed")]
    Hacbrewpack(#[source] hacbrewpack::Error),

    /// The `hactool` utility failed.
    #[error("`hactool` failed")]
    Hactool(#[source] hactool::Error),
}

impl CliError for Error {}
