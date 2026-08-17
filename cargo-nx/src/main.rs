//! `cargo-nx`: a Cargo subcommand for building Nintendo Switch homebrew.

use tracing_subscriber::EnvFilter;

mod cmd;
mod crypto;
mod keyset;
mod logging;
mod pack;
mod signing;
mod ui;
mod unpack;

fn main() {
    // Set up the diagnostic logger. User-facing output goes through `ui`, so this
    // channel stays silent until `RUST_LOG` asks for it: the default filter would
    // otherwise print every command failure twice, once as a trace line and once as
    // the report the user is meant to read.
    let filter = match std::env::var("RUST_LOG") {
        Ok(directives) => EnvFilter::new(directives),
        Err(_) => EnvFilter::new("off"),
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Parse the command-line arguments and dispatch to the subcommand.
    let Cargo::Nx(CargoNxArgs { subcommand }) = clap::Parser::parse();
    let rc = match subcommand {
        CargoNxSubcommand::New(args) => finish("new", cmd::new::handle_subcommand(args)),
        CargoNxSubcommand::Build(args) => finish("build", cmd::build::handle_subcommand(args)),
        CargoNxSubcommand::Bundle(args) => finish("bundle", cmd::bundle::handle_subcommand(args)),
        CargoNxSubcommand::Link(args) => finish("link", cmd::link::handle_subcommand(args)),
        CargoNxSubcommand::Tool(args) => finish("tool", cmd::tool::handle_subcommand(args)),
    };

    std::process::exit(rc);
}

#[derive(clap::Parser)]
#[clap(name = "cargo", bin_name = "cargo")]
pub enum Cargo {
    Nx(CargoNxArgs),
}

#[derive(clap::Args)]
#[clap(author, version, about)]
pub struct CargoNxArgs {
    #[command(subcommand)]
    pub subcommand: CargoNxSubcommand,
}

#[derive(clap::Subcommand)]
pub enum CargoNxSubcommand {
    #[command(
        about = "Create a new Rust project for the Nintendo Switch",
        after_help = include_str!("cmd/new__after_help.md")
    )]
    New(cmd::new::Args),
    #[command(
        about = "Build a Rust project for the Nintendo Switch",
        after_help = include_str!("cmd/build__after_help.md")
    )]
    Build(cmd::build::Args),
    #[command(
        about = "Package a pre-built ELF as an NRO or NSP",
        after_help = include_str!("cmd/bundle__after_help.md")
    )]
    Bundle(cmd::bundle::Args),
    #[command(
        about = "Send a file to the Nintendo Switch",
        after_help = include_str!("cmd/link__after_help.md")
    )]
    Link(cmd::link::Args),
    #[command(
        about = "Switch homebrew toolchain utilities",
        after_help = include_str!("cmd/tool__after_help.md")
    )]
    Tool(ToolArgs),
}

#[derive(clap::Args)]
pub struct ToolArgs {
    #[command(subcommand)]
    pub subcommand: ToolSubcommand,
}

#[derive(clap::Subcommand)]
pub enum ToolSubcommand {
    #[command(
        about = "Convert an ELF file to NRO format",
        after_help = include_str!("cmd/tool/elf2nro__after_help.md")
    )]
    Elf2nro(cmd::tool::elf2nro::Args),
    #[command(
        about = "Convert an ELF file to NSO format",
        after_help = include_str!("cmd/tool/elf2nso__after_help.md")
    )]
    Elf2nso(cmd::tool::elf2nso::Args),
    #[command(
        about = "Convert an ELF file to KIP format",
        after_help = include_str!("cmd/tool/elf2kip__after_help.md")
    )]
    Elf2kip(cmd::tool::elf2kip::Args),
    #[command(
        name = "build_pfs0",
        about = "Build a PFS0 archive from a directory",
        after_help = include_str!("cmd/tool/build_pfs0__after_help.md")
    )]
    BuildPfs0(cmd::tool::build_pfs0::Args),
    #[command(
        name = "build_romfs",
        about = "Build a RomFS image from a directory",
        after_help = include_str!("cmd/tool/build_romfs__after_help.md")
    )]
    BuildRomfs(cmd::tool::build_romfs::Args),
    #[command(
        about = "Convert JSON metadata to NPDM format",
        after_help = include_str!("cmd/tool/npdmtool__after_help.md")
    )]
    Npdmtool(cmd::tool::npdmtool::Args),
    #[command(
        about = "Create or manipulate NACP files",
        after_help = include_str!("cmd/tool/nacptool__after_help.md")
    )]
    Nacptool(cmd::tool::nacptool::Args),
    #[command(
        name = "bin2s",
        about = "Convert binary files to GAS assembly source",
        after_help = include_str!("cmd/tool/bin2s__after_help.md")
    )]
    Bin2s(cmd::tool::bin2s::Args),
    #[command(
        name = "bin2c",
        alias = "raw2c",
        about = "Convert binary files to C source",
        after_help = include_str!("cmd/tool/bin2c__after_help.md")
    )]
    Bin2c(cmd::tool::bin2c::Args),
    #[command(
        name = "hacbrewpack",
        about = "Pack a homebrew title into an installable NSP",
        after_help = include_str!("cmd/tool/hacbrewpack__after_help.md")
    )]
    Hacbrewpack(cmd::tool::hacbrewpack::Args),
    #[command(
        name = "hactool",
        about = "Read, verify, and extract an NCA or NSP",
        after_help = include_str!("cmd/tool/hactool__after_help.md")
    )]
    Hactool(cmd::tool::hactool::Args),
}

/// Report a command result and resolve it to a process exit code.
///
/// On success returns `0`. On failure, prints the error and its full source
/// chain via [`ui::error`] and returns the error's [`ui::CliError::exit_code`].
/// Report a finished subcommand and produce the process exit code.
///
/// A failure is reported twice on purpose: to the user through [`ui::error`], and to
/// the diagnostic channel with its full source chain, which is what an operator
/// running with `RUST_LOG` set is looking for.
fn finish<E: ui::CliError>(command: &'static str, result: Result<(), E>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(err) => {
            tracing::error!(
                command,
                error = %err,
                error_source = logging::error_source(&err),
                "subcommand failed"
            );
            ui::error(&err);
            err.exit_code()
        }
    }
}
