//! `hacbrewpack` subcommand — pack a homebrew title into an installable NSP.
//!
//! Five archives at most make up a title, and they are built in a fixed order because the last one
//! describes the others: the program, the control, the two optional manuals, and finally the content
//! meta, whose records carry the hashes of everything already built. The NSP is then those archives
//! in one flat container, named for the title.
//!
//! Everything is assembled in memory and written once. The directories the caller names are read
//! from and written to at the edges of this module; nothing below it touches a filesystem.

use std::path::{Path, PathBuf};

use nx_object::{
    raw::{cnmt::CnmtContentType, nca::NcaContentType},
    write::{
        CnmtBuilder, NcaBuilder, Pfs0Builder, RomFsBuilder,
        cnmt::ContentRecord,
        nca::{KeyGeneration, Section, SectionData, SectionEncryption},
    },
};

mod archive;
mod keyset_file;
mod nacp;
mod npdm;
mod settings;
mod signing;
mod title_id;

use self::{
    archive::{Archive, ArchiveKeys},
    settings::{KeyAreaKey, SdkVersion},
    title_id::TitleId,
};
use crate::ui;

/// Bytes of archive one hash covers in an executable partition.
const EXEFS_HASH_BLOCK_SIZE: u32 = 0x10000;

/// Bytes of archive one hash covers in a logo or metadata partition.
const SMALL_HASH_BLOCK_SIZE: u32 = 0x1000;

/// Handle the `hacbrewpack` invocation.
///
/// # Errors
///
/// Returns an error if the keyset is missing or incomplete, if an input directory cannot be read, if
/// the descriptor or control property is malformed, or if an output cannot be written.
pub fn handle_subcommand(args: Args) -> Result<(), Error> {
    let keyset = keyset_file::load(args.keyset.as_deref()).map_err(Error::LoadKeyset)?;

    let header_key = keyset.header_key().ok_or(Error::MissingHeaderKey)?;
    let key_area_key =
        keyset
            .key_area_key_application(args.keygeneration)
            .ok_or(Error::MissingKeyAreaKey {
                generation: args.keygeneration.to_u8(),
            })?;
    let keys = ArchiveKeys {
        header_key,
        key_area_key,
    };

    let title_id = patch_descriptor(&args)?;
    if title_id.is_above_conventional_range() {
        ui::warning(&format!(
            "title ID {title_id} sits above the range homebrew conventionally uses"
        ));
    }
    patch_control(&args)?;

    ui::status("Packing", "program");
    let program = build_program(&args, &keys, title_id)?;
    ui::status("Packing", "control");
    let control = build_control(&args, &keys, title_id)?;

    let mut contents = vec![
        (CnmtContentType::Program, &program),
        (CnmtContentType::Control, &control),
    ];

    let html_document = match args.htmldocdir.as_deref() {
        Some(dir) => {
            ui::status("Packing", "manual");
            Some(build_manual(&args, &keys, title_id, dir)?)
        }
        None => None,
    };
    let legal_information = match args.legalinfodir.as_deref() {
        Some(dir) => {
            ui::status("Packing", "legal information");
            Some(build_manual(&args, &keys, title_id, dir)?)
        }
        None => None,
    };

    if let Some(manual) = &html_document {
        contents.push((CnmtContentType::HtmlDocument, manual));
    }
    if let Some(manual) = &legal_information {
        contents.push((CnmtContentType::LegalInformation, manual));
    }

    ui::status("Packing", "content meta");
    let meta = build_meta(&args, &keys, title_id, &contents)?;

    let mut archives: Vec<(String, &Archive)> = contents
        .iter()
        .map(|(_, archive)| (archive.file_name(""), *archive))
        .collect();
    archives.push((meta.file_name("cnmt"), &meta));

    if args.keepncadir {
        write_archives(&args.ncadir, &archives)?;
    }

    let nsp_path = write_package(&args.nspdir, title_id, &archives)?;

    ui::status("Packed", &format!("{} ({title_id})", nsp_path.display()));

    Ok(())
}

/// Read `main.npdm`, back it up if it is about to change, patch it, and write it back.
///
/// Returns the title ID the whole build is stamped with.
fn patch_descriptor(args: &Args) -> Result<TitleId, Error> {
    let path = args.exefsdir.join("main.npdm");
    let mut descriptor = read_file(&path)?;

    let patch = npdm::Patch {
        title_id: args.titleid,
        sign_program_header: !args.nosignncasig2,
    };
    let changes = patch.title_id.is_some() || patch.sign_program_header;

    if changes {
        back_up(&args.backupdir, &path)?;
    }

    let title_id = npdm::process(&mut descriptor, &patch).map_err(Error::ProcessNpdm)?;

    if changes {
        write_file(&path, &descriptor)?;
    }

    Ok(title_id)
}

/// Read `control.nacp`, back it up if it is about to change, patch it, and write it back.
///
/// The ID fields are rewritten only when the caller named a title ID: a descriptor's own ID is
/// already what the control property was authored against, so stamping it back in would be a
/// no-op that still costs a backup.
fn patch_control(args: &Args) -> Result<(), Error> {
    let path = args.controldir.join("control.nacp");
    let mut control = read_file(&path)?;

    let patch = nacp::Patch {
        name: args.titlename.clone(),
        publisher: args.titlepublisher.clone(),
        title_id: args.titleid,
        logo_handling_auto: !args.nopatchnacplogo,
    };
    let changes = patch.name.is_some()
        || patch.publisher.is_some()
        || patch.title_id.is_some()
        || patch.logo_handling_auto;

    if changes {
        back_up(&args.backupdir, &path)?;
    }

    nacp::process(&mut control, &patch).map_err(Error::ProcessNacp)?;

    if changes {
        write_file(&path, &control)?;
    }

    Ok(())
}

/// Build the program archive: the executable partition, the filesystem, and the logo.
fn build_program(args: &Args, keys: &ArchiveKeys<'_>, title_id: TitleId) -> Result<Archive, Error> {
    let mut builder = new_builder(args, NcaContentType::Program, title_id)?
        .section(
            0,
            Section {
                data: SectionData::Partition {
                    archive: read_partition(&args.exefsdir)?,
                    hash_block_size: EXEFS_HASH_BLOCK_SIZE,
                },
                encryption: args.section_encryption(),
            },
        )
        .map_err(Error::BuildNca)?;

    if !args.noromfs {
        builder = builder
            .section(
                1,
                Section {
                    data: SectionData::RomFs(read_filesystem(&args.romfsdir)?),
                    encryption: args.section_encryption(),
                },
            )
            .map_err(Error::BuildNca)?;
    }

    if !args.nologo {
        // The logo is left in the clear whatever the rest of the archive does: the console reads it
        // before the title is mounted, so there is nothing yet to decrypt it with.
        builder = builder
            .section(
                2,
                Section {
                    data: SectionData::Partition {
                        archive: read_partition(&args.logodir)?,
                        hash_block_size: SMALL_HASH_BLOCK_SIZE,
                    },
                    encryption: SectionEncryption::None,
                },
            )
            .map_err(Error::BuildNca)?;
    }

    finish(builder, keys, !args.nosignncasig2)
}

/// Build the control archive, which carries the icon and the control property.
fn build_control(args: &Args, keys: &ArchiveKeys<'_>, title_id: TitleId) -> Result<Archive, Error> {
    let builder = new_builder(args, NcaContentType::Control, title_id)?
        .section(
            0,
            Section {
                data: SectionData::RomFs(read_filesystem(&args.controldir)?),
                encryption: args.section_encryption(),
            },
        )
        .map_err(Error::BuildNca)?;

    finish(builder, keys, false)
}

/// Build a manual archive from the filesystem at `dir`.
fn build_manual(
    args: &Args,
    keys: &ArchiveKeys<'_>,
    title_id: TitleId,
    dir: &Path,
) -> Result<Archive, Error> {
    let builder = new_builder(args, NcaContentType::Manual, title_id)?
        .section(
            0,
            Section {
                data: SectionData::RomFs(read_filesystem(dir)?),
                encryption: args.section_encryption(),
            },
        )
        .map_err(Error::BuildNca)?;

    finish(builder, keys, false)
}

/// Build the metadata archive naming every content already built.
fn build_meta(
    args: &Args,
    keys: &ArchiveKeys<'_>,
    title_id: TitleId,
    contents: &[(CnmtContentType, &Archive)],
) -> Result<Archive, Error> {
    let mut meta = CnmtBuilder::new(title_id.to_u64());
    for (content_type, archive) in contents {
        meta = meta
            .add_content(ContentRecord {
                hash: archive.hash,
                size: archive.bytes.len() as u64,
                content_type: *content_type,
            })
            .map_err(Error::BuildCnmt)?;
    }

    let name = meta.file_name();
    let partition = Pfs0Builder::new()
        .add_file(name, meta.build())
        .map_err(Error::PackCnmt)?
        .build();

    let builder = new_builder(args, NcaContentType::Meta, title_id)?
        .section(
            0,
            Section {
                data: SectionData::Partition {
                    archive: partition,
                    hash_block_size: SMALL_HASH_BLOCK_SIZE,
                },
                encryption: args.section_encryption(),
            },
        )
        .map_err(Error::BuildNca)?;

    finish(builder, keys, false)
}

/// Start a builder carrying the settings every archive of this title shares.
fn new_builder(
    args: &Args,
    content_type: NcaContentType,
    title_id: TitleId,
) -> Result<NcaBuilder, Error> {
    NcaBuilder::new(content_type, title_id.to_u64())
        .sdk_version(args.sdkversion.to_u32())
        .key_generation(args.keygeneration)
        .key_area_key(
            nx_object::write::nca::SECTION_KEY_INDEX,
            args.keyareakey.to_bytes(),
        )
        .map_err(Error::BuildNca)
}

/// Build the container and hand it to the encryption pass.
fn finish(
    builder: NcaBuilder,
    keys: &ArchiveKeys<'_>,
    sign_header: bool,
) -> Result<Archive, Error> {
    let plain = builder.build().map_err(Error::LayOutNca)?;
    archive::finish(plain, keys, sign_header).map_err(Error::FinishNca)
}

/// Read `dir` as a flat partition archive.
fn read_partition(dir: &Path) -> Result<Vec<u8>, Error> {
    Ok(Pfs0Builder::from_directory(dir)
        .map_err(|err| Error::ReadPartition {
            path: dir.to_path_buf(),
            source: err,
        })?
        .build())
}

/// Read `dir` as a read-only filesystem image.
fn read_filesystem(dir: &Path) -> Result<Vec<u8>, Error> {
    RomFsBuilder::from_directory(dir)
        .map_err(|err| Error::ReadFilesystem {
            path: dir.to_path_buf(),
            source: err,
        })?
        .build()
        .map_err(Error::BuildFilesystem)
}

/// Write every archive into `dir`, replacing whatever was there.
fn write_archives(dir: &Path, archives: &[(String, &Archive)]) -> Result<(), Error> {
    // Removing first is what makes a re-run produce the directory the build describes rather than
    // that directory plus the leftovers of a title packed earlier.
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|err| Error::Write {
            path: dir.to_path_buf(),
            source: err,
        })?;
    }
    create_dir(dir)?;

    for (name, archive) in archives {
        write_file(&dir.join(name), &archive.bytes)?;
    }

    Ok(())
}

/// Pack every archive into one NSP under `dir` and return where it landed.
fn write_package(
    dir: &Path,
    title_id: TitleId,
    archives: &[(String, &Archive)],
) -> Result<PathBuf, Error> {
    let mut package = Pfs0Builder::new();
    for (name, archive) in archives {
        package = package
            .add_file(name.clone(), archive.bytes.clone())
            .map_err(Error::PackNsp)?;
    }

    create_dir(dir)?;
    let path = dir.join(format!("{title_id}.nsp"));
    write_file(&path, &package.build())?;

    Ok(path)
}

/// Copy `path` into `dir` under a name carrying the time it was taken.
fn back_up(dir: &Path, path: &Path) -> Result<(), Error> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::Read {
            path: path.to_path_buf(),
            source: std::io::Error::other("the path names no file"),
        })?
        .to_string_lossy()
        .into_owned();

    create_dir(dir)?;
    let stamp = chrono::Utc::now().timestamp();
    let contents = read_file(path)?;
    write_file(&dir.join(format!("{stamp}_{name}")), &contents)
}

/// Read a whole file, naming it if that fails.
fn read_file(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|err| Error::Read {
        path: path.to_path_buf(),
        source: err,
    })
}

/// Write a whole file, naming it if that fails.
fn write_file(path: &Path, contents: &[u8]) -> Result<(), Error> {
    std::fs::write(path, contents).map_err(|err| Error::Write {
        path: path.to_path_buf(),
        source: err,
    })
}

/// Create a directory and its parents, naming it if that fails.
fn create_dir(path: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(path).map_err(|err| Error::Write {
        path: path.to_path_buf(),
        source: err,
    })
}

#[derive(clap::Args)]
pub struct Args {
    /// Path to the keyset file
    #[arg(short = 'k', long)]
    pub keyset: Option<PathBuf>,

    /// Directory the packed NSP is written to
    #[arg(long, default_value = "hacbrewpack_nsp")]
    pub nspdir: PathBuf,

    /// Directory the individual NCAs are written to, with `--keepncadir`
    #[arg(long, default_value = "hacbrewpack_nca")]
    pub ncadir: PathBuf,

    /// Accepted for compatibility and unused: every intermediate is built in memory
    #[arg(long)]
    pub tempdir: Option<PathBuf>,

    /// Directory the originals of patched inputs are copied to
    #[arg(long, default_value = "hacbrewpack_backup")]
    pub backupdir: PathBuf,

    /// Directory holding the executable and its descriptor
    #[arg(long, default_value = "exefs")]
    pub exefsdir: PathBuf,

    /// Directory holding the title's read-only filesystem
    #[arg(long, default_value = "romfs")]
    pub romfsdir: PathBuf,

    /// Directory holding the title's logo
    #[arg(long, default_value = "logo")]
    pub logodir: PathBuf,

    /// Directory holding the icon and the control property
    #[arg(long, default_value = "control")]
    pub controldir: PathBuf,

    /// Directory holding the HTML manual, which is omitted when unset
    #[arg(long)]
    pub htmldocdir: Option<PathBuf>,

    /// Directory holding the legal information, which is omitted when unset
    #[arg(long)]
    pub legalinfodir: Option<PathBuf>,

    /// Skip the program's read-only filesystem section
    #[arg(long)]
    pub noromfs: bool,

    /// Skip the program's logo section
    #[arg(long)]
    pub nologo: bool,

    /// Keyset generation the key area is wrapped with
    #[arg(long, default_value = "1")]
    pub keygeneration: KeyGeneration,

    /// Key the sections are encrypted with, as 32 hex digits
    #[arg(long, default_value = "04040404040404040404040404040404")]
    pub keyareakey: KeyAreaKey,

    /// SDK version the archives claim, in hex
    #[arg(long, default_value = "000C1100")]
    pub sdkversion: SdkVersion,

    /// Leave every section in the clear
    #[arg(long)]
    pub plaintext: bool,

    /// Write the individual NCAs alongside the NSP
    #[arg(long)]
    pub keepncadir: bool,

    /// Skip advertising and using the header signing key
    #[arg(long)]
    pub nosignncasig2: bool,

    /// Title ID to stamp in, overriding the one in the descriptor
    #[arg(long)]
    pub titleid: Option<TitleId>,

    /// Title name to write into every interface language
    #[arg(long)]
    pub titlename: Option<String>,

    /// Publisher to write into every interface language
    #[arg(long)]
    pub titlepublisher: Option<String>,

    /// Leave the control property's logo handling as it is
    #[arg(long)]
    pub nopatchnacplogo: bool,
}

impl Args {
    /// How the sections that can be encrypted are protected.
    fn section_encryption(&self) -> SectionEncryption {
        if self.plaintext {
            SectionEncryption::None
        } else {
            SectionEncryption::Ctr
        }
    }
}

/// Errors from the `hacbrewpack` subcommand
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The keyset could not be found, read, or parsed.
    #[error("failed to load the keyset")]
    LoadKeyset(#[source] keyset_file::LoadError),

    /// The keyset carries no key to encrypt an archive header with.
    #[error("the keyset carries no `header_key`, and none can be derived from it")]
    MissingHeaderKey,

    /// The keyset carries no application key area key for the generation asked for.
    ///
    /// Holds the generation that was requested.
    #[error(
        "the keyset carries no `key_area_key_application` for key generation {generation}, \
         and none can be derived from it"
    )]
    MissingKeyAreaKey {
        /// The generation that was requested.
        generation: u8,
    },

    /// The program descriptor could not be validated or patched.
    #[error("failed to process `main.npdm`")]
    ProcessNpdm(#[source] npdm::ProcessError),

    /// The control property could not be validated or patched.
    #[error("failed to process `control.nacp`")]
    ProcessNacp(#[source] nacp::ProcessError),

    /// A directory could not be collected into a partition archive.
    #[error("failed to collect a partition from '{}'", path.display())]
    ReadPartition {
        /// The directory being read.
        path: PathBuf,
        /// Why it could not be read.
        #[source]
        source: nx_object::write::pfs0::FromDirectoryError,
    },

    /// A directory could not be collected into a filesystem image.
    #[error("failed to collect a filesystem from '{}'", path.display())]
    ReadFilesystem {
        /// The directory being read.
        path: PathBuf,
        /// Why it could not be read.
        #[source]
        source: nx_object::write::romfs::FromDirectoryError,
    },

    /// A filesystem image could not be laid out.
    #[error("failed to build a filesystem image")]
    BuildFilesystem(#[source] nx_object::write::romfs::BuildError),

    /// A section or key could not be placed in an archive.
    #[error("failed to assemble an NCA")]
    BuildNca(#[source] nx_object::write::nca::AddSectionError),

    /// An archive could not be laid out.
    #[error("failed to lay out an NCA")]
    LayOutNca(#[source] nx_object::write::nca::BuildError),

    /// An archive could not be encrypted or signed.
    #[error("failed to encrypt an NCA")]
    FinishNca(#[source] archive::FinishError),

    /// A content record could not be added to the content meta.
    #[error("failed to record a content in the metadata")]
    BuildCnmt(#[source] nx_object::write::cnmt::AddContentError),

    /// The content meta could not be packed into its partition.
    #[error("failed to pack the metadata")]
    PackCnmt(#[source] nx_object::write::pfs0::AddFileError),

    /// An archive could not be packed into the NSP.
    #[error("failed to pack the NSP")]
    PackNsp(#[source] nx_object::write::pfs0::AddFileError),

    /// A file could not be read.
    #[error("failed to read '{}'", path.display())]
    Read {
        /// The path that could not be read.
        path: PathBuf,
        /// The failure the filesystem reported.
        #[source]
        source: std::io::Error,
    },

    /// A file or directory could not be written.
    #[error("failed to write '{}'", path.display())]
    Write {
        /// The path that could not be written.
        path: PathBuf,
        /// The failure the filesystem reported.
        #[source]
        source: std::io::Error,
    },
}
