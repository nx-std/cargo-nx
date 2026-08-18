//! `hactool` subcommand — read, verify, and extract the archives the console loads.
//!
//! The inverse of `hacbrewpack`, and deliberately narrower than the tool it is named for: it reads
//! what this workspace can produce — an NCA, the NSP that carries one, and the KIP1 `elf2kip`
//! emits — and says so plainly when handed anything else. Gamecard images, boot packages, savedata,
//! and update partitions are out of scope, because nothing here builds them and nothing here could
//! test a reader for them.
//!
//! Two limits are worth knowing before reading the output. An NCA carries two signatures and only
//! the second is checkable here: the first is verified against a modulus that lives in the console.
//! And an archive can only be opened with the keys it was sealed with, so a keyset that lacks the
//! generation the archive names fails at the door rather than producing partial output.
//!
//! Everything is read into memory and decrypted once; the directories the caller names are written
//! at the edges of this module.

use std::path::{Path, PathBuf};

use nx_object::{
    raw::{
        cnmt::{CnmtContentMetaType, CnmtContentType},
        nca::{NCA_SECTION_COUNT, NcaContentType, NcaCryptType, NcaFsType},
    },
    read::{
        cnmt::{self, Cnmt},
        kip::{self, Kip1},
        nca::{Nca, NcaSection, Superblock},
        pfs0::{self, Pfs0},
    },
};
use sha2::{Digest as _, Sha256};

mod extract;

use crate::{
    keyset,
    ui::{self, CliError},
    unpack::{
        nca::{self, PlainNca},
        verify,
    },
};

/// Magic identifying a PFS0, which is how an NSP is told from an NCA without being asked.
const PFS0_MAGIC: &[u8; 4] = b"PFS0";

/// Magic identifying a KIP1, which leads the file in the clear.
const KIP1_MAGIC: &[u8; 4] = b"KIP1";

/// Suffix the archive carrying a title's content meta is named with.
const META_SUFFIX: &str = ".cnmt.nca";

/// Handle the `hactool` invocation.
///
/// # Errors
///
/// Returns an error if the input cannot be read, if its type cannot be determined, if the keyset is
/// missing or lacks the keys the archive needs, if the archive is malformed, or if an output
/// directory cannot be written. A failed verification is reported but does not fail the command;
/// `--verify` reports what it found and leaves the decision to the caller.
pub fn handle_subcommand(args: Args) -> Result<(), Error> {
    let image = std::fs::read(&args.file).map_err(|err| Error::ReadInput {
        path: args.file.clone(),
        source: err,
    })?;

    match args.intype.unwrap_or_else(|| detect(&image)) {
        InputType::Nsp => handle_nsp(&args, &image),
        InputType::Nca => handle_nca(&args, &image),
        InputType::Kip => handle_kip(&args, &image),
    }
}

/// Read, report, and extract an NSP.
fn handle_nsp(args: &Args, image: &[u8]) -> Result<(), Error> {
    let pfs0 = Pfs0::try_from_bytes(image).map_err(Error::ParseNsp)?;

    ui::raw(&render_nsp(&pfs0));

    if args.verify {
        ui::raw(&render_package_verification(args, &pfs0)?);
    }

    if let Some(dir) = &args.outdir {
        let written = extract::partition(image, dir).map_err(Error::ExtractNsp)?;
        ui::status(
            "Extracted",
            &format!("{written} files to {}", dir.display()),
        );
    }

    Ok(())
}

/// Decrypt, report, verify, and extract an NCA.
fn handle_nca(args: &Args, image: &[u8]) -> Result<(), Error> {
    let keyset = keyset::file::load(args.keyset.as_deref()).map_err(Error::LoadKeyset)?;
    let plain = nca::decrypt(image, &keyset).map_err(Error::Decrypt)?;

    let archive = Nca::try_from_bytes(&plain.bytes).map_err(Error::ParseNca)?;

    ui::raw(&render_nca(&archive, &plain));

    if let Some(rendered) = render_cnmt(&archive) {
        ui::raw(&rendered);
    }

    if args.verify {
        ui::raw(&render_verification(&archive, &plain));
    }

    if let Some(path) = &args.plaintext {
        extract::raw(&plain.bytes, path).map_err(Error::WritePlaintext)?;
        ui::status("Wrote", &format!("{}", path.display()));
    }

    extract_sections(args, &archive)
}

/// Write out whatever section directories the caller named.
fn extract_sections(args: &Args, archive: &Nca<'_>) -> Result<(), Error> {
    for section in archive.sections() {
        if let Some(dir) = args.section_dir(section.index()) {
            extract::raw(section.bytes(), &dir.join("section.bin")).map_err(Error::WriteSection)?;
            ui::status(
                "Extracted",
                &format!("section {} to {}", section.index(), dir.display()),
            );
        }

        // The executable partition is section 0 by convention; the logo is a PFS0 too, and
        // extracting it into the exefs directory would be wrong.
        if let (Some(dir), 0, Superblock::Pfs0(_)) =
            (&args.exefsdir, section.index(), section.superblock())
        {
            let written = extract::partition(section.data(), dir).map_err(Error::ExtractExeFs)?;
            ui::status(
                "Extracted",
                &format!("{written} files to {}", dir.display()),
            );
        }

        if let (Some(dir), Superblock::RomFs(_)) = (&args.romfsdir, section.superblock()) {
            let written = extract::romfs(section.data(), dir).map_err(Error::ExtractRomFs)?;
            ui::status(
                "Extracted",
                &format!("{written} files to {}", dir.display()),
            );
        }
    }

    Ok(())
}

/// Read, report, and extract a KIP1.
///
/// A KIP1 carries no keys and no signature, so this path needs neither a keyset nor `--verify`:
/// there is nothing to decrypt and nothing to check a signature against.
fn handle_kip(args: &Args, image: &[u8]) -> Result<(), Error> {
    let kip = Kip1::try_from_bytes(image).map_err(Error::ParseKip)?;

    ui::raw(&render_kip(&kip));

    let Some(dir) = &args.outdir else {
        return Ok(());
    };

    for segment in kip.segments() {
        let bytes = segment.decompress().map_err(Error::DecompressSegment)?;
        let name = format!("{}.bin", segment_name(segment.index()));
        extract::raw(&bytes, &dir.join(name)).map_err(Error::WriteSegment)?;
    }

    ui::status("Extracted", &format!("4 segments to {}", dir.display()));

    Ok(())
}

/// Render a KIP1's header and every segment it carries.
fn render_kip(kip: &Kip1<'_>) -> String {
    let mut out = String::from("KIP1:\n");
    out.push_str(&format!("  Name:            {}\n", kip.name()));
    out.push_str(&format!("  Title ID:        {:016x}\n", kip.title_id()));
    out.push_str(&format!("  Flags:           {:#04x}\n", kip.header().flags));

    for segment in kip.segments() {
        out.push_str(&format!(
            "  Segment {} ({}):\n",
            segment.index(),
            segment_name(segment.index())
        ));
        out.push_str(&format!("    Address:       {:#x}\n", segment.address()));
        out.push_str(&format!(
            "    Stored:        {} bytes{}\n",
            segment.stored().len(),
            if segment.is_compressed() {
                " (BLZ)"
            } else {
                ""
            }
        ));
        out.push_str(&format!(
            "    Expanded:      {} bytes\n",
            segment.decompressed_size()
        ));
    }

    out
}

/// The name segment `index` is known by, which is what an extracted file is called.
fn segment_name(index: usize) -> &'static str {
    match index {
        0 => "text",
        1 => "rodata",
        2 => "data",
        _ => "bss",
    }
}

/// Render the content meta an archive carries, when it is the one that carries it.
///
/// Returns `None` for every archive but the meta: only that one holds a CNMT, and a caller asking
/// for the records of a program archive is asking for something that is not there.
fn render_cnmt(archive: &Nca<'_>) -> Option<String> {
    if archive.content_type() != NcaContentType::Meta {
        return None;
    }

    // The meta archive holds one PFS0 section, and the CNMT is the single file in it.
    let section = archive.sections().next()?;
    let pfs0 = Pfs0::try_from_bytes(section.data()).ok()?;
    let file = pfs0.files().next()?;
    let cnmt = Cnmt::try_from_bytes(file.data()).ok()?;

    let mut out = String::from("Content meta:\n");
    out.push_str(&format!("  Title ID:        {:016x}\n", cnmt.title_id()));
    out.push_str(&format!("  Title version:   {}\n", cnmt.title_version()));
    out.push_str(&format!(
        "  Meta type:       {}\n",
        meta_type_name(cnmt.meta_type())
    ));

    for record in cnmt.records() {
        out.push_str(&format!(
            "    {:<18} {} ({} bytes)\n",
            content_type_label(record.content_type()),
            hex(record.nca_id()),
            record.size()
        ));
    }

    Some(out)
}

/// The name a content meta type is reported under.
fn meta_type_name(meta_type: Option<CnmtContentMetaType>) -> &'static str {
    match meta_type {
        Some(CnmtContentMetaType::Application) => "Application",
        Some(CnmtContentMetaType::Patch) => "Patch",
        Some(CnmtContentMetaType::AddOnContent) => "AddOnContent",
        Some(CnmtContentMetaType::Delta) => "Delta",
        None => "(unrecognized)",
    }
}

/// The label a content record's type is listed under.
fn content_type_label(content_type: Option<CnmtContentType>) -> &'static str {
    match content_type {
        Some(CnmtContentType::Meta) => "Meta",
        Some(CnmtContentType::Program) => "Program",
        Some(CnmtContentType::Data) => "Data",
        Some(CnmtContentType::Control) => "Control",
        Some(CnmtContentType::HtmlDocument) => "HtmlDocument",
        Some(CnmtContentType::LegalInformation) => "LegalInformation",
        Some(CnmtContentType::DeltaFragment) => "DeltaFragment",
        None => "(unrecognized)",
    }
}

/// Check every archive in a package against the content meta that names it.
///
/// This is the check a package as a whole can fail while each of its archives passes: an NCA whose
/// own hashes verify can still be the wrong file, the wrong size, or missing entirely, and only the
/// content meta says which files should be there.
///
/// Opening the meta archive needs the keyset, so unlike listing or extracting a package, this
/// cannot run without one.
fn render_package_verification(args: &Args, pfs0: &Pfs0<'_>) -> Result<String, Error> {
    let Some(meta_file) = pfs0.files().find(|file| file.name().ends_with(META_SUFFIX)) else {
        return Ok(format!(
            "Package:\n  {:<32} no {META_SUFFIX} in the package\n",
            "content meta"
        ));
    };

    let keyset = keyset::file::load(args.keyset.as_deref()).map_err(Error::LoadKeyset)?;
    let plain = nca::decrypt(meta_file.data(), &keyset).map_err(Error::Decrypt)?;
    let archive = Nca::try_from_bytes(&plain.bytes).map_err(Error::ParseNca)?;

    let section = archive.sections().next().ok_or(Error::MetaWithoutSection)?;
    let meta_partition = Pfs0::try_from_bytes(section.data()).map_err(Error::ParseNsp)?;
    let cnmt_file = meta_partition
        .files()
        .next()
        .ok_or(Error::MetaWithoutSection)?;
    let cnmt = Cnmt::try_from_bytes(cnmt_file.data()).map_err(Error::ParseCnmt)?;

    let mut out = String::from("Package:\n");
    out.push_str(&format!(
        "  {:<32} {} records\n",
        "content meta",
        cnmt.record_count()
    ));

    for record in cnmt.records() {
        let name = format!("{}.nca", hex(record.nca_id()));
        let label = format!(
            "{} {}",
            content_type_label(record.content_type()),
            &name[..16]
        );

        let Some(file) = pfs0.file_by_name(&name) else {
            out.push_str(&outcome(
                &label,
                Err(format!("'{name}' is not in the package")),
            ));
            continue;
        };

        if file.data().len() as u64 != record.size() {
            out.push_str(&outcome(
                &label,
                Err(format!(
                    "recorded {} bytes, package holds {}",
                    record.size(),
                    file.data().len()
                )),
            ));
            continue;
        }

        let digest: [u8; 0x20] = Sha256::digest(file.data()).into();
        if &digest != record.hash() {
            out.push_str(&outcome(
                &label,
                Err("content hash does not match".to_owned()),
            ));
            continue;
        }

        out.push_str(&outcome(&label, Ok(())));
    }

    Ok(out)
}

/// Which kind of container `image` is, judged by what leads it.
///
/// An NCA cannot be recognized this way — its header is ciphertext — so anything that is not a PFS0
/// is treated as one, and a wrong guess surfaces as a failed header decryption rather than silently.
fn detect(image: &[u8]) -> InputType {
    match image.get(..4) {
        Some(magic) if magic == PFS0_MAGIC => InputType::Nsp,
        Some(magic) if magic == KIP1_MAGIC => InputType::Kip,
        _ => InputType::Nca,
    }
}

/// Render what an NSP holds.
fn render_nsp(pfs0: &Pfs0<'_>) -> String {
    let mut out = String::from("NSP:\n");
    out.push_str(&format!("  Files: {}\n", pfs0.file_count()));
    for file in pfs0.files() {
        out.push_str(&format!(
            "    {:<48} {} bytes\n",
            file.name(),
            file.data().len()
        ));
    }
    out
}

/// Render an archive's header and every section it carries.
fn render_nca(archive: &Nca<'_>, plain: &PlainNca) -> String {
    let header = archive.header();

    let mut out = String::from("NCA:\n");
    out.push_str(&format!(
        "  Content type:    {}\n",
        content_type_name(archive.content_type())
    ));
    out.push_str(&format!("  Title ID:        {:016x}\n", archive.title_id()));
    out.push_str(&format!(
        "  Size:            {} bytes\n",
        archive.nca_size()
    ));
    out.push_str(&format!(
        "  Key generation:  {}\n",
        archive.key_generation()
    ));
    out.push_str(&format!(
        "  Rights ID:       {}\n",
        if header.rights_id == [0; 0x10] {
            "(none, key area crypto)".to_owned()
        } else {
            hex(&header.rights_id)
        }
    ));

    out.push_str("  Key area (unwrapped):\n");
    for (index, key) in plain.key_area.iter().enumerate() {
        out.push_str(&format!("    [{index}] {}\n", hex(key)));
    }

    for section in archive.sections() {
        out.push_str(&render_section(&section));
    }

    out
}

/// Render one section's extent, filesystem, and encryption.
fn render_section(section: &NcaSection<'_>) -> String {
    let range = section.range();
    let mut out = format!("  Section {}:\n", section.index());
    out.push_str(&format!(
        "    Offset:        {:#x} .. {:#x}\n",
        range.start, range.end
    ));
    out.push_str(&format!(
        "    Filesystem:    {}\n",
        fs_type_name(section.fs_type())
    ));
    out.push_str(&format!(
        "    Encryption:    {}\n",
        encryption_name(section.encryption())
    ));
    out.push_str(&format!(
        "    Contents:      {} bytes\n",
        section.data().len()
    ));
    out
}

/// Run every check the archive supports and render what each one found.
///
/// A failing check is rendered rather than returned: the point of `--verify` is to say which of the
/// checks failed, and stopping at the first would hide the rest.
fn render_verification(archive: &Nca<'_>, plain: &PlainNca) -> String {
    let mut out = String::from("Verification:\n");

    out.push_str(&match verify::header_signature(&plain.bytes) {
        Ok(verify::SignatureCheck::Verified) => outcome("header signature", Ok(())),
        // Not a failure: only a title's program archive is signed, so every other archive of a
        // correctly packed title reaches here.
        Ok(verify::SignatureCheck::Absent) => {
            format!("  {:<32} not signed\n", "header signature")
        }
        Err(err) => outcome("header signature", Err(err.to_string())),
    });

    for section in archive.sections() {
        out.push_str(&outcome(
            &format!("section {} FS header hash", section.index()),
            verify::fs_header_hash(archive, section.index()).map_err(|err| err.to_string()),
        ));
        out.push_str(&outcome(
            &format!("section {} contents", section.index()),
            verify::section_hashes(&section).map_err(|err| err.to_string()),
        ));
    }

    out
}

/// Render one check as a pass or a failure with its reason.
fn outcome(check: &str, result: Result<(), String>) -> String {
    match result {
        Ok(()) => format!("  {check:<32} OK\n"),
        Err(reason) => format!("  {check:<32} FAILED ({reason})\n"),
    }
}

/// The name a content type is reported under.
fn content_type_name(content_type: NcaContentType) -> &'static str {
    match content_type {
        NcaContentType::Program => "Program",
        NcaContentType::Meta => "Meta",
        NcaContentType::Control => "Control",
        NcaContentType::Manual => "Manual",
        NcaContentType::Data => "Data",
        NcaContentType::PublicData => "PublicData",
    }
}

/// The name a filesystem type is reported under.
fn fs_type_name(fs_type: NcaFsType) -> &'static str {
    match fs_type {
        NcaFsType::RomFs => "RomFS",
        NcaFsType::Pfs0 => "PFS0",
    }
}

/// The name an encryption scheme is reported under.
fn encryption_name(encryption: NcaCryptType) -> &'static str {
    match encryption {
        NcaCryptType::None => "none (plaintext)",
        NcaCryptType::Xts => "AES-XTS",
        NcaCryptType::Ctr => "AES-CTR",
        NcaCryptType::Bktr => "AES-CTR (BKTR)",
    }
}

/// Render `bytes` as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Which container the input is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum InputType {
    /// A single content archive.
    Nca,
    /// A submission package, which is a PFS0 holding archives.
    Nsp,
    /// A kernel initial process image.
    Kip,
}

#[derive(clap::Args)]
pub struct Args {
    /// File to read: an NCA, or an NSP holding them
    pub file: PathBuf,

    /// Path to the keyset file
    #[arg(short = 'k', long)]
    pub keyset: Option<PathBuf>,

    /// Kind of container the file is, detected from its contents when unset
    #[arg(short = 't', long, value_enum)]
    pub intype: Option<InputType>,

    /// Check the header signature and every hash covering the archive
    ///
    /// For a package this also checks every archive against the content meta naming it, which needs
    /// the keyset the metadata archive was sealed with.
    #[arg(long)]
    pub verify: bool,

    /// Write the decrypted archive to this path
    #[arg(long)]
    pub plaintext: Option<PathBuf>,

    /// Directory the files of an NSP, or the segments of a KIP1, are extracted to
    #[arg(long)]
    pub outdir: Option<PathBuf>,

    /// Directory the executable partition is extracted to
    #[arg(long)]
    pub exefsdir: Option<PathBuf>,

    /// Directory the read-only filesystem is extracted to
    #[arg(long)]
    pub romfsdir: Option<PathBuf>,

    /// Directory section 0 is written to, verification structures included
    #[arg(long)]
    pub section0dir: Option<PathBuf>,

    /// Directory section 1 is written to, verification structures included
    #[arg(long)]
    pub section1dir: Option<PathBuf>,

    /// Directory section 2 is written to, verification structures included
    #[arg(long)]
    pub section2dir: Option<PathBuf>,

    /// Directory section 3 is written to, verification structures included
    #[arg(long)]
    pub section3dir: Option<PathBuf>,
}

impl Args {
    /// The directory section `index` is to be written to, if the caller named one.
    ///
    /// The four flags are one setting with an index, so they are read as one here rather than
    /// branched on at the point that needs them.
    fn section_dir(&self, index: usize) -> Option<&Path> {
        let dirs: [&Option<PathBuf>; NCA_SECTION_COUNT] = [
            &self.section0dir,
            &self.section1dir,
            &self.section2dir,
            &self.section3dir,
        ];

        dirs.get(index).and_then(|dir| dir.as_deref())
    }
}

/// Errors from the `hactool` utility.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input file could not be read.
    ///
    /// Holds the path and the failure the filesystem reported.
    #[error("failed to read '{}'", path.display())]
    ReadInput {
        /// The path that could not be read.
        path: PathBuf,
        /// The failure the filesystem reported.
        #[source]
        source: std::io::Error,
    },
    /// The keyset could not be found, read, or parsed.
    #[error("failed to load the keyset")]
    LoadKeyset(#[source] keyset::file::LoadError),
    /// The archive could not be decrypted with the keys the keyset holds.
    #[error("failed to decrypt the archive")]
    Decrypt(#[source] nca::DecryptError),
    /// The decrypted archive is not a valid NCA.
    #[error("failed to parse the decrypted archive")]
    ParseNca(#[source] nx_object::read::nca::FromBytesError),
    /// The input is not a valid NSP.
    #[error("failed to parse the package")]
    ParseNsp(#[source] pfs0::FromBytesError),
    /// The input is not a valid KIP1.
    #[error("failed to parse the KIP1 image")]
    ParseKip(#[source] kip::FromBytesError),
    /// The content meta could not be read.
    #[error("failed to parse the content meta")]
    ParseCnmt(#[source] cnmt::FromBytesError),
    /// The metadata archive carries no section holding a content meta.
    ///
    /// A meta archive is one PFS0 section holding one CNMT, so an archive without them is not the
    /// metadata archive its name claims.
    #[error("the metadata archive holds no content meta")]
    MetaWithoutSection,
    /// A KIP1 segment could not be expanded.
    #[error("failed to expand a KIP1 segment")]
    DecompressSegment(#[source] kip::DecompressError),
    /// A KIP1 segment could not be written.
    #[error("failed to write a KIP1 segment")]
    WriteSegment(#[source] extract::WriteError),
    /// The decrypted archive could not be written.
    #[error("failed to write the decrypted archive")]
    WritePlaintext(#[source] extract::WriteError),
    /// A raw section could not be written.
    #[error("failed to write a section")]
    WriteSection(#[source] extract::WriteError),
    /// The files of an NSP could not be extracted.
    #[error("failed to extract the package")]
    ExtractNsp(#[source] extract::PartitionError),
    /// The executable partition could not be extracted.
    #[error("failed to extract the executable partition")]
    ExtractExeFs(#[source] extract::PartitionError),
    /// The read-only filesystem could not be extracted.
    #[error("failed to extract the read-only filesystem")]
    ExtractRomFs(#[source] extract::RomFsError),
}

impl CliError for Error {}

#[cfg(test)]
mod tests {
    use super::{
        CnmtContentType, InputType, content_type_label, detect, meta_type_name, segment_name,
    };

    #[test]
    fn detect_with_a_pfs0_magic_returns_nsp() {
        //* Given
        let image = b"PFS0\x02\x00\x00\x00".to_vec();

        //* When
        let kind = detect(&image);

        //* Then
        assert_eq!(kind, InputType::Nsp);
    }

    #[test]
    fn detect_with_a_kip1_magic_returns_kip() {
        //* Given
        let image = b"KIP1\x00\x00\x00\x00".to_vec();

        //* When
        let kind = detect(&image);

        //* Then
        assert_eq!(kind, InputType::Kip);
    }

    #[test]
    fn segment_name_names_the_four_loaded_segments() {
        //* Given
        let indices = 0..4;

        //* When
        let names: Vec<&str> = indices.map(segment_name).collect();

        //* Then
        assert_eq!(names, ["text", "rodata", "data", "bss"]);
    }

    #[test]
    fn meta_type_name_with_an_unmodelled_type_says_so() {
        //* Given
        // The reader reports a meta type it does not model as absent, and the label has to make
        // that legible rather than pick a plausible-looking name.
        let meta_type = None;

        //* When
        let name = meta_type_name(meta_type);

        //* Then
        assert_eq!(name, "(unrecognized)");
    }

    #[test]
    fn content_type_label_with_a_known_type_names_it() {
        //* Given
        let content_type = Some(CnmtContentType::Program);

        //* When
        let label = content_type_label(content_type);

        //* Then
        assert_eq!(label, "Program");
    }

    #[test]
    fn detect_with_an_encrypted_header_returns_nca() {
        //* Given
        // An NCA leads with ciphertext, so anything that is not a PFS0 is treated as one.
        let image = vec![0x9Au8; 0x40];

        //* When
        let kind = detect(&image);

        //* Then
        assert_eq!(kind, InputType::Nca);
    }

    #[test]
    fn detect_with_a_buffer_shorter_than_a_magic_returns_nca() {
        //* Given
        let image = vec![0x50u8, 0x46];

        //* When
        let kind = detect(&image);

        //* Then
        assert_eq!(kind, InputType::Nca);
    }
}
