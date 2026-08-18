//! Writing what an archive holds out to a directory.
//!
//! Every name written here came out of an image this tool did not build, so no name reaches the
//! filesystem before [`safe_component`] has checked it. A RomFS or PFS0 entry called `../../…`
//! would otherwise place a file outside the directory the user named, which is the one way a
//! read-only operation can still damage something.
//!
//! Files are written through a temporary path and renamed into place, so an interrupted extraction
//! leaves whole files and half-written temporaries rather than truncated files that look complete.
//! Re-running an extraction over the same directory therefore produces the same result as running
//! it once.

use std::path::{Path, PathBuf};

use nx_object::read::{
    pfs0::{self, Pfs0},
    romfs::{self, RomFs, RomFsDir, RomFsEntry},
};

/// Write every file in `image` under `dir`, recreating the directory tree.
///
/// Returns the number of files written.
///
/// # Errors
///
/// Returns an error if the image is not a RomFS, if an entry names a path component that would
/// escape `dir`, if a file's bounds fall outside the image, or if a directory or file cannot be
/// written.
pub fn romfs(image: &[u8], dir: &Path) -> Result<usize, RomFsError> {
    let romfs = RomFs::try_from_bytes(image).map_err(RomFsError::Parse)?;
    let root = romfs.root_dir().map_err(RomFsError::RootDir)?;

    write_dir(&root, dir)
}

/// Error returned by [`romfs`].
#[derive(Debug, thiserror::Error)]
pub enum RomFsError {
    /// The image is not a RomFS, or is truncated.
    #[error("failed to parse the RomFS image")]
    Parse(#[source] romfs::FromBytesError),
    /// The image parsed but its root directory could not be read.
    #[error("failed to read the RomFS root directory")]
    RootDir(#[source] romfs::RootDirError),
    /// An entry names something that would place a file outside the output directory.
    ///
    /// Extraction stops here rather than skipping the entry: an image carrying such a name is
    /// hostile or corrupt, and neither is worth continuing through.
    #[error("the image holds an unsafe entry name")]
    UnsafeName(#[source] UnsafeNameError),
    /// A file's bounds fall outside the image.
    ///
    /// Holds the entry that could not be read.
    #[error("failed to read '{name}' from the image")]
    ReadFile {
        /// Name of the entry.
        name: String,
        /// Why the bounds were rejected.
        #[source]
        source: romfs::FromBytesError,
    },
    /// A directory or file could not be written.
    #[error("failed to write the extracted tree")]
    Write(#[source] WriteError),
}

/// Write every file in `archive` into `dir`, which a PFS0 holds flat.
///
/// Returns the number of files written.
///
/// # Errors
///
/// Returns an error if the archive is not a PFS0, if an entry names a path component that would
/// escape `dir`, or if a file cannot be written.
pub fn partition(archive: &[u8], dir: &Path) -> Result<usize, PartitionError> {
    let pfs0 = Pfs0::try_from_bytes(archive).map_err(PartitionError::Parse)?;

    create_dir(dir).map_err(PartitionError::Write)?;

    let mut written = 0;
    for file in pfs0.files() {
        let name = safe_component(file.name()).map_err(PartitionError::UnsafeName)?;
        write_file(&dir.join(name), file.data()).map_err(PartitionError::Write)?;
        written += 1;
    }

    Ok(written)
}

/// Error returned by [`partition`].
#[derive(Debug, thiserror::Error)]
pub enum PartitionError {
    /// The archive is not a PFS0, or is truncated.
    #[error("failed to parse the PFS0 archive")]
    Parse(#[source] pfs0::FromBytesError),
    /// An entry names something that would place a file outside the output directory.
    #[error("the archive holds an unsafe entry name")]
    UnsafeName(#[source] UnsafeNameError),
    /// A file could not be written.
    #[error("failed to write the extracted files")]
    Write(#[source] WriteError),
}

/// Write `bytes` to `path`, replacing whatever was there.
///
/// # Errors
///
/// Returns an error if the parent directory cannot be created, or if the file cannot be written or
/// moved into place.
pub fn raw(bytes: &[u8], path: &Path) -> Result<(), WriteError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        create_dir(parent)?;
    }

    write_file(path, bytes)
}

/// Error returned by [`raw`], and carried by the three extraction functions above.
///
/// Shared rather than split per function because every one of them writes through the same two
/// steps and can return any of these three failures.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// A directory could not be created.
    ///
    /// Holds the path and the failure the filesystem reported.
    #[error("failed to create the directory '{}'", path.display())]
    CreateDir {
        /// The directory that could not be created.
        path: PathBuf,
        /// The failure the filesystem reported.
        #[source]
        source: std::io::Error,
    },
    /// A file could not be written.
    ///
    /// Holds the temporary path and the failure the filesystem reported. Nothing was moved into
    /// place, so the destination still holds whatever it held before.
    #[error("failed to write '{}'", path.display())]
    Write {
        /// The temporary path that could not be written.
        path: PathBuf,
        /// The failure the filesystem reported.
        #[source]
        source: std::io::Error,
    },
    /// A written file could not be moved into place.
    ///
    /// Holds the destination and the failure the filesystem reported. The temporary file is left
    /// beside it rather than removed, so nothing that was written is discarded.
    #[error("failed to move '{}' into place", path.display())]
    Rename {
        /// The destination that could not be reached.
        path: PathBuf,
        /// The failure the filesystem reported.
        #[source]
        source: std::io::Error,
    },
}

/// Write one directory's children under `path`, recursing into subdirectories.
fn write_dir(dir: &RomFsDir<'_>, path: &Path) -> Result<usize, RomFsError> {
    create_dir(path).map_err(RomFsError::Write)?;

    let mut written = 0;
    for entry in dir.entries() {
        match entry {
            RomFsEntry::Dir(child) => {
                let name = safe_component(child.name()).map_err(RomFsError::UnsafeName)?;
                written += write_dir(&child, &path.join(name))?;
            }
            RomFsEntry::File(file) => {
                let name = safe_component(file.name()).map_err(RomFsError::UnsafeName)?;
                let data = file.data().map_err(|err| RomFsError::ReadFile {
                    name: file.name().to_owned(),
                    source: err,
                })?;
                write_file(&path.join(name), data).map_err(RomFsError::Write)?;
                written += 1;
            }
        }
    }

    Ok(written)
}

/// The name `component` stands for, if it names one entry and nothing else.
///
/// # Errors
///
/// Returns an error for an empty name, for `.` and `..`, and for any name carrying a path
/// separator — each of which would resolve somewhere other than one child of the current directory.
fn safe_component(component: &str) -> Result<&str, UnsafeNameError> {
    if component.is_empty() {
        return Err(UnsafeNameError::Empty);
    }

    if component == "." || component == ".." {
        return Err(UnsafeNameError::Traversal {
            name: component.to_owned(),
        });
    }

    if component.contains('/') || component.contains('\\') || component.contains('\0') {
        return Err(UnsafeNameError::Separator {
            name: component.to_owned(),
        });
    }

    Ok(component)
}

/// Error returned by [`safe_component`].
#[derive(Debug, thiserror::Error)]
pub enum UnsafeNameError {
    /// The entry has no name.
    ///
    /// A name that is not valid UTF-8 also arrives here, because the reader renders one as empty.
    #[error("an entry has an empty name")]
    Empty,
    /// The entry names the current or parent directory.
    ///
    /// Holds the name. Joining it would step outside the directory being extracted into.
    #[error("the entry name '{name}' would escape the output directory")]
    Traversal {
        /// The rejected name.
        name: String,
    },
    /// The entry name carries a path separator or an interior NUL.
    ///
    /// Holds the name. An entry names one child, so a separator means the image is describing a
    /// path rather than a name.
    #[error("the entry name '{name}' is not a single path component")]
    Separator {
        /// The rejected name.
        name: String,
    },
}

/// Create `dir` and every parent it needs.
fn create_dir(dir: &Path) -> Result<(), WriteError> {
    std::fs::create_dir_all(dir).map_err(|err| WriteError::CreateDir {
        path: dir.to_path_buf(),
        source: err,
    })
}

/// Write `bytes` to `path` through a temporary file beside it.
///
/// The rename is what makes the write atomic: the destination either holds the previous file or the
/// complete new one, never a prefix of it.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), WriteError> {
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);

    std::fs::write(&temp, bytes).map_err(|err| WriteError::Write {
        path: temp.clone(),
        source: err,
    })?;

    std::fs::rename(&temp, path).map_err(|err| WriteError::Rename {
        path: path.to_path_buf(),
        source: err,
    })
}

#[cfg(test)]
mod tests {
    use super::{UnsafeNameError, raw, safe_component};

    #[test]
    fn safe_component_with_an_ordinary_name_returns_it() {
        //* Given
        let name = "main.npdm";

        //* When
        let result = safe_component(name);

        //* Then
        assert_eq!(result.expect("an ordinary name is safe"), "main.npdm");
    }

    #[test]
    fn safe_component_with_a_parent_reference_fails() {
        //* Given
        let name = "..";

        //* When
        let result = safe_component(name);

        //* Then
        assert!(matches!(result, Err(UnsafeNameError::Traversal { .. })));
    }

    #[test]
    fn safe_component_with_a_path_separator_fails() {
        //* Given
        // What a hostile image carries: a name that resolves outside the output directory.
        let name = "../../etc/passwd";

        //* When
        let result = safe_component(name);

        //* Then
        assert!(matches!(result, Err(UnsafeNameError::Separator { .. })));
    }

    #[test]
    fn safe_component_with_a_backslash_fails() {
        //* Given
        let name = "dir\\file";

        //* When
        let result = safe_component(name);

        //* Then
        assert!(matches!(result, Err(UnsafeNameError::Separator { .. })));
    }

    #[test]
    fn safe_component_with_an_empty_name_fails() {
        //* Given
        // The reader renders a name that is not valid UTF-8 as empty, so this covers that too.
        let name = "";

        //* When
        let result = safe_component(name);

        //* Then
        assert!(matches!(result, Err(UnsafeNameError::Empty)));
    }

    #[test]
    fn raw_with_a_missing_parent_directory_creates_it() {
        //* Given
        let dir = tempfile::tempdir().expect("a temp directory should be available");
        let path = dir.path().join("nested").join("section0.bin");

        //* When
        let result = raw(b"contents", &path);

        //* Then
        result.expect("the write should succeed");
        assert_eq!(
            std::fs::read(&path).expect("the file should exist"),
            b"contents"
        );
    }

    #[test]
    fn raw_over_an_existing_file_replaces_it() {
        //* Given
        // Re-running an extraction must land on the same result as running it once.
        let dir = tempfile::tempdir().expect("a temp directory should be available");
        let path = dir.path().join("section0.bin");
        raw(b"first", &path).expect("the first write should succeed");

        //* When
        let result = raw(b"second", &path);

        //* Then
        result.expect("the second write should succeed");
        assert_eq!(
            std::fs::read(&path).expect("the file should exist"),
            b"second"
        );
    }
}
