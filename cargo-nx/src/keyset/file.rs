//! Finding and reading the keyset file.
//!
//! A caller who names a file gets that file or an error. A caller who names none has the four
//! conventional names tried in the working directory and then the per-user location, in that order,
//! so a project that ships its own keyset wins over the one installed for the account.

use std::path::{Path, PathBuf};

use crate::keyset::{Keyset, ParseKeysetError};

/// Names a keyset is conventionally stored under in a project directory, in search order.
const CONVENTIONAL_NAMES: &[&str] = &["keys.dat", "keys.txt", "keys.ini", "prod.keys"];

/// Read and parse the keyset at `explicit`, or at the first conventional location that exists.
///
/// # Errors
///
/// Returns an error if a named file cannot be read, if no conventional location holds one, or if the
/// file that was found is not a keyset.
pub fn load(explicit: Option<&Path>) -> Result<Keyset, LoadError> {
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => search().ok_or_else(|| LoadError::NotFound {
            searched: search_paths(),
        })?,
    };

    let text = std::fs::read_to_string(&path).map_err(|err| LoadError::Read {
        path: path.clone(),
        source: err,
    })?;

    text.parse()
        .map_err(|err| LoadError::Parse { path, source: err })
}

/// The first conventional location that holds a readable file.
fn search() -> Option<PathBuf> {
    search_paths().into_iter().find(|path| path.is_file())
}

/// Every location searched when the caller names no keyset, in order.
fn search_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = CONVENTIONAL_NAMES.iter().map(PathBuf::from).collect();

    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        paths.push(PathBuf::from(home).join(".switch").join("prod.keys"));
    }

    paths
}

/// Error returned by [`load`].
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// No conventional location holds a keyset.
    ///
    /// Holds every location that was searched.
    #[error(
        "no keyset found; searched {}",
        searched.iter().map(|path| path.display().to_string()).collect::<Vec<_>>().join(", ")
    )]
    NotFound {
        /// Every location that was searched.
        searched: Vec<PathBuf>,
    },
    /// The keyset file could not be read.
    ///
    /// Holds the path and the failure the filesystem reported.
    #[error("failed to read the keyset '{}'", path.display())]
    Read {
        /// The path that could not be read.
        path: PathBuf,
        /// The failure the filesystem reported.
        #[source]
        source: std::io::Error,
    },
    /// The file was read but is not a keyset.
    ///
    /// Holds the path and why it was rejected.
    #[error("failed to parse the keyset '{}'", path.display())]
    Parse {
        /// The path that was rejected.
        path: PathBuf,
        /// Why it was rejected.
        #[source]
        source: ParseKeysetError,
    },
}
