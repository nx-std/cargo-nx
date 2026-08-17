//! Turning the archives the console loads back into the parts they were built from.
//!
//! The inverse of [`crate::pack`], and the same split of concerns: nothing here touches a
//! filesystem, and nothing here decides what to do with what it recovers. Bytes in, bytes out.
//!
//! Reading runs the packing steps backwards, and the order is forced the same way. An NCA's header
//! is ciphertext, so no field in it — not the section table, not the length — can be believed until
//! the header key has been applied; only then is there a key area to unwrap, and only then a section
//! key to decrypt sections with. [`nca::decrypt`] performs that sequence; [`verify`] checks the
//! hashes and the signature over the result.

pub mod nca;
pub mod verify;
