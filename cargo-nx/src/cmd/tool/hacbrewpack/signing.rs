//! The RSA-2048 keypair that makes a program NCA's second signature verify.
//!
//! An NCA header carries two signatures. The first is checked against a modulus built into the
//! console and cannot be produced here. The second is checked against the public key stored in the
//! program's own NPDM, which means a title that supplies both halves of a keypair satisfies it: the
//! public key is patched into the NPDM's ACID, and the private key signs the header.
//!
//! The keypair below is therefore not a secret and is not meant to be one. It authenticates nothing
//! — it only closes a loop the console checks internally, and every title built by this tool shares
//! it. Nothing about it is console-derived.
//!
//! Both signatures cover the `0x200` bytes of the header starting at its magic, not the header as a
//! whole, so signing happens after every field in that range is final and before the header is
//! encrypted.

use rsa::{
    RsaPrivateKey,
    pkcs1::DecodeRsaPrivateKey as _,
    pss::SigningKey,
    signature::{RandomizedSigner as _, SignatureEncoding as _},
};
use sha2::Sha256;

/// Bytes in an RSA-2048 signature, and in the modulus that verifies it.
pub const SIGNATURE_SIZE: usize = 0x100;

/// The private half, as PKCS#1 PEM.
const PRIVATE_KEY_PEM: &str = include_str!("signing_key.pem");

/// The public modulus, big-endian, as the ACID stores it.
///
/// Kept as bytes rather than derived from [`PRIVATE_KEY_PEM`] at every call: this is what gets
/// written into an NPDM, and the ACID expects exactly these `0x100` bytes with no leading-zero
/// trimming.
const PUBLIC_MODULUS: [u8; SIGNATURE_SIZE] = [
    0xbd, 0x54, 0x73, 0xb7, 0xef, 0x26, 0x13, 0xba, 0x04, 0xe1, 0x19, 0x26, 0x4a, 0x1d, 0xf0, 0xb3,
    0x80, 0x86, 0x94, 0x18, 0xfb, 0xba, 0x11, 0xe4, 0x7f, 0x00, 0xa9, 0x3c, 0x5b, 0x27, 0xe1, 0x33,
    0x55, 0x74, 0xb4, 0x68, 0x61, 0x86, 0x35, 0xee, 0x34, 0x18, 0x59, 0x3b, 0x5c, 0x39, 0x83, 0xcc,
    0x70, 0x7c, 0x70, 0x52, 0x98, 0x09, 0xca, 0xca, 0x46, 0x37, 0xc4, 0x06, 0x5c, 0x49, 0x09, 0xa9,
    0x8f, 0x23, 0x20, 0xbb, 0xf6, 0x78, 0xed, 0x23, 0x04, 0x6b, 0x60, 0xec, 0x1a, 0xf6, 0x69, 0xf5,
    0x01, 0xa7, 0xaf, 0xf1, 0x04, 0xe3, 0x13, 0xd9, 0x19, 0x58, 0x55, 0x7e, 0x87, 0xe1, 0xad, 0x54,
    0x03, 0x5f, 0x47, 0xce, 0x67, 0x27, 0xf9, 0x3d, 0x61, 0x74, 0x3c, 0x12, 0xea, 0x80, 0x58, 0xa6,
    0x2f, 0x2b, 0x25, 0x29, 0xb4, 0xfa, 0xaf, 0xb2, 0x07, 0x7e, 0x1d, 0xb9, 0xe3, 0x64, 0x56, 0xc9,
    0x38, 0x78, 0xa6, 0xe3, 0x08, 0xd3, 0x4a, 0x16, 0x2f, 0x97, 0x83, 0x23, 0x41, 0x8b, 0x8d, 0x5d,
    0xe7, 0xb4, 0x8f, 0x0a, 0xb9, 0x1c, 0x9b, 0xff, 0x6d, 0x91, 0xa8, 0x11, 0xa2, 0xb1, 0x3c, 0xbc,
    0xb7, 0x05, 0x3d, 0xc5, 0xdc, 0x60, 0xe8, 0xdd, 0x5c, 0x7d, 0xcb, 0xe1, 0x74, 0xd7, 0xab, 0xbb,
    0x31, 0xc7, 0x2b, 0x40, 0x23, 0xae, 0x9e, 0xad, 0xf4, 0x9c, 0xe1, 0x7b, 0xa7, 0x92, 0x82, 0xe2,
    0x7d, 0xc6, 0xdf, 0x30, 0xe0, 0x77, 0x82, 0x31, 0x82, 0xa1, 0x0b, 0x3a, 0x19, 0xf6, 0xa2, 0x01,
    0x4d, 0xd3, 0xc3, 0x17, 0xb0, 0x43, 0xb8, 0x5d, 0xa2, 0xab, 0xe3, 0xe4, 0x69, 0xbd, 0x57, 0x21,
    0xea, 0xcd, 0xe0, 0xc5, 0xe6, 0x65, 0x13, 0x96, 0x67, 0x9d, 0xd8, 0x8e, 0xa6, 0xe0, 0x42, 0xf1,
    0x6d, 0x5d, 0x5b, 0xd2, 0x55, 0x20, 0xb9, 0x1e, 0x59, 0x13, 0x3c, 0x17, 0xc2, 0x25, 0x56, 0xc7,
];

/// The public modulus to patch into an NPDM's ACID, so the header signature below verifies.
pub fn acid_public_key() -> &'static [u8; SIGNATURE_SIZE] {
    &PUBLIC_MODULUS
}

/// Sign `data` with RSA-2048-PSS over SHA-256.
///
/// PSS is randomised, so two signatures over the same header differ. That is the scheme the console
/// checks and not a choice available here, and it is the one thing in a build that is not
/// reproducible byte for byte.
///
/// # Errors
///
/// Returns an error if the built-in key cannot be parsed or the signature cannot be produced.
/// Neither depends on the input, so a failure here means the build is broken rather than the title.
pub fn sign_header(data: &[u8]) -> Result<[u8; SIGNATURE_SIZE], SignError> {
    let private_key =
        RsaPrivateKey::from_pkcs1_pem(PRIVATE_KEY_PEM).map_err(SignError::ParseKey)?;
    let signing_key = SigningKey::<Sha256>::new(private_key);

    let signature = signing_key
        .sign_with_rng(&mut rand::thread_rng(), data)
        .to_bytes();

    signature
        .as_ref()
        .try_into()
        .map_err(|_| SignError::UnexpectedLength {
            length: signature.len(),
        })
}

/// Error returned by [`sign_header`].
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The built-in private key could not be parsed.
    #[error("the built-in signing key could not be parsed")]
    ParseKey(#[source] rsa::pkcs1::Error),
    /// The signature is not the size an RSA-2048 signature must be.
    ///
    /// Holds the length that was produced.
    #[error("produced a {length}-byte signature, expected {SIGNATURE_SIZE}")]
    UnexpectedLength {
        /// The length that was produced.
        length: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::{SIGNATURE_SIZE, acid_public_key, sign_header};

    #[test]
    fn sign_header_produces_a_full_width_signature() {
        //* Given
        let header = [0x42u8; 0x200];

        //* When
        let signature = sign_header(&header).expect("the built-in key should sign");

        //* Then
        assert_eq!(signature.len(), SIGNATURE_SIZE);
    }

    #[test]
    fn sign_header_produces_a_signature_the_patched_public_key_verifies() {
        //* Given
        // The whole point of the pair: what the NPDM advertises must verify what signs the header.
        let header = [0x42u8; 0x200];
        let signature = sign_header(&header).expect("the built-in key should sign");

        //* When
        let modulus = rsa::BigUint::from_bytes_be(acid_public_key());
        let public_key = rsa::RsaPublicKey::new(modulus, rsa::BigUint::from(65537u32))
            .expect("the built-in modulus should form a public key");
        let verifying_key = rsa::pss::VerifyingKey::<sha2::Sha256>::new(public_key);
        let result = rsa::signature::Verifier::verify(
            &verifying_key,
            &header,
            &rsa::pss::Signature::try_from(signature.as_slice())
                .expect("a 0x100-byte signature should convert"),
        );

        //* Then
        assert!(
            result.is_ok(),
            "the console checks the header against exactly this key"
        );
    }
}
