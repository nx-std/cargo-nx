//! The AES modes the console's containers are encrypted with.
//!
//! Three modes, each used in exactly one place: ECB wraps a key area and derives one key from
//! another, CTR encrypts a section's contents, and XTS encrypts an NCA header. None of them is a
//! general-purpose encryption API — every function here takes the key as a fixed-size array and the
//! buffer it transforms in place, because that is the shape the formats need.
//!
//! The XTS variant is not the one the standard describes. Nintendo numbers its sectors with a
//! big-endian tweak where the specification uses a little-endian one, so [`aes_xts_encrypt`] builds
//! the tweak itself rather than taking the crate's default.

use aes::{
    Aes128,
    cipher::{
        Array, BlockCipherEncrypt as _, KeyInit as _, KeyIvInit as _, StreamCipher as _,
        consts::U16,
    },
};

/// AES-128 in counter mode, big-endian counter, which is what an NCA section uses.
type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// Encrypt `data` in place with AES-128 in ECB mode.
///
/// ECB is the right mode in the two places it is used — wrapping a key area and deriving one key
/// from another — because each block is an independent key, not a message with structure to hide.
///
/// # Panics
///
/// Panics if `data` is not a whole number of 16-byte blocks. Every caller passes a key area or a
/// key, both of which are.
pub fn aes_ecb_encrypt(key: &[u8; 0x10], data: &mut [u8]) {
    assert_eq!(
        data.len() % 0x10,
        0,
        "ECB transforms whole blocks, and every caller passes key material"
    );

    let cipher = Aes128::new(&Array::from(*key));
    for block in data.chunks_exact_mut(0x10) {
        let mut cell = Array::<u8, U16>::default();
        cell.copy_from_slice(block);
        cipher.encrypt_block(&mut cell);
        block.copy_from_slice(&cell);
    }
}

/// Decrypt `data` in place with AES-128 in ECB mode.
///
/// The inverse of [`aes_ecb_encrypt`], used by the key derivation chain: the console's key sources
/// are decrypted rather than encrypted to arrive at the keys they seed.
///
/// # Panics
///
/// Panics if `data` is not a whole number of 16-byte blocks.
pub fn aes_ecb_decrypt(key: &[u8; 0x10], data: &mut [u8]) {
    assert_eq!(
        data.len() % 0x10,
        0,
        "ECB transforms whole blocks, and every caller passes key material"
    );

    let cipher = Aes128::new(&Array::from(*key));
    for block in data.chunks_exact_mut(0x10) {
        let mut cell = Array::<u8, U16>::default();
        cell.copy_from_slice(block);
        aes::cipher::BlockCipherDecrypt::decrypt_block(&cipher, &mut cell);
        block.copy_from_slice(&cell);
    }
}

/// Encrypt `data` in place with AES-128-CTR, starting from `counter`.
///
/// CTR is its own inverse, so this decrypts as well. `counter` must be the counter for the first
/// byte of `data`; [`nx_object::write::nca::PlainNca::ctr_sections`] derives it from the section's
/// position in the file.
pub fn aes_ctr_apply(key: &[u8; 0x10], counter: &[u8; 0x10], data: &mut [u8]) {
    let mut cipher = Aes128Ctr::new(&Array::from(*key), &Array::from(*counter));
    cipher.apply_keystream(data);
}

/// Encrypt `data` in place with AES-128-XTS, using the console's sector numbering.
///
/// `key` is the two XTS keys concatenated: the first sixteen bytes encrypt, the second sixteen build
/// the tweak. Sectors are numbered from zero and are `sector_size` bytes each.
///
/// # Panics
///
/// Panics if `data` is not a whole number of sectors. XTS without ciphertext stealing cannot encrypt
/// a partial one, and the only caller passes a `0xC00`-byte header in `0x200`-byte sectors.
pub fn aes_xts_encrypt(key: &[u8; 0x20], data: &mut [u8], sector_size: usize) {
    assert_eq!(
        data.len() % sector_size,
        0,
        "XTS here has no ciphertext stealing, so a partial sector cannot be encrypted"
    );

    // Split rather than sliced: an infallible copy leaves no error to discard, and a fallback key
    // here would silently encrypt the header with the wrong one.
    let mut data_half = [0u8; 0x10];
    let mut tweak_half = [0u8; 0x10];
    data_half.copy_from_slice(&key[..0x10]);
    tweak_half.copy_from_slice(&key[0x10..]);

    let data_key = Aes128::new(&Array::from(data_half));
    let tweak_key = Aes128::new(&Array::from(tweak_half));
    let xts = xts_mode::Xts128::new(data_key, tweak_key);

    xts.encrypt_area(data, sector_size, 0, nintendo_tweak);
}

/// Decrypt `data` in place with AES-128-XTS, using the console's sector numbering.
///
/// The inverse of [`aes_xts_encrypt`], and the first step in reading an archive: an NCA header is
/// ciphertext on disk, so nothing in it can be trusted — including its length fields — until this
/// has run.
///
/// # Panics
///
/// Panics if `data` is not a whole number of sectors. XTS without ciphertext stealing cannot decrypt
/// a partial one, and the only caller passes a `0xC00`-byte header in `0x200`-byte sectors.
pub fn aes_xts_decrypt(key: &[u8; 0x20], data: &mut [u8], sector_size: usize) {
    assert_eq!(
        data.len() % sector_size,
        0,
        "XTS here has no ciphertext stealing, so a partial sector cannot be decrypted"
    );

    // Split rather than sliced, for the same reason as in `aes_xts_encrypt`: an infallible copy
    // leaves no error to discard, and a fallback key here would silently produce noise.
    let mut data_half = [0u8; 0x10];
    let mut tweak_half = [0u8; 0x10];
    data_half.copy_from_slice(&key[..0x10]);
    tweak_half.copy_from_slice(&key[0x10..]);

    let data_key = Aes128::new(&Array::from(data_half));
    let tweak_key = Aes128::new(&Array::from(tweak_half));
    let xts = xts_mode::Xts128::new(data_key, tweak_key);

    xts.decrypt_area(data, sector_size, 0, nintendo_tweak);
}

/// The tweak for `sector`, written big-endian.
///
/// The XTS specification numbers sectors little-endian; the console does not, and an image built
/// with the specification's tweak decrypts to noise on hardware.
fn nintendo_tweak(sector: u128) -> Array<u8, U16> {
    Array::from(sector.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::{
        aes_ctr_apply, aes_ecb_decrypt, aes_ecb_encrypt, aes_xts_decrypt, aes_xts_encrypt,
        nintendo_tweak,
    };

    #[test]
    fn aes_ecb_decrypt_undoes_aes_ecb_encrypt() {
        //* Given
        let key = [0x2Bu8; 0x10];
        let plaintext = [0x99u8; 0x40];
        let mut buffer = plaintext;

        //* When
        aes_ecb_encrypt(&key, &mut buffer);
        let ciphertext = buffer;
        aes_ecb_decrypt(&key, &mut buffer);

        //* Then
        assert_ne!(ciphertext, plaintext, "encryption should change the bytes");
        assert_eq!(buffer, plaintext, "decryption should undo it");
    }

    #[test]
    fn aes_ctr_apply_returns_the_input_when_applied_twice() {
        //* Given
        let key = [0x11u8; 0x10];
        let counter = [0u8; 0x10];
        let plaintext = [0x77u8; 0x30];
        let mut buffer = plaintext;

        //* When
        aes_ctr_apply(&key, &counter, &mut buffer);
        let ciphertext = buffer;
        aes_ctr_apply(&key, &counter, &mut buffer);

        //* Then
        assert_ne!(ciphertext, plaintext, "encryption should change the bytes");
        assert_eq!(buffer, plaintext, "CTR is its own inverse");
    }

    #[test]
    fn nintendo_tweak_numbers_sectors_big_endian() {
        //* Given
        let sector = 1u128;

        //* When
        let tweak = nintendo_tweak(sector);

        //* Then
        assert_eq!(
            tweak.as_slice(),
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "the console puts the sector index in the last byte, not the first"
        );
    }

    #[test]
    fn aes_xts_decrypt_undoes_aes_xts_encrypt() {
        //* Given
        let key = [0x5Cu8; 0x20];
        let plaintext = [0xA5u8; 0xC00];
        let mut buffer = plaintext;

        //* When
        aes_xts_encrypt(&key, &mut buffer, 0x200);
        let ciphertext = buffer;
        aes_xts_decrypt(&key, &mut buffer, 0x200);

        //* Then
        assert_ne!(ciphertext, plaintext, "encryption should change the bytes");
        assert_eq!(buffer, plaintext, "decryption should undo it");
    }

    #[test]
    fn aes_xts_encrypt_gives_each_sector_its_own_tweak() {
        //* Given
        // Two identical sectors: distinct ciphertext is what proves the tweak advanced.
        let key = [0x5Cu8; 0x20];
        let mut buffer = [0xA5u8; 0x400];

        //* When
        aes_xts_encrypt(&key, &mut buffer, 0x200);

        //* Then
        assert_ne!(
            &buffer[..0x200],
            &buffer[0x200..],
            "identical sectors must not encrypt identically"
        );
    }
}
