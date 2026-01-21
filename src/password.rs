//! Xiaomi air purifier filter password derivation.
//!
//! Implements the SHA-1 based password generation algorithm used by Xiaomi
//! to protect the NFC tags on their air purifier filters.
//!
//! # Algorithm
//!
//! 1. Compute SHA-1 hash of the 7-byte UID
//! 2. Use first byte of hash as index seed
//! 3. Extract 4 password bytes at computed indices:
//!    - seed % 20
//!    - (seed + 5) % 20
//!    - (seed + 13) % 20
//!    - (seed + 17) % 20
//!
//! # Test Vector (from unethical.info)
//!
//! ```text
//! UID: 04:A0:3C:AA:1E:70:80
//! SHA-1: bcaf806333ccf720cd441a167f914fbe6ea4a513
//! First byte (seed): 0xBC = 188
//! Indices: 188%20=8, (188+5)%20=13, (188+13)%20=1, (188+17)%20=5
//! Password bytes: hash[8]=CD, hash[13]=91, hash[1]=AF, hash[5]=CC
//! Password: CD:91:AF:CC
//! ```
//!
//! # References
//!
//! - <https://unethical.info/2024/01/24/hacking-my-air-purifier/>

use sha1::{Digest, Sha1};

/// Derives the 4-byte NTAG password from a 7-byte UID.
///
/// # Arguments
///
/// * `uid` - The 7-byte UID read from the NTAG tag
///
/// # Returns
///
/// A 4-byte array containing the derived password
pub fn derive_password(uid: &[u8; 7]) -> [u8; 4] {
    let hash = Sha1::digest(uid);
    let seed = hash[0] as usize;

    [
        hash[seed % 20],
        hash[(seed + 5) % 20],
        hash[(seed + 13) % 20],
        hash[(seed + 17) % 20],
    ]
}
