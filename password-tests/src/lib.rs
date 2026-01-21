//! Password derivation tests for Xiaomi filter reset.
//!
//! This is a separate crate that can run tests on the host machine
//! without requiring the flipperzero-sys embedded target.
//!
//! # Running Tests
//!
//! ```bash
//! cd password-tests && cargo test
//! ```

use sha1::{Digest, Sha1};

/// Derives the 4-byte NTAG password from a 7-byte UID.
///
/// This is the same algorithm as in the main crate's password module.
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

/// Formats a byte slice as a colon-separated hex string into a fixed buffer.
pub fn format_hex_colons(bytes: &[u8], buf: &mut [u8]) -> usize {
    const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
    let mut pos = 0;

    for (i, &byte) in bytes.iter().enumerate() {
        if i > 0 && pos < buf.len() {
            buf[pos] = b':';
            pos += 1;
        }
        if pos + 1 < buf.len() {
            buf[pos] = HEX_CHARS[(byte >> 4) as usize];
            buf[pos + 1] = HEX_CHARS[(byte & 0x0F) as usize];
            pos += 2;
        }
    }
    pos
}

/// Formats a byte slice as a contiguous hex string (no separators).
pub fn format_hex(bytes: &[u8], buf: &mut [u8]) -> usize {
    const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
    let mut pos = 0;

    for &byte in bytes.iter() {
        if pos + 1 < buf.len() {
            buf[pos] = HEX_CHARS[(byte >> 4) as usize];
            buf[pos + 1] = HEX_CHARS[(byte & 0x0F) as usize];
            pos += 2;
        }
    }
    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test case from unethical.info:
    /// UID: 04A03CAA1E7080
    /// SHA-1: bcaf806333ccf720cd441a167f914fbe6ea4a513
    /// First byte (seed): 0xBC = 188
    /// Indices: 188%20=8, (188+5)%20=13, (188+13)%20=1, (188+17)%20=5
    /// Password bytes: hash[8]=CD, hash[13]=91, hash[1]=AF, hash[5]=CC
    /// Password: CD91AFCC
    #[test]
    fn test_derive_password_unethical_info_example() {
        let uid: [u8; 7] = [0x04, 0xA0, 0x3C, 0xAA, 0x1E, 0x70, 0x80];
        let password = derive_password(&uid);
        assert_eq!(password, [0xCD, 0x91, 0xAF, 0xCC]);
    }

    #[test]
    fn test_sha1_hash_intermediate() {
        // Verify the intermediate SHA-1 hash matches expected value
        let uid: [u8; 7] = [0x04, 0xA0, 0x3C, 0xAA, 0x1E, 0x70, 0x80];
        let hash = Sha1::digest(&uid);

        // Expected: bcaf806333ccf720cd441a167f914fbe6ea4a513
        assert_eq!(hash[0], 0xBC); // First byte (seed)
        assert_eq!(hash[1], 0xAF);
        assert_eq!(hash[5], 0xCC);
        assert_eq!(hash[8], 0xCD);
        assert_eq!(hash[13], 0x91);
    }

    #[test]
    fn test_format_hex_colons() {
        let uid: [u8; 7] = [0x04, 0xA0, 0x3C, 0xAA, 0x1E, 0x70, 0x80];
        let mut buf = [0u8; 32];
        let len = format_hex_colons(&uid, &mut buf);

        assert_eq!(&buf[..len], b"04:A0:3C:AA:1E:70:80");
    }

    #[test]
    fn test_format_hex() {
        let password: [u8; 4] = [0xCD, 0x91, 0xAF, 0xCC];
        let mut buf = [0u8; 16];
        let len = format_hex(&password, &mut buf);

        assert_eq!(&buf[..len], b"CD91AFCC");
    }

    #[test]
    fn test_password_index_calculation() {
        // Verify the index calculation manually
        let seed: usize = 0xBC; // 188

        assert_eq!(seed % 20, 8);
        assert_eq!((seed + 5) % 20, 13);
        assert_eq!((seed + 13) % 20, 1);
        assert_eq!((seed + 17) % 20, 5);
    }
}
