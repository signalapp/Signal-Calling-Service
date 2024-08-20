//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto;

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes128,
};
use zeroize::Zeroizing;

pub const SRTP_KEY_LEN: usize = 16;
pub const SRTP_SALT_LEN: usize = 12;
pub const SRTP_IV_LEN: usize = 12;
pub const SRTP_AUTH_TAG_LEN: usize = 16;

pub type Key = Zeroizing<[u8; SRTP_KEY_LEN]>;
pub type Salt = [u8; SRTP_SALT_LEN];
pub type Iv = [u8; SRTP_IV_LEN];
// In the order [client_key, client_salt, server_key, server_salt]
pub const MASTER_KEY_MATERIAL_LEN: usize =
    SRTP_KEY_LEN + SRTP_SALT_LEN + SRTP_KEY_LEN + SRTP_SALT_LEN;
pub type MasterKeyMaterial = Zeroizing<[u8; MASTER_KEY_MATERIAL_LEN]>;

pub fn new_master_key_material() -> MasterKeyMaterial {
    MasterKeyMaterial::new([0u8; MASTER_KEY_MATERIAL_LEN])
}

#[derive(Debug, Clone)]
pub struct KeyAndSalt {
    pub key: Key,
    pub salt: Salt,
}

#[derive(Debug, Clone)]
pub struct KeysAndSalts {
    pub rtp: KeyAndSalt,
    pub rtcp: KeyAndSalt,
}

impl KeysAndSalts {
    // Returns (client, server)
    pub fn derive_client_and_server_from_master_key_material(
        master_key_material: &MasterKeyMaterial,
    ) -> (KeysAndSalts, KeysAndSalts) {
        let client_key: Key =
            Zeroizing::new(master_key_material[..SRTP_KEY_LEN].try_into().unwrap());
        let client_salt: Salt = master_key_material[SRTP_KEY_LEN..][..SRTP_SALT_LEN]
            .try_into()
            .unwrap();
        let server_key: Key = Zeroizing::new(
            master_key_material[SRTP_KEY_LEN..][SRTP_SALT_LEN..][..SRTP_KEY_LEN]
                .try_into()
                .unwrap(),
        );
        let server_salt: Salt = master_key_material[SRTP_KEY_LEN..][SRTP_SALT_LEN..]
            [SRTP_KEY_LEN..][..SRTP_SALT_LEN]
            .try_into()
            .unwrap();
        let client = Self::derive_from_master(&KeyAndSalt {
            key: client_key,
            salt: client_salt,
        });
        let server = Self::derive_from_master(&KeyAndSalt {
            key: server_key,
            salt: server_salt,
        });
        (client, server)
    }

    // See https://github.com/cisco/libsrtp/blob/master/crypto/cipher/aes_icm_ossl.c#L278
    // and https://github.com/cisco/libsrtp/blob/master/srtp/srtp.c#L632
    // and https://tools.ietf.org/html/rfc3711#section-4.3.2 for label constants.
    pub fn derive_from_master(master: &KeyAndSalt) -> Self {
        Self {
            rtp: KeyAndSalt {
                key: Self::derive_key_from_master(master, 0),
                salt: Self::derive_salt_from_master(master, 2),
            },
            rtcp: KeyAndSalt {
                key: Self::derive_key_from_master(master, 3),
                salt: Self::derive_salt_from_master(master, 5),
            },
        }
    }

    fn derive_key_from_master(master: &KeyAndSalt, label: u8) -> Key {
        let cipher = Aes128::new(GenericArray::from_slice(&master.key[..]));
        let mut derived = Zeroizing::new([0; SRTP_KEY_LEN]);
        derived[..SRTP_SALT_LEN].copy_from_slice(&master.salt);
        derived[7] ^= label;
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut derived[..]));
        derived
    }

    fn derive_salt_from_master(master: &KeyAndSalt, label: u8) -> Salt {
        Self::derive_key_from_master(master, label)[..SRTP_SALT_LEN]
            .try_into()
            .unwrap()
    }
}

pub fn rtp_iv(ssrc: u32, seqnum: u64, salt: &[u8; 12]) -> [u8; 12] {
    // We're trying to XOR the following 12-byte value (from RFC 7714 section 8.1) with the salt.
    //     0  0  0  0  0  0  0  0  0  0  1  1
    //     0  1  2  3  4  5  6  7  8  9  0  1
    //   +--+--+--+--+--+--+--+--+--+--+--+--+
    //   |00|00|    SSRC   |     ROC   | SEQ |
    //   +--+--+--+--+--+--+--+--+--+--+--+--+

    // This is bytes 0-7. Notice that the ROC part of the seqnum gets split.
    let mut combined_lower = ssrc as u64;
    combined_lower <<= 16;
    combined_lower |= (seqnum >> 32) & 0xFFFF;
    let salt_lower = u64::from_be_bytes(salt[..8].try_into().unwrap());
    let result_lower = (salt_lower ^ combined_lower).to_be_bytes();

    // This is bytes 8-11.
    let salt_upper = u32::from_be_bytes(salt[8..].try_into().unwrap());
    let result_upper = (salt_upper ^ (seqnum as u32)).to_be_bytes();

    [
        result_lower[0],
        result_lower[1],
        result_lower[2],
        result_lower[3],
        result_lower[4],
        result_lower[5],
        result_lower[6],
        result_lower[7],
        result_upper[0],
        result_upper[1],
        result_upper[2],
        result_upper[3],
    ]
}

/// Creates a test key by repeating the byte
#[cfg(test)]
pub fn key_from(seed: u8) -> Key {
    [seed; SRTP_KEY_LEN].into()
}

/// Creates a test salt by repeating the byte
#[cfg(test)]
pub fn salt_from(seed: u8) -> Salt {
    [seed; SRTP_SALT_LEN]
}

/// returns (decrypt, encrypt) pair of keys
#[cfg(test)]
pub fn new_srtp_keys(seed: u8) -> (KeysAndSalts, KeysAndSalts) {
    let decrypt = KeysAndSalts {
        rtp: KeyAndSalt {
            key: key_from(seed + 1),
            salt: salt_from(seed + 2),
        },
        rtcp: KeyAndSalt {
            key: key_from(seed + 3),
            salt: salt_from(seed + 4),
        },
    };
    let encrypt = KeysAndSalts {
        rtp: KeyAndSalt {
            key: key_from(seed + 5),
            salt: salt_from(seed + 6),
        },
        rtcp: KeyAndSalt {
            key: key_from(seed + 7),
            salt: salt_from(seed + 8),
        },
    };
    (decrypt, encrypt)
}

#[cfg(test)]
mod test {
    use super::super::types::*;
    use super::*;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_rtp_iv() {
        // This was the original implementation of rtp_iv, which very closely matches RFC 7714
        // but generated poor assembly.
        #[allow(clippy::identity_op)]
        fn reference(ssrc: Ssrc, seqnum: FullSequenceNumber, salt: &Salt) -> Iv {
            let ssrc = ssrc.to_be_bytes();
            let seqnum = seqnum.to_be_bytes();
            [
                0 ^ salt[0],
                0 ^ salt[1],
                ssrc[0] ^ salt[2],
                ssrc[1] ^ salt[3],
                ssrc[2] ^ salt[4],
                ssrc[3] ^ salt[5],
                // Treat as a u48.  In other words, the ROC then the truncated seqnum
                seqnum[2] ^ salt[6],
                seqnum[3] ^ salt[7],
                seqnum[4] ^ salt[8],
                seqnum[5] ^ salt[9],
                seqnum[6] ^ salt[10],
                seqnum[7] ^ salt[11],
            ]
        }

        let mut rng = thread_rng();
        for _ in 0..100 {
            let ssrc = rng.gen();
            let seqnum = rng.gen::<u64>() & 0x0000_FFFF_FFFF_FFFF; // 48 bits only
            let salt = rng.gen();

            assert_eq!(
                reference(ssrc, seqnum, &salt),
                rtp_iv(ssrc, seqnum, &salt),
                "{:x} {:x} {}",
                ssrc,
                seqnum,
                hex::encode(salt),
            );
        }
    }
}
