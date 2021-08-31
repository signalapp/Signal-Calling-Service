//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use calling_server::*;
use hex_literal::hex;
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, CryptoRng, Rng, SeedableRng};
use std::time::{Duration, SystemTime};

/// Generated DER from the sample private key in RFC 6979 A.2.5.
static SERVER_PRIVATE_KEY_DER: &[u8] = include_bytes!("dtls-server-private-key.der");
/// Client-provided entropy that matches the packet in seeds/dtls/certificate-with-prefixed-rng-seed
static CLIENT_RANDOM: [u8; 32] =
    hex!("c84bd1aeaa4d7456e6c30aa3d514feb9f33afce48cab77a53d83d7d0b4bdb0b7");
/// Client-provided fingerprint that matches the packet in seeds/dtls/certificate-with-prefixed-rng-seed
static CLIENT_FINGERPRINT: [u8; 32] =
    hex!("74daf1fa3bbd8705527b5045ba20348d626d9cf002a7b468c30faf600f40f5f4");
/// The timestamp that matches the packet in seeds/dtls/certificate-with-prefixed-rng-seed
static NOW_MILLIS: u64 = 1625082261580;

fn random_dtls_state(
    now: SystemTime,
    rng_seed: u64,
) -> (dtls::HandshakeState, impl Rng + CryptoRng) {
    // Make sure no one uses this RNG before HandshakeState::after_hello,
    // to make sure it's consistent with what's in seeds/dtls/certificate-with-prefixed-rng-seed.
    let mut rng = StdRng::seed_from_u64(rng_seed);
    // A seed of 0 was used to generate seeds/dtls/certificate-with-prefixed-rng-seed,
    // so we need to make sure that that seed tests certificate packet parsing.
    if rng_seed & 1 == 0 {
        let state = dtls::HandshakeState::after_hello(CLIENT_RANDOM, now, &mut rng);
        (state, rng)
    } else {
        (dtls::HandshakeState::new(), rng)
    }
}

fuzz_target!(|input: (u64, &[u8])| {
    let (seed, data) = input;
    if dtls::looks_like_packet(data) {
        let now = SystemTime::UNIX_EPOCH + Duration::from_millis(NOW_MILLIS);
        let (mut state, mut rng) = random_dtls_state(now, seed);
        state.process_packet(
            data,
            &[],
            SERVER_PRIVATE_KEY_DER,
            &CLIENT_FINGERPRINT,
            now,
            &mut rng,
        );
    }
});
