//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

// We use DTLS to do a Diffie-Helman key exchange in order to be backwards
// compatible with existing clients.
// But since it's such a complicated way of doing so, the plan is to replace it
// with a simple mechanism over signaling, similar to Signal 1:1 calls.
// (see https://github.com/signalapp/ringrtc/blob/4ec87d14515b4b89945ebddbfd5a5d799b0bd8f8/src/rust/src/core/connection.rs#L1880)
// After all clients have been updated to use the new mechanism, the plan is to
// delete this file.

//! Implementation of DTLS, defined by the following RFCs:
// DTLS 1.2: https://tools.ietf.org/html/rfc6347
// TLS 1.2: https://tools.ietf.org/html/rfc5246
// DTLS-SRTP: https://tools.ietf.org/html/rfc5764 and https://tools.ietf.org/html/rfc5705
// DTLS for WebRTC: https://tools.ietf.org/html/draft-ietf-rtcweb-security-arch-20
// ExtendedMasterSecret: https://tools.ietf.org/html/rfc7627
//
// The handshake looks like this:
// 1.  Client->Server: ClientHello(version, random, cipher_suites, elliptical_curves, elliptical_curve_point_formats, srtp_profiles)
// 2.  (optional) Server->Client: HelloVerifyRequest(cookie)
// 3.  (optional) Client->Server: Same ClientHello as #1, but with cookie from HelloVerifyRequest
// 4.  Server->Client:
//       ServerHello(version, random, cipher_suite, elliptical_curves, elliptical_curve_point_formats, srtp_profiles)
//     + Certificate(certificate_der)
//     + ServeKeyExchange(named_curve, dh_public_key_sec1, hash_algorithm, signature_algorithm, signature_der)
//       (signature_der is a signature of the random values plus the named_curve and dh_public_key_sec1
//        and is signed with the private key paired to the public key in the certificate)
//     + CertificateRequest(certificate_types, signature_algorithms)
//     + ServerHelloDone
// 5.  Client->Server:
//       Certificate(certificate_der)
//     + ClientKeyExchange(dh_public_key_sec1)
//     + CertificateVerify(hash_algorithm, signature_algorithm, signature_der)
//       (signature_der is a signature of all the messages so far (ClientHello + ServerHello + Certificate ...)
//        and is signed with the private key paired to the public key in the certificate)
//     + ChangeCipherSpec (record/content type 20 instead of type 22)
//       (payload is one byte = 1)
//     + Finished(verify_data)
//       (has epoch 1, which resets seqnums, and is encrypted)
// 6.  Server sends Client
//     + ChangeCipherSpec (record/content type 20 instead of type 22)
//       (payload is one byte = 1)
//     + Finished(verify_data)
//       (has epoch 1, which resets seqnums, and is encrypted)
// 7.  Both sides compute the pre-master secret by doing ECDH with their own dh_private_key and the peer's dh_public_key.
// 8.  Both sides compute a master secret from the pre-master secret and the random values.
// 9.  Both sides compute an SRTP master key using the master secret
//
//
// Records/Messages are encoded in the following way:
// 1-byte record type = 22 (Handshake)
// 2-byte version = [254, 255] (1.0) or [254, 253] (1.2)
// 2-byte epoch = 0 (for everything but Finished) or 1 (for Finished)
// 6-byte seqnum = 0 (ClientHello/ServerHello) or 1 (Certificate + KeyExchange) or 2 (Finished)
// 2-byte len = 12 + handshake_body_len
// 1-byte handshake message type
// 3-byte len = handshake_body_len
// 2-byte seqnum = 0
// 3-byte fragment offset = 0
// 3-byte fragment len = handshake_body_len
// handshake_body_len-byte handshake_body, which is a serialized form of any of these:
//  ClientHello (handshake message type = 1)
//   2-byte version = [254, 253] (1.2)
//   32-byte random (first 4 bytes are unix time in milliseconds)
//   1-byte-len-prefixed session_id = ""
//   1-byte-len-prefixed cookie
//   2-byte-len-prefixed cipher_suites
//    2 bytes each from https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
//    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = [0xC0, 0x2B]
//   1-byte-len-prefixed compression_methods
//    (1 byte each)
//    Uncompressed = 0 (must be supported according to https://tools.ietf.org/html/rfc4492#section-5.1.2)
//   optional 2-byte-len-prefixed extensions
//    2-byte extension_id
//     values at https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
//      EllipticCurves = 10,
//      EllipticCurvePointFormats = 11,
//      SignatureAlgorithms = 13,
//      SrtpProfiles = 14,
//    2-byte-len-prefixed extension_value, which is a serialized form of any of these:
//     EllipticCurves (extension ID = 10)
//      2-byte-len-prefixed elliptic_curves
//       2 bytes each
//       values at (https://tools.ietf.org/html/rfc4492#section-5.1.2 and https://tools.ietf.org/html/rfc8446#section-4.2.7)
//        x25519 = 29
//        secp256r1 = 23
//     EllipticCurvePointFormats (extension ID = 11)
//      1-byte-len-prefixed elliptic_curve_point_formats
//       1 byte each
//        ansiX962_compressed_prime =
//        uncompressed = 0
//     SignatureAlgorithms (extension ID = 13)
//      2-byte-len-prefixed signature_algorithms
//       2 bytes each, split into:
//        1-byte hash_algorithm
//        1-byte signature_algorithm
//     SrtpProfiles (extension ID = 14)
//      2-byte-len-prefixed srtp_profiles
//       2 bytes each
//        SRTP_AES128_CM_HMAC_SHA1_80 = 1
//        SRTP_AEAD_AES_256_GCM = 8
//        SRTP_AEAD_AES_128_GCM = 7
//     ExtendedMasterSecret (extension ID = 23)
//      0 bytes
//
//  HelloVerifyRequest (handshake message type = 3)
//   2-byte version = [254, 253] (1.2)
//   1-byte-len-prefixed cookie
//  ServerHello (handshake message type = 2)
//   2-byte version = [254, 253] (1.2)
//   32-byte random (first 4 bytes are unix time in milliseconds)
//   1-byte-len-prefixed session_id
//   2-byte cipher_suite
//   1-byte compression_method
//   optional 2-byte-len-prefixed extensions
//    Same as ClientHello above
//
//  Certificate (11)
//   3-byte len-prefixed certificates
//    3-byte len-prefixed certificate (in ASN.1 format)
//
//  ServerKeyExchange (handshake message type = 12)
//   (assuming ECDHE with named curve)
//    1-byte curve type
//     named_curve = 3
//    2-byte named curve
//     x25519 = 29
//     secp256r1 = 23
//    1-byte len-prefixed public_key (for DH, in sec1 format)
//    1-byte hash algorithm
//     SHA256 = 4
//    1-byte signature algorithm
//     ECDSA = 3
//    2-byte len-prefixed signature (in ASN1 DER format)
//     signs hash of above random values plus above record/message
//      32-byte client random
//      32-byte server random
//      1-byte curve type = 3
//      2-byte named curve
//      1-byte-len-prefixed public_key
//
//  CertificateRequest (handshake message type = 13)
//   1-byte-len-prefixed certificate_bytes
//    1 byte each
//    ecdsa_sign = 64
//   2-byte-len-prefixed signature_algorithms
//    2 bytes each
//   2-byte-len-prefixed certificate_authorities
//    2-byte-len-prefixed certificate_authority
//
//  ServerHelloDone (handshake message type = 14)
//   0 bytes
//
//  ClientKeyExchange (handshake message type = 16)
//   1-byte-len-prefixed dh_public_key (in sec1 format)
//
//  CertificateVerify (handshake message type = 15)
//   2-byte signature algorithm
//   2-byte-len-prefixed signature
//    signs SHA256(all the record bodies (not including record headers, but including handshake message headers) so far)
//    (ClientHello + ServerHello + Certificate + ServerKeyExhange + CertificateRequest + ServerHelloDone + Certificate + ClientKeyExchange)
//
//  Finished (handshake message type = 20)
//   8-byte explicit nonce (assuming AES-GCM)
//   64-byte ciphertext of verify_data (assuming SHA256)
//     PRF(master_secret, "client finished", SHA256(all the record bodies (not including record headers, but including handshake message headers) so far))
//      (ClientHello + ServerHello + Certificate + ServerKeyExhange + CertificateRequest + ServerHelloDone + Certificate + ClientKeyExchange + CertificateVerify + Finished)
//   16-byte MAC
//   The encryption and mac are done using a IV which is:
//    4-byte salt derived from DHE
//    8-byte explicit nonce (which may be the TLS sequence number, which is the DTLS epoch plus sequence number)
//
// Important things to know:
// - WebRTC only supports secp256r1 for ECDSA, so that's what we'll use.
// - HelloVerifyRequest is not needed because we only do DTLS after doing ICE, which prevents DOS attacks
// - We do not support ExtendedMasterSecret because RFC 7627 says
//   "Handshakes using ECDHE ciphersuites are also vulnerable if they allow arbitrary explicit
//    curves or use curves with small subgroups", which we do not (we only allow P256).

use std::{
    convert::{TryFrom, TryInto},
    time::SystemTime,
};

use aes::cipher::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, Aes128Gcm, NewAead};
use ecdsa::{
    elliptic_curve::SecretKey,
    signature::{DigestVerifier, Signer},
};
use hmac::{Hmac, Mac, NewMac};
use log::*;
use p256::{
    ecdh::EphemeralSecret,
    ecdsa::{Signature, SigningKey, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::FromPrivateKey,
    PublicKey,
};
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::common::{
    read_as_many_as_possible, read_bytes, read_from_end, read_u16, read_u16_len_prefixed,
    read_u16_len_prefixed_u16s, read_u24, read_u24_len_prefixed, read_u48, read_u8,
    read_u8_len_prefixed, write_u16_len_prefixed, write_u24_len_prefixed, write_u8_len_prefixed,
    Empty, ReadOption, Writer, U24, U48,
};

const VERSION_1_0: u16 = u16::from_be_bytes([254, 255]);
const VERSION_1_2: u16 = u16::from_be_bytes([254, 253]);
const CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02B;
const CURVE_P256: u16 = 23;
const CERTIFICATE_TYPE_ECDSA: u8 = 64;
const SIGNATURE_ALGORITHM_ECDSA_P256_SHA256: u16 = 0x0403;
const SRTP_PROFILE_AES_128_GCM: u16 = 7;
const CURVE_TYPE_NAMED: u8 = 3;
const COMPRESSION_METHOD_UNCOMPRESSED: u8 = 0;
const POINT_FORMAT_UNCOMPRESSED: u8 = 0;

const HELLO_RANDOM_LEN: usize = 32;
const KEY_LEN: usize = 16;
const SALT_LEN: usize = 4;
const TAG_LEN: usize = 16;
// srtp::KEY_LEN * 2 + srtp::SALT_LEN * 2
const SRTP_MASTER_KEY_LEN: usize = 56;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
enum RecordType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
enum HandshakeMessageType {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
}

#[derive(Copy, Clone)]
#[repr(u16)]
enum HelloExtensionType {
    EllipticCurves = 10,
    PointFormats = 11,
    SignatureAlgorithms = 13,
    SrtpProfiles = 14, // AKA UseSrtp
}

pub fn looks_like_packet(packet: &[u8]) -> bool {
    packet.len() > 1 && (20u8..=23u8).contains(&packet[0])
}

// TODO: Consider fixing "large size difference between variants", but
// 200 bytes per client may not be much to worry about.
#[allow(clippy::large_enum_variant)]
pub enum HandshakeState {
    WaitingForClientHello,
    ReceivedClientHelloAndSentServerHello {
        // For master key derivation
        // TODO: Use zeroize?
        client_random: [u8; HELLO_RANDOM_LEN],
        server_random: [u8; HELLO_RANDOM_LEN],
        dh_ephemeral_secret: EphemeralSecret,
        transcript: Sha256,

        // For resending
        server_hello_packet: Vec<u8>,
    },
    ReceivedFinishedAndSentFinished {
        srtp_master_key: Zeroizing<[u8; SRTP_MASTER_KEY_LEN]>,

        // For resending
        server_finished_packet: Vec<u8>,
    },
    // Either sent or received a fatal alert
    Failed,
}

impl Default for HandshakeState {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeState {
    pub fn new() -> Self {
        Self::WaitingForClientHello
    }

    pub fn srtp_master_key(&self) -> Option<&[u8; SRTP_MASTER_KEY_LEN]> {
        if let Self::ReceivedFinishedAndSentFinished {
            srtp_master_key, ..
        } = self
        {
            Some(srtp_master_key)
        } else {
            None
        }
    }

    // Only the initial processing needs the DERs, but it's much easier to pass it in here
    // than to keep track of references in WaitingForClientHello.
    // Similarly with the expected client fingerprint.
    pub fn process_packet(
        &mut self,
        packet: &[u8],
        server_certificate_der: &[u8],
        server_private_key_der: &[u8],
        expected_client_fingerprint: &[u8; 32],
        now: SystemTime,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Option<Vec<u8>> {
        let ((_epoch, _seqnum, record_type, record_body), _rest) = read_record(packet)?;
        match record_type {
            RecordType::Alert => {
                // TODO: Only do this for fatal alerts
                debug!("Received Alert");
                event!("calling.dtls.alert");
                *self = Self::Failed;
                None
            }
            RecordType::Handshake => {
                let ((handshake_message_type, handshake_body), _rest) =
                    read_handshake_message(record_body)?;
                match (&self, handshake_message_type) {
                    (Self::WaitingForClientHello, HandshakeMessageType::ClientHello) => {
                        trace!("ClientHello");
                        let client_hello = record_body;
                        let (client_random, _rest) = read_client_hello_body(handshake_body)?;
                        let server_random = generate_server_random(now, rng);
                        let dh_ephemeral_secret = EphemeralSecret::random(rng);
                        let signing_key = SigningKey::from(
                            SecretKey::from_pkcs8_der(server_private_key_der).ok()?,
                        );
                        let (dh_public_key_sec1, signature_der) = sign_public_key(
                            &dh_ephemeral_secret.public_key(),
                            &client_random,
                            &server_random,
                            &signing_key,
                        )?;

                        let (server_hello_packet, transcript) =
                            write_server_hello_packet_and_transcript(
                                client_hello,
                                &server_random,
                                server_certificate_der,
                                &dh_public_key_sec1,
                                &signature_der,
                            );

                        *self = Self::ReceivedClientHelloAndSentServerHello {
                            client_random,
                            server_random,
                            dh_ephemeral_secret,
                            transcript,
                            server_hello_packet: server_hello_packet.clone(),
                        };
                        Some(server_hello_packet)
                    }
                    (
                        Self::ReceivedClientHelloAndSentServerHello {
                            server_hello_packet,
                            ..
                        },
                        HandshakeMessageType::ClientHello,
                    ) => {
                        trace!("ClientHello - resend");
                        // Just resend the packet
                        // The handshake may fail if the client sends a different ClientHello
                        // then than the first time, but the client isn't supposed to do that.
                        // I suppose we could send an Alert, but that's not much different.
                        Some(server_hello_packet.clone())
                    }
                    (
                        Self::ReceivedClientHelloAndSentServerHello {
                            client_random,
                            server_random,
                            dh_ephemeral_secret,
                            transcript,
                            ..
                        },
                        HandshakeMessageType::Certificate,
                    ) => {
                        trace!("Certificate");
                        let ((actual_client_fingerprint, client_verifying_key, certificate), rest) =
                            read_certificate_record(packet)?;
                        let ((client_dh_public_key, client_key_exchange), rest) =
                            read_client_key_exchange_record(rest)?;
                        let ((client_signature, certificate_verify), rest) =
                            read_certificate_verify_record(rest)?;
                        let (_change_cipher_spec, rest) = read_change_cipher_spec_record(rest)?;

                        let actual_client_fingerprint = actual_client_fingerprint.finalize();
                        if actual_client_fingerprint.as_slice() != &expected_client_fingerprint[..]
                        {
                            // TODO return Result/Alert
                            warn!("Verification of client fingerprint failed. Expected {:X?} but got {:X?}.", expected_client_fingerprint, actual_client_fingerprint);
                            return None;
                        }

                        let mut signed_transcript = transcript.clone();
                        [certificate, client_key_exchange].write(&mut signed_transcript);
                        if let Err(err) =
                            client_verifying_key.verify_digest(signed_transcript, &client_signature)
                        {
                            // TODO: Send alert instead
                            warn!("Verification of client signature failed: {:?}", err);
                            #[cfg(not(fuzzing))]
                            return None;
                        }

                        let pre_master_secret =
                            dh_ephemeral_secret.diffie_hellman(&client_dh_public_key);
                        let client_server_random =
                            (&client_random[..], &server_random[..]).to_vec();
                        let server_client_random =
                            (&server_random[..], &client_random[..]).to_vec();
                        let master_secret = prf_sha256(
                            pre_master_secret.as_bytes(),
                            b"master secret",
                            &client_server_random,
                            48,
                        );
                        let srtp_master_key = Zeroizing::new(
                            prf_sha256(
                                &master_secret,
                                b"EXTRACTOR-dtls_srtp",
                                &client_server_random,
                                SRTP_MASTER_KEY_LEN,
                            )
                            .as_slice()
                            .try_into()
                            .unwrap(),
                        );
                        // Watch out: key expansion uses (server_random, client_random) instead of (client_random, server_random).
                        let key_material = prf_sha256(
                            &master_secret,
                            b"key expansion",
                            &server_client_random[..],
                            KEY_LEN * 2 + SALT_LEN * 2,
                        );
                        let client_key: [u8; KEY_LEN] = key_material[..KEY_LEN].try_into().unwrap();
                        let server_key: [u8; KEY_LEN] =
                            key_material[KEY_LEN..][..KEY_LEN].try_into().unwrap();
                        let client_salt: [u8; SALT_LEN] = key_material[KEY_LEN..][KEY_LEN..]
                            [..SALT_LEN]
                            .try_into()
                            .unwrap();
                        let server_salt: [u8; SALT_LEN] = key_material[KEY_LEN..][KEY_LEN..]
                            [SALT_LEN..][..SALT_LEN]
                            .try_into()
                            .unwrap();

                        // This has to be read after the key derivation because we have to use the keys to decrypt it.
                        let (client_finished, _rest) =
                            read_client_finished_record(rest, &client_key, client_salt)?;

                        let mut full_transcript = transcript.clone();
                        [
                            certificate,
                            client_key_exchange,
                            certificate_verify,
                            &client_finished,
                        ]
                        .write(&mut full_transcript);
                        let server_verify_data = prf_sha256(
                            &master_secret,
                            b"server finished",
                            &full_transcript.finalize(),
                            12,
                        );
                        let server_finished_packet = write_server_finished_packet(
                            &server_verify_data[..],
                            &server_key,
                            server_salt,
                        )
                        .to_vec();

                        // It doesn't seem like we gain anything from verifying the Finished
                        // message, so we'll just skip doing that.

                        *self = Self::ReceivedFinishedAndSentFinished {
                            srtp_master_key,
                            server_finished_packet: server_finished_packet.clone(),
                        };
                        Some(server_finished_packet)
                    }
                    (
                        Self::ReceivedFinishedAndSentFinished {
                            server_finished_packet,
                            ..
                        },
                        HandshakeMessageType::Certificate,
                    ) => {
                        trace!("Certificate - resend");
                        // Just resend the packet
                        // The handshake may fail if the client sends a different Certificate
                        // then than the first time, but the client isn't supposed to do that.
                        // I suppose we could send an Alert, but that's not much different.
                        Some(server_finished_packet.clone())
                    }
                    (_, _) => {
                        // TODO: Return a Result and send an alert.
                        warn!(
                            "Received unexpected DTLS packet with handshake message type {:?}",
                            handshake_message_type
                        );
                        None
                    }
                }
            }
            _ => {
                warn!("Received unexpected record type: {:?}", record_type);
                None
            }
        }
    }

    #[cfg(fuzzing)]
    pub fn after_hello(
        client_random: [u8; HELLO_RANDOM_LEN],
        now: SystemTime,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Self {
        // Must use rng the same way ClientHello is handled above,
        // so that we can replay a client packet.
        let server_random = generate_server_random(now, rng);
        let dh_ephemeral_secret = EphemeralSecret::random(rng);
        Self::ReceivedClientHelloAndSentServerHello {
            client_random,
            server_random,
            dh_ephemeral_secret,
            transcript: Default::default(),
            server_hello_packet: Default::default(),
        }
    }
}

fn generate_server_random(
    now: SystemTime,
    rng: &mut (impl Rng + CryptoRng),
) -> [u8; HELLO_RANDOM_LEN] {
    let mut server_random = [0u8; HELLO_RANDOM_LEN];
    let unix_time = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32;
    server_random[0..4].copy_from_slice(&unix_time.to_be_bytes());
    rng.fill(&mut server_random[4..]);
    server_random
}

// Returns (public_key_sec1, signature_der)
fn sign_public_key(
    public_key: &PublicKey,
    client_random: &[u8; HELLO_RANDOM_LEN],
    server_random: &[u8; HELLO_RANDOM_LEN],
    signing_key: &SigningKey,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let encoded_public_key = public_key.to_encoded_point(false /* compress_encoded_point */);
    let tbs = (
        &client_random[..],
        &server_random[..],
        [CURVE_TYPE_NAMED],
        CURVE_P256,
        write_u8_len_prefixed(encoded_public_key.as_bytes()),
    )
        .to_vec();
    let signature = signing_key.try_sign(&tbs).ok()?;
    let public_key_sec1 = encoded_public_key.as_bytes().to_vec();
    let signature_der = signature.to_der().as_bytes().to_vec();
    Some((public_key_sec1, signature_der))
}

// From https://tools.ietf.org/html/rfc5246#section-5
fn prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], out_len: usize) -> Zeroizing<Vec<u8>> {
    assert!(out_len <= 64);
    let mut a1 = hmac_sha256(secret, &[label, seed]).into_bytes();
    let mut a2 = hmac_sha256(secret, &[&a1]).into_bytes();
    let mut b1 = hmac_sha256(secret, &[a1.as_slice(), label, seed]).into_bytes();
    let mut b2 = hmac_sha256(secret, &[a2.as_slice(), label, seed]).into_bytes();
    let result = Zeroizing::new(b1.into_iter().chain(b2.into_iter()).take(out_len).collect());

    a1.zeroize();
    a2.zeroize();
    b1.zeroize();
    b2.zeroize();

    result
}

fn hmac_sha256(secret: &[u8], inputs: &[&[u8]]) -> hmac::crypto_mac::Output<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    for input in inputs {
        mac.update(input);
    }
    mac.finalize()
}

// Returns the "client random"
fn read_client_hello_body(input: &[u8]) -> ReadOption<[u8; HELLO_RANDOM_LEN]> {
    let (version, rest) = read_u16(input)?;
    let (random, rest) = read_bytes(rest, HELLO_RANDOM_LEN)?;
    let (_session_id, rest) = read_u8_len_prefixed(rest)?;
    let (_cookie, rest) = read_u8_len_prefixed(rest)?;
    let (cipher_suites, rest) = read_u16_len_prefixed_u16s(rest)?;
    let (compression_methods, rest) = read_u8_len_prefixed(rest)?;

    if version != VERSION_1_2 {
        warn!(
            "Failed to parse DTLS packet because handshake version({}) is not 1.2",
            version
        );
        return None;
    }
    let random = random.try_into().unwrap();
    if !cipher_suites.contains(&CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) {
        // TODO: Return a Result and send an alert.
        warn!("Failed to parse DTLS ClientHello because it does not include cipher suite ECDHE_ECDSA_WITH_AES_128_GCM_SHA25");
        return None;
    }
    if !compression_methods.contains(&COMPRESSION_METHOD_UNCOMPRESSED) {
        // TODO: Return a Result and send an alert
        warn!("Failed to parse DTLS ClientHello because it does not include compression methocd UNCOMPRESSED");
        return None;
    }

    if let Some((extensions, rest)) = read_u16_len_prefixed(rest) {
        let (extensions, _rest) = read_as_many_as_possible(extensions, read_hello_extension)?;
        for (extension_type, extension_val) in extensions {
            match extension_type {
                x if x == HelloExtensionType::EllipticCurves as u16 => {
                    let (elliptic_curves, _) = read_u16_len_prefixed_u16s(extension_val)?;
                    if !elliptic_curves.contains(&CURVE_P256) {
                        warn!("Failed to parse DTLS ClientHello because it does not include curve P256");
                        return None;
                    }
                }
                x if x == HelloExtensionType::SignatureAlgorithms as u16 => {
                    let (signature_algorithms, _) = read_u16_len_prefixed_u16s(extension_val)?;
                    if !signature_algorithms.contains(&SIGNATURE_ALGORITHM_ECDSA_P256_SHA256) {
                        warn!("Failed to parse DTLS ClientHello because it does not include signature algorithm ECDSA_P256_SHA256");
                        return None;
                    }
                }
                x if x == HelloExtensionType::SrtpProfiles as u16 => {
                    let (srtp_profiles, _) = read_u16_len_prefixed_u16s(extension_val)?;
                    if !srtp_profiles.contains(&SRTP_PROFILE_AES_128_GCM) {
                        warn!("Failed to parse DTLS ClientHello because it does not include SRTP profile AES_128_GCM");
                        return None;
                    }
                }
                _ => {}
            }
        }
        Some((random, rest))
    } else {
        Some((random, rest))
    }
}

fn write_server_hello_packet_and_transcript(
    client_hello: &[u8],
    server_random: &[u8; HELLO_RANDOM_LEN],
    server_certificate_der: &[u8],
    server_dh_public_key_sec1: &[u8],
    server_signature_der: &[u8],
) -> (Vec<u8>, Sha256) {
    let server_hello = write_server_hello_handshake_message(0, server_random);
    let server_certificate = write_certificate_handshake_message(1, server_certificate_der);
    let server_key_exchange = write_server_key_exchange_handshake_message(
        2,
        server_dh_public_key_sec1,
        server_signature_der,
    );
    let certificate_request = write_certificate_request_handshake_message(3);
    let server_hello_done = write_server_hello_done_handshake_message(4);
    let server_hello_messages: [&dyn Writer; 5] = [
        &server_hello,
        &server_certificate,
        &server_key_exchange,
        &certificate_request,
        &server_hello_done,
    ];

    let transcript = Writer::to_sha256(&(client_hello, &server_hello_messages[..]));
    let server_hello_packet = write_records(
        0,         /* epoch */
        U48::ZERO, /* first seqnum */
        RecordType::Handshake,
        &server_hello_messages[..],
    )
    .to_vec();
    (server_hello_packet, transcript)
}

fn write_server_hello_handshake_message(
    seqnum: u16,
    server_random: &[u8; HELLO_RANDOM_LEN],
) -> impl Writer + '_ {
    let main = (
        VERSION_1_2,
        &server_random[..],
        write_u8_len_prefixed(Empty {}), /* Session ID */
        CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        [COMPRESSION_METHOD_UNCOMPRESSED],
    );
    let extensions = write_u16_len_prefixed((
        write_hello_extension(
            HelloExtensionType::EllipticCurves,
            write_u16_len_prefixed([CURVE_P256]),
        ),
        write_hello_extension(
            HelloExtensionType::PointFormats,
            write_u8_len_prefixed([POINT_FORMAT_UNCOMPRESSED]),
        ),
        write_hello_extension(
            HelloExtensionType::SrtpProfiles,
            (
                write_u16_len_prefixed([SRTP_PROFILE_AES_128_GCM]),
                [0u8], /* MKI length */
            ),
        ),
    ));
    let body = (main, extensions);
    write_handshake_message(seqnum, HandshakeMessageType::ServerHello, body)
}

fn write_hello_extension(r#type: HelloExtensionType, val: impl Writer) -> impl Writer {
    let id = r#type as u16;
    let val = write_u16_len_prefixed(val);
    (id, val)
}

// Returns (type, val)
fn read_hello_extension(input: &[u8]) -> ReadOption<(u16, &[u8])> {
    let (r#type, rest) = read_u16(input)?;
    let (val, rest) = read_u16_len_prefixed(rest)?;
    Some(((r#type, val), rest))
}

fn write_certificate_handshake_message(seqnum: u16, certificate_der: &[u8]) -> impl Writer + '_ {
    let body = write_u24_len_prefixed([write_u24_len_prefixed(certificate_der)]);
    write_handshake_message(seqnum, HandshakeMessageType::Certificate, body)
}

fn write_server_key_exchange_handshake_message<'a>(
    seqnum: u16,
    dh_public_key_sec1: &'a [u8],
    signature_der: &'a [u8],
) -> impl Writer + 'a {
    let public_key = write_u8_len_prefixed(dh_public_key_sec1);
    let signature = write_u16_len_prefixed(signature_der);
    let body = (
        [CURVE_TYPE_NAMED],
        CURVE_P256,
        public_key,
        SIGNATURE_ALGORITHM_ECDSA_P256_SHA256,
        signature,
    );
    write_handshake_message(seqnum, HandshakeMessageType::ServerKeyExchange, body)
}

fn write_certificate_request_handshake_message(seqnum: u16) -> impl Writer {
    let certificate_types = write_u8_len_prefixed([CERTIFICATE_TYPE_ECDSA]);
    let signature_types = write_u16_len_prefixed(SIGNATURE_ALGORITHM_ECDSA_P256_SHA256);
    let certificate_authorities = write_u16_len_prefixed(Empty {});
    let body = (certificate_types, signature_types, certificate_authorities);
    write_handshake_message(seqnum, HandshakeMessageType::CertificateRequest, body)
}

fn write_server_hello_done_handshake_message(seqnum: u16) -> impl Writer {
    write_handshake_message(seqnum, HandshakeMessageType::ServerHelloDone, Empty {})
}

fn write_finished_handshake_message(seqnum: u16, verify_data: &[u8]) -> impl Writer + '_ {
    write_handshake_message(seqnum, HandshakeMessageType::Finished, verify_data)
}

// Returns (certificate_fingerprint, verifying_key, certificate_record_body)
fn read_certificate_record(input: &[u8]) -> ReadOption<(Sha256, VerifyingKey, &[u8])> {
    let (certificate_record_body, record_rest) = read_handshake_record(input)?;
    let ((r#type, body), _) = read_handshake_message(certificate_record_body)?;
    if r#type != HandshakeMessageType::Certificate {
        // TODO: Send alert instead
        warn!(
            "Expected client Certificate record but got handshake message type {:?}",
            r#type
        );
        return None;
    }

    let (certificate_ders, _) = read_u24_len_prefixed(body)?;
    let (certificate_der, _) = read_u24_len_prefixed(certificate_ders)?;
    let fingerprint = certificate_der.to_sha256();

    let certificate_public_key_sec1 = match parse_public_key_from_certificate_der(certificate_der) {
        Err(err) => {
            // TODO: Return a Result and send an alert.
            warn!(
                "Failed to parse ECDHE public key from certificate: {:?}",
                err
            );
            return None;
        }
        Ok(key) => key,
    };
    let verifying_key = match VerifyingKey::from_sec1_bytes(certificate_public_key_sec1) {
        Err(err) => {
            // TODO: Return a Result and send an alert.
            warn!(
                "Failed to parse ECDHE public key from SEC1 value: {:?}",
                err
            );
            return None;
        }
        Ok(key) => key,
    };
    Some((
        (fingerprint, verifying_key, certificate_record_body),
        record_rest,
    ))
}

fn parse_public_key_from_certificate_der(certificate_der: &[u8]) -> der::Result<&[u8]> {
    let certificate: der::Any = certificate_der.try_into()?;
    certificate.sequence(|certificate| {
        let tbs: der::Any = certificate.decode()?;
        let _signature_algorithm: der::Any = certificate.decode()?;
        let _signature: der::Any = certificate.decode()?;
        tbs.sequence(|tbs| {
            let _version: der::Any = tbs.decode()?;
            let _serial_number: der::Any = tbs.decode()?;
            let _signature_algorithm: der::Any = tbs.decode()?;
            let _issuer: der::Any = tbs.decode()?;
            let _validity: der::Any = tbs.decode()?;
            let _subject: der::Any = tbs.decode()?;
            let subject_public_key_info: der::Any = tbs.decode()?;
            subject_public_key_info.sequence(|subject_public_key_info| {
                let _public_key_algorithm: der::Any = subject_public_key_info.decode()?;
                let public_key: der::Any = subject_public_key_info.decode()?;
                Ok(public_key.bit_string()?.as_bytes())
            })
        })
    })
}

// Returns (client_dh_public_key, record_body)
fn read_client_key_exchange_record(input: &[u8]) -> ReadOption<(PublicKey, &[u8])> {
    let (client_key_exchange, record_rest) = read_handshake_record(input)?;
    let ((r#type, body), _) = read_handshake_message(client_key_exchange)?;
    if r#type != HandshakeMessageType::ClientKeyExchange {
        // TODO: Send alert instead
        warn!(
            "Expected client ClientKeyExchange record but got handshake message type {:?}",
            r#type
        );
        return None;
    }

    let (client_dh_public_key_sec1, _rest) = read_u8_len_prefixed(body)?;
    let client_dh_public_key = match PublicKey::from_sec1_bytes(client_dh_public_key_sec1) {
        Err(err) => {
            // TODO: Return a Result and send an alert.
            warn!("Failed to parse ECDHE public key: {:?}", err);
            return None;
        }
        Ok(key) => key,
    };

    Some(((client_dh_public_key, client_key_exchange), record_rest))
}

// Returns (signature, record body)
fn read_certificate_verify_record(input: &[u8]) -> ReadOption<(Signature, &[u8])> {
    let (certificate_verify, record_rest) = read_handshake_record(input)?;
    let ((r#type, body), _) = read_handshake_message(certificate_verify)?;
    if r#type != HandshakeMessageType::CertificateVerify {
        // TODO: Send alert instead
        warn!(
            "Expected client CertificateVerify record but got handshake message type {:?}",
            r#type
        );
        return None;
    }

    let (signature_algorithm, rest) = read_u16(body)?;
    if signature_algorithm != SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 {
        // TODO: Return a Result and send an alert.
        warn!(
            "Dropping DTLS packet.  Expected signature algorithm of ECDSA_P256_SHA256. Got {}",
            signature_algorithm
        );
        return None;
    }

    let (signature_der, _rest) = read_u16_len_prefixed(rest)?;
    let signature = match Signature::from_der(signature_der) {
        Err(err) => {
            // TODO: Return a Result and send an alert.
            warn!("Failed to parse client signature: {:?}", err);
            return None;
        }
        Ok(signature) => signature,
    };

    Some(((signature, certificate_verify), record_rest))
}

fn read_handshake_record(input: &[u8]) -> ReadOption<&[u8]> {
    let ((_epoch, _seqnum, record_type, body), rest) = read_record(input)?;
    if record_type != RecordType::Handshake {
        // TODO: Send alert instead
        warn!(
            "Expected client Handshake record but got record type {:?}",
            record_type
        );
        return None;
    }
    Some((body, rest))
}

fn read_change_cipher_spec_record(input: &[u8]) -> ReadOption<&[u8]> {
    let ((_epoch, _seqnum, record_type, change_cipher_spec), rest) = read_record(input)?;
    if record_type != RecordType::ChangeCipherSpec {
        // TODO: Send alert instead
        warn!(
            "Expected client ChangeCipherSpec record but got record type {:?}",
            record_type
        );
        return None;
    }
    Some((change_cipher_spec, rest))
}

// Return client_finished handshake message body
fn read_client_finished_record<'a>(
    input: &'a [u8],
    key: &'a [u8; KEY_LEN],
    salt: [u8; SALT_LEN],
) -> ReadOption<'a, Vec<u8>> {
    let ((record_type, client_finished), rest) = read_decrypted_record(input, key, salt)?;
    if record_type != RecordType::Handshake {
        // TODO: Send alert instead
        warn!(
            "Expected client Finished record but got record type {:?}",
            record_type
        );
        return None;
    }
    Some((client_finished, rest))
}

fn write_server_finished_packet<'a>(
    server_verify_data: &'a [u8],
    server_key: &'a [u8; KEY_LEN],
    server_salt: [u8; SALT_LEN],
) -> impl Writer + 'a {
    let change_cipher_spec = write_change_cipher_spec_record();
    let server_finished =
        write_server_finished_record(&server_verify_data, &server_key, server_salt);
    (change_cipher_spec, server_finished)
}

fn write_change_cipher_spec_record() -> impl Writer {
    let epoch = 0;
    let seqnum = U48::from(5u32);
    write_record(epoch, seqnum, RecordType::ChangeCipherSpec, &[1u8])
}

fn write_server_finished_record<'a>(
    server_verify_data: &'a [u8],
    server_key: &'a [u8; KEY_LEN],
    server_salt: [u8; SALT_LEN],
) -> impl Writer + 'a {
    let epoch = 1;
    let seqnum = 5;
    let body = write_finished_handshake_message(seqnum, &server_verify_data);
    write_encrypted_record(
        epoch,
        U48::from(seqnum),
        RecordType::Handshake,
        body,
        server_key,
        server_salt,
    )
}

fn write_encrypted_record(
    epoch: u16,
    seqnum: U48,
    record_type: RecordType,
    plaintext: impl Writer,
    key: &[u8; KEY_LEN],
    salt: [u8; SALT_LEN],
) -> impl Writer {
    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let explicit_nonce = (epoch, seqnum);
    let iv = (salt.to_vec(), explicit_nonce).to_vec();
    let aad = write_aad(epoch, seqnum, record_type, plaintext.written_len()).to_vec();
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&iv), &aad, &mut ciphertext)
        .unwrap()
        .to_vec();
    let body = (epoch, seqnum, ciphertext, tag);
    write_record(epoch, seqnum, record_type, body)
}

// Returns (record_type, plaintext)
fn read_decrypted_record<'input>(
    input: &'input [u8],
    key: &[u8; KEY_LEN],
    salt: [u8; SALT_LEN],
) -> ReadOption<'input, (RecordType, Vec<u8>)> {
    let ((epoch, seqnum, record_type, body), _rest) = read_record(input)?;
    let (explicit_nonce, rest) = read_bytes(body, 8)?;
    let (tag, ciphertext) = read_from_end(rest, TAG_LEN)?;

    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let iv = (salt.to_vec(), explicit_nonce).to_vec();
    let aad = write_aad(epoch, seqnum, record_type, ciphertext.len()).to_vec();
    let mut plaintext = ciphertext.to_vec();
    if let Err(err) = cipher.decrypt_in_place_detached(
        GenericArray::from_slice(&iv),
        &aad,
        &mut plaintext,
        GenericArray::from_slice(tag),
    ) {
        warn!("Failed to decrypt record: {:?}", err);
        return None;
    }
    Some(((record_type, plaintext), rest))
}

fn write_aad(epoch: u16, seqnum: U48, record_type: RecordType, len: usize) -> impl Writer {
    (epoch, seqnum, [record_type as u8], VERSION_1_2, len as u16)
}

fn write_records<'writers>(
    epoch: u16,
    first_seqnum: U48,
    record_type: RecordType,
    messages: &'writers [&'writers dyn Writer],
) -> impl Writer + 'writers {
    messages
        .iter()
        .enumerate()
        .map(|(i, message)| {
            let seqnum = first_seqnum.wrapping_add(U48::from(i as u32));
            write_record(epoch, seqnum, record_type, message)
        })
        .collect::<Vec<_>>()
}

fn write_record(
    epoch: u16,
    seqnum: U48,
    record_type: RecordType,
    body: impl Writer,
) -> impl Writer {
    (
        [record_type as u8],
        VERSION_1_2,
        epoch,
        seqnum,
        write_u16_len_prefixed(body),
    )
}

// Returns (epoch, seqnum, record_type, body)
fn read_record(input: &[u8]) -> ReadOption<(u16, U48, RecordType, &[u8])> {
    let (record_type, rest) = read_u8(input)?;
    let (version, rest) = read_u16(rest)?;
    let (epoch, rest) = read_u16(rest)?;
    let (seqnum, rest) = read_u48(rest)?;
    let (body, rest) = read_u16_len_prefixed(rest)?;

    let record_type = match record_type {
        x if x == RecordType::ChangeCipherSpec as u8 => RecordType::ChangeCipherSpec,
        x if x == RecordType::Alert as u8 => RecordType::Alert,
        x if x == RecordType::Handshake as u8 => RecordType::Handshake,
        _ => {
            warn!(
                "Failed to parse DTLS packet because of unknown record type: {}",
                record_type
            );
            return None;
        }
    };
    if version != VERSION_1_0 && version != VERSION_1_2 {
        warn!(
            "Failed to parse DTLS packet because version({}) is not 1.0 or 1.2",
            version
        );
        return None;
    }

    Some(((epoch, seqnum, record_type, body), rest))
}

fn write_handshake_message(
    seqnum: u16,
    handshake_message_type: HandshakeMessageType,
    body: impl Writer,
) -> impl Writer {
    let r#type = handshake_message_type as u8;
    let body_len = U24::try_from(body.written_len() as u32).unwrap();
    let fragment_offset = U24::ZERO;
    let fragment_len = body_len;
    let header = ([r#type], body_len, seqnum, fragment_offset, fragment_len);
    (header, body)
}

// Returns handshake (type, body)
fn read_handshake_message(input: &[u8]) -> ReadOption<(HandshakeMessageType, &[u8])> {
    let (r#type, rest) = read_u8(input)?;
    let (body_len, rest) = read_u24(rest)?;
    let (_seqnum, rest) = read_u16(rest)?;
    let (fragment_offset, rest) = read_u24(rest)?;
    let (fragment_len, rest) = read_u24(rest)?;
    let (body, rest) = read_bytes(rest, body_len.into())?;

    let r#type = match r#type {
        x if x == HandshakeMessageType::ClientHello as u8 => HandshakeMessageType::ClientHello,
        x if x == HandshakeMessageType::Certificate as u8 => HandshakeMessageType::Certificate,
        x if x == HandshakeMessageType::CertificateVerify as u8 => {
            HandshakeMessageType::CertificateVerify
        }
        x if x == HandshakeMessageType::ClientKeyExchange as u8 => {
            HandshakeMessageType::ClientKeyExchange
        }
        x if x == HandshakeMessageType::Finished as u8 => HandshakeMessageType::Finished,
        _ => {
            warn!(
                "Failed to parse DTLS packet because of unknown handshake message type: {}",
                r#type
            );
            return None;
        }
    };
    if fragment_len != body_len {
        warn!(
            "Failed to parse DTLS handshake packet because fragment_len({}) != body_len({})",
            fragment_len, body_len
        );
        return None;
    }
    if fragment_offset != U24::ZERO {
        warn!(
            "Failed to parse DTLS handshake packet because fragment_offset({}) != 0",
            fragment_offset
        );
        return None;
    }

    Some(((r#type, body), rest))
}
