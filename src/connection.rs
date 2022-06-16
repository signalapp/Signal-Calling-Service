//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::SocketAddr;

use log::*;
use thiserror::Error;

use crate::{
    common::{DataRate, DataSize, Duration, Instant},
    googcc, ice, rtp,
};

// This is a value sent in each RTCP message that isn't used anywhere, but
// we have to pick a value.
pub const RTCP_SENDER_SSRC: rtp::Ssrc = 0;
// This is the amount of time we want to give to batching of NACKs to avoid
// sending too many due to small jitter.  And it helps avoid using too much
// CPU for no value.
// Note: as long as the tick interval is more than this value,
// this interval doesn't matter.  But we leave it anyway in case the
// tick interval ever decreases.
const NACK_CALCULATION_INTERVAL: Duration = Duration::from_millis(20);
// This is the amount of time we want to give to batching of ACKs
// to avoid sending too many packets.
// Note: as long as the tick interval is more than or equal to this value,
// this interval doesn't matter.  But we leave it anyway in case the
// tick interval ever decreases.
const ACK_CALCULATION_INTERVAL: Duration = Duration::from_millis(100);

pub type PacketToSend = Vec<u8>;

#[derive(Error, Debug, Eq, PartialEq)]
pub enum Error {
    #[error("received ICE with invalid hmac: {0:?}")]
    ReceivedIceWithInvalidHmac(Vec<u8>),
    #[error("received ICE with invalid username: {0:?}")]
    ReceivedIceWithInvalidUsername(Vec<u8>),
    #[error("received invalid RTP packet")]
    ReceivedInvalidRtp,
    #[error("received invalid RTCP packet")]
    ReceivedInvalidRtcp,
}

/// The state of a connection to a client.
/// Combines the ICE and SRTP/SRTCP state.
/// Takes care of transport auth, crypto, ACKs, NACKs,
/// retransmissions, congestion control, and IP mobility.
pub struct Connection {
    created: Instant,

    /// How long we should wait without an incoming ICE binding request
    /// before we treat the client as "inactive".  Once "inactive", the SFU
    /// should drop the client.  See Connection::inactive().
    inactivity_timeout: Duration,

    ice: Ice,
    rtp: Rtp,
    congestion_control: CongestionControl,

    /// When receiving ICE binding requests from different addresses,
    /// the Connection decides which should be used for sending packets.
    /// See Connection::outgoing_addr().
    outgoing_addr: Option<SocketAddr>,
}

struct Ice {
    // Immutable
    /// Username expected by server in binding requests from clients.
    request_username: Vec<u8>,
    /// Username expected by clients in binding responses from server.
    response_username: Vec<u8>,
    /// Used to verify the HMAC in requests and generate HMACS in response.
    pwd: Vec<u8>,

    // Mutable
    /// The last time a valid ice binding request from the client was received.
    binding_request_received: Option<Instant>,
}

struct Rtp {
    // Immutable
    /// The SSRC used for sending transport-CC ACKs.
    #[cfg_attr(not(test), allow(dead_code))]
    ack_ssrc: rtp::Ssrc,

    endpoint: rtp::Endpoint,

    /// The last time ACKs were sent.
    acks_sent: Option<Instant>,

    /// The last time NACKs were sent.
    nacks_sent: Option<Instant>,
}

struct CongestionControl {
    controller: googcc::CongestionController,

    /// Padding is sent if both of these are set, and will
    /// be sent with the set interval with the set SSRC.
    /// See Connection::set_padding_send_rate.
    padding_interval: Option<Duration>,
    padding_ssrc: Option<rtp::Ssrc>,

    /// The last time padding was sent, or if padding can't be sent yet,
    /// the last time we knew padding couldn't be sent
    /// (see Connection::send_padding_if_its_been_too_long)
    // Used to calculate when to send padding next.
    padding_sent: Instant,
}

pub type DhePublicKey = [u8; 32];

impl Connection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ice_request_username: Vec<u8>,
        ice_response_username: Vec<u8>,
        ice_pwd: Vec<u8>,
        srtp_master_key_material: rtp::MasterKeyMaterial,
        ack_ssrc: rtp::Ssrc,
        googcc_config: googcc::Config,
        inactivity_timeout: Duration,
        now: Instant,
    ) -> Self {
        let (decrypt, encrypt) =
            rtp::KeysAndSalts::derive_client_and_server_from_master_key_material(
                &srtp_master_key_material,
            );
        let rtp_endpoint = rtp::Endpoint::new(decrypt, encrypt, now, RTCP_SENDER_SSRC, ack_ssrc);
        Self {
            created: now,

            inactivity_timeout,

            ice: Ice {
                request_username: ice_request_username,
                response_username: ice_response_username,
                pwd: ice_pwd,

                binding_request_received: None,
            },
            rtp: Rtp {
                ack_ssrc,
                endpoint: rtp_endpoint,
                acks_sent: None,
                nacks_sent: None,
            },
            congestion_control: CongestionControl {
                controller: googcc::CongestionController::new(googcc_config, now),

                padding_interval: None,
                padding_ssrc: None,

                padding_sent: now,
            },
            outgoing_addr: None,
        }
    }

    // This is a convenience for the SFU to be able to iterate over Connections
    // and remove them from a table of username => Connection if the Connection is inactive.
    pub fn ice_request_username(&self) -> &[u8] {
        &self.ice.request_username
    }

    /// All packets except for ICE binding responses should be sent to this address, if there is one.
    pub fn outgoing_addr(&self) -> Option<SocketAddr> {
        self.outgoing_addr
    }

    /// Validate an incoming ICE binding request.  If it's valid, update the activity
    /// (the connection won't be inactive for a while) and possibly the outgoing address.
    /// Returns an ICE binding response to send back to the client, which should be sent
    /// back to the address from which the request came, not to the outgoing_addr.
    pub fn handle_ice_binding_request(
        &mut self,
        sender_addr: SocketAddr,
        binding_request: ice::BindingRequest,
        now: Instant,
    ) -> Result<PacketToSend, Error> {
        let verified_binding_request = binding_request
            .verify_hmac(&self.ice.pwd)
            .map_err(|_| Error::ReceivedIceWithInvalidHmac(binding_request.hmac().to_vec()))?;

        // This should never happen because sfu.rs should never call us with an invalid username.
        // But defense in depth is good too.
        if verified_binding_request.username() != self.ice.request_username {
            return Err(Error::ReceivedIceWithInvalidUsername(
                verified_binding_request.username().to_vec(),
            ));
        }
        // The client may send ICE binding requests from many different addresses
        // (probably different network interfaces).
        // At any given time, only one will be nominated, which means the client
        // wants to receive using that address.
        // Other addresses are only being checked as "backup".  We should send
        // back responses for those, but not switch to sending to them.
        // Over time, the nominated address may change, and we switch to the new
        // one whenever it does.
        if verified_binding_request.nominated() && self.outgoing_addr != Some(sender_addr) {
            event!("calling.sfu.ice.outgoing_addr_switch");
            self.outgoing_addr = Some(sender_addr);
        }
        self.ice.binding_request_received = Some(now);

        Ok(
            verified_binding_request
                .to_binding_response(&self.ice.response_username, &self.ice.pwd),
        )
    }

    // This effectively overrides the DHE, which is more convenient for tests.
    #[cfg(test)]
    fn set_srtp_keys(
        &mut self,
        decrypt: rtp::KeysAndSalts,
        encrypt: rtp::KeysAndSalts,
        now: Instant,
    ) {
        self.rtp.endpoint =
            rtp::Endpoint::new(decrypt, encrypt, now, RTCP_SENDER_SSRC, self.rtp.ack_ssrc);
    }

    /// Decrypts an incoming RTP packet and returns it.
    /// Also remembers that we may need to send ACKs and NACKs
    /// at the next call to tick().
    pub fn handle_rtp_packet<'packet>(
        &mut self,
        incoming_packet: &'packet mut [u8],
        now: Instant,
    ) -> Result<rtp::Packet<&'packet mut [u8]>, Error> {
        let rtp_endpoint = &mut self.rtp.endpoint;
        rtp_endpoint
            .receive_rtp(incoming_packet, now)
            .ok_or(Error::ReceivedInvalidRtp)
    }

    /// Decrypts an incoming RTCP packet and processes it.
    /// Returns 3 things, all or none of which could happen at once
    /// (because RTCP packets can be "compound"):
    /// 1. Key frame requests contained in the RTCP packet
    /// 2. RTX packets triggered by NACKs in the RTCP packet,
    ///    which should be sent to the Connection::outgoing_addr().
    /// 3. A new target send rate calculated from ACKs in the RTCP packet.
    pub fn handle_rtcp_packet(
        &mut self,
        incoming_packet: &mut [u8],
        now: Instant,
    ) -> Result<HandleRtcpResult, Error> {
        let rtp_endpoint = &mut self.rtp.endpoint;
        let rtcp = rtp_endpoint
            .receive_rtcp(incoming_packet, now)
            .ok_or(Error::ReceivedInvalidRtcp)?;

        let new_target_send_rate = self
            .congestion_control
            .controller
            .recalculate_target_send_rate(rtcp.acks);
        // TODO: Adjust the ACK interval like WebRTC does.  Something like this:
        // ack_interval = (DataSize::from_bytes(68) / (new_target_send_rate * 0.05)).clamp(Duration::from_millis(50), Duration::from_millis(250));
        // WebRTC sends this initially every 100ms
        // and then adjusts it to between 50ms and 250ms based on the target send rate.
        // It tries to hit 5% of the target send rate and assumes an average
        // TCC feedback size of 68 bytes (including IP, UDP, SRTP, and RTCP overhead).

        let mut outgoing_rtx = vec![];
        if let Some(outgoing_addr) = self.outgoing_addr {
            for rtp::Nack { ssrc, seqnums } in rtcp.nacks {
                for seqnum in seqnums {
                    if let Some(rtx) = rtp_endpoint.resend_rtp(ssrc, seqnum, now) {
                        outgoing_rtx.push((rtx.into_serialized(), outgoing_addr));
                    } else {
                        debug!("Ignoring NACK for (SSRC, seqnum) that is either too old or invalid: ({}, {})", ssrc, seqnum);
                    }
                }
            }
        }

        Ok(HandleRtcpResult {
            incoming_key_frame_requests: rtcp.key_frame_requests,
            outgoing_rtx,
            new_target_send_rate,
        })
    }

    /// This must be called regularly (at least every 100ms, preferably more often) to
    /// keep ACKs and NACKs being sent to the client.
    // It would make more sense to return a Vec of packets, since the outgoing address is fixed,
    // but that actually makes it more difficult for sfu.rs to aggregate the
    // results of calling this across many connections.
    // So we use (packet, addr) for convenience.
    pub fn tick(&mut self, packets_to_send: &mut Vec<(PacketToSend, SocketAddr)>, now: Instant) {
        self.send_acks_if_its_been_too_long(packets_to_send, now);
        self.send_nacks_if_its_been_too_long(packets_to_send, now);
    }

    /// If an ICE binding request has been received, a Connection is inactive if it's been more
    /// than "inactivity_timeout" (passed into Connection::new()) since the last ICE binding request.
    /// Otherwise, it's that amount of timeout since the time the Connection was created.
    pub fn inactive(&self, now: Instant) -> bool {
        let last_activity = self.ice.binding_request_received.unwrap_or(self.created);
        now >= last_activity + self.inactivity_timeout
    }

    /// Encrypts the outgoing RTP and potentially adds padding packets.
    /// Sends nothing if there is no outgoing address.
    pub fn send_rtp(
        &mut self,
        outgoing_rtp: rtp::Packet<Vec<u8>>,
        // It would make more sense to return a Vec of packets, since the outgoing address is fixed,
        // but that actually makes it more difficult for sfu.rs to aggregate the
        // results of calling this across many connections.
        // So we use this vec of (packet, addr) for convenience.
        rtp_to_send: &mut Vec<(PacketToSend, SocketAddr)>,
        now: Instant,
    ) {
        let rtp_endpoint = &mut self.rtp.endpoint;
        if let Some(outgoing_addr) = self.outgoing_addr {
            if let Some(outgoing_rtp) = rtp_endpoint.send_rtp(outgoing_rtp, now) {
                rtp_to_send.push((outgoing_rtp.into_serialized(), outgoing_addr));
            }
        }
        self.send_padding_if_its_been_too_long(now, rtp_to_send);
    }

    /// Creates an encrypted key frame request to be sent to
    /// Connection::outgoing_addr().
    /// Will return None if SRTCP encryption fails.
    // TODO: Use Result instead of Option
    pub fn send_key_frame_request(
        &mut self,
        key_frame_request: rtp::KeyFrameRequest,
        // It would make more sense to return Option<Packet>, since the outgoing address is fixed,
        // but that actually makes it more difficult for sfu.rs to aggregate the
        // results of calling this across many connections.
        // So we use (packet, addr) for convenience.
    ) -> Option<(PacketToSend, SocketAddr)> {
        let outgoing_addr = self.outgoing_addr?;
        let rtp_endpoint = &mut self.rtp.endpoint;
        let rtcp_packet = rtp_endpoint.send_pli(key_frame_request.ssrc)?;
        Some((rtcp_packet, outgoing_addr))
    }

    // TODO: Use Result instead of Option
    // It would make more sense to return a Vec of packets, since the outgoing address is fixed,
    // but that actually makes it more difficult for sfu.rs to aggregate the
    // results of calling this across many connections.
    // So we use (packet, addr) for convenience.
    fn send_acks_if_its_been_too_long(
        &mut self,
        packets_to_send: &mut Vec<(PacketToSend, SocketAddr)>,
        now: Instant,
    ) {
        if let Some(acks_sent) = self.rtp.acks_sent {
            if now < acks_sent + ACK_CALCULATION_INTERVAL {
                // We sent ACKs recently. Wait to resend/recalculate them.
                return;
            }
        }

        let rtp_endpoint = &mut self.rtp.endpoint;
        if let Some(outgoing_addr) = self.outgoing_addr {
            for ack_packet in rtp_endpoint.send_acks() {
                packets_to_send.push((ack_packet, outgoing_addr));
            }

            self.rtp.acks_sent = Some(now);
        }
    }

    // It would make more sense to return a Vec of packets, since the outgoing address is fixed,
    // but that actually makes it more difficult for sfu.rs to aggregate the
    // results of calling this across many connections.
    // So we use (packet, addr) for convenience.
    fn send_nacks_if_its_been_too_long(
        &mut self,
        packets_to_send: &mut Vec<(PacketToSend, SocketAddr)>,
        now: Instant,
    ) {
        if let Some(nacks_sent) = self.rtp.nacks_sent {
            if now < nacks_sent + NACK_CALCULATION_INTERVAL {
                // We sent NACKs recently. Wait to resend/recalculate them.
                return;
            }
        }

        let rtp_endpoint = &mut self.rtp.endpoint;
        if let Some(outgoing_addr) = self.outgoing_addr {
            for nack_packet in rtp_endpoint.send_nacks(now) {
                packets_to_send.push((nack_packet, outgoing_addr));
            }

            self.rtp.nacks_sent = Some(now);
        }
    }

    pub fn set_padding_send_rate(
        &mut self,
        padding_send_rate: DataRate,
        padding_ssrc: Option<rtp::Ssrc>,
    ) {
        let expected_padding_packet_size = DataSize::from_bytes(1200);
        // Avoid dividing by 0.
        self.congestion_control.padding_interval = if padding_send_rate > DataRate::default() {
            Some(expected_padding_packet_size / padding_send_rate)
        } else {
            None
        };
        self.congestion_control.padding_ssrc = padding_ssrc;
    }

    pub fn send_request_to_congestion_controller(&mut self, request: googcc::Request) {
        self.congestion_control.controller.request(request)
    }

    fn send_padding_if_its_been_too_long(
        &mut self,
        now: Instant,
        // It would make more sense to return a Vec of packets, since the outgoing address is fixed,
        // but that actually makes it more difficult for sfu.rs to aggregate the
        // results of calling this across many connections.
        // So we use this vec of (packet, addr) for convenience.
        rtp_to_send: &mut Vec<(PacketToSend, SocketAddr)>,
    ) {
        if self.congestion_control.padding_interval.is_none()
            || self.congestion_control.padding_ssrc.is_none()
            || self.outgoing_addr.is_none()
        {
            // If we can't/shouldn't send padding yet, update the "sent" time
            // so that when we can send padding, it's based on the time when we could/should, not
            // on the time from before we could/should.
            self.congestion_control.padding_sent = now;
            return;
        }
        let padding_interval = self.congestion_control.padding_interval.unwrap();
        let padding_ssrc = self.congestion_control.padding_ssrc.unwrap();
        let rtp_endpoint = &mut self.rtp.endpoint;
        let outgoing_addr = self.outgoing_addr.unwrap();

        let missed: Duration = now.saturating_duration_since(self.congestion_control.padding_sent);
        let intervals_missed = missed.as_micros() / padding_interval.as_micros();

        for _ in 0..intervals_missed {
            if let Some(padding) = rtp_endpoint.send_padding(padding_ssrc, now) {
                rtp_to_send.push((padding.into_serialized(), outgoing_addr));
            }
        }

        self.congestion_control.padding_sent += padding_interval * intervals_missed as u32;
    }
}

/// Result of Connection::handle_rtcp_packet().
/// See Connection::handle_rtcp_packet().
pub struct HandleRtcpResult {
    pub incoming_key_frame_requests: Vec<rtp::KeyFrameRequest>,
    // It would make more sense to use a Vec of packets, since the outgoing address is fixed,
    // but that actually makes it more difficult for sfu.rs to aggregate the
    // outgoing packets across many connections.
    // So we use (packet, addr) for convenience.
    pub outgoing_rtx: Vec<(PacketToSend, SocketAddr)>,
    pub new_target_send_rate: Option<DataRate>,
}

#[cfg(test)]
mod connection_tests {
    use std::borrow::Borrow;

    use super::*;
    use crate::{common::Writer, transportcc as tcc};

    fn new_connection(now: Instant) -> Connection {
        let ice_request_username = b"server:client";
        let ice_response_username = b"client:server";
        let ice_pwd = b"the_pwd_should_be_long";
        let ack_ssrc = 0xACC;
        let googcc_config = googcc::Config {
            initial_target_send_rate: DataRate::from_kbps(500),
            ..Default::default()
        };
        let inactivity_timeout = Duration::from_secs(30);
        Connection::new(
            ice_request_username.to_vec(),
            ice_response_username.to_vec(),
            ice_pwd.to_vec(),
            zeroize::Zeroizing::new([0u8; 56]),
            ack_ssrc,
            googcc_config,
            inactivity_timeout,
            now,
        )
    }

    fn new_srtp_keys(seed: u8) -> (rtp::KeysAndSalts, rtp::KeysAndSalts) {
        let decrypt = rtp::KeysAndSalts {
            rtp: rtp::KeyAndSalt {
                key: [seed + 1; rtp::SRTP_KEY_LEN].into(),
                salt: [seed + 2; rtp::SRTP_SALT_LEN],
            },
            rtcp: rtp::KeyAndSalt {
                key: [seed + 3; rtp::SRTP_KEY_LEN].into(),
                salt: [seed + 4; rtp::SRTP_SALT_LEN],
            },
        };
        let encrypt = rtp::KeysAndSalts {
            rtp: rtp::KeyAndSalt {
                key: [seed + 5; rtp::SRTP_KEY_LEN].into(),
                salt: [seed + 6; rtp::SRTP_SALT_LEN],
            },
            rtcp: rtp::KeyAndSalt {
                key: [seed + 7; rtp::SRTP_KEY_LEN].into(),
                salt: [seed + 8; rtp::SRTP_SALT_LEN],
            },
        };
        (decrypt, encrypt)
    }

    fn handle_ice_binding_request(
        connection: &mut Connection,
        client_addr: SocketAddr,
        transaction_id: u128,
        nominated: bool,
        now: Instant,
    ) -> Result<PacketToSend, Error> {
        let transaction_id = transaction_id.to_be_bytes();
        let request_packet = ice::create_binding_request_packet(
            &transaction_id,
            &connection.ice.request_username,
            &connection.ice.pwd,
            nominated,
        );

        let parsed_request = ice::BindingRequest::parse(&request_packet).unwrap();
        connection.handle_ice_binding_request(client_addr, parsed_request, now)
    }

    fn new_encrypted_rtp(
        seqnum: rtp::FullSequenceNumber,
        tcc_seqnum: Option<tcc::FullSequenceNumber>,
        encrypt: &rtp::KeysAndSalts,
    ) -> rtp::Packet<Vec<u8>> {
        let ssrc = 10000;
        let timestamp = 1000;
        // Note: for this to work with the RTX/NACK tests, this has to be a "NACKable" PT.
        let pt = 108;
        let payload = b"payload";
        let mut incoming_rtp =
            rtp::Packet::with_empty_tag(pt, seqnum, timestamp, ssrc, tcc_seqnum, payload);
        incoming_rtp
            .encrypt_in_place(&encrypt.rtp.key, &encrypt.rtp.salt)
            .unwrap();
        incoming_rtp
    }

    fn new_encrypted_rtx_rtp(
        rtx_seqnum: rtp::FullSequenceNumber,
        seqnum: rtp::FullSequenceNumber,
        tcc_seqnum: Option<tcc::FullSequenceNumber>,
        encrypt: &rtp::KeysAndSalts,
    ) -> rtp::Packet<Vec<u8>> {
        // This gets bumped to 10001 in to_rtx() below.
        let ssrc = 10000;
        let timestamp = 1000;
        // Note: for this to work with the RTX/NACK tests, this has to be a "NACKable" PT.
        // This gets bumped to 118 in to_rtx() below.
        let pt = 108;
        let payload = b"payload";
        let incoming_rtp =
            rtp::Packet::with_empty_tag(pt, seqnum, timestamp, ssrc, tcc_seqnum, payload);
        let mut incoming_rtx_rtp = incoming_rtp.to_rtx(rtx_seqnum);
        incoming_rtx_rtp
            .encrypt_in_place(&encrypt.rtp.key, &encrypt.rtp.salt)
            .unwrap();
        incoming_rtx_rtp
    }

    fn decrypt_rtp<T: Borrow<[u8]>>(
        encrypted_rtp: &rtp::Packet<T>,
        decrypt: &rtp::KeysAndSalts,
    ) -> rtp::Packet<Vec<u8>> {
        let mut decrypted_rtp: rtp::Packet<Vec<u8>> = encrypted_rtp.to_owned();
        decrypted_rtp
            .decrypt_in_place(&decrypt.rtp.key, &decrypt.rtp.salt)
            .unwrap();
        decrypted_rtp
    }

    type TccAck = (tcc::FullSequenceNumber, tcc::RemoteInstant);

    fn decrypt_rtcp(
        encrypted_rtcp: &mut [u8],
        encrypt: &rtp::KeysAndSalts,
    ) -> Option<(Vec<TccAck>, Vec<rtp::Nack>)> {
        let rtcp = rtp::ControlPacket::parse_and_decrypt_in_place(
            encrypted_rtcp,
            &encrypt.rtcp.key,
            &encrypt.rtcp.salt,
        )?;
        let acks = rtcp
            .tcc_feedbacks
            .iter()
            .filter_map(|payload| tcc::read_feedback(payload, &mut 0))
            .flat_map(|(_seqnum, acks)| acks)
            .collect::<Vec<_>>();
        Some((acks, rtcp.nacks))
    }

    #[test]
    fn test_ice() {
        let mut now = Instant::now();
        let client_addr1 = "1.2.3.4:5".parse().unwrap();
        let client_addr2 = "6.7.8.9:10".parse().unwrap();

        let mut connection = new_connection(now);

        let mut transaction_id = 0u128;
        let mut handle_request = |connection: &mut Connection,
                                  client_addr: SocketAddr,
                                  nominated: bool,
                                  now: Instant|
         -> Result<(PacketToSend, PacketToSend), Error> {
            transaction_id += 1;
            let actual_response = handle_ice_binding_request(
                connection,
                client_addr,
                transaction_id,
                nominated,
                now,
            )?;
            let transaction_id = transaction_id.to_be_bytes();
            let expected_response = ice::create_binding_response_packet(
                &transaction_id,
                &connection.ice.response_username,
                &connection.ice.pwd,
                nominated,
            );
            Ok((expected_response, actual_response))
        };

        assert_eq!(
            Err(Error::ReceivedIceWithInvalidUsername(
                b"invalid username".to_vec()
            )),
            connection.handle_ice_binding_request(
                client_addr1,
                ice::BindingRequest::parse(&ice::create_binding_request_packet(
                    &1u128.to_be_bytes(),
                    b"invalid username",
                    &connection.ice.pwd,
                    true,
                ))
                .unwrap(),
                now,
            )
        );

        assert_eq!(
            Err(Error::ReceivedIceWithInvalidHmac(vec![
                188, 197, 217, 82, 17, 192, 254, 173, 197, 92, 225, 78, 242, 135, 248, 26, 195,
                241, 184, 110
            ],)),
            connection.handle_ice_binding_request(
                client_addr1,
                ice::BindingRequest::parse(
                    ice::create_binding_request_packet(
                        &1u128.to_be_bytes(),
                        &connection.ice.request_username,
                        b"invalid pwd",
                        true,
                    )
                    .as_slice(),
                )
                .unwrap(),
                now,
            )
        );

        now += Duration::from_secs(60);
        let (actual_response, expected_response) =
            handle_request(&mut connection, client_addr1, true, now).unwrap();
        assert_eq!(expected_response, actual_response);
        assert_eq!(Some(client_addr1), connection.outgoing_addr());
        assert!(!connection.inactive(now));

        now += Duration::from_secs(30);
        assert!(connection.inactive(now));

        now += Duration::from_secs(1);
        let (actual_response, expected_response) =
            handle_request(&mut connection, client_addr2, false, now).unwrap();
        assert_eq!(expected_response, actual_response);
        // The outgoing address didn't change because the request wasn't nominated.
        assert_eq!(Some(client_addr1), connection.outgoing_addr());
        assert!(!connection.inactive(now));

        now += Duration::from_secs(1);
        let (actual_response, expected_response) =
            handle_request(&mut connection, client_addr2, true, now).unwrap();
        assert_eq!(expected_response, actual_response);
        // The outgoing address did change because the request was nominated.
        assert_eq!(Some(client_addr2), connection.outgoing_addr());
        assert!(!connection.inactive(now));

        now += Duration::from_secs(1);
        let (actual_response, expected_response) =
            handle_request(&mut connection, client_addr1, true, now).unwrap();
        assert_eq!(expected_response, actual_response);
        // The outgoing address changes back with a nomination to the original address
        assert_eq!(Some(client_addr1), connection.outgoing_addr());
        assert!(!connection.inactive(now));

        now += Duration::from_secs(30);
        assert!(connection.inactive(now));
    }

    #[test]
    fn test_receive_srtp() {
        let now = Instant::now();
        let mut connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt.clone(), encrypt.clone(), now);

        let encrypted_rtp = new_encrypted_rtp(1, None, &decrypt);
        let expected_decrypted_rtp = decrypt_rtp(&encrypted_rtp, &decrypt);
        assert_eq!(
            expected_decrypted_rtp.to_owned(),
            connection
                .handle_rtp_packet(&mut encrypted_rtp.into_serialized(), now)
                .unwrap()
                .to_owned()
        );

        let encrypted_rtp = new_encrypted_rtp(2, None, &encrypt);
        assert_eq!(
            Err(Error::ReceivedInvalidRtp),
            connection.handle_rtp_packet(&mut encrypted_rtp.into_serialized(), now)
        );

        let encrypted_rtp = new_encrypted_rtx_rtp(5, 2, None, &decrypt);
        let expected_decrypted_rtp = decrypt_rtp(&encrypted_rtp, &decrypt);
        assert_eq!(
            expected_decrypted_rtp.borrow().to_owned(),
            connection
                .handle_rtp_packet(&mut encrypted_rtp.into_serialized(), now)
                .unwrap()
                .to_owned()
        );
    }

    #[test]
    fn test_send_srtp() {
        let now = Instant::now();
        let mut connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt, encrypt.clone(), now);

        let encrypted_rtp = new_encrypted_rtp(2, None, &encrypt);
        let unencrypted_rtp = decrypt_rtp(&encrypted_rtp, &encrypt);

        let mut rtp_to_send = vec![];
        connection.send_rtp(unencrypted_rtp.clone(), &mut rtp_to_send, now);

        // Can't send yet because there is no outgoing address.
        assert_eq!(0, rtp_to_send.len());

        let client_addr = "1.2.3.4:5".parse().unwrap();
        handle_ice_binding_request(&mut connection, client_addr, 1, true, now).unwrap();
        connection.send_rtp(unencrypted_rtp, &mut rtp_to_send, now);

        assert_eq!(
            vec![(encrypted_rtp.into_serialized(), client_addr)],
            rtp_to_send
        );
    }

    #[test]
    fn test_send_srtp_with_padding() {
        let now = Instant::now();
        let at = |ms| now + Duration::from_millis(ms);

        let mut connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt, encrypt.clone(), now);
        let client_addr = "1.2.3.4:5".parse().unwrap();
        handle_ice_binding_request(&mut connection, client_addr, 1, true, now).unwrap();

        let padding_ssrc = 2000u32;
        connection.set_padding_send_rate(DataRate::from_kbps(500), Some(padding_ssrc));

        let encrypted_rtp = new_encrypted_rtp(2, None, &encrypt);
        let unencrypted_rtp = decrypt_rtp(&encrypted_rtp, &encrypt);
        let mut rtp_to_send = vec![];
        // 500kbps * 20ms = 1250 bytes, just enough for a padding packet of around 1200 bytes
        connection.send_rtp(unencrypted_rtp.clone(), &mut rtp_to_send, at(20));
        assert_eq!(2, rtp_to_send.len());
        assert_eq!(
            (encrypted_rtp.clone().into_serialized(), client_addr),
            rtp_to_send[0]
        );
        assert_eq!(1172, rtp_to_send[1].0.len());
        let actual_padding_header = rtp::Header::parse(&rtp_to_send[1].0).unwrap();
        assert_eq!(padding_ssrc, actual_padding_header.ssrc);
        assert_eq!(99, actual_padding_header.payload_type);
        assert_eq!(1136, actual_padding_header.payload_range.len());

        // Don't send padding if the rate is 0.
        connection.set_padding_send_rate(DataRate::from_kbps(0), Some(padding_ssrc));
        let mut rtp_to_send = vec![];
        connection.send_rtp(unencrypted_rtp.clone(), &mut rtp_to_send, at(40));
        assert_eq!(
            vec![(encrypted_rtp.clone().into_serialized(), client_addr)],
            rtp_to_send
        );

        // Don't send padding if the SSRC isn't set.
        connection.set_padding_send_rate(DataRate::from_kbps(500), None);
        let mut rtp_to_send = vec![];
        connection.send_rtp(unencrypted_rtp.clone(), &mut rtp_to_send, at(40));
        assert_eq!(
            vec![(encrypted_rtp.clone().into_serialized(), client_addr)],
            rtp_to_send
        );

        // Can still send some more
        connection.set_padding_send_rate(DataRate::from_kbps(500), Some(padding_ssrc));
        let mut rtp_to_send = vec![];
        connection.send_rtp(unencrypted_rtp, &mut rtp_to_send, at(60));
        assert_eq!(2, rtp_to_send.len());
        assert_eq!(
            (encrypted_rtp.into_serialized(), client_addr),
            rtp_to_send[0]
        );
        assert_eq!(1172, rtp_to_send[1].0.len());
        let actual_padding_header = rtp::Header::parse(&rtp_to_send[1].0).unwrap();
        assert_eq!(padding_ssrc, actual_padding_header.ssrc);
        assert_eq!(99, actual_padding_header.payload_type);
        assert_eq!(1136, actual_padding_header.payload_range.len());
    }

    #[test]
    fn test_send_rtx() {
        let now = Instant::now();
        let at = |ms| now + Duration::from_millis(ms);

        let mut connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt.clone(), encrypt.clone(), now);
        let client_addr = "1.2.3.4:5".parse().unwrap();
        handle_ice_binding_request(&mut connection, client_addr, 1, true, now).unwrap();

        let encrypted_rtp = new_encrypted_rtp(1, None, &encrypt);
        let unencrypted_rtp = decrypt_rtp(&encrypted_rtp, &encrypt);
        let mut rtp_to_send = vec![];
        connection.send_rtp(unencrypted_rtp.clone(), &mut rtp_to_send, at(20));
        assert_eq!(
            vec![(encrypted_rtp.clone().into_serialized(), client_addr)],
            rtp_to_send
        );

        let mut nacks = rtp::ControlPacket::serialize_and_encrypt(
            rtp::RTCP_TYPE_GENERIC_FEEDBACK,
            rtp::RTCP_FORMAT_NACK,
            RTCP_SENDER_SSRC,
            rtp::write_nack(
                encrypted_rtp.ssrc(),
                vec![encrypted_rtp.seqnum()].into_iter(),
            ),
            1,
            &decrypt.rtcp.key,
            &decrypt.rtcp.salt,
        )
        .unwrap();
        let result = connection.handle_rtcp_packet(&mut nacks, now).unwrap();
        let mut expected_rtx = unencrypted_rtp.to_rtx(1);
        expected_rtx
            .encrypt_in_place(&encrypt.rtp.key, &encrypt.rtp.salt)
            .unwrap();
        assert_eq!(
            vec![(expected_rtx.into_serialized(), client_addr)],
            result.outgoing_rtx
        );

        let encrypted_rtp2 = new_encrypted_rtp(2, None, &encrypt);
        let unencrypted_rtp2 = decrypt_rtp(&encrypted_rtp2, &encrypt);
        let mut rtp_to_send = vec![];
        connection.send_rtp(unencrypted_rtp2.clone(), &mut rtp_to_send, at(40));
        assert_eq!(
            vec![(encrypted_rtp2.clone().into_serialized(), client_addr)],
            rtp_to_send
        );

        // The first one is resent again, and the second one is sent for the first time.
        let mut nacks2 = rtp::ControlPacket::serialize_and_encrypt(
            rtp::RTCP_TYPE_GENERIC_FEEDBACK,
            rtp::RTCP_FORMAT_NACK,
            RTCP_SENDER_SSRC,
            rtp::write_nack(
                encrypted_rtp.ssrc(),
                vec![encrypted_rtp.seqnum(), encrypted_rtp2.seqnum()].into_iter(),
            ),
            2,
            &decrypt.rtcp.key,
            &decrypt.rtcp.salt,
        )
        .unwrap();
        let result = connection.handle_rtcp_packet(&mut nacks2, now).unwrap();
        let mut expected_rtx = unencrypted_rtp.to_rtx(2);
        expected_rtx
            .encrypt_in_place(&encrypt.rtp.key, &encrypt.rtp.salt)
            .unwrap();
        let mut expected_rtx2 = unencrypted_rtp2.to_rtx(3);
        expected_rtx2
            .encrypt_in_place(&encrypt.rtp.key, &encrypt.rtp.salt)
            .unwrap();
        assert_eq!(
            vec![
                (expected_rtx.into_serialized(), client_addr),
                (expected_rtx2.into_serialized(), client_addr)
            ],
            result.outgoing_rtx
        );
    }

    #[test]
    fn test_send_acks_and_nacks() {
        let now = Instant::now();
        let at = |ms| now + Duration::from_millis(ms);

        let mut connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt.clone(), encrypt.clone(), now);

        connection
            .handle_rtp_packet(
                &mut new_encrypted_rtp(1, Some(101), &decrypt).into_serialized(),
                at(1),
            )
            .unwrap();

        connection
            .handle_rtp_packet(
                &mut new_encrypted_rtp(3, Some(103), &decrypt).into_serialized(),
                at(3),
            )
            .unwrap();

        let mut packets_to_send = vec![];

        // Can't send yet because there is no outgoing address.
        connection.tick(&mut packets_to_send, at(4));
        assert_eq!(0, packets_to_send.len());

        let client_addr = "1.2.3.4:5".parse().unwrap();
        handle_ice_binding_request(&mut connection, client_addr, 1, true, at(5)).unwrap();
        assert_eq!(Some(client_addr), connection.outgoing_addr());

        // Now we can send ACKs and NACKs
        connection.tick(&mut packets_to_send, at(6));
        assert_eq!(2, packets_to_send.len());

        let expected_acks = vec![
            (101u64, tcc::RemoteInstant::from_millis(1)),
            (103u64, tcc::RemoteInstant::from_millis(3)),
        ];
        let (actual_acks, actual_nacks) =
            decrypt_rtcp(&mut packets_to_send[0].0, &encrypt).unwrap();
        assert_eq!(client_addr, packets_to_send[0].1);
        assert_eq!(expected_acks, actual_acks);
        assert_eq!(0, actual_nacks.len());

        let expected_nacks = vec![rtp::Nack {
            ssrc: 10000,
            seqnums: vec![2],
        }];
        let (actual_acks, actual_nacks) =
            decrypt_rtcp(&mut packets_to_send[1].0, &encrypt).unwrap();
        assert_eq!(client_addr, packets_to_send[1].1);
        assert_eq!(expected_nacks, actual_nacks);
        assert_eq!(0, actual_acks.len());

        // We resend NACKs but not acks
        connection.tick(&mut packets_to_send, at(1000));
        assert_eq!(3, packets_to_send.len());
        assert_eq!(client_addr, packets_to_send[2].1);
        let (actual_acks, actual_nacks) =
            decrypt_rtcp(&mut packets_to_send[2].0, &encrypt).unwrap();
        assert_eq!(expected_nacks, actual_nacks);
        assert_eq!(0, actual_acks.len());

        // But once the NACKed packet is received, we stop NACKing it
        connection
            .handle_rtp_packet(
                &mut new_encrypted_rtp(2, Some(102), &decrypt).into_serialized(),
                at(10002),
            )
            .unwrap();
        connection.tick(&mut packets_to_send, at(1000));
        assert_eq!(3, packets_to_send.len());
    }

    #[test]
    fn test_send_key_frame_requests() {
        let now = Instant::now();

        let mut connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt, encrypt.clone(), now);
        let client_addr = "1.2.3.4:5".parse().unwrap();
        handle_ice_binding_request(&mut connection, client_addr, 1, true, now).unwrap();

        let ssrc = 10;
        let (mut encrypted_rtcp, outgoing_addr) = connection
            .send_key_frame_request(rtp::KeyFrameRequest { ssrc })
            .unwrap();
        let rtcp = rtp::ControlPacket::parse_and_decrypt_in_place(
            &mut encrypted_rtcp,
            &encrypt.rtcp.key,
            &encrypt.rtcp.salt,
        )
        .unwrap();

        assert_eq!(client_addr, outgoing_addr);
        assert_eq!(vec![rtp::KeyFrameRequest { ssrc }], rtcp.key_frame_requests);
    }

    #[test]
    fn test_receive_key_frame_requests() {
        let now = Instant::now();

        let mut connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt.clone(), encrypt, now);

        let ssrc = 1000u32;
        let mut rtcp = rtp::ControlPacket::serialize_and_encrypt(
            rtp::RTCP_TYPE_SPECIFIC_FEEDBACK,
            rtp::RTCP_FORMAT_PLI,
            RTCP_SENDER_SSRC,
            ssrc,
            1,
            &decrypt.rtcp.key,
            &decrypt.rtcp.salt,
        )
        .unwrap();

        let result = connection.handle_rtcp_packet(&mut rtcp, now).unwrap();
        assert_eq!(
            vec![rtp::KeyFrameRequest { ssrc }],
            result.incoming_key_frame_requests
        );
    }

    #[test]
    fn test_receive_acks() {
        let now = Instant::now();
        let at = |ms| now + Duration::from_millis(ms);

        let mut connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt.clone(), encrypt.clone(), now);
        let client_addr = "1.2.3.4:5".parse().unwrap();
        handle_ice_binding_request(&mut connection, client_addr, 1, true, now).unwrap();

        for seqnum in 1..=25 {
            let sent = at(10 * seqnum);
            let received = at(10 * (seqnum + 1));

            let encrypted_rtp = new_encrypted_rtp(seqnum, Some(seqnum), &encrypt);
            let unencrypted_rtp = decrypt_rtp(&encrypted_rtp, &encrypt);
            connection.send_rtp(unencrypted_rtp, &mut vec![], sent);

            let mut acks = rtp::ControlPacket::serialize_and_encrypt(
                rtp::RTCP_TYPE_GENERIC_FEEDBACK,
                rtp::RTCP_FORMAT_TRANSPORT_CC,
                RTCP_SENDER_SSRC,
                tcc::write_feedback(10000, &mut 0, now, vec![(seqnum, received)].into_iter())
                    .collect::<Vec<_>>(),
                1,
                &decrypt.rtcp.key,
                &decrypt.rtcp.salt,
            )
            .unwrap();
            let result = connection.handle_rtcp_packet(&mut acks, now).unwrap();

            let expected_new_target_send_rate = match seqnum {
                3 => Some(501),
                22 => Some(502),
                23 => Some(503),
                24 => Some(504),
                25 => Some(505),
                _ => None,
            }
            .map(DataRate::from_kbps);
            assert_eq!(
                expected_new_target_send_rate, result.new_target_send_rate,
                "failed at seqnum {}",
                seqnum
            );
        }

        // Cap the target send rate by a new ideal send rate.
        connection.send_request_to_congestion_controller(googcc::Request {
            base: DataRate::from_kbps(100),
            ideal: DataRate::from_kbps(250),
        });

        for seqnum in 26..=35 {
            let sent = at(10 * seqnum);
            let received = at(10 * (seqnum + 1));

            let encrypted_rtp = new_encrypted_rtp(seqnum, Some(seqnum), &encrypt);
            let unencrypted_rtp = decrypt_rtp(&encrypted_rtp, &encrypt);
            connection.send_rtp(unencrypted_rtp, &mut vec![], sent);

            let mut acks = rtp::ControlPacket::serialize_and_encrypt(
                rtp::RTCP_TYPE_GENERIC_FEEDBACK,
                rtp::RTCP_FORMAT_TRANSPORT_CC,
                RTCP_SENDER_SSRC,
                tcc::write_feedback(10000, &mut 0, now, vec![(seqnum, received)].into_iter())
                    .collect::<Vec<_>>(),
                1,
                &decrypt.rtcp.key,
                &decrypt.rtcp.salt,
            )
            .unwrap();
            let result = connection.handle_rtcp_packet(&mut acks, now).unwrap();

            assert_eq!(
                Some(DataRate::from_kbps(375)),
                result.new_target_send_rate,
                "failed at seqnum {}",
                seqnum
            );
        }

        // Uncap the target send rate by a new ideal send rate.
        connection.send_request_to_congestion_controller(googcc::Request {
            base: DataRate::from_kbps(100),
            ideal: DataRate::from_kbps(1000),
        });

        for seqnum in 36..=40 {
            let sent = at(10 * seqnum);
            let received = at(10 * (seqnum + 1));

            let encrypted_rtp = new_encrypted_rtp(seqnum, Some(seqnum), &encrypt);
            let unencrypted_rtp = decrypt_rtp(&encrypted_rtp, &encrypt);
            connection.send_rtp(unencrypted_rtp, &mut vec![], sent);
            let mut acks = rtp::ControlPacket::serialize_and_encrypt(
                rtp::RTCP_TYPE_GENERIC_FEEDBACK,
                rtp::RTCP_FORMAT_TRANSPORT_CC,
                RTCP_SENDER_SSRC,
                tcc::write_feedback(10000, &mut 0, now, vec![(seqnum, received)].into_iter())
                    .collect::<Vec<_>>(),
                1,
                &decrypt.rtcp.key,
                &decrypt.rtcp.salt,
            )
            .unwrap();
            let result = connection.handle_rtcp_packet(&mut acks, now).unwrap();

            let expected_new_target_send_rate = match seqnum {
                36 => Some(501),
                37 => Some(502),
                38 => Some(503),
                39 => Some(504),
                40 => Some(505),
                _ => None,
            }
            .map(DataRate::from_kbps);
            assert_eq!(
                expected_new_target_send_rate, result.new_target_send_rate,
                "failed at seqnum {}",
                seqnum
            );
        }
    }
}
