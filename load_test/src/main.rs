//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#[macro_use]
extern crate log;

use std::{
    cmp::{max, min},
    collections::HashSet,
    env::{self, VarError},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    ops::DerefMut,
    process::{self, exit},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Once,
    },
    thread::sleep,
    time::SystemTime,
};

use anyhow::{anyhow, Context, Result};
use byteorder::{BigEndian, ByteOrder};
use calling_backend::{
    call::{DemuxIdExt, CLIENT_SERVER_DATA_PAYLOAD_TYPE, CLIENT_SERVER_DATA_SSRC},
    ice::{self, BindingRequest, BindingResponse, StunPacketBuilder, TransactionId},
    protos::{
        device_to_sfu::{video_request_message::VideoRequest, VideoRequestMessage},
        DeviceToSfu,
    },
    rtp::{self, new_master_key_material, Packet, OPUS_PAYLOAD_TYPE},
    transportcc::Ack,
    *,
};
use calling_common::{DemuxId, Duration, Instant, PixelSize};
use calling_frontend::api::v2::{JoinRequest, JoinResponse};
use env_logger::Env;
use hex::{FromHex, ToHex};
use hkdf::Hkdf;
use itertools::Itertools;
use mrp::{self, MrpStream};
use prost::Message;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

const MAX_MRP_WINDOW_SIZE: usize = 256;
const PING_INTERVAL: Duration = Duration::from_secs(5);
const AUDIO_INTERVAL: Duration = Duration::from_millis(60);
const VIDEO_INTERVAL: Duration = Duration::from_millis(33);
const ACK_INTERVAL: Duration = Duration::from_millis(100);
const HEIGHT_REQUEST_INTERVAL: Duration = Duration::from_millis(1000);
const REPORT_INTERVAL: Duration = Duration::from_millis(500);
const RATE_LIMIT_INTERVAL: Duration = Duration::from_millis(1000);
const RATE_LIMITER_SLOP_TIME: Duration = Duration::from_millis(25);
const LOST_PING_LIMIT: usize = 5;

fn main() -> Result<()> {
    // Initialize logging.
    env_logger::Builder::from_env(
        Env::default()
            .default_filter_or("load_test=trace")
            .default_write_style_or("never"),
    )
    .format(calling_common::format_log_line)
    .init();

    let args: Vec<String> = env::args().collect();

    info!("Signal Calling load testing starting up...");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    if args.len() != 3 {
        error!("URL is mandatory: {} http://example.org:80 token", args[0]);
        exit(1);
    }
    let url = args[1].to_owned();
    let token = &args[2];

    let uri = format!("{}/v2/conference/participants", url);
    let ice_client_ufrag = ice::random_ufrag();
    let ice_client_pwd = ice::random_pwd();
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_dhe_public_key = PublicKey::from(&client_secret).to_bytes();
    let hkdf_extra_info = [0u8; 0];

    let join_request = JoinRequest {
        admin_passkey: None,
        ice_ufrag: ice_client_ufrag.to_string(),
        ice_pwd: ice_client_pwd.to_string(),
        dhe_public_key: client_dhe_public_key.encode_hex(),
        hkdf_extra_info: None,
    };

    info!("joining via PUT {}", uri);
    let uuid = token.split(':').next().unwrap();

    let client = reqwest::blocking::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()?;
    let response = client
        .put(uri)
        .header("User-Agent", "Signal-Internal")
        .basic_auth(uuid, Some(token))
        .json(&join_request)
        .send()?;
    if !response.status().is_success() {
        error!("expected success, got {:?}", response);
        error!("body {:?}", response.text());
        exit(1);
    }
    let join_response: JoinResponse = response
        .json()
        .context("failed to convert body to join response")?;

    info!("join response {:?}", join_response);

    let demux_id = DemuxId::try_from(join_response.demux_id)?;
    let ice_server_ufrag = join_response.ice_ufrag;
    let ice_server_pwd = join_response.ice_pwd.into_bytes();
    let ice_client_pwd = ice_client_pwd.into_bytes();

    let ice_server_username =
        ice::join_username(ice_client_ufrag.as_bytes(), ice_server_ufrag.as_bytes());
    let ice_client_username =
        ice::join_username(ice_server_ufrag.as_bytes(), ice_client_ufrag.as_bytes());

    let server_dhe_public_key = match <[u8; 32]>::from_hex(join_response.dhe_public_key) {
        Ok(server_dhe_public_key) => server_dhe_public_key,
        Err(_) => {
            error!("Invalid dhe_public_key in the response.");
            exit(1);
        }
    };

    let server_ip: IpAddr = join_response.ips[0].parse()?;
    let server_addr = SocketAddr::new(server_ip, join_response.port);
    let bind_addr = if server_ip.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(server_addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(1).into()))?;
    let now = Instant::now();

    let shared_secret = client_secret.diffie_hellman(&PublicKey::from(server_dhe_public_key));
    let mut srtp_master_key_material = new_master_key_material();
    Hkdf::<Sha256>::new(None, shared_secret.as_bytes())
        .expand_multi_info(
            &[
                b"Signal_Group_Call_20211105_SignallingDH_SRTPKey_KDF",
                &hkdf_extra_info[..],
            ],
            srtp_master_key_material.deref_mut(),
        )
        .expect("Expand SRTP master key material");

    // Note: encrypt and decrypt flipped from server
    let (encrypt, decrypt) = rtp::KeysAndSalts::derive_client_and_server_from_master_key_material(
        &srtp_master_key_material,
    );

    let mut endpoint = rtp::Endpoint::new(
        decrypt,
        encrypt,
        now,
        0,
        call::LayerId::Video0.to_ssrc(demux_id),
    );

    let mut mrp_stream: MrpStream<protos::DeviceToSfu, protos::SfuToDevice> =
        MrpStream::with_capacity_limit(MAX_MRP_WINDOW_SIZE);

    let audio_ssrc = call::LayerId::Audio.to_ssrc(demux_id);
    let video0_ssrc = call::LayerId::Video0.to_ssrc(demux_id);
    let video1_ssrc = call::LayerId::Video1.to_ssrc(demux_id);
    let video2_ssrc = call::LayerId::Video2.to_ssrc(demux_id);

    let video0_size = PixelSize {
        width: 160,
        height: 120,
    };
    let video1_size = PixelSize {
        width: 320,
        height: 240,
    };
    let video2_size = PixelSize {
        width: 640,
        height: 480,
    };

    let mut last_ping_sent = now - PING_INTERVAL;
    let mut last_audio_sent = now - AUDIO_INTERVAL;
    let mut last_video_sent = now - VIDEO_INTERVAL;
    let mut last_ack_sent = now - ACK_INTERVAL;
    let mut last_height_request_sent = now;
    let mut height_refresh = false;
    let mut last_stats_report = now;
    let mut last_rate_limit = now;

    let mut is_least_demux_id = false;

    let mut lost_pings = 0;
    let mut last_transaction_id = TransactionId::new();
    let mut audio_sequence = 0;
    let mut frame = 0;
    let mut video0_sequence = 0;
    let mut video1_sequence = 0;
    let mut video2_sequence = 0;
    let mut client_server_sequence = 0;

    let mut active_demux_ids = HashSet::new();

    let mut estimator = Estimator::new();
    let mut stats = Stats::new();

    let mut out_buf = [0u8; 1500];

    let mut buf = [0u8; 1500];
    let mut is_key_frame = false;

    // (server randomized) demux_id based sleep so all the test clients don't live in lock step
    sleep(std::time::Duration::from_millis(
        (u32::from(demux_id) >> 23).into(),
    ));

    let scenario: &dyn Scenario = match env::var("SCENARIO") {
        Ok(s) => match s.as_str() {
            "periodic" => &Periodic::default(),
            "pipunpip" => &PipUnpip::default(),
            "pipunpip_bwlimit" => &PipUnpipBWLimit::default(),
            "unlimited" => &Unlimited::default(),
            s => {
                error!("unknown scenario: {}", s);
                exit(1);
            }
        },
        Err(VarError::NotPresent) => {
            error!("environment variable SCENARIO must be set");
            exit(1);
        }
        Err(e) => {
            error!("error when retreiving environment variable SCENARIO: {}", e);
            exit(1);
        }
    };

    info!("using Scenario: {}", scenario.name());

    let mut rate_limiter = RateLimiter::new(Instant::now());

    while running.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now.saturating_duration_since(last_ping_sent) >= PING_INTERVAL {
            lost_pings += 1;
            if lost_pings > LOST_PING_LIMIT {
                error!("{} pings lost, server is probably dead", LOST_PING_LIMIT);
                exit(1);
            }
            last_transaction_id = TransactionId::new();
            let request = StunPacketBuilder::new_binding_request(&last_transaction_id)
                .set_username(&ice_server_username)
                .build(&ice_server_pwd);

            socket.send(&request)?;
            last_ping_sent = now;
        }
        if now.saturating_duration_since(last_audio_sent) >= AUDIO_INTERVAL {
            let truncated_ntp = (ntp_now() >> 16) as u32;
            BigEndian::write_u32(&mut out_buf[0..4], truncated_ntp);

            let packet = Packet::with_empty_tag(
                OPUS_PAYLOAD_TYPE,
                audio_sequence,
                truncated_ntp,
                audio_ssrc,
                None,
                None,
                &out_buf[0..300],
            );
            if let Some(packet) = endpoint.send_rtp(packet, now) {
                audio_sequence = audio_sequence.wrapping_add(1);
                socket.send(&packet.into_serialized())?;
                last_audio_sent = now;
            } else {
                error!("no audio");
                exit(1);
            }
        }

        if now.saturating_duration_since(last_video_sent) >= VIDEO_INTERVAL {
            // Send ~ 30 fps
            // Send 1x ~  400 byte video0 frame  ~ 100kbps
            // Send 1x ~ 1100 byte video1 frame  ~ 300kbps
            // Send 2x ~ 1100 byte video2 frames ~ 600kbps
            // No pacing

            let truncated_ntp = (ntp_now() >> 16) as u32;
            BigEndian::write_u32(&mut out_buf[0..4], truncated_ntp);

            let packets = [
                Packet::dummy_video(
                    video0_sequence,
                    video0_ssrc,
                    frame,
                    Some(video0_size),
                    is_key_frame,
                    truncated_ntp,
                    &out_buf[0..400],
                ),
                Packet::dummy_video(
                    video1_sequence,
                    video1_ssrc,
                    frame,
                    Some(video1_size),
                    is_key_frame,
                    truncated_ntp,
                    &out_buf[0..1100],
                ),
                Packet::dummy_video(
                    video2_sequence,
                    video2_ssrc,
                    frame,
                    Some(video2_size),
                    is_key_frame,
                    truncated_ntp,
                    &out_buf[0..1100],
                ),
                Packet::dummy_video(
                    video2_sequence + 1,
                    video2_ssrc,
                    frame,
                    None,
                    false,
                    truncated_ntp,
                    &out_buf[0..1100],
                ),
            ];

            video0_sequence = video0_sequence.wrapping_add(1);
            video1_sequence = video1_sequence.wrapping_add(1);
            video2_sequence = video2_sequence.wrapping_add(2);

            for packet in packets {
                if let Some(packet) = endpoint.send_rtp(packet, now) {
                    endpoint.remember_sent(&packet, now);
                    socket.send(&packet.into_serialized())?;
                } else {
                    error!("no video");
                    exit(1);
                }
            }

            frame = frame.wrapping_add(1);
            last_video_sent = now;
            is_key_frame = false;
        }

        if now.saturating_duration_since(last_ack_sent) >= ACK_INTERVAL {
            for payload in endpoint.send_acks() {
                socket.send(&payload)?;
            }
            last_ack_sent = now;
        }

        if height_refresh
            || now.saturating_duration_since(last_height_request_sent) >= HEIGHT_REQUEST_INTERVAL
        {
            height_refresh = false;
            if let Some(first) = active_demux_ids.iter().cloned().sorted().next() {
                if demux_id < first {
                    if !is_least_demux_id {
                        error!("lowest demux {} {:?}", process::id(), demux_id);
                        stats.start(now);
                        last_rate_limit = now - RATE_LIMIT_INTERVAL;
                    }
                    is_least_demux_id = true;
                } else {
                    if is_least_demux_id {
                        error!(
                            "not lowest demux {} {:?} > {:?}",
                            process::id(),
                            demux_id,
                            first
                        );
                    }

                    is_least_demux_id = false;
                }
            }

            let msg = match scenario.want_video(is_least_demux_id, stats.seconds_since_start(now)) {
                WantVideo::PiP => {
                    let mut active = active_demux_ids.iter().cloned().sorted();
                    let mut requests = Vec::with_capacity(active_demux_ids.len());
                    if let Some(first) = active.next() {
                        requests.push(VideoRequest {
                            height: Some(1),
                            demux_id: Some(first.into()),
                        });
                    }
                    requests.extend(active.map(|demux_id| VideoRequest {
                        height: Some(0),
                        demux_id: Some(demux_id.into()),
                    }));

                    DeviceToSfu {
                        video_request: Some(VideoRequestMessage {
                            requests,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }
                }
                WantVideo::All => DeviceToSfu {
                    video_request: Some(VideoRequestMessage {
                        requests: active_demux_ids
                            .iter()
                            .map(|demux_id| VideoRequest {
                                height: Some(480),
                                demux_id: Some((*demux_id).into()),
                            })
                            .collect(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                WantVideo::None => DeviceToSfu {
                    video_request: Some(VideoRequestMessage {
                        requests: active_demux_ids
                            .iter()
                            .map(|demux_id| VideoRequest {
                                height: Some(0),
                                demux_id: Some((*demux_id).into()),
                            })
                            .collect(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            };

            let packet = Packet::with_empty_tag(
                CLIENT_SERVER_DATA_PAYLOAD_TYPE,
                client_server_sequence,
                0,
                CLIENT_SERVER_DATA_SSRC,
                None,
                None,
                &msg.encode_to_vec(),
            );
            if let Some(packet) = endpoint.send_rtp(packet, now) {
                client_server_sequence = client_server_sequence.wrapping_add(1);
                socket.send(&packet.into_serialized())?;
                last_height_request_sent = now;
            } else {
                error!("no height request");
                exit(1);
            }

            let _ = mrp_stream.try_send_ack(|header| {
                let ack = protos::DeviceToSfu {
                    mrp_header: Some(header.into()),
                    ..Default::default()
                };

                let packet = Packet::with_empty_tag(
                    CLIENT_SERVER_DATA_PAYLOAD_TYPE,
                    client_server_sequence,
                    0,
                    CLIENT_SERVER_DATA_SSRC,
                    None,
                    None,
                    &ack.encode_to_vec(),
                );
                if let Some(packet) = endpoint.send_rtp(packet, now) {
                    client_server_sequence = client_server_sequence.wrapping_add(1);
                    socket.send(&packet.into_serialized())?;
                    Ok(())
                } else {
                    error!("mrp ack send failed");
                    exit(1);
                }
            });
        }

        if now.saturating_duration_since(last_stats_report) >= REPORT_INTERVAL {
            if is_least_demux_id {
                stats.report(now, rate_limiter.delay(now));
            }
            last_stats_report = now;
        }

        if now.saturating_duration_since(last_rate_limit) >= RATE_LIMIT_INTERVAL {
            if is_least_demux_id {
                rate_limiter.limit(scenario.limit_kbps(stats.seconds_since_start(now)));
            } else {
                rate_limiter.limit(None);
            }
        }

        if let Ok(len) = rate_limiter.recv(&socket, Instant::now(), &mut buf) {
            let now = Instant::now();
            let incoming_packet = &mut buf[0..len];
            stats.bytes_total += len;
            if rtp::looks_like_rtp(incoming_packet) {
                match endpoint.receive_rtp(incoming_packet, now) {
                    Some(packet) => {
                        let truncated_ntp_now = (ntp_now() >> 16) as u32;
                        let timestamp = BigEndian::read_u32(packet.payload());
                        let time_diff = truncated_ntp_now.wrapping_sub(timestamp);

                        if packet.is_video() {
                            let demux_id = DemuxId::from_ssrc(packet.ssrc());
                            if !active_demux_ids.contains(&demux_id) {
                                height_refresh = true;
                                active_demux_ids.insert(demux_id);
                            }
                            stats.bytes_video += len;
                            stats.video_delay.push(time_diff);
                        } else if packet.is_audio() {
                            stats.bytes_audio += len;
                            stats.audio_delay.push(time_diff);
                        } else if packet.ssrc() == CLIENT_SERVER_DATA_SSRC
                            && packet.payload_type() == CLIENT_SERVER_DATA_PAYLOAD_TYPE
                        {
                            if let Ok(proto) = protos::SfuToDevice::decode(packet.payload()) {
                                let ready = if let Some(mrp_header) = proto.mrp_header.as_ref() {
                                    match mrp_stream.receive_and_merge(&mrp_header.into(), proto) {
                                        Ok(ready_protos) => ready_protos,
                                        Err(e) => {
                                            // received a malformed header, drop packet
                                            error!("invalid mrp header {}", e);
                                            vec![]
                                        }
                                    }
                                } else {
                                    vec![proto]
                                };

                                for proto in ready {
                                    if let Some(current_devices) = proto.current_devices {
                                        stats.layer0 = 0;
                                        stats.layer1 = 0;
                                        stats.layer2 = 0;

                                        for height in current_devices.allocated_heights {
                                            if height == 120 {
                                                stats.layer0 += 1;
                                            } else if height == 240 {
                                                stats.layer1 += 1;
                                            } else if height == 480 {
                                                stats.layer2 += 1;
                                            } else {
                                                error!("weird height {}", height);
                                            }
                                        }

                                        for demux_id in current_devices.demux_ids_with_video {
                                            let demux_id = DemuxId::from_const(demux_id);
                                            if !active_demux_ids.contains(&demux_id) {
                                                height_refresh = true;
                                                active_demux_ids.insert(demux_id);
                                            }
                                        }
                                    } else {
                                        error!("weird proto {:?}", proto);
                                    }

                                    if let Some(server_stats) = proto.stats {
                                        stats.target_kbps =
                                            server_stats.target_send_rate_kbps.unwrap_or_default();
                                        stats.ideal_kbps =
                                            server_stats.ideal_send_rate_kbps.unwrap_or_default();
                                        stats.allocated_kbps = server_stats
                                            .allocated_send_rate_kbps
                                            .unwrap_or_default();
                                    }
                                }
                            }
                        } else if packet.is_padding() {
                            stats.bytes_padding += len;
                        } else {
                            todo!("unknown packet {:?}", packet);
                        }
                    }
                    None => {
                        stats.bytes_discard += len;
                    }
                }
            } else if rtp::looks_like_rtcp(incoming_packet) {
                let rtcp = endpoint.receive_rtcp(incoming_packet, now).unwrap();

                //error!("rtcp in {:?}", rtcp);
                if !rtcp.key_frame_requests.is_empty() {
                    is_key_frame = true;
                    //error!("key frame request: {:?}", rtcp.key_frame_requests);
                }
                if !rtcp.acks.is_empty() {
                    estimator.update(&rtcp.acks);
                }
            } else if let Some(binding_request) = BindingRequest::try_from_buffer(incoming_packet)?
            {
                let username = binding_request.username().unwrap();
                if username != ice_client_username {
                    error!("unexpected username");
                    exit(1);
                }
                binding_request.verify_integrity(&ice_client_pwd)?;
                let response =
                    StunPacketBuilder::new_binding_response(&binding_request.transaction_id())
                        .set_username(&ice_server_username)
                        .set_xor_mapped_address(&server_addr)
                        .build(&ice_client_pwd);

                socket.send(&response)?;
            } else if let Some(binding_response) =
                BindingResponse::try_from_buffer(incoming_packet)?
            {
                let username = binding_response.username().unwrap();
                if username != ice_client_username {
                    error!("unexpected username");
                    exit(1);
                }
                binding_response.verify_integrity(&ice_server_pwd)?;
                if binding_response.transaction_id() == last_transaction_id {
                    lost_pings = 0;
                }
            } else {
                error!("else");
            }
        }
    }

    for _ in 0..2 {
        info!("sending Leave");
        let proto = protos::DeviceToSfu {
            leave: Some(protos::device_to_sfu::LeaveMessage {}),
            ..Default::default()
        };
        let packet = Packet::with_empty_tag(
            CLIENT_SERVER_DATA_PAYLOAD_TYPE,
            audio_sequence,
            0,
            CLIENT_SERVER_DATA_SSRC,
            None,
            None,
            proto.encode_to_vec().as_slice(),
        );
        if let Some(packet) = endpoint.send_rtp(packet, now) {
            socket.send(&packet.into_serialized())?;
            sleep(Duration::from_millis(100).into());
        } else {
            error!("couldn't leave");
        }
    }
    info!("exiting...");
    Ok(())
}

struct Estimator {}

impl Estimator {
    fn new() -> Self {
        Self {}
    }
    fn update(&mut self, _: &[Ack]) {}
}

const UNIX_EPOCH_IN_NTP_SECONDS: u32 = 2_208_988_800; //RFC 5905 Figure 4

fn ntp_now() -> u64 {
    // NTP timestamp is fixed point 32 bits of seconds, 32 bit fractional second
    let since_unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let seconds = (since_unix.as_secs() as u32).wrapping_add(UNIX_EPOCH_IN_NTP_SECONDS);
    let fraction: u64 = ((since_unix.subsec_nanos() as u64) << 32) / 1_000_000_000;
    ((seconds as u64) << 32) | fraction
}
#[derive(Default)]
struct Stats {
    bytes_total: usize,
    bytes_audio: usize,
    bytes_video: usize,
    bytes_padding: usize,
    bytes_discard: usize,

    video_delay: Vec<u32>,

    audio_delay: Vec<u32>,

    layer0: u32,
    layer1: u32,
    layer2: u32,

    target_kbps: u32,
    ideal_kbps: u32,
    allocated_kbps: u32,
    start: Option<Instant>,
    last_report: Option<Instant>,
}

fn min_max_avg(vec: &Vec<u32>) -> (u32, u32, u64) {
    let mut min_v = u32::MAX;
    let mut max_v = 0;
    let mut total: u64 = 0;
    let count = vec.len() as u64;
    if count == 0 {
        return (0, 0, 0);
    }

    for v in vec {
        min_v = min(min_v, *v);
        max_v = max(max_v, *v);
        total += *v as u64;
    }
    (min_v, max_v, total / count)
}

static CSV_HEADER: Once = Once::new();
impl Stats {
    fn new() -> Self {
        Self {
            last_report: Some(Instant::now()),
            ..Default::default()
        }
    }

    fn start(&mut self, now: Instant) {
        self.start = Some(now);
        self.last_report = Some(now);
        self.bytes_total = 0;
        self.bytes_audio = 0;
        self.bytes_video = 0;
        self.bytes_padding = 0;
        self.bytes_discard = 0;
    }

    fn seconds_since_start(&self, now: Instant) -> u64 {
        if let Some(start) = self.start {
            now.saturating_duration_since(start).as_secs()
        } else {
            0
        }
    }

    fn report(&mut self, now: Instant, rate_limit_delay: f64) {
        let (video_delay_min, video_delay_max, video_delay_avg) = min_max_avg(&self.video_delay);
        let (audio_delay_min, audio_delay_max, audio_delay_avg) = min_max_avg(&self.audio_delay);

        let time = now
            .saturating_duration_since(self.start.unwrap_or(now))
            .as_secs_f64();

        let interval = match now
            .saturating_duration_since(self.last_report.unwrap_or(now))
            .as_secs_f64()
        {
            0.0 => REPORT_INTERVAL.as_secs_f64(),
            i => i,
        };

        CSV_HEADER.call_once(|| {
            println!(
                "{}",
                [
                    "time",
                    "process_id",
                    "rate_limit_delay_ms",
                    "inbound_total_kbps",
                    "inbound_audio_kbps",
                    "inbound_video_kbps",
                    "inbound_padding_kbps",
                    "inbound_discard_kbps",
                    "video_delay_avg",
                    "video_delay_min",
                    "video_delay_max",
                    "audio_delay_avg",
                    "audio_delay_min",
                    "audio_delay_max",
                    "layer0_count",
                    "layer1_count",
                    "layer2_count",
                    "target_kbps",
                    "ideal_kbps",
                    "allocated_kbps"
                ]
                .join(",")
            );
        });

        println!(
            "{:.3},{},{:.0},{:.0},{:.0},{:.0},{:.0},{:.0},{:.0},{:.0},{:.0},{:.0},{:.0},{:.0},{},{},{},{},{},{}",
            time,
            process::id(),
            rate_limit_delay * 1000.0,
            (self.bytes_total as f64) * 8.0 / 1000.0 / interval,
            (self.bytes_audio as f64) * 8.0 / 1000.0 / interval,
            (self.bytes_video as f64) * 8.0 / 1000.0 / interval,
            (self.bytes_padding as f64) * 8.0 / 1000.0 / interval,
            (self.bytes_discard as f64)  * 8.0 / 1000.0 / interval,
            (video_delay_avg as f64) / 65.536,
            (video_delay_min as f64) / 65.536,
            (video_delay_max as f64) / 65.536,
            (audio_delay_avg as f64) / 65.536,
            (audio_delay_min as f64) / 65.536,
            (audio_delay_max as f64) / 65.536,
            self.layer0,
            self.layer1,
            self.layer2,
            self.target_kbps,
            self.ideal_kbps,
            self.allocated_kbps,
        );

        self.video_delay.clear();
        self.audio_delay.clear();

        self.bytes_total = 0;
        self.bytes_audio = 0;
        self.bytes_video = 0;
        self.bytes_padding = 0;
        self.bytes_discard = 0;
        self.last_report = Some(now);
    }
}

enum WantVideo {
    PiP,
    All,
    None,
}

trait Scenario {
    fn want_video(&self, is_least_demux_id: bool, seconds: u64) -> WantVideo;
    fn limit_kbps(&self, seconds: u64) -> Option<u64>;
    fn name(&self) -> &str;
}

#[derive(Default)]
struct Periodic {}

impl Scenario for Periodic {
    fn want_video(&self, is_least_demux_id: bool, _seconds: u64) -> WantVideo {
        if is_least_demux_id {
            WantVideo::All
        } else {
            WantVideo::None
        }
    }

    fn limit_kbps(&self, seconds: u64) -> Option<u64> {
        if (seconds % 30) < 20 {
            Some(4000)
        } else {
            Some(1000)
        }
    }

    fn name(&self) -> &str {
        "Periodic"
    }
}

#[derive(Default)]
struct PipUnpip {}

impl Scenario for PipUnpip {
    fn want_video(&self, is_least_demux_id: bool, seconds: u64) -> WantVideo {
        if is_least_demux_id {
            // pip for 15 seconds, unpip for 30
            if (seconds % 45) < 15 {
                WantVideo::PiP
            } else {
                WantVideo::All
            }
        } else {
            WantVideo::None
        }
    }

    fn limit_kbps(&self, _seconds: u64) -> Option<u64> {
        Some(2000)
    }

    fn name(&self) -> &str {
        "PipUnpip"
    }
}

#[derive(Default)]
struct PipUnpipBWLimit {}

impl Scenario for PipUnpipBWLimit {
    fn want_video(&self, is_least_demux_id: bool, seconds: u64) -> WantVideo {
        if is_least_demux_id {
            // pip for 15 seconds, unpip for 30
            if (seconds % 45) < 15 {
                WantVideo::PiP
            } else {
                WantVideo::All
            }
        } else {
            WantVideo::None
        }
    }

    fn limit_kbps(&self, seconds: u64) -> Option<u64> {
        let mod_seconds = seconds % 45;
        if !(15..=20).contains(&mod_seconds) {
            // 2 Mbps normally
            Some(2000)
        } else {
            // limited during first 5 seconds of unpip
            Some(1500)
        }
    }

    fn name(&self) -> &str {
        "PipUnpipBWLimit"
    }
}

#[derive(Default)]
struct Unlimited {}

impl Scenario for Unlimited {
    fn want_video(&self, _is_least_demux_id: bool, _seconds: u64) -> WantVideo {
        WantVideo::All
    }

    fn limit_kbps(&self, _seconds: u64) -> Option<u64> {
        None
    }

    fn name(&self) -> &str {
        "Unlimited"
    }
}

struct RateLimiter {
    kbps: Option<u64>,
    next_recv: Instant,
}

impl RateLimiter {
    fn new(now: Instant) -> Self {
        Self {
            kbps: None,
            next_recv: now - RATE_LIMITER_SLOP_TIME,
        }
    }

    fn limit(&mut self, limit: Option<u64>) {
        self.kbps = limit;
    }

    fn recv(&mut self, socket: &UdpSocket, now: Instant, buf: &mut [u8]) -> Result<usize> {
        if let Some(limit) = self.kbps {
            if now + Duration::from_millis(1) >= self.next_recv {
                match socket.recv(buf) {
                    Ok(len) => {
                        let seconds = ((len * 8) as f64) / 1000.0 / (limit as f64);
                        self.next_recv += Duration::from_secs_f64(seconds);

                        self.next_recv = self
                            .next_recv
                            .clamp(now - RATE_LIMITER_SLOP_TIME, now + RATE_LIMITER_SLOP_TIME);
                        Ok(len)
                    }
                    Err(e) => Err(e.into()),
                }
            } else {
                sleep(Duration::from_millis(1).into());
                Err(anyhow!("too soon"))
            }
        } else {
            Ok(socket.recv(buf)?)
        }
    }

    fn delay(&self, now: Instant) -> f64 {
        let ret = if self.kbps.is_none() {
            0.0
        } else if now > self.next_recv {
            -(now.saturating_duration_since(self.next_recv).as_secs_f64())
        } else {
            self.next_recv.saturating_duration_since(now).as_secs_f64()
        };
        ret.clamp(-1.0, 1.0)
    }
}
