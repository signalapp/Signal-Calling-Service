//
// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use calling_backend::googcc;
use calling_backend::transportcc::{Ack, RemoteInstant};
use calling_common::{DataRate, DataSize, Duration, Instant};

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;

fn make_ack(gen: &mut Unstructured, epoch: Instant) -> Result<Ack, arbitrary::Error> {
    let size = DataSize::from_bytes(gen.int_in_range(0..=2048)?);

    let departure_micros: u64 = gen.int_in_range(0..=60_000_000)?;
    // Arrival is relative to departure (usually after, but check for edge cases too!)
    let arrival_micros =
        departure_micros.saturating_sub(1_000_000) + gen.int_in_range(0..=30_000_000)?;
    // Feedback arrival is relative to remote arrival (usually after, but check for edge cases again)
    let feedback_arrival_micros =
        arrival_micros.saturating_sub(1_000_000) + gen.int_in_range(0..=30_000_000)?;

    let departure = epoch + Duration::from_micros(departure_micros);
    let arrival = RemoteInstant::from_micros(arrival_micros);
    let feedback_arrival = epoch + Duration::from_micros(feedback_arrival_micros);
    Ok(Ack {
        size,
        departure,
        arrival,
        feedback_arrival,
    })
}

fuzz_target!(|data: &[u8]| {
    let mut gen = Unstructured::new(data);
    let epoch = Instant::now(); // only used relatively

    let mut cc = googcc::CongestionController::new(googcc::Config::default(), epoch);
    cc.request(googcc::Request {
        base: DataRate::from_kbps(100),
        ideal: DataRate::from_kbps(10_000),
    });

    // Consume all available entropy.
    while let Ok(ack) = make_ack(&mut gen, epoch) {
        // Process acks one at a time so that they can't be sorted into a "better" order.
        cc.recalculate_target_send_rate(vec![ack]);
    }
});
