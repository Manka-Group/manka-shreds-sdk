//! Mutated server output, decoded by this SDK.
//!
//! These decoders run inside a consumer's process, against bytes from a network peer. A panic here
//! is not a failed decode — it is the consumer's process dying, and on a trading system that is the
//! worst possible failure mode. It has to be impossible regardless of what arrives.
//!
//! The golden fixtures are real server output, so mutating *them* produces input that gets past the
//! cheap checks and reaches the arithmetic. Uniform random bytes never would.
//!
//! Decoding is only half of it. `Transaction::read` succeeding does not mean the transaction is
//! coherent — the counts inside it become loop bounds and slice indices in the accessors, so every
//! accessor is driven to exhaustion on anything that decodes. A count the decoder waved through and
//! an accessor then trusted is exactly the shape of bug this is looking for.

use std::path::PathBuf;

use manka_shreds_sdk::{
    Duplicate, Entry, SlotEnd, SlotStart, Transaction,
    protocol::{FRAME_HEADER_LEN, FilterAck, HelloAck, Lag, read_frame_header},
};

fn load(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("reading {}: {err}", path.display()))
}

/// Deterministic xorshift, so a failure is reproducible from the seed alone.
struct Rand(u64);

impl Rand {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 { 0 } else { (self.next() % bound as u64) as usize }
    }
}

/// Corrupts `bytes`, keeping enough structure to reach the code behind the length checks.
fn mutate(bytes: &mut Vec<u8>, rng: &mut Rand) {
    if bytes.is_empty() {
        return;
    }
    match rng.below(6) {
        0 => {
            let at = rng.below(bytes.len());
            bytes[at] ^= 1 << (rng.below(8) as u8);
        }
        1 => {
            let at = rng.below(bytes.len());
            bytes[at] = rng.next() as u8;
        }
        2 => {
            // The header region, where the counts and offsets live. This is what turns a decode
            // into a loop over a length the sender chose.
            let at = rng.below(bytes.len().min(64));
            bytes[at] = rng.next() as u8;
        }
        3 => {
            let keep = rng.below(bytes.len() + 1);
            bytes.truncate(keep);
        }
        4 => {
            let extra = rng.below(64);
            bytes.extend(std::iter::repeat_n(rng.next() as u8, extra));
        }
        _ => {
            if bytes.len() > 8 {
                let len = 1 + rng.below(bytes.len() / 4);
                let from = rng.below(bytes.len() - len);
                let to = rng.below(bytes.len() - len);
                let run: Vec<u8> = bytes[from..from + len].to_vec();
                bytes[to..to + len].copy_from_slice(&run);
            }
        }
    }
}

/// Reads everything a consumer could read, so a count the decoder accepted is actually used.
fn exhaust(tx: &Transaction<'_>) {
    let _ = tx.slot();
    let _ = tx.parent_slot();
    let _ = tx.signature();
    let _ = tx.is_vote();
    let _ = tx.recovered();
    let _ = tx.verification();
    let _ = tx.pipeline_ns();
    let _ = tx.message_version();
    let _ = tx.leader();
    let _ = tx.recent_blockhash();
    let _ = tx.raw_tx();

    // Bounded, because a corrupted count could otherwise describe a very long walk. The bound is
    // far above anything real, so it never hides a bug — it only stops the test taking a minute.
    for (index, key) in tx.account_keys().enumerate().take(4_096) {
        let _ = key;
        let _ = tx.account_key(index);
    }
    for signature in tx.signatures().take(4_096) {
        let _ = signature;
    }
    for instruction in tx.instructions().take(4_096) {
        let _ = tx.account_key(instruction.program_id_index as usize);
        let _ = instruction.accounts;
        let _ = instruction.data;
    }
    for lookup in tx.lookups().take(4_096) {
        let _ = lookup.account_key;
        let _ = lookup.writable_indexes;
        let _ = lookup.readonly_indexes;
    }
    // Indices past the end must answer `None`, not panic.
    let _ = tx.account_key(usize::MAX);
    let _ = tx.account_key(0);
}

#[test]
fn mutated_transactions_never_panic() {
    let seeds = ["tx_simple.bin", "tx_full.bin", "tx_legacy.bin"];
    let mut rng = Rand(0x243f_6a88_85a3_08d3);
    let mut decoded = 0usize;

    for round in 0..40_000 {
        let mut mutant = load(seeds[round % seeds.len()]);
        for _ in 0..=rng.below(3) {
            mutate(&mut mutant, &mut rng);
        }
        if let Ok(tx) = Transaction::read(&mutant) {
            decoded += 1;
            exhaust(&tx);
        }
    }

    assert!(
        decoded > 500,
        "only {decoded} of 40000 mutants decoded, so the accessors — where a bad count is actually \
         used — were barely reached"
    );
}

#[test]
fn mutated_events_never_panic() {
    let mut rng = Rand(0x9e37_79b9_7f4a_7c15);
    let seeds = [
        "entry.bin",
        "slot_start.bin",
        "slot_start_bare.bin",
        "slot_end.bin",
        "duplicate.bin",
    ];
    let mut decoded = 0usize;

    for round in 0..40_000 {
        let name = seeds[round % seeds.len()];
        let mut mutant = load(name);
        for _ in 0..=rng.below(3) {
            mutate(&mut mutant, &mut rng);
        }

        // Every decoder against every fixture, not just its own: a consumer routes on the frame
        // kind, and a corrupted kind byte sends a payload to the wrong reader.
        if let Ok(entry) = Entry::read(&mutant) {
            decoded += 1;
            let _ = (entry.slot, entry.num_hashes, entry.hash, entry.tx_count);
        }
        if let Ok(start) = SlotStart::read(&mutant) {
            decoded += 1;
            let _ = (start.slot, start.parent_slot, start.leader);
        }
        if let Ok(end) = SlotEnd::read(&mutant) {
            decoded += 1;
            let _ = (end.slot, end.data_shreds, end.recovered_sets, end.missing_shreds);
        }
        if let Ok(duplicate) = Duplicate::read(&mutant) {
            decoded += 1;
            let _ = (duplicate.slot, duplicate.index, duplicate.is_data);
        }
    }

    assert!(decoded > 500, "only {decoded} event mutants decoded");
}

#[test]
fn mutated_control_messages_never_panic() {
    let mut rng = Rand(0x0123_4567_89ab_cdef);
    let seeds = ["hello_ack.bin", "filter_ack.bin", "lag.bin", "error.bin"];

    for round in 0..40_000 {
        let mut mutant = load(seeds[round % seeds.len()]);
        for _ in 0..=rng.below(3) {
            mutate(&mut mutant, &mut rng);
        }
        if let Ok(ack) = HelloAck::read(&mutant) {
            let _ = (ack.session_id, ack.granted, ack.keepalive_ms, ack.dictionary_id);
        }
        if let Ok(ack) = FilterAck::read(&mutant) {
            // The detail is a length-prefixed string the server chose, so its length is the field
            // most worth corrupting.
            let _ = (ack.accepted, ack.cost, ack.detail.len());
        }
        if let Ok(lag) = Lag::read(&mutant) {
            let _ = (lag.dropped, lag.resume_seq);
        }
    }
}

/// A frame header is the first thing read from the socket, and its length field decides how much
/// the client will then wait for and allocate.
#[test]
fn mutated_frames_never_panic_the_header_reader() {
    let mut rng = Rand(0xdead_beef_0bad_f00d);
    let seeds = ["frame_plain.bin", "frame_zstd.bin", "frame_matched.bin"];
    let mut headers = 0usize;

    for round in 0..40_000 {
        let mut mutant = load(seeds[round % seeds.len()]);
        for _ in 0..=rng.below(3) {
            mutate(&mut mutant, &mut rng);
        }
        let Ok(header) = read_frame_header(&mutant) else {
            continue;
        };
        headers += 1;
        let _ = (header.kind, header.seq, header.compressed, header.matched);

        // A length the sender chose must never be used to slice without checking it fits, which is
        // what a consumer following the documented pattern would do.
        if let Some(payload) = mutant
            .get(FRAME_HEADER_LEN..)
            .and_then(|rest| rest.get(..header.len))
        {
            if let Ok(tx) = Transaction::read(payload) {
                exhaust(&tx);
            }
        }
    }

    assert!(headers > 1_000, "only {headers} frame headers parsed");
}
