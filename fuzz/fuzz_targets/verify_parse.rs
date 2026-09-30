#![no_main]
use libfuzzer_sys::fuzz_target;
use sq_pq::params::PROOF_BYTES;
use sq_pq::proof::Proof;
use sq_pq::transcript::Transcript;

// Fixed public inputs (the fuzzer varies only encodings, never secrets).
const Y: [u8; 32] = [0x5A; 32];

fuzz_target!(|data: &[u8]| {
    if data.len() == PROOF_BYTES {
        let mut raw: [u8; PROOF_BYTES] = [0; PROOF_BYTES];
        raw.copy_from_slice(data);
        // Must never panic: parse errors and verification failures are
        // both acceptable outcomes; only panics/hangs are bugs.
        if let Ok(p) = Proof::from_bytes(&raw) {
            let _ = sq_pq::verifier::verify(&dummy_a(), &dummy_y(), 0, &p);
        }
    } else if !data.is_empty() && data.len() <= 2048 {
        // Transcript absorb path with arbitrary labels/data splits.
        // (A previous revision sliced `data[1..0]` here when the split was
        // zero — caught by this fuzzer in minutes. Splits stay ordered.)
        let lo: usize = 1.min(data.len());
        let split: usize = lo + (data[0] as usize) % (data.len() + 1 - lo);
        let mut t: Transcript = Transcript::new(b"sq-pq/v0.1/R*");
        let _ = t.absorb(&data[lo..split], data);
        let mut out: [u8; 32] = [0; 32];
        let _ = t.squeeze(0x46, &mut out);
    }
    let _ = Y;
});

fn dummy_a() -> sq_pq::commit::MatrixA {
    [[[0; 64]; 8]; 4]
}

fn dummy_y() -> sq_pq::commit::Commitment {
    [[0; 64]; 4]
}
