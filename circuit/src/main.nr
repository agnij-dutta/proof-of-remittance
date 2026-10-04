// Proof of Remittance predicate circuit.
//
// TLSNotary gives the verifier SHA-256 commitments to two byte ranges of the
// bank's HTTPS response: the credit's `amount` string and its `ts` number.
// A TLSNotary plaintext-hash commitment is sha256(plaintext || blinder).
//
// This circuit proves, without revealing either value:
//   1. amount_hash = sha256(amount_bytes || amount_blinder)
//   2. ts_hash     = sha256(ts_bytes || ts_blinder)
//   3. amount_bytes parses as a decimal "<digits>.<2 digits>" worth >= threshold_paise
//   4. ts_bytes parses as a 10 digit unix timestamp >= min_ts

global MAX_AMOUNT_LEN: u32 = 16;
global BLINDER_LEN: u32 = 16;
global TS_LEN: u32 = 10;

fn main(
    // Public inputs (the on-chain escrow supplies threshold + min_ts, the
    // notary attestation supplies the two hashes).
    threshold_paise: pub u64,
    min_ts: pub u64,
    amount_hash: pub [u8; 32],
    ts_hash: pub [u8; 32],
    // Private inputs.
    amount: [u8; MAX_AMOUNT_LEN],
    amount_len: u32,
    amount_blinder: [u8; BLINDER_LEN],
    ts: [u8; TS_LEN],
    ts_blinder: [u8; BLINDER_LEN],
) {
    assert(amount_len >= 4, "amount too short");
    assert(amount_len <= MAX_AMOUNT_LEN, "amount too long");

    // 1. amount commitment
    let mut amount_input: [u8; MAX_AMOUNT_LEN + BLINDER_LEN] = [0; MAX_AMOUNT_LEN + BLINDER_LEN];
    for i in 0..(MAX_AMOUNT_LEN + BLINDER_LEN) {
        let mut b: u8 = 0;
        if i < amount_len {
            b = amount[i];
        } else {
            let j = i - amount_len;
            if j < BLINDER_LEN {
                b = amount_blinder[j];
            }
        }
        amount_input[i] = b;
    }
    let h = sha256::sha256_var(amount_input, amount_len + BLINDER_LEN);
    assert(h == amount_hash, "amount commitment mismatch");

    // 2. ts commitment (fixed length)
    let mut ts_input: [u8; TS_LEN + BLINDER_LEN] = [0; TS_LEN + BLINDER_LEN];
    for i in 0..TS_LEN {
        ts_input[i] = ts[i];
    }
    for i in 0..BLINDER_LEN {
        ts_input[TS_LEN + i] = ts_blinder[i];
    }
    let th = sha256::sha256_var(ts_input, TS_LEN + BLINDER_LEN);
    assert(th == ts_hash, "ts commitment mismatch");

    // 3. amount >= threshold
    let paise = parse_amount_paise(amount, amount_len);
    assert(paise >= threshold_paise, "amount below threshold");

    // 4. ts >= min_ts
    let t = parse_digits(ts);
    assert(t >= min_ts, "credit older than min_ts");
}

fn digit(b: u8) -> u64 {
    assert((b >= 48) & (b <= 57), "not a digit");
    (b - 48) as u64
}

// "<1+ digits>.<2 digits>" -> integer paise. Every byte before len must be a
// digit except the single '.' at len - 3.
fn parse_amount_paise(amount: [u8; MAX_AMOUNT_LEN], len: u32) -> u64 {
    let dot = len - 3;
    let mut value: u64 = 0;
    for i in 0..MAX_AMOUNT_LEN {
        if i < len {
            if i == dot {
                assert(amount[i] == 46, "expected '.' before 2 decimal places");
            } else {
                value = value * 10 + digit(amount[i]);
            }
        }
    }
    value
}

fn parse_digits(ts: [u8; TS_LEN]) -> u64 {
    let mut v: u64 = 0;
    for i in 0..TS_LEN {
        v = v * 10 + digit(ts[i]);
    }
    v
}

#[test]
fn test_parse() {
    let mut a: [u8; MAX_AMOUNT_LEN] = [0; MAX_AMOUNT_LEN];
    let s = "50000.00".as_bytes();
    for i in 0..8 {
        a[i] = s[i];
    }
    assert(parse_amount_paise(a, 8) == 5000000);
    assert(parse_digits("1791094449".as_bytes()) == 1791094449);
}

#[test(should_fail_with = "expected '.' before 2 decimal places")]
fn test_bad_format() {
    let mut a: [u8; MAX_AMOUNT_LEN] = [0; MAX_AMOUNT_LEN];
    let s = "500000.0".as_bytes();
    for i in 0..8 {
        a[i] = s[i];
    }
    let _ = parse_amount_paise(a, 8);
}

// ---------------------------------------------------------------- end-to-end
// These call `main` with commitments computed the same way TLSNotary does
// (sha256(plaintext || 16-byte blinder)), so they exercise the binding as
// well as the parsing.

global TEST_TS: [u8; TS_LEN] = [49, 55, 57, 49, 48, 57, 54, 48, 48, 56]; // "1791096008"
global TEST_BLINDER_A: [u8; BLINDER_LEN] = [7; BLINDER_LEN];
global TEST_BLINDER_T: [u8; BLINDER_LEN] = [9; BLINDER_LEN];

fn pad_amount<let N: u32>(s: str<N>) -> [u8; MAX_AMOUNT_LEN] {
    let b = s.as_bytes();
    let mut a: [u8; MAX_AMOUNT_LEN] = [0; MAX_AMOUNT_LEN];
    for i in 0..N {
        a[i] = b[i];
    }
    a
}

fn commit_amount(amount: [u8; MAX_AMOUNT_LEN], len: u32, blinder: [u8; BLINDER_LEN]) -> [u8; 32] {
    let mut input: [u8; MAX_AMOUNT_LEN + BLINDER_LEN] = [0; MAX_AMOUNT_LEN + BLINDER_LEN];
    for i in 0..MAX_AMOUNT_LEN {
        if i < len {
            input[i] = amount[i];
        }
    }
    for i in 0..BLINDER_LEN {
        input[len + i] = blinder[i];
    }
    sha256::sha256_var(input, len + BLINDER_LEN)
}

fn commit_ts(ts: [u8; TS_LEN], blinder: [u8; BLINDER_LEN]) -> [u8; 32] {
    let mut input: [u8; TS_LEN + BLINDER_LEN] = [0; TS_LEN + BLINDER_LEN];
    for i in 0..TS_LEN {
        input[i] = ts[i];
    }
    for i in 0..BLINDER_LEN {
        input[TS_LEN + i] = blinder[i];
    }
    sha256::sha256_var(input, TS_LEN + BLINDER_LEN)
}

/// Runs `main` for an honest commitment to `s` and the fixed test timestamp.
fn run_honest<let N: u32>(s: str<N>, threshold: u64, min_ts: u64) {
    let a = pad_amount(s);
    main(
        threshold,
        min_ts,
        commit_amount(a, N, TEST_BLINDER_A),
        commit_ts(TEST_TS, TEST_BLINDER_T),
        a,
        N,
        TEST_BLINDER_A,
        TEST_TS,
        TEST_BLINDER_T,
    );
}

#[test]
fn test_main_accepts_amount_above_threshold() {
    run_honest("50000.00", 4500000, 1791096000);
}

#[test]
fn test_main_accepts_amount_equal_to_threshold_and_ts_equal_to_min() {
    run_honest("45000.00", 4500000, 1791096008);
}

#[test(should_fail_with = "amount below threshold")]
fn test_main_rejects_amount_one_paisa_short() {
    run_honest("44999.99", 4500000, 0);
}

#[test(should_fail_with = "credit older than min_ts")]
fn test_main_rejects_stale_credit() {
    run_honest("50000.00", 4500000, 1791096009);
}

#[test]
fn test_main_accepts_max_length_amount() {
    // 16 bytes: 13 integer digits. 999,999,999,999,999 paise fits in u64.
    run_honest("9999999999999.99", 999999999999999, 0);
}

#[test]
fn test_main_leading_zeros_do_not_change_value() {
    run_honest("00050000.00", 5000000, 0);
}

#[test(should_fail_with = "amount commitment mismatch")]
fn test_main_rejects_wrong_blinder() {
    let a = pad_amount("50000.00");
    main(
        4500000,
        0,
        commit_amount(a, 8, TEST_BLINDER_A),
        commit_ts(TEST_TS, TEST_BLINDER_T),
        a,
        8,
        [8; BLINDER_LEN],
        TEST_TS,
        TEST_BLINDER_T,
    );
}

#[test(should_fail_with = "amount commitment mismatch")]
fn test_main_rejects_different_amount_under_same_commitment() {
    // The commitment is to "50000.00"; the prover claims "90000.00".
    let real = pad_amount("50000.00");
    let claimed = pad_amount("90000.00");
    main(
        4500000,
        0,
        commit_amount(real, 8, TEST_BLINDER_A),
        commit_ts(TEST_TS, TEST_BLINDER_T),
        claimed,
        8,
        TEST_BLINDER_A,
        TEST_TS,
        TEST_BLINDER_T,
    );
}

#[test(should_fail_with = "amount commitment mismatch")]
fn test_main_rejects_shifted_split_between_amount_and_blinder() {
    // Same 24 committed bytes, but the prover claims the amount is one byte
    // longer (moving the first blinder byte into the amount). SHA-256 binds
    // the total length, and the blinder is fixed at 16 bytes, so the split
    // cannot move.
    let real = pad_amount("50000.00");
    let mut claimed = real;
    claimed[8] = TEST_BLINDER_A[0];
    main(
        4500000,
        0,
        commit_amount(real, 8, TEST_BLINDER_A),
        commit_ts(TEST_TS, TEST_BLINDER_T),
        claimed,
        9,
        TEST_BLINDER_A,
        TEST_TS,
        TEST_BLINDER_T,
    );
}

#[test(should_fail_with = "ts commitment mismatch")]
fn test_main_rejects_different_ts_under_same_commitment() {
    let a = pad_amount("50000.00");
    let later: [u8; TS_LEN] = [49, 57, 57, 57, 57, 57, 57, 57, 57, 57]; // "1999999999"
    main(
        4500000,
        0,
        commit_amount(a, 8, TEST_BLINDER_A),
        commit_ts(TEST_TS, TEST_BLINDER_T),
        a,
        8,
        TEST_BLINDER_A,
        later,
        TEST_BLINDER_T,
    );
}

#[test(should_fail_with = "not a digit")]
fn test_main_rejects_negative_amount() {
    run_honest("-50000.00", 0, 0);
}

#[test(should_fail_with = "not a digit")]
fn test_main_rejects_thousands_separator() {
    run_honest("50,000.00", 0, 0);
}

#[test(should_fail_with = "expected '.' before 2 decimal places")]
fn test_main_rejects_one_decimal_place() {
    run_honest("50000.0", 0, 0);
}

#[test(should_fail_with = "amount too short")]
fn test_main_rejects_too_short_amount() {
    run_honest(".00", 0, 0);
}

#[test(should_fail_with = "amount too long")]
fn test_main_rejects_amount_len_over_max() {
    let a = pad_amount("50000.00");
    main(
        0,
        0,
        [0; 32],
        commit_ts(TEST_TS, TEST_BLINDER_T),
        a,
        17,
        TEST_BLINDER_A,
        TEST_TS,
        TEST_BLINDER_T,
    );
}
