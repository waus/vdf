use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use sha2::{Digest, Sha256};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

const NEXT_PRIME_SMALL_TABLE: &[u64] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];

const MILLER_RABIN_BASES: &[u64] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub y: Vec<u8>,
    pub pi: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicParams {
    pub modulus: Vec<u8>,
    pub lambda: usize,
    pub k: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VdfError {
    EmptyModulus,
    InvalidModulus,
    InvalidK { got: usize },
    LambdaMismatch { got: usize, actual: usize },
    NegativeDifficulty,
    EmptyProofY,
    EmptyProofPi,
}

fn hash_byte_len(k: usize) -> Result<usize, VdfError> {
    let bits = k
        .checked_mul(2)
        .and_then(|value| value.checked_add(7))
        .ok_or(VdfError::InvalidK { got: k })?;
    Ok((bits / 8).max(32))
}

#[derive(Debug, Clone)]
pub struct Wesolowski {
    n: BigUint,
    lambda: usize,
    k: usize,
}

impl Wesolowski {
    pub fn with_modulus(modulus: BigUint, k: usize) -> Result<Self, VdfError> {
        if modulus <= BigUint::from(2u8) || modulus.is_even() {
            return Err(VdfError::InvalidModulus);
        }
        if k < 2 {
            return Err(VdfError::InvalidK { got: k });
        }
        hash_byte_len(k)?;

        let lambda = modulus.bits() as usize;
        Ok(Self {
            n: modulus,
            lambda,
            k,
        })
    }

    pub fn with_public_params(params: PublicParams) -> Result<Self, VdfError> {
        if params.modulus.is_empty() {
            return Err(VdfError::EmptyModulus);
        }

        let modulus = BigUint::from_bytes_be(&params.modulus);
        let actual = modulus.bits() as usize;
        if params.lambda != 0 && params.lambda != actual {
            return Err(VdfError::LambdaMismatch {
                got: params.lambda,
                actual,
            });
        }

        Self::with_modulus(modulus, params.k)
    }

    pub fn public_params(&self) -> PublicParams {
        PublicParams {
            modulus: self.n.to_bytes_be(),
            lambda: self.lambda,
            k: self.k,
        }
    }

    pub fn prove(&self, payload: &[u8], difficulty: i64) -> Result<Proof, VdfError> {
        if difficulty < 0 {
            return Err(VdfError::NegativeDifficulty);
        }

        let difficulty = difficulty as usize;
        let x = self.input_from_payload(payload)?;
        let exp = two_pow(difficulty);
        let y = x.modpow(&exp, &self.n);
        let y_bytes = biguint_to_bytes(&y);
        let l = self.prime_from_statement(payload, difficulty, &y_bytes)?;

        let q = &exp / &l;
        let pi = x.modpow(&q, &self.n);

        Ok(Proof {
            y: y_bytes,
            pi: biguint_to_bytes(&pi),
        })
    }

    pub fn proove(&self, payload: &[u8], difficulty: i64) -> Result<Proof, VdfError> {
        self.prove(payload, difficulty)
    }

    pub fn verify(&self, payload: &[u8], difficulty: i64, proof: &Proof) -> Result<bool, VdfError> {
        if difficulty < 0 {
            return Err(VdfError::NegativeDifficulty);
        }
        if proof.y.is_empty() {
            return Err(VdfError::EmptyProofY);
        }
        if proof.pi.is_empty() {
            return Err(VdfError::EmptyProofPi);
        }

        let difficulty = difficulty as usize;
        let x = self.input_from_payload(payload)?;
        let y = BigUint::from_bytes_be(&proof.y);
        let pi = BigUint::from_bytes_be(&proof.pi);
        if y >= self.n || pi >= self.n {
            return Ok(false);
        }
        let y_bytes = biguint_to_bytes(&y);
        let l = self.prime_from_statement(payload, difficulty, &y_bytes)?;

        Ok(self.naive_verify(&x, &y, difficulty, &l, &pi))
    }

    pub fn naive_verify(
        &self,
        x: &BigUint,
        y: &BigUint,
        squarings: usize,
        l: &BigUint,
        pi: &BigUint,
    ) -> bool {
        if *l <= BigUint::one() {
            return false;
        }

        let r = verify_exponent(squarings, l);
        let left = pi.modpow(l, &self.n);
        let right = x.modpow(&r, &self.n);
        (left * right) % &self.n == *y
    }

    fn input_from_payload(&self, payload: &[u8]) -> Result<BigUint, VdfError> {
        let mut x = self.expand_hash_to_int("rsavdf:x:v1", 0, payload, None)?;
        x %= &self.n;
        if x.is_zero() {
            x = BigUint::one();
        }
        Ok(x)
    }

    fn prime_from_statement(
        &self,
        payload: &[u8],
        difficulty: usize,
        output: &[u8],
    ) -> Result<BigUint, VdfError> {
        let seed = self.expand_hash_to_int("rsavdf:l:v1", difficulty, payload, Some(output))?;
        Ok(next_prime(&seed))
    }

    fn expand_hash_to_int(
        &self,
        domain: &str,
        difficulty: usize,
        payload: &[u8],
        extra: Option<&[u8]>,
    ) -> Result<BigUint, VdfError> {
        let byte_len = hash_byte_len(self.k)?;
        let mut out = Vec::with_capacity(byte_len + Sha256::output_size());
        let diff_bytes = (difficulty as u64).to_be_bytes();
        let mut counter = 0u32;

        while out.len() < byte_len {
            let mut hasher = Sha256::new();
            hasher.update(domain.as_bytes());
            hasher.update(diff_bytes);
            hasher.update(payload);
            if let Some(extra) = extra {
                hasher.update(extra);
            }
            hasher.update(counter.to_be_bytes());
            out.extend_from_slice(&hasher.finalize());
            counter = counter.wrapping_add(1);
        }

        Ok(BigUint::from_bytes_be(&out[..byte_len]))
    }
}

pub fn two_pow(power: usize) -> BigUint {
    BigUint::one() << power
}

pub fn verify_exponent(squarings: usize, l: &BigUint) -> BigUint {
    BigUint::from(2u8).modpow(&BigUint::from(squarings), l)
}

pub fn next_prime(n: &BigUint) -> BigUint {
    let two = BigUint::from(2u8);
    if *n <= two {
        return two;
    }

    let mut candidate = n.clone();
    if candidate.is_even() {
        candidate += BigUint::one();
    }

    if candidate.bits() <= 6 {
        let value = candidate.to_u64().unwrap_or(0);
        for p in NEXT_PRIME_SMALL_TABLE {
            if value <= *p {
                return BigUint::from(*p);
            }
        }
    }

    while !is_probable_prime(&candidate) {
        candidate += &two;
    }
    candidate
}

fn is_probable_prime(n: &BigUint) -> bool {
    let two = BigUint::from(2u8);
    if *n < two {
        return false;
    }
    if *n == two {
        return true;
    }
    if n.is_even() {
        return false;
    }

    for p in NEXT_PRIME_SMALL_TABLE {
        let p_big = BigUint::from(*p);
        if *n == p_big {
            return true;
        }
        if n % &p_big == BigUint::zero() {
            return false;
        }
    }

    let one = BigUint::one();
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s = 0u32;
    while d.is_even() {
        d >>= 1;
        s += 1;
    }

    'outer: for base in MILLER_RABIN_BASES {
        let a = BigUint::from(*base);
        if a >= n_minus_one {
            continue;
        }

        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }

        for _ in 1..s {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                continue 'outer;
            }
        }

        return false;
    }

    true
}

fn biguint_to_bytes(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.is_empty() {
        vec![0]
    } else {
        bytes
    }
}

fn estimate_exp_work(exp: &BigUint) -> usize {
    if exp.is_zero() {
        return 1;
    }
    let bit_len = exp.bits() as usize;
    if bit_len <= 1 {
        return 1;
    }
    let one_less = exp - BigUint::one();
    if (exp & one_less).is_zero() {
        return bit_len - 1;
    }
    let squarings = bit_len - 1;
    let expected_multiplies = (bit_len + 1) / 2;
    squarings + expected_multiplies
}

#[repr(C)]
pub struct VdfrsaCtx {
    modulus: BigUint,
}

#[repr(C)]
pub struct VdfrsaProveSession {
    modulus: BigUint,
    x: BigUint,
    q: BigUint,
}

thread_local! {
    static LAST_ERROR: RefCell<CString> =
        RefCell::new(CString::new("native backend call failed").unwrap());
}

fn set_last_error(message: impl AsRef<str>) {
    let sanitized = message.as_ref().replace('\0', " ");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new(sanitized)
            .unwrap_or_else(|_| CString::new("native backend call failed").unwrap());
    });
}

fn ffi_guard<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, ()> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(message)) => {
            set_last_error(message);
            Err(())
        }
        Err(_) => {
            set_last_error("native backend panicked");
            Err(())
        }
    }
}

unsafe fn bytes_from_raw<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a [u8], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(format!("{name} pointer is null"));
    }
    Ok(std::slice::from_raw_parts(ptr, len))
}

unsafe fn write_bytes(
    out: *mut *mut u8,
    out_len: *mut usize,
    bytes: Vec<u8>,
) -> Result<(), String> {
    if out.is_null() || out_len.is_null() {
        return Err("invalid output pointer".to_string());
    }
    let len = bytes.len();
    let header = std::mem::size_of::<usize>();
    let layout = Layout::from_size_align(header + len, std::mem::align_of::<usize>())
        .map_err(|_| "invalid allocation layout".to_string())?;
    let raw = alloc(layout);
    if raw.is_null() {
        return Err("malloc failed".to_string());
    }
    (raw as *mut usize).write(len);
    let data = raw.add(header);
    ptr::copy_nonoverlapping(bytes.as_ptr(), data, len);
    *out = data;
    *out_len = len;
    Ok(())
}

fn ffi_hash_byte_len(k: usize) -> Result<usize, String> {
    hash_byte_len(k).map_err(|_| format!("invalid k: {k}"))
}

fn input_from_payload_for_modulus(
    modulus: &BigUint,
    k: usize,
    payload: &[u8],
) -> Result<BigUint, String> {
    let mut x = expand_hash_to_int_for_k("rsavdf:x:v1", k, 0, payload, None)?;
    x %= modulus;
    if x.is_zero() {
        x = BigUint::one();
    }
    Ok(x)
}

fn prime_from_statement_for_k(
    k: usize,
    payload: &[u8],
    difficulty: usize,
    output: &[u8],
) -> Result<BigUint, String> {
    let seed = expand_hash_to_int_for_k("rsavdf:l:v1", k, difficulty, payload, Some(output))?;
    Ok(next_prime(&seed))
}

fn expand_hash_to_int_for_k(
    domain: &str,
    k: usize,
    difficulty: usize,
    payload: &[u8],
    extra: Option<&[u8]>,
) -> Result<BigUint, String> {
    let byte_len = ffi_hash_byte_len(k)?;
    let mut out = Vec::with_capacity(byte_len + Sha256::output_size());
    let diff_bytes = (difficulty as u64).to_be_bytes();
    let mut counter = 0u32;

    while out.len() < byte_len {
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update(diff_bytes);
        hasher.update(payload);
        if let Some(extra) = extra {
            hasher.update(extra);
        }
        hasher.update(counter.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter = counter.wrapping_add(1);
    }

    Ok(BigUint::from_bytes_be(&out[..byte_len]))
}

#[no_mangle]
pub unsafe extern "C" fn vdfrsa_ctx_new(modulus: *const u8, modulus_len: usize) -> *mut VdfrsaCtx {
    match ffi_guard(|| {
        let modulus = BigUint::from_bytes_be(bytes_from_raw(modulus, modulus_len, "modulus")?);
        if modulus <= BigUint::from(2u8) || modulus.is_even() {
            return Err("modulus must be odd and greater than 2".to_string());
        }
        Ok(Box::into_raw(Box::new(VdfrsaCtx { modulus })))
    }) {
        Ok(ctx) => ctx,
        Err(()) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn vdfrsa_ctx_free(ctx: *mut VdfrsaCtx) {
    if !ctx.is_null() {
        drop(Box::from_raw(ctx));
    }
}

#[no_mangle]
pub unsafe extern "C" fn vdfrsa_ctx_mod_pow(
    ctx: *const VdfrsaCtx,
    base: *const u8,
    base_len: usize,
    exponent: *const u8,
    exponent_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> c_int {
    match ffi_guard(|| {
        let ctx = ctx
            .as_ref()
            .ok_or_else(|| "invalid modulus context".to_string())?;
        let base = BigUint::from_bytes_be(bytes_from_raw(base, base_len, "base")?);
        let exponent = BigUint::from_bytes_be(bytes_from_raw(exponent, exponent_len, "exponent")?);
        let result = base.modpow(&exponent, &ctx.modulus);
        write_bytes(out, out_len, biguint_to_bytes(&result))?;
        Ok(())
    }) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn vdfrsa_ctx_prove(
    ctx: *const VdfrsaCtx,
    k: c_int,
    payload: *const u8,
    payload_len: usize,
    difficulty: i64,
    out_y: *mut *mut u8,
    out_y_len: *mut usize,
    out_pi: *mut *mut u8,
    out_pi_len: *mut usize,
) -> c_int {
    match ffi_guard(|| {
        let ctx = ctx
            .as_ref()
            .ok_or_else(|| "invalid modulus context".to_string())?;
        if k < 2 {
            return Err("k must be at least 2".to_string());
        }
        if difficulty < 0 {
            return Err("difficulty must be non-negative".to_string());
        }
        let payload = bytes_from_raw(payload, payload_len, "payload")?;
        let difficulty = difficulty as usize;
        let x = input_from_payload_for_modulus(&ctx.modulus, k as usize, payload)?;
        let exp = two_pow(difficulty);
        let y = x.modpow(&exp, &ctx.modulus);
        let y_bytes = biguint_to_bytes(&y);
        let l = prime_from_statement_for_k(k as usize, payload, difficulty, &y_bytes)?;
        let q = &exp / &l;
        let pi = x.modpow(&q, &ctx.modulus);
        write_bytes(out_y, out_y_len, y_bytes)?;
        write_bytes(out_pi, out_pi_len, biguint_to_bytes(&pi))?;
        Ok(())
    }) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn vdfrsa_ctx_prove_stage1(
    ctx: *const VdfrsaCtx,
    k: c_int,
    payload: *const u8,
    payload_len: usize,
    difficulty: i64,
    out_session: *mut *mut VdfrsaProveSession,
    out_y: *mut *mut u8,
    out_y_len: *mut usize,
    out_second_work: *mut i64,
) -> c_int {
    match ffi_guard(|| {
        let ctx = ctx
            .as_ref()
            .ok_or_else(|| "invalid modulus context".to_string())?;
        if out_session.is_null() || out_second_work.is_null() {
            return Err("invalid output pointer".to_string());
        }
        if k < 2 {
            return Err("k must be at least 2".to_string());
        }
        if difficulty < 0 {
            return Err("difficulty must be non-negative".to_string());
        }
        let payload = bytes_from_raw(payload, payload_len, "payload")?;
        let difficulty = difficulty as usize;
        let x = input_from_payload_for_modulus(&ctx.modulus, k as usize, payload)?;
        let exp = two_pow(difficulty);
        let y = x.modpow(&exp, &ctx.modulus);
        let y_bytes = biguint_to_bytes(&y);
        let l = prime_from_statement_for_k(k as usize, payload, difficulty, &y_bytes)?;
        let q = &exp / &l;
        let second_work = estimate_exp_work(&q) as i64;
        let session = Box::new(VdfrsaProveSession {
            modulus: ctx.modulus.clone(),
            x,
            q,
        });
        write_bytes(out_y, out_y_len, y_bytes)?;
        *out_second_work = second_work;
        *out_session = Box::into_raw(session);
        Ok(())
    }) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn vdfrsa_prove_session_finish(
    session: *mut VdfrsaProveSession,
    out_pi: *mut *mut u8,
    out_pi_len: *mut usize,
) -> c_int {
    match ffi_guard(|| {
        let session = session
            .as_ref()
            .ok_or_else(|| "invalid prove session".to_string())?;
        let pi = session.x.modpow(&session.q, &session.modulus);
        write_bytes(out_pi, out_pi_len, biguint_to_bytes(&pi))?;
        Ok(())
    }) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn vdfrsa_prove_session_free(session: *mut VdfrsaProveSession) {
    if !session.is_null() {
        drop(Box::from_raw(session));
    }
}

#[no_mangle]
pub unsafe extern "C" fn vdfrsa_quotient(
    dividend: *const u8,
    dividend_len: usize,
    divisor: *const u8,
    divisor_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> c_int {
    match ffi_guard(|| {
        let dividend = BigUint::from_bytes_be(bytes_from_raw(dividend, dividend_len, "dividend")?);
        let divisor = BigUint::from_bytes_be(bytes_from_raw(divisor, divisor_len, "divisor")?);
        if divisor.is_zero() {
            return Err("division by zero".to_string());
        }
        write_bytes(out, out_len, biguint_to_bytes(&(dividend / divisor)))?;
        Ok(())
    }) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn vdfrsa_buffer_free(buffer: *mut u8) {
    if !buffer.is_null() {
        let header = std::mem::size_of::<usize>();
        let raw = buffer.sub(header);
        let len = *(raw as *const usize);
        if let Ok(layout) = Layout::from_size_align(header + len, std::mem::align_of::<usize>()) {
            dealloc(raw, layout);
        }
    }
}

#[no_mangle]
pub extern "C" fn vdfrsa_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Vector {
        payload: &'static [u8],
        difficulty: i64,
        modulus_hex: &'static str,
        output_hex: &'static str,
        witness_hex: &'static str,
    }

    const VECTORS: &[Vector] = &[
        Vector {
            payload: b"vector-1",
            difficulty: 0,
            modulus_hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            output_hex: "84798b7e1b817980f962b2adf61f950f9d91f9f91b5bfc5d95a40fd78b771708",
            witness_hex: "01",
        },
        Vector {
            payload: b"vector-2",
            difficulty: 17,
            modulus_hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            output_hex: "4ac17f16907772b2f21d3196a242f99cfbbd332c128998fc3bbbfde9c3a3a50b6d2d787cc4aca5aa934e33d9b8a0b097c6bbfa4cd6e1972c0b9090f7932a664c899cc5aeda95300e8aa42227f7dd2f05fc966d939b5369896a8aee46a5f8c80330de93cc73f5e904877a50dad1d01eaa1e6a87a0b287732670d6b8a8cb7ff8b8d33cc9b4516a5fd29f8d7ed720",
            witness_hex: "01",
        },
        Vector {
            payload: b"vector-3",
            difficulty: 257,
            modulus_hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            output_hex: "e938ffbd7a2fcfcaafdd90d947e1de46175b2fce48ddc8cf261dff620ccc7d55b4c70919330d6d65fa6652130b81fd69caa872d2ede408f00906721747ded152551201ec017702e66262b928a68de392f58cf451fc22ce30e6d443a48f1e09989da995afe5a10a9095f040feb0626fa8b9abb22ddd087a6f181d02f126579ca38a6085a99273af010555edc0d7",
            witness_hex: "aa0cbb0fc4e4c68a289727fc9c1cf2d79059cb37785b220aa285602dbe21c7f1730fc3fdfc7928449d36405fb4e44b1c354940d40ad076fce190157c7765aefe14b539099f675e5bda024612e1c0a773297618cff7adc7409bad0ec47add9cd1",
        },
    ];

    #[test]
    fn prove_matches_payload_vectors() {
        for vector in VECTORS {
            let modulus = BigUint::from_bytes_be(&hex::decode(vector.modulus_hex).unwrap());
            let vdf = Wesolowski::with_modulus(modulus, 128).unwrap();
            let proof = vdf.prove(vector.payload, vector.difficulty).unwrap();

            assert_eq!(hex::encode(&proof.y), vector.output_hex);
            assert_eq!(hex::encode(&proof.pi), vector.witness_hex);
            assert!(vdf
                .verify(vector.payload, vector.difficulty, &proof)
                .unwrap());
        }
    }

    #[test]
    fn verify_rejects_wrong_payload() {
        let vector = &VECTORS[1];
        let modulus = BigUint::from_bytes_be(&hex::decode(vector.modulus_hex).unwrap());
        let vdf = Wesolowski::with_modulus(modulus, 128).unwrap();
        let proof = vdf.prove(vector.payload, vector.difficulty).unwrap();

        assert!(!vdf
            .verify(b"other-payload", vector.difficulty, &proof)
            .unwrap());
    }

    #[test]
    fn verify_canonicalizes_y_before_challenge_hash() {
        let vector = &VECTORS[1];
        let modulus = BigUint::from_bytes_be(&hex::decode(vector.modulus_hex).unwrap());
        let vdf = Wesolowski::with_modulus(modulus, 128).unwrap();
        let proof = vdf.prove(vector.payload, vector.difficulty).unwrap();
        let mut non_canonical = proof.clone();
        non_canonical.y.insert(0, 0);

        assert!(vdf
            .verify(vector.payload, vector.difficulty, &non_canonical)
            .unwrap());
    }

    #[test]
    fn verify_rejects_out_of_range_proof_values() {
        let vector = &VECTORS[1];
        let modulus = BigUint::from_bytes_be(&hex::decode(vector.modulus_hex).unwrap());
        let vdf = Wesolowski::with_modulus(modulus.clone(), 128).unwrap();
        let proof = vdf.prove(vector.payload, vector.difficulty).unwrap();

        let mut y_out_of_range = proof.clone();
        y_out_of_range.y = biguint_to_bytes(&(BigUint::from_bytes_be(&proof.y) + &modulus));
        assert!(!vdf
            .verify(vector.payload, vector.difficulty, &y_out_of_range)
            .unwrap());

        let mut pi_out_of_range = proof.clone();
        pi_out_of_range.pi = biguint_to_bytes(&(BigUint::from_bytes_be(&proof.pi) + &modulus));
        assert!(!vdf
            .verify(vector.payload, vector.difficulty, &pi_out_of_range)
            .unwrap());
    }

    #[test]
    fn rejects_k_that_overflows_hash_byte_len() {
        let modulus = BigUint::from_bytes_be(&hex::decode(VECTORS[0].modulus_hex).unwrap());
        assert!(matches!(
            Wesolowski::with_modulus(modulus.clone(), usize::MAX),
            Err(VdfError::InvalidK { got }) if got == usize::MAX
        ));
        assert!(ffi_hash_byte_len(usize::MAX).is_err());
    }

    #[test]
    fn proove_alias_delegates_to_prove() {
        let vector = &VECTORS[0];
        let modulus = BigUint::from_bytes_be(&hex::decode(vector.modulus_hex).unwrap());
        let vdf = Wesolowski::with_modulus(modulus, 128).unwrap();

        assert_eq!(
            vdf.prove(vector.payload, vector.difficulty).unwrap(),
            vdf.proove(vector.payload, vector.difficulty).unwrap()
        );
    }

    #[test]
    fn verify_exponent_handles_even_modulus() {
        assert_eq!(verify_exponent(1, &BigUint::from(2u8)), BigUint::zero());
    }

    #[test]
    fn ffi_accepts_empty_payload_null_pointer() {
        let vector = &VECTORS[0];
        let modulus = hex::decode(vector.modulus_hex).unwrap();

        unsafe {
            let ctx = vdfrsa_ctx_new(modulus.as_ptr(), modulus.len());
            assert!(!ctx.is_null());

            let mut y = ptr::null_mut();
            let mut y_len = 0usize;
            let mut pi = ptr::null_mut();
            let mut pi_len = 0usize;

            let rc = vdfrsa_ctx_prove(
                ctx,
                128,
                ptr::null(),
                0,
                4,
                &mut y,
                &mut y_len,
                &mut pi,
                &mut pi_len,
            );

            assert_eq!(rc, 0);
            assert!(!y.is_null());
            assert!(y_len > 0);
            assert!(!pi.is_null());
            assert!(pi_len > 0);

            vdfrsa_buffer_free(y);
            vdfrsa_buffer_free(pi);
            vdfrsa_ctx_free(ctx);
        }
    }
}
