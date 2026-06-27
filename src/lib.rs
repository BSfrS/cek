//! CEK (Chicken Encryption Kit) core library.
//!
//! A CLI-based asymmetric "Chicken Encryption" system using modular
//! arithmetic / multi-prime algo. No external crypto libraries are used:
//! all math primitives are implemented from scratch here.

pub mod cli;

use rand::seq::SliceRandom;
use std::path::PathBuf;

pub const MAGIC_PREFIX: [u8; 3] = [0xC4, 0x1C, 0xEB];

// ---------------------------------------------------------------------------
// 1. Math utilities
// ---------------------------------------------------------------------------

/// Greatest common divisor (Euclidean algorithm).
pub fn gcd(a: u64, b: u64) -> u64 {
    let mut a = a;
    let mut b = b;
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Extended Euclidean algorithm.
///
/// Returns `(g, x, y)` such that `a*x + b*y = g` where `g = gcd(a, b)`.
/// Uses signed arithmetic for the Bezout coefficients.
pub fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (g, x, y) = extended_gcd(b, a % b);
        (g, y, x - (a / b) * y)
    }
}

/// Modular multiplicative inverse of `e` modulo `phi` via the extended GCD.
///
/// Returns `None` if `e` and `phi` are not coprime (no inverse exists).
pub fn mod_inverse(e: u64, phi: u64) -> Option<u64> {
    let (g, x, _) = extended_gcd(e as i64, phi as i64);
    if g != 1 {
        return None;
    }
    let phi_i = phi as i64;
    // Normalize x into the range [0, phi).
    let inv = ((x % phi_i) + phi_i) % phi_i;
    Some(inv as u64)
}

/// Modular exponentiation: `base^exp mod modulus` via square-and-multiply.
pub fn mod_pow(base: u64, exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    let mut result: u128 = 1;
    let mut base = (base % modulus) as u128;
    let modulus = modulus as u128;
    let mut exp = exp;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    result as u64
}

/// Simple primality test using trial division. Fine for the small primes
/// used by this system (products fit in 10 bits, primes are tiny).
pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n < 4 {
        return true;
    }
    if n.is_multiple_of(2) {
        return false;
    }
    let mut i = 3u64;
    while i * i <= n {
        if n.is_multiple_of(i) {
            return false;
        }
        i += 2;
    }
    true
}

/// Find all valid prime pairs `(p, q)` where `p != q` and
/// `257 <= p*q <= 1023`. Pairs are unordered (we store `p < q`).
pub fn valid_prime_pairs() -> Vec<(u64, u64)> {
    // Primes up to 1023 are more than enough (smallest factor of a product
    // <= 1023 cannot exceed 31, but we collect generously).
    let primes: Vec<u64> = (2..=512).filter(|&n| is_prime(n)).collect();
    let mut pairs = Vec::new();
    for (i, &p) in primes.iter().enumerate() {
        for &q in primes.iter().skip(i + 1) {
            if p == q {
                continue;
            }
            let n = p * q;
            if (257..=1023).contains(&n) {
                pairs.push((p, q));
            }
        }
    }
    pairs
}

// ---------------------------------------------------------------------------
// 2. Hashing
// ---------------------------------------------------------------------------

/// A simple Merkle-Damgard-style hash producing an 8-byte digest.
///
/// Uses a 32-byte internal state for good mixing, then folds it down
/// to 8 bytes via XOR. Sized to match the 10-bit moduli.
pub fn chicken_hash(data: &[u8]) -> [u8; 8] {
    let mut state: [u8; 32] = *b"chickenchickenchickenchickenchic";

    for (i, &b) in data.iter().enumerate() {
        state[i % 32] ^= b;
        state[(i + 13) % 32] = state[(i + 13) % 32].wrapping_add(b);

        if (i + 1) % 32 == 0 {
            mix_state(&mut state);
        }
    }

    for _ in 0..4 {
        mix_state(&mut state);
    }

    let mut out = [0u8; 8];
    for (i, &b) in state.iter().enumerate() {
        out[i % 8] ^= b;
    }
    out
}

fn mix_state(state: &mut [u8; 32]) {
    let prev = *state;
    for j in 0..32 {
        state[j] = prev[j].wrapping_add(prev[(j + 1) % 32]).rotate_left(3) ^ prev[(j + 7) % 32];
    }
}

// ---------------------------------------------------------------------------
// 3. Password helpers
// ---------------------------------------------------------------------------

/// Derive a stream of `length` bytes from `password` via iterative chicken_hash.
/// Each output byte is returned as a `u64` (range 0–255).
fn derive_key_stream(password: &str, length: usize) -> Vec<u64> {
    let mut stream: Vec<u8> = Vec::new();
    let mut seed = password.as_bytes().to_vec();
    while stream.len() < length {
        let hash = chicken_hash(&seed);
        stream.extend_from_slice(&hash);
        seed = hash.to_vec();
    }
    stream.truncate(length);
    stream.iter().map(|&b| b as u64).collect()
}

/// XOR each value in `data` with a byte from the password-derived key stream.
/// XOR is its own inverse, so the same function encrypts and decrypts.
///
/// All key data values are ≤ 1023 (10-bit) and key stream bytes are ≤ 255
/// (8-bit), so XOR results stay within 10 bits — valid chicken-format values.
fn password_xor(data: &[u64], password: &str) -> Vec<u64> {
    let key_stream = derive_key_stream(password, data.len());
    data.iter().zip(key_stream.iter()).map(|(&d, &k)| d ^ k).collect()
}

/// Return 8 verification values (0–255 each) derived from the password hash.
/// Stored in the key file so a wrong password can be detected early.
fn password_verify_values(password: &str) -> Vec<u64> {
    chicken_hash(password.as_bytes()).iter().map(|&b| b as u64).collect()
}

/// Return `true` if `input` is in minichicken (single-line) format.
pub fn is_minichicken_format(input: &str) -> bool {
    input.split_whitespace().next().map_or(false, |t| t != "chicken")
}

/// Return `true` if `input` appears to be a password-protected key file
/// (key type marker == `PasswordProtected`).
pub fn is_password_protected(input: &str) -> bool {
    match parse_chicken_sections(input) {
        Ok(sections) => sections.first().and_then(|s| s.first()) == Some(&(KeyType::PasswordProtected as u64)),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// 4. Key types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Public = 1,
    Private = 2,
    PasswordProtected = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    /// `e` for a public key, `d` for a private key.
    pub exponent: u64,
    /// `n = p * q`.
    pub modulus: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFile {
    pub key_type: KeyType,
    pub owner: String,
    pub pairs: Vec<KeyPair>,
}

// ---------------------------------------------------------------------------
// 3. Key generation
// ---------------------------------------------------------------------------

/// Generate a key vector of multiple independent pairs.
///
/// Returns `(public_key, private_key)`. The number of pairs is
/// `N = ceil(bits / 10)`. `bits` must be in `256..=4096`.
pub fn generate_keys(owner: &str, bits: u32) -> (KeyFile, KeyFile) {
    assert!(
        (256..=4096).contains(&bits),
        "bits must be in range 256..=4096, got {bits}"
    );

    let n_pairs = (bits as usize).div_ceil(10);
    let all_pairs = valid_prime_pairs();
    assert!(!all_pairs.is_empty(), "no valid prime pairs available");

    let mut rng = rand::thread_rng();

    let mut public_pairs = Vec::with_capacity(n_pairs);
    let mut private_pairs = Vec::with_capacity(n_pairs);

    for _ in 0..n_pairs {
        // Pick a random valid (p, q) prime pair.
        let &(p, q) = all_pairs.choose(&mut rng).expect("non-empty pairs");
        let n = p * q;
        let phi = (p - 1) * (q - 1);

        // Find the smallest e >= 2 coprime to phi.
        let mut e = 2u64;
        while gcd(e, phi) != 1 {
            e += 1;
        }

        let d = mod_inverse(e, phi).expect("e coprime to phi => inverse exists");

        public_pairs.push(KeyPair {
            exponent: e,
            modulus: n,
        });
        private_pairs.push(KeyPair {
            exponent: d,
            modulus: n,
        });
    }

    let public = KeyFile {
        key_type: KeyType::Public,
        owner: owner.to_string(),
        pairs: public_pairs,
    };
    let private = KeyFile {
        key_type: KeyType::Private,
        owner: owner.to_string(),
        pairs: private_pairs,
    };

    (public, private)
}

// ---------------------------------------------------------------------------
// 4. Format serialization / deserialization helpers
// ---------------------------------------------------------------------------

/// Build a single "chicken line" representing `value` (offset +1 applied):
/// the word "chicken" repeated `value + 1` times, space separated.
fn chicken_line(value: u64) -> String {
    let count = value + 1;
    vec!["chicken"; count as usize].join(" ")
}

const MINI_SEPARATOR: &str = "0";

fn parse_chicken_line(line: &str) -> Result<u64, String> {
    let count = line.split_whitespace().count() as u64;
    for word in line.split_whitespace() {
        if word != "chicken" {
            return Err(format!("unexpected token in chicken line: {word:?}"));
        }
    }
    if count == 0 {
        return Err("empty chicken line".to_string());
    }
    Ok(count - 1)
}

fn parse_chicken_sections(input: &str) -> Result<Vec<Vec<u64>>, String> {
    let trimmed = input.trim_end_matches(['\n', '\r']);

    let first_token = trimmed
        .split_whitespace()
        .next()
        .ok_or_else(|| "empty input".to_string())?;

    let is_minichicken = first_token != "chicken";

    if is_minichicken {
        let mut sections = vec![Vec::new()];
        for tok in trimmed.split_whitespace() {
            if tok == MINI_SEPARATOR {
                sections.push(Vec::new());
                continue;
            }
            let stored: u64 = tok
                .parse()
                .map_err(|_| format!("invalid number token: {tok:?}"))?;
            if stored == 0 {
                return Err(format!("stored value {stored} below offset"));
            }
            sections.last_mut().unwrap().push(stored - 1);
        }
        Ok(sections)
    } else {
        let mut sections = vec![Vec::new()];
        for line in trimmed.lines() {
            let line = line.trim();
            if line.is_empty() {
                if !sections.last().unwrap().is_empty() {
                    sections.push(Vec::new());
                }
                continue;
            }
            let v = parse_chicken_line(line)?;
            sections.last_mut().unwrap().push(v);
        }
        if sections.last().is_some_and(|s| s.is_empty()) {
            sections.pop();
        }
        Ok(sections)
    }
}

fn serialize_chicken_sections(sections: &[&[u64]], minichicken: bool) -> String {
    if minichicken {
        let parts: Vec<String> = sections
            .iter()
            .map(|section| {
                section
                    .iter()
                    .map(|&v| (v + 1).to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect();
        parts.join(&format!(" {MINI_SEPARATOR} "))
    } else {
        let mut lines = Vec::new();
        for (i, section) in sections.iter().enumerate() {
            if i > 0 {
                lines.push(String::new());
            }
            for &v in *section {
                lines.push(chicken_line(v));
            }
        }
        lines.join("\n")
    }
}

fn owner_to_values(owner: &str) -> Vec<u64> {
    owner.bytes().map(|b| b as u64).collect()
}

fn values_to_owner(values: &[u64]) -> Result<String, String> {
    let bytes: Result<Vec<u8>, String> = values
        .iter()
        .map(|&v| u8::try_from(v).map_err(|_| format!("owner byte value {v} out of range")))
        .collect();
    String::from_utf8(bytes?).map_err(|e| format!("invalid UTF-8 in owner: {e}"))
}

impl KeyFile {
    pub fn to_chicken_format(&self, minichicken: bool) -> String {
        let type_section = [self.key_type as u64];
        let owner_section = owner_to_values(&self.owner);
        let mut data_section = Vec::with_capacity(self.pairs.len() * 2);
        for pair in &self.pairs {
            data_section.push(pair.exponent);
            data_section.push(pair.modulus);
        }
        serialize_chicken_sections(&[&type_section, &owner_section, &data_section], minichicken)
    }

    pub fn from_chicken_format(input: &str) -> Result<Self, String> {
        let sections = parse_chicken_sections(input)?;
        // Detect password-protected key before the section-count check.
        if sections.first().and_then(|s| s.first()) == Some(&(KeyType::PasswordProtected as u64)) {
            return Err("this key is password-protected; provide a password to decrypt it".to_string());
        }
        if sections.len() != 3 {
            return Err(format!(
                "key file must have 3 sections (type, owner, data), got {}",
                sections.len()
            ));
        }
        let key_type = match sections[0].as_slice() {
            [1] => KeyType::Public,
            [2] => KeyType::Private,
            _ => return Err(format!("invalid key type marker: {:?}", sections[0])),
        };
        let owner = values_to_owner(&sections[1])?;
        let data = &sections[2];
        if data.len() % 2 != 0 {
            return Err(format!(
                "key file must contain an even number of data values, got {}",
                data.len()
            ));
        }
        let pairs = data
            .chunks_exact(2)
            .map(|c| KeyPair {
                exponent: c[0],
                modulus: c[1],
            })
            .collect();
        Ok(KeyFile {
            key_type,
            owner,
            pairs,
        })
    }

    /// Serialize this private key as a password-protected chicken / minichicken file.
    ///
    /// The output is valid chicken format: key type marker 3, owner section,
    /// verification section (8 hash bytes), and XOR-encrypted key data.
    pub fn to_protected_chicken_format(&self, password: &str, minichicken: bool) -> String {
        let type_section = [KeyType::PasswordProtected as u64];
        let owner_section = owner_to_values(&self.owner);
        let verify_section = password_verify_values(password);

        let mut data_section = Vec::with_capacity(self.pairs.len() * 2);
        for pair in &self.pairs {
            data_section.push(pair.exponent);
            data_section.push(pair.modulus);
        }
        let encrypted_data = password_xor(&data_section, password);

        serialize_chicken_sections(
            &[&type_section, &owner_section, &verify_section, &encrypted_data],
            minichicken,
        )
    }

    /// Parse a password-protected chicken / minichicken key file, decrypt it,
    /// and return a plain `Private` key.
    ///
    /// Returns an error if the password is incorrect or the file is malformed.
    pub fn from_protected_chicken_format(input: &str, password: &str) -> Result<Self, String> {
        let sections = parse_chicken_sections(input)?;
        if sections.len() != 4 {
            return Err(format!(
                "password-protected key file must have 4 sections, got {}",
                sections.len()
            ));
        }
        if sections[0].as_slice() != [KeyType::PasswordProtected as u64] {
            return Err("not a password-protected key file".to_string());
        }
        let owner = values_to_owner(&sections[1])?;

        let expected_verify = password_verify_values(password);
        if sections[2] != expected_verify {
            return Err("incorrect password".to_string());
        }

        let data = password_xor(&sections[3], password);
        if data.len() % 2 != 0 {
            return Err(format!(
                "decrypted key data must contain an even number of values, got {}",
                data.len()
            ));
        }
        let pairs = data
            .chunks_exact(2)
            .map(|c| KeyPair {
                exponent: c[0],
                modulus: c[1],
            })
            .collect();
        Ok(KeyFile {
            key_type: KeyType::Private,
            owner,
            pairs,
        })
    }
}

// ---------------------------------------------------------------------------
// 5. Ciphertext format
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherData {
    pub owner: String,
    pub values: Vec<u64>,
    pub signature: Option<Vec<u64>>,
}

impl CipherData {
    pub fn to_chicken_format(&self, minichicken: bool) -> String {
        let owner_section = owner_to_values(&self.owner);
        if let Some(ref sig) = self.signature {
            serialize_chicken_sections(&[&owner_section, &self.values, sig], minichicken)
        } else {
            serialize_chicken_sections(&[&owner_section, &self.values], minichicken)
        }
    }

    pub fn from_chicken_format(input: &str) -> Result<Self, String> {
        let sections = parse_chicken_sections(input)?;
        match sections.len() {
            2 => {
                let owner = values_to_owner(&sections[0])?;
                Ok(CipherData {
                    owner,
                    values: sections[1].clone(),
                    signature: None,
                })
            }
            3 => {
                let owner = values_to_owner(&sections[0])?;
                Ok(CipherData {
                    owner,
                    values: sections[1].clone(),
                    signature: Some(sections[2].clone()),
                })
            }
            n => Err(format!(
                "ciphertext must have 2 or 3 sections (owner, data[, signature]), got {n}"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Encrypt / Decrypt
// ---------------------------------------------------------------------------

/// Encrypt a plaintext byte stream using the key, rotating cyclically
/// through the key pairs. A magic prefix is prepended so that decryption
/// can detect a wrong key.
pub fn encrypt(plaintext: &[u8], key: &KeyFile) -> CipherData {
    assert!(!key.pairs.is_empty(), "key has no pairs");
    let n = key.pairs.len();
    let prefixed: Vec<u8> = MAGIC_PREFIX
        .iter()
        .chain(plaintext.iter())
        .copied()
        .collect();
    let values = prefixed
        .iter()
        .enumerate()
        .map(|(x, &byte)| {
            let pair = &key.pairs[x % n];
            mod_pow(byte as u64, pair.exponent, pair.modulus)
        })
        .collect();
    CipherData {
        owner: key.owner.clone(),
        values,
        signature: None,
    }
}

/// Decrypt ciphertext using the key, rotating cyclically through the key
/// pairs. Returns an error if the magic prefix doesn't match (wrong key
/// or corrupted data).
pub fn decrypt(cipher: &CipherData, key: &KeyFile) -> Result<Vec<u8>, String> {
    assert!(!key.pairs.is_empty(), "key has no pairs");
    let n = key.pairs.len();
    let all_bytes: Vec<u8> = cipher
        .values
        .iter()
        .enumerate()
        .map(|(x, &c)| {
            let pair = &key.pairs[x % n];
            mod_pow(c, pair.exponent, pair.modulus) as u8
        })
        .collect();

    if all_bytes.len() < MAGIC_PREFIX.len() || all_bytes[..MAGIC_PREFIX.len()] != MAGIC_PREFIX {
        return Err("decryption failed: wrong key or corrupted data".to_string());
    }

    Ok(all_bytes[MAGIC_PREFIX.len()..].to_vec())
}

// ---------------------------------------------------------------------------
// 7. Sign / Verify
// ---------------------------------------------------------------------------

fn canonical_unsigned(cipher: &CipherData) -> String {
    let unsigned = CipherData {
        owner: cipher.owner.clone(),
        values: cipher.values.clone(),
        signature: None,
    };
    unsigned.to_chicken_format(false)
}

/// Sign ciphertext by hashing its canonical form and encrypting the hash
/// with a private key. Returns a new `CipherData` with the signature attached.
pub fn sign(cipher: &CipherData, private_key: &KeyFile) -> CipherData {
    assert_eq!(private_key.key_type, KeyType::Private);
    assert!(!private_key.pairs.is_empty(), "key has no pairs");

    let canonical = canonical_unsigned(cipher);
    let hash = chicken_hash(canonical.as_bytes());

    let n = private_key.pairs.len();
    let sig_values: Vec<u64> = hash
        .iter()
        .enumerate()
        .map(|(i, &byte)| {
            let pair = &private_key.pairs[i % n];
            mod_pow(byte as u64, pair.exponent, pair.modulus)
        })
        .collect();

    CipherData {
        owner: cipher.owner.clone(),
        values: cipher.values.clone(),
        signature: Some(sig_values),
    }
}

/// Verify a signature on ciphertext using a public key.
pub fn verify(cipher: &CipherData, public_key: &KeyFile) -> Result<(), String> {
    assert_eq!(public_key.key_type, KeyType::Public);
    assert!(!public_key.pairs.is_empty(), "key has no pairs");

    let sig_values = cipher
        .signature
        .as_ref()
        .ok_or_else(|| "ciphertext is not signed".to_string())?;

    let n = public_key.pairs.len();
    let decrypted_hash: Vec<u8> = sig_values
        .iter()
        .enumerate()
        .map(|(i, &val)| {
            let pair = &public_key.pairs[i % n];
            mod_pow(val, pair.exponent, pair.modulus) as u8
        })
        .collect();

    let canonical = canonical_unsigned(cipher);
    let expected_hash = chicken_hash(canonical.as_bytes());

    if decrypted_hash.as_slice() != expected_hash.as_slice() {
        return Err("signature verification failed: hash mismatch".to_string());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 8. Key path resolution
// ---------------------------------------------------------------------------

pub fn resolve_key_path(path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.exists() {
        return p;
    }

    let mut fallback = dirs::home_dir().expect("cannot determine home directory");
    fallback.push(".cek");
    fallback.push(path);
    if fallback.exists() {
        return fallback;
    }

    p
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(54, 24), 6);
        assert_eq!(gcd(17, 5), 1);
        assert_eq!(gcd(0, 9), 9);
    }

    #[test]
    fn test_extended_gcd() {
        let (g, x, y) = extended_gcd(240, 46);
        assert_eq!(g, 2);
        assert_eq!(240 * x + 46 * y, g);
    }

    #[test]
    fn test_mod_inverse() {
        // From PLAN.md: e=5, phi=288 => d=173
        assert_eq!(mod_inverse(5, 288), Some(173));
        // e=3, phi=616 => d=411
        assert_eq!(mod_inverse(3, 616), Some(411));
        assert_eq!(mod_inverse(2, 4), None);
    }

    #[test]
    fn test_mod_pow() {
        assert_eq!(mod_pow(4, 13, 497), 445);
        assert_eq!(mod_pow(2, 10, 1000), 24);
        assert_eq!(mod_pow(123, 0, 7), 1);
    }

    #[test]
    fn test_is_prime() {
        assert!(is_prime(2));
        assert!(is_prime(17));
        assert!(is_prime(31));
        assert!(!is_prime(1));
        assert!(!is_prime(0));
        assert!(!is_prime(323)); // 17*19
    }

    #[test]
    fn test_valid_prime_pairs() {
        let pairs = valid_prime_pairs();
        assert!(!pairs.is_empty());
        for &(p, q) in &pairs {
            assert!(is_prime(p));
            assert!(is_prime(q));
            assert_ne!(p, q);
            let n = p * q;
            assert!((257..=1023).contains(&n));
        }
        // The PLAN.md example pairs should be present.
        assert!(pairs.contains(&(17, 19)));
        assert!(pairs.contains(&(23, 29)));
    }

    #[test]
    fn test_generate_and_roundtrip() {
        let (pubk, privk) = generate_keys("cluckmaster", 256);
        assert_eq!(pubk.pairs.len(), 26); // ceil(256/10)
        assert_eq!(privk.pairs.len(), 26);
        assert_eq!(pubk.owner, "cluckmaster");
        assert_eq!(pubk.key_type, KeyType::Public);
        assert_eq!(privk.key_type, KeyType::Private);

        let msg: Vec<u8> = (0u8..=255).collect();
        let cipher = encrypt(&msg, &pubk);
        let back = decrypt(&cipher, &privk).expect("decryption should succeed");
        assert_eq!(back, msg);
        assert_eq!(cipher.owner, "cluckmaster");
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let (pubk1, _privk1) = generate_keys("alice", 256);
        let (_pubk2, privk2) = generate_keys("bob", 256);

        let msg = b"hello chickens";
        let cipher = encrypt(msg, &pubk1);
        let result = decrypt(&cipher, &privk2);
        assert!(result.is_err());
    }

    #[test]
    fn test_keyfile_chicken_format_roundtrip() {
        let kf = KeyFile {
            key_type: KeyType::Public,
            owner: "cluckmaster".to_string(),
            pairs: vec![
                KeyPair {
                    exponent: 5,
                    modulus: 323,
                },
                KeyPair {
                    exponent: 3,
                    modulus: 667,
                },
            ],
        };

        let std = kf.to_chicken_format(false);
        let lines: Vec<&str> = std.lines().collect();
        // Line 0: type marker (1 = public → 2 chickens)
        assert_eq!(lines[0].split_whitespace().count(), 2);
        // Line 1: empty line separator
        assert_eq!(lines[1], "");
        // Lines 2..12: owner bytes (11 bytes for "cluckmaster")
        // Line 13: empty line separator
        assert_eq!(lines[13], "");
        // Line 14: first exponent (5 → 6 chickens)
        assert_eq!(lines[14].split_whitespace().count(), 6);
        let parsed = KeyFile::from_chicken_format(&std).unwrap();
        assert_eq!(parsed, kf);

        let mini = kf.to_chicken_format(true);
        // type=1(+1=2), owner "cluckmaster" bytes +1, data values +1
        assert_eq!(
            mini,
            "2 0 100 109 118 100 108 110 98 116 117 102 115 0 6 324 4 668"
        );
        let parsed_mini = KeyFile::from_chicken_format(&mini).unwrap();
        assert_eq!(parsed_mini, kf);
    }

    #[test]
    fn test_keyfile_type_preserved() {
        let kf_priv = KeyFile {
            key_type: KeyType::Private,
            owner: "a".to_string(),
            pairs: vec![KeyPair {
                exponent: 10,
                modulus: 323,
            }],
        };
        let mini = kf_priv.to_chicken_format(true);
        assert!(mini.starts_with("3 0")); // Private = 2, stored as 3
        let parsed = KeyFile::from_chicken_format(&mini).unwrap();
        assert_eq!(parsed.key_type, KeyType::Private);
    }

    #[test]
    fn test_cipherdata_format_roundtrip() {
        let cd = CipherData {
            owner: "hen".to_string(),
            values: vec![0, 5, 255],
            signature: None,
        };
        let std = cd.to_chicken_format(false);
        let parsed = CipherData::from_chicken_format(&std).unwrap();
        assert_eq!(parsed, cd);

        let mini = cd.to_chicken_format(true);
        // "hen" bytes: 104 101 110 → +1 each
        assert_eq!(mini, "105 102 111 0 1 6 256");
        let parsed_mini = CipherData::from_chicken_format(&mini).unwrap();
        assert_eq!(parsed_mini, cd);
    }

    #[test]
    fn test_format_detection() {
        // minichicken: owner bytes then 0 then data
        let mini = "112 120 111 102 115 0 1 2 3";
        let cd = CipherData::from_chicken_format(mini).unwrap();
        assert_eq!(cd.owner, "owner");
        assert_eq!(cd.values, vec![0, 1, 2]);

        // standard: verify roundtrip through chicken format
        let cd2 = CipherData {
            owner: "ox".to_string(),
            values: vec![1, 0],
            signature: None,
        };
        let std = cd2.to_chicken_format(false);
        let parsed = CipherData::from_chicken_format(&std).unwrap();
        assert_eq!(parsed.owner, "ox");
        assert_eq!(parsed.values, vec![1, 0]);
    }

    #[test]
    fn test_chicken_hash_deterministic() {
        let h1 = chicken_hash(b"hello chickens");
        let h2 = chicken_hash(b"hello chickens");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_chicken_hash_different_inputs() {
        let h1 = chicken_hash(b"hello");
        let h2 = chicken_hash(b"hellp");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_chicken_hash_empty() {
        let h = chicken_hash(b"");
        assert_eq!(h.len(), 8);
        assert_ne!(h, [0u8; 8]);
    }

    #[test]
    fn test_chicken_hash_long_input() {
        let data: Vec<u8> = (0u8..=255).cycle().take(10_000).collect();
        let h = chicken_hash(&data);
        assert_eq!(h.len(), 8);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (pubk, privk) = generate_keys("signer", 256);
        let (enc_pubk, _) = generate_keys("recipient", 256);
        let cipher = encrypt(b"secret message", &enc_pubk);
        let signed = sign(&cipher, &privk);
        assert!(signed.signature.is_some());
        assert!(verify(&signed, &pubk).is_ok());
    }

    #[test]
    fn test_verify_wrong_key() {
        let (_, privk_a) = generate_keys("alice", 256);
        let (pubk_b, _) = generate_keys("bob", 256);
        let (enc_pubk, _) = generate_keys("recipient", 256);
        let cipher = encrypt(b"data", &enc_pubk);
        let signed = sign(&cipher, &privk_a);
        assert!(verify(&signed, &pubk_b).is_err());
    }

    #[test]
    fn test_verify_tampered_data() {
        let (pubk, privk) = generate_keys("signer", 256);
        let (enc_pubk, _) = generate_keys("recipient", 256);
        let cipher = encrypt(b"original", &enc_pubk);
        let mut signed = sign(&cipher, &privk);
        signed.values[0] = signed.values[0].wrapping_add(1);
        assert!(verify(&signed, &pubk).is_err());
    }

    #[test]
    fn test_verify_tampered_signature() {
        let (pubk, privk) = generate_keys("signer", 256);
        let (enc_pubk, _) = generate_keys("recipient", 256);
        let cipher = encrypt(b"data", &enc_pubk);
        let mut signed = sign(&cipher, &privk);
        if let Some(ref mut sig) = signed.signature {
            sig[0] = sig[0].wrapping_add(1);
        }
        assert!(verify(&signed, &pubk).is_err());
    }

    #[test]
    fn test_password_protected_roundtrip() {
        let (_, privk) = generate_keys("hen", 256);
        for mini in [false, true] {
            let protected = privk.to_protected_chicken_format("s3cr3t", mini);
            assert!(is_password_protected(&protected));
            let recovered = KeyFile::from_protected_chicken_format(&protected, "s3cr3t").unwrap();
            assert_eq!(recovered.key_type, KeyType::Private);
            assert_eq!(recovered.owner, privk.owner);
            assert_eq!(recovered.pairs, privk.pairs);
        }
    }

    #[test]
    fn test_password_protected_wrong_password() {
        let (_, privk) = generate_keys("hen", 256);
        let protected = privk.to_protected_chicken_format("correct", false);
        assert!(KeyFile::from_protected_chicken_format(&protected, "wrong").is_err());
    }

    #[test]
    fn test_password_protected_rejected_by_from_chicken_format() {
        let (_, privk) = generate_keys("hen", 256);
        let protected = privk.to_protected_chicken_format("pw", false);
        let err = KeyFile::from_chicken_format(&protected).unwrap_err();
        assert!(err.contains("password-protected"));
    }

    #[test]
    fn test_password_protected_encrypt_decrypt_e2e() {
        let (pubk, privk) = generate_keys("hen", 256);
        let protected = privk.to_protected_chicken_format("pw", false);
        let recovered = KeyFile::from_protected_chicken_format(&protected, "pw").unwrap();
        let cipher = encrypt(b"bock bock", &pubk);
        let plain = decrypt(&cipher, &recovered).unwrap();
        assert_eq!(plain, b"bock bock");
    }

    #[test]
    fn test_verify_unsigned() {
        let (pubk, _) = generate_keys("signer", 256);
        let (enc_pubk, _) = generate_keys("recipient", 256);
        let cipher = encrypt(b"data", &enc_pubk);
        assert!(verify(&cipher, &pubk).is_err());
    }

    #[test]
    fn test_cipherdata_signed_format_roundtrip() {
        let cd = CipherData {
            owner: "hen".to_string(),
            values: vec![10, 20, 30],
            signature: Some(vec![100, 200, 300]),
        };
        let std = cd.to_chicken_format(false);
        let parsed = CipherData::from_chicken_format(&std).unwrap();
        assert_eq!(parsed, cd);

        let mini = cd.to_chicken_format(true);
        let parsed_mini = CipherData::from_chicken_format(&mini).unwrap();
        assert_eq!(parsed_mini, cd);
    }

    #[test]
    fn test_signed_format_backwards_compatible() {
        let unsigned = CipherData {
            owner: "ox".to_string(),
            values: vec![1, 2],
            signature: None,
        };
        let text = unsigned.to_chicken_format(false);
        let parsed = CipherData::from_chicken_format(&text).unwrap();
        assert_eq!(parsed.signature, None);
        assert_eq!(parsed.values, vec![1, 2]);
    }
}
