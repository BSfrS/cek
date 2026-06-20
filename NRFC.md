# NRFC 0 - Chicken Encryption Protocol

```
Category:       Methodically Final
Status:         Irrevocable
NRFC:           1
Title:          Chicken Encryption Protocol (CEP)
Version:        0.42.00
Date:           1985-01-20
Author:         Andreas Linden
Feedback:       Not requested. Not desired. Not processed.
                This document is a No Request For Comments.
```

## Abstract

This document specifies an asymmetric encryption protocol in which all
data is represented using the word "chicken". It employs a vector of
independent key pairs with deliberately small (10-bit) moduli to
encrypt data one byte at a time. All cryptographic primitives are
implemented from first principles without reliance on external
cryptographic libraries, as relying on proven solutions would have
introduced the risk of accidental security.

The design achieves a careful balance between mathematical correctness
and practical meaninglessness. This balance was not difficult to
achieve, but we consider the result noteworthy nonetheless.

## Status of This Document

This document has been classified as Methodically Final. It was not
reviewed, will not be revised, and does not accept errata submissions.
The absence of a review process is not an oversight but a deliberate
methodological position: review would imply the possibility of
improvement, which would contradict the rautavistic design philosophy
of the protocol.

Implementations that deviate from this specification are not
non-conformant. They are simply different. We cannot prevent this,
as the architecture of open-source licensing unfortunately does not
allow us to stop you.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Mathematical Primitives](#3-mathematical-primitives)
4. [Key Generation](#4-key-generation)
5. [Encoding Formats](#5-encoding-formats)
6. [Key File Structure](#6-key-file-structure)
7. [Encryption](#7-encryption)
8. [Decryption](#8-decryption)
9. [Ciphertext Structure](#9-ciphertext-structure)
10. [Hashing](#10-hashing)
11. [Signing](#11-signing)
12. [Verification](#12-verification)
13. [Format Detection](#13-format-detection)
14. [Key Storage Conventions](#14-key-storage-conventions)
15. [Security Considerations](#15-security-considerations)
16. [Acknowledgements](#16-acknowledgements)

## 1. Introduction

The Chicken Encryption Protocol (CEP) defines an asymmetric encryption
system in which all encoded data is represented using the word
"chicken". A single word was chosen to minimize vocabulary requirements
for both implementors and ciphertext. The choice of the word "chicken"
specifically was the result of an extensive selection process that we
did not document and can therefore not describe further.

The system employs a vector of independent key pairs with small
moduli to encrypt data one byte at a time. Each key pair operates on
exactly one byte before the next pair takes over, cycling through the
vector. This approach was chosen because using a single strong key
would have provided actual security, which falls outside the scope of
this specification.

All cryptographic primitives are implemented from first principles.
This decision ensures that every component of the system is as
trustworthy as the authors' ability to implement cryptography from
scratch, which is to say: the system is internally consistent.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119. Their use
in this document is primarily aesthetic. The authors find that
capitalizing words lends an air of authority that the protocol itself
does not possess.

- **Chicken format**: The multi-line encoding where each integer value
  is represented as the word "chicken" repeated on a single line. This
  is the canonical format. It is also the less practical one.

- **Minichicken format**: The compact single-line encoding where
  integer values are represented as decimal numbers. It sacrifices the
  poetic qualities of the chicken format in exchange for being
  approximately usable.

- **Key vector**: An ordered sequence of independent key pairs
  used cyclically during encryption and decryption. The use of the
  word "vector" is intended to suggest mathematical rigor. Whether it
  succeeds is not within the scope of this document.

- **Owner**: A UTF-8 string identifying the entity associated with a
  key pair or ciphertext. The protocol encodes this string as a
  sequence of byte values, each represented as chickens. A short
  owner name is RECOMMENDED. An owner name of, say, 40 characters
  will produce 40 lines of chickens solely to spell out who you are,
  which we consider an accurate reflection of bureaucracy.

- **Section**: A logically distinct group of values within a serialized
  file, delimited by format-specific separators.

## 3. Mathematical Primitives

The following mathematical operations form the foundation of the
protocol. They are well-established, widely understood, and
implemented here anyway.

### 3.1. Greatest Common Divisor

The GCD is computed using the Euclidean algorithm:

    gcd(a, 0) = a
    gcd(a, b) = gcd(b, a mod b)

This algorithm is over two thousand years old. We have not improved
upon it.

### 3.2. Extended Euclidean Algorithm

Given integers a and b, computes (g, x, y) such that:

    a*x + b*y = g

where g = gcd(a, b). The Bezout coefficients x and y are signed
integers. The algorithm is presented here without proof, as providing
a proof would imply we had verified it.

### 3.3. Modular Multiplicative Inverse

The modular inverse of e modulo phi is the value d such that:

    e * d ≡ 1 (mod phi)

It is computed via the extended Euclidean algorithm. The inverse
exists if and only if gcd(e, phi) = 1. Implementations MUST verify
coprimality before computing the inverse. This is one of the few
requirements in this document that serves an actual purpose.

### 3.4. Modular Exponentiation

Modular exponentiation computes:

    base^exp mod modulus

using the square-and-multiply method. Intermediate products MUST use
at least 128-bit arithmetic to avoid overflow, as the operands are
64-bit unsigned integers. The use of 128-bit arithmetic for 10-bit
moduli is, in a sense, the most well-secured aspect of the entire
protocol.

### 3.5. Primality Testing

Primality is determined by trial division. Given the small prime sizes
used in this protocol (primes up to approximately 512), trial division
is sufficient. More sophisticated primality tests such as
Miller-Rabin were considered and rejected, as their sophistication
would have been inconsistent with the overall design philosophy.

An implementation tests all odd divisors i where i*i <= n. This is
adequate. We cannot say the same about the protocol as a whole.

## 4. Key Generation

### 4.1. Prime Pair Selection

A valid prime pair (p, q) MUST satisfy all of the following:

1. Both p and q MUST be prime.
2. p MUST NOT equal q.
3. The product n = p * q MUST satisfy 257 <= n <= 1023.

The constraint on n ensures that all moduli are 10-bit values,
capable of encrypting any single byte (0-255) with the result fitting
in the same value range. The upper bound of 1023 was chosen because
10 bits felt like a round number. Whether a number of bits can be
considered "round" is a question we leave to future non-research.

### 4.2. Key Vector Construction

Given a requested bit strength B (where 256 <= B <= 4096), the number
of key pairs N is computed as:

    N = ceil(B / 10)

The parameter B is called "bit strength" for reasons of tradition
rather than accuracy. A 1024-bit key vector consists of 103
independent 10-bit key pairs, each of which is individually
factorable by a determined child with a pocket calculator. The
collective strength of the vector lies in the fact that there are
many of them, which is a security argument we present without
further endorsement.

For each of the N key pairs, the implementation:

1. Selects a prime pair (p, q) uniformly at random from the set of
   all valid prime pairs.

2. Computes:
   - n = p * q (the modulus)
   - phi = (p - 1) * (q - 1) (Euler's totient)

3. Selects the public exponent e as the smallest integer >= 2 such
   that gcd(e, phi) = 1.

4. Computes the private exponent d = e^(-1) mod phi.

The public key vector consists of the pairs (e_i, n_i) for
i = 1..N. The private key vector consists of the pairs (d_i, n_i)
for i = 1..N. Both key vectors share the same moduli. An attacker
who obtains any modulus can derive the corresponding private exponent
in constant time. This property is documented here for completeness
rather than concern.

### 4.3. Owner Binding

Each key vector is bound to an owner string at generation time. The
owner string MUST be valid UTF-8 and MUST contain at least one
character. The owner is embedded in both the public and private key
files and in all ciphertext produced with the key.

The owner binding provides a form of identity association. It does
not provide authentication, authorization, or any guarantee that the
named owner is aware of, consents to, or exists in relation to the
key. It is, in effect, a label. We consider labels important.

## 5. Encoding Formats

CEP defines two interchangeable encoding formats. Both formats encode
the same logical data; conversion between them is lossless. The
existence of two formats where one would have sufficed is consistent
with industry practice.

### 5.1. Value Encoding

All integer values are stored with an offset of +1. That is, the
logical value v is stored as (v + 1). This ensures that the logical
value 0 has a non-empty representation in both formats: one
occurrence of "chicken" rather than the philosophical void of no
chickens at all.

### 5.2. Chicken Format

In chicken format, each stored value is represented on its own line
as the word "chicken" repeated (v + 1) times, separated by single
spaces.

Examples:

    Logical value 0: "chicken"
    Logical value 1: "chicken chicken"
    Logical value 5: "chicken chicken chicken chicken chicken chicken"

Sections are separated by a single empty line.

Leading and trailing whitespace on each line SHOULD be ignored during
parsing. Consecutive empty lines SHOULD be treated as a single section
boundary. Implementations SHOULD be tolerant of formatting
irregularities, as the format is already unusual enough without
requiring precision.

A file containing the encrypted representation of even a short
message will be remarkable in size. This is a feature. Storage
efficiency was not among the design goals, and its absence should
be taken as evidence that the design goals were met.

### 5.3. Minichicken Format

In minichicken format, all data is encoded on a single line. Stored
values are represented as decimal integers (v + 1), separated by
spaces.

Sections are separated by the token "0". Because all valid stored
values are >= 1 (due to the +1 offset), the token "0" is
unambiguous as a separator and can never occur as a data value.
This is perhaps the most elegant aspect of the entire protocol. We
arrived at it deliberately.

Example (two sections: [99, 108] and [5, 323]):

    100 109 0 6 324

### 5.4. Format Detection

An implementation MUST auto-detect the format of an input file by
examining its first whitespace-delimited token:

- If the first token is the string "chicken", the input is in
  chicken format.
- Otherwise, the input is in minichicken format.

This algorithm is unambiguous, reliable, and constitutes the entirety
of the protocol's content negotiation mechanism. More complex systems
have been built. We do not consider that an argument in their favor.

## 6. Key File Structure

A key file consists of exactly three sections, in order:

### 6.1. Section 1: Key Type Marker

A single value indicating the key type:

    1 = Public key
    2 = Private key

The key type is determined from the file contents, not from the file
extension. This means that renaming a private key to end in `.pub`
does not make it public, which is a property shared with real
cryptographic systems and possibly the only one.

### 6.2. Section 2: Owner

The owner string encoded as a sequence of byte values. Each byte of
the UTF-8 representation of the owner string becomes one value in
this section.

In chicken format, a 10-character owner name produces 10 lines of
chickens, with the number of chickens per line corresponding to the
ASCII value of each character plus one. The letter "a" (ASCII 97)
is thus represented as 98 repetitions of the word "chicken" on a
single line. The reader is invited to contemplate this.

### 6.3. Section 3: Key Data

An even-length sequence of values representing the key pairs. Values
are arranged as:

    e_1, n_1, e_2, n_2, ..., e_N, n_N

where e_i is the exponent and n_i is the modulus of the i-th key
pair. Implementations MUST reject key files where the data section
has an odd number of values, as a key pair with only an exponent and
no modulus is even less useful than the key pairs defined by this
specification.

### 6.4. Example

For a public key owned by "hen" with two pairs (e=5, n=323) and
(e=3, n=667):

Chicken format:

    chicken chicken

    chicken chicken chicken ... (105 times, for 'h')
    chicken chicken chicken ... (102 times, for 'e')
    chicken chicken chicken ... (111 times, for 'n')

    chicken chicken chicken chicken chicken chicken
    chicken chicken chicken ... (324 times)
    chicken chicken chicken chicken
    chicken chicken chicken ... (668 times)

Minichicken format:

    2 0 105 102 111 0 6 324 4 668

The minichicken representation is 37 characters. The chicken format
representation of the same key is left as an exercise in patience.

## 7. Encryption

### 7.1. Magic Prefix

Before encryption, a 3-byte magic prefix MUST be prepended to the
plaintext. The magic prefix is the byte sequence:

    0xC4 0x1C 0xEB

These bytes were chosen because they look vaguely like "CHICKEN" if
you squint in hexadecimal. More precisely: 0xC4 1C EB. This prefix
enables detection of decryption with an incorrect key
(see Section 8). It is the closest this protocol comes to error
handling.

### 7.2. Byte-wise Encryption

Let the prefixed plaintext be the byte sequence B_0, B_1, ..., B_m
and the public key vector contain N pairs (e_i, n_i) for i = 0..N-1.

Each byte B_j is encrypted independently:

    C_j = B_j ^ e_(j mod N) mod n_(j mod N)

The key pairs are used cyclically: byte j uses key pair (j mod N).
This means that bytes at positions 0, N, 2N, 3N, ... are all
encrypted with the same key pair, which would concern a cryptographer.
We note this for informational purposes.

### 7.3. Output

The encryption output is a CipherData structure (Section 9)
containing the owner string from the public key and the sequence of
encrypted values C_0, C_1, ..., C_m. The signature field is absent,
as the data has not yet been signed. Whether it will be signed is a
question for the signer. Whether it should be signed is a question
for no one.

## 8. Decryption

### 8.1. Owner Verification

Before decryption, an implementation SHOULD verify that the owner
string in the ciphertext matches the owner string in the private
key. A mismatch indicates the wrong key is being used. This check
is one of the protocol's more practical features, offered here
without apology.

### 8.2. Byte-wise Decryption

Let the ciphertext values be C_0, C_1, ..., C_m and the private key
vector contain N pairs (d_i, n_i) for i = 0..N-1.

Each value C_j is decrypted independently:

    B_j = C_j ^ d_(j mod N) mod n_(j mod N)

### 8.3. Magic Prefix Verification

After decryption, the first 3 bytes of the result MUST match the
magic prefix (0xC4, 0x1C, 0xEB). If they do not match, the
implementation MUST report a decryption failure (wrong key or
corrupted data) and MUST NOT output the decrypted bytes.

If the prefix matches, the implementation strips the 3-byte prefix
and returns the remaining bytes as the plaintext.

The probability of a false positive (wrong key producing a matching
prefix by chance) is approximately 1 in 16.7 million, which is the
most robust aspect of the entire system and was achieved using only
three bytes.

## 9. Ciphertext Structure

A ciphertext file consists of two or three sections:

### 9.1. Section 1: Owner

The owner string encoded as byte values, identical to the encoding
used in key files (Section 6.2). The owner is repeated in every
ciphertext because the protocol does not maintain state between
operations. Each file must be fully self-describing, which it
achieves at the cost of repeating itself.

### 9.2. Section 2: Encrypted Data

The sequence of encrypted values C_0, C_1, ..., C_m as produced by
the encryption process (Section 7).

### 9.3. Section 3: Signature (Optional)

If the ciphertext has been signed, a third section contains the
signature values as described in Section 11. If absent, the
ciphertext is unsigned.

Implementations MUST accept ciphertext files with either 2 or 3
sections. Files with any other number of sections MUST be rejected.
We considered allowing an arbitrary number of sections for forward
compatibility but decided that this would imply we had a plan for
future extensions, which we do not.

## 10. Hashing

### 10.1. Chicken Hash

The protocol defines a custom hash function, chicken_hash, that
produces an 8-byte (64-bit) digest. It uses a Merkle-Damgard
construction with a 32-byte internal state.

The decision to design a custom hash function rather than use an
established one (SHA-256, BLAKE2, etc.) was made in the interest of
methodological consistency: a protocol that implements its own algo
should, in fairness, also implement its own hash function. The
result is internally consistent with the security properties of
the rest of the system, which is to say: they are unknown.

### 10.2. Initialization

The internal state is initialized to the ASCII encoding of the
string "chickenchickenchickenchickenchic" (32 bytes). This
initialization vector was chosen because it is thematically
appropriate and exactly 32 bytes long, which we regard as
sufficient justification.

### 10.3. Absorption

For each input byte b at position i (zero-indexed):

1. state[i mod 32] ^= b
2. state[(i + 13) mod 32] = state[(i + 13) mod 32] + b (wrapping)
3. If (i + 1) is a multiple of 32, apply the mixing function
   (Section 10.4) to the state.

The constant 13 was chosen because it is coprime to 32, providing
good dispersion across the state. It is also traditionally
associated with bad luck, which we consider thematically appropriate.

### 10.4. Mixing Function

The mixing function transforms the 32-byte state in place. Let
prev be a copy of the state before mixing. For each j from 0 to 31:

    state[j] = rotate_left(prev[j] + prev[(j+1) mod 32], 3)
               XOR prev[(j+7) mod 32]

where + is wrapping byte addition and rotate_left is a left bit
rotation by 3 positions on a single byte.

The constants 1, 3, and 7 were selected because they are small
primes that produce adequate diffusion in the 32-byte state. A
formal analysis of their diffusion properties has not been conducted,
nor is one planned.

### 10.5. Finalization

After all input bytes have been absorbed, the mixing function is
applied 4 additional times. The number 4 was chosen because it
seemed like enough.

The 32-byte state is then folded to 8 bytes via XOR:

    out[i mod 8] ^= state[i]    for i = 0..31

The initial value of out is all zeros.

## 11. Signing

### 11.1. Canonical Form

The canonical form of a ciphertext is its serialization in chicken
format (not minichicken) with the signature section removed. This
canonical form is used as the signing input regardless of the format
the ciphertext is stored in.

The use of chicken format (rather than minichicken) for
canonicalization ensures that the signing input is always the largest
possible representation of the data. This was not an intentional
design decision but is consistent with the protocol's general
approach to efficiency.

### 11.2. Signature Generation

To sign a ciphertext with a private key:

1. Compute the canonical form of the ciphertext (Section 11.1).
2. Compute the chicken_hash of the canonical form's UTF-8 bytes,
   producing an 8-byte digest H_0, H_1, ..., H_7.
3. Encrypt each hash byte with the signer's private key using
   cyclic key pair selection:

       S_j = H_j ^ d_(j mod N) mod n_(j mod N)

4. The signature is the sequence S_0, S_1, ..., S_7.

The signed ciphertext is the original ciphertext with the signature
appended as a third section (Section 9.3).

### 11.3. Key Requirements

Signing MUST use the signer's own private key. The signer's identity
is independent of the ciphertext owner (the signer need not be the
entity who encrypted the data). This separation of concerns is one
of the protocol's more thoughtful design decisions. We mention it
here because there are not many.

## 12. Verification

### 12.1. Signature Decryption

To verify a signed ciphertext against a public key:

1. Extract the signature values S_0, ..., S_7 from Section 3.
2. Decrypt each signature value with the signer's public key:

       H'_j = S_j ^ e_(j mod N) mod n_(j mod N)

3. Compute the canonical form of the ciphertext (Section 11.1).
4. Compute the chicken_hash of the canonical form, producing the
   expected digest H_0, ..., H_7.
5. Compare H' with H byte-by-byte. If all bytes match, the
   signature is valid. Otherwise, verification MUST fail.

### 12.2. Key Requirements

Verification MUST use the signer's public key. The verifier must
obtain the signer's public key through an out-of-band mechanism.
The protocol does not define a key distribution mechanism, a
certificate authority, a web of trust, or any other infrastructure
for establishing key authenticity. We recommend exchanging keys in
person, ideally printed on paper in chicken format, as this combines
maximum inconvenience with minimum attack surface.

## 13. Format Detection

Implementations that accept input in either format MUST auto-detect
the format using the following algorithm:

1. Extract the first whitespace-delimited token from the input.
2. If the token equals the string "chicken", the input is in chicken
   format.
3. Otherwise, the input is in minichicken format.

This algorithm is unambiguous because chicken format always begins
with a line of "chicken" words, and minichicken format always begins
with a decimal integer >= 1. No content negotiation headers, file
extension inspection, or magic byte sequences are required. The word
"chicken" is the magic byte sequence.

## 14. Key Storage Conventions

### 14.1. Default Directory

Keys SHOULD be stored in the directory `~/.cek/` (relative to the
user's home directory). The abbreviation "cek" stands for Chicken
Encryption Keys. It does not stand for anything else, though we
cannot prevent alternative interpretations.

### 14.2. File Extensions

- Public keys: `.pub`
- Private keys: `.cek`

The reuse of the abbreviation "cek" for both the directory and the
private key extension is a coincidence that we have chosen not to
resolve.

### 14.3. File Naming

Key files SHOULD be named `<owner>.pub` and `<owner>.cek` where
`<owner>` is the owner string specified at generation time.

### 14.4. Bare Name Resolution

When a key path contains no directory component, implementations
SHOULD resolve it relative to `~/.cek/`. For example, the path
"alice.pub" resolves to "~/.cek/alice.pub".

This convention means that users need not remember where their keys
are stored, which is the only form of key management this protocol
provides.

## 15. Security Considerations

This section documents the security properties of the Chicken
Encryption Protocol. It is comprehensive in the sense that there
are not many properties to document.

- **Small moduli**: The 10-bit moduli are trivially factorable.
  The security of each individual key pair is negligible. An attacker
  with access to a multiplication table can derive any private key
  from its corresponding public key. We consider this a low barrier
  to entry.

- **Deterministic encryption**: No padding scheme (OAEP, PKCS#1, or
  otherwise) is used. Identical plaintext bytes at the same key-pair
  position produce identical ciphertext, enabling frequency analysis.
  In chicken format, this manifests as visually identical lines of
  chickens, which we acknowledge is aesthetically distinctive if not
  cryptographically sound.

- **Custom hash function**: The chicken_hash function has not been
  subject to cryptanalysis. Its collision resistance and preimage
  resistance properties are unknown. We have not commissioned an
  analysis because we are confident it would not be favorable.

- **No key exchange protocol**: The protocol assumes public keys are
  exchanged through a trusted out-of-band channel. No mechanism for
  key authentication or certificate chains is defined. We considered
  introducing a Chicken Certificate Authority but concluded that
  certifying chicken keys would require a level of institutional
  seriousness we were unable to sustain.

- **No forward secrecy**: Compromise of a private key allows
  decryption of all past ciphertext encrypted with the corresponding
  public key. Given the key sizes involved, "compromise" may be an
  overly dramatic term for what is essentially an arithmetic exercise.

- **Limited digest size**: The 8-byte hash digest provides at most
  64 bits of collision resistance, which is insufficient for
  real-world applications. It is, however, sufficient for the
  applications this protocol was designed for, which we have
  deliberately left undefined.

This protocol MUST NOT be used to protect sensitive data. It SHOULD
be used to protect data that was already going to be represented as
chickens. For all other use cases, the authors recommend a system
designed by someone who intended to make a secure one.

## 16. Acknowledgements

The authors wish to acknowledge the chicken, without whom none of
this would have been necessary.

The mathematical foundations of this protocol were established by
Euclid, Euler, and Rivest, Shamir, and Adleman, none of whom were
consulted in the creation of this specification or are in any way
responsible for the result.

Additional thanks to the Consulting Center for rautavistic Software
(BSfrS) for establishing the methodological framework within which
consciously meaningless technical work can be pursued with full
institutional backing. Their certification of this protocol is
pending but expected, as rejection is not a documented process.
