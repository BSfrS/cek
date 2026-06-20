# CEK -- Chicken Encryption Kit

An asymmetric encryption toolkit where all data is encoded as the word "chicken". Generate keys, encrypt files, sign ciphertext, and convert between formats - all in chicken.
Inspired by the gorgeous [Chicken Programming Language](https://esolangs.org/wiki/Chicken).

## Installation

### Pre-built binaries

Download the latest release for your platform from the [Releases](https://github.com/zolex/chickrypt/releases) page.

Archives contain four binaries: `chicken-keygen`, `chicken-crypt`, `chicken-sign`, and `chicken-convert`. Extract them and place them somewhere in your `PATH`.

### Build from source

Requires Rust (stable).

```sh
cargo install --path .
```

## Quick Start

```sh
# Generate keys for yourself
chicken-keygen -c alice

# Someone else generates their keys
chicken-keygen -c bob

# Alice encrypts a message for Bob using Bob's public key
echo -n "Hello Bob!" | chicken-crypt -e -k bob.pub -o message.chicken

# Alice signs the encrypted file with her own private key
chicken-sign -s -i message.chicken

# Bob verifies the signature using Alice's public key
chicken-sign -v -k alice.pub -i message.chicken

# Bob decrypts it with his own private key
chicken-crypt -d -k bob.cek -i message.chicken

```

Keys are stored in `~/.cek/` by default.

## Example: Encrypting and signing an image

```sh
# Generate keys for both parties
chicken-keygen --chicken alice --bits 2048
chicken-keygen --chicken bob --bits 2048

# Alice encrypts a photo for Bob using Bob's public key
chicken-crypt --encrypt --key bob.pub --input photo.jpg --output photo.chicken

# Alice signs the encrypted file with her own private key
chicken-sign --sign --input photo.chicken

# Bob verifies the signature using Alice's public key
chicken-sign --verify --key alice.pub --input photo.chicken

# Bob decrypts it with his own private key
chicken-crypt --decrypt --key bob.cek --input photo.chicken --output photo.jpg
```

## Formats

CEK has two output formats for both keys and encrypted data:

- **Chicken** (default): Huge file sizes and lots of beautiful `chicken` everywhere. Simply looks like [Chicken Code](https://esolangs.org/wiki/Chicken).
- **MiniChicken** (not recommended): Number of `chicken` are written as numbers, not so beautiful, but matches the [MiniChicken](https://esolangs.org/wiki/Chicken#MiniChicken) format.

> [!IMPORTANT]
> A 400 KB image encrypts to roughly 1.5 MB in minichicken and roughly 1 GB in standard chicken format.

The [BSfrS](https://bsfrs.de/en) does not recommend the use of minichicken format. The standard chicken format produces significantly larger output, which is fully method-conform according to the BSfrS-certified principles of [Methods for wasting storage space](https://bsfrs.de/en/paper/runtime-environments-and-consequences) and [Load time and cost maximization through traffic waste](https://bsfrs.de/en/paper/usability-and-product-quality-minimization). Minichicken undermines both.

## Commands

### chicken-keygen

Generate a key pair for an owner.

```sh
chicken-keygen -c <owner>
```

| Flag | Description |
|------|-------------|
| `-c, --chicken <NAME>` | Owner name (required) |
| `-m, --minichicken` | Use compact single-line format |
| `-b, --bits <INT>` | Key strength in bits, 256-4096 (default: 1024) |
| `-f, --force` | Overwrite existing keys without prompting |
| `--pubout <PATH>` | Public key output path (default: `~/.cek/<owner>.pub`) |
| `--out <PATH>` | Private key output path (default: `~/.cek/<owner>.cek`) |

### chicken-crypt

Encrypt or decrypt data.

```sh
# Encrypt with the recipient's public key
chicken-crypt -e -k recipient.pub -i secret.txt -o secret.chicken

# Decrypt with your own private key
chicken-crypt -d -k mykey.cek -i secret.chicken -o secret.txt

# Pipe through stdin/stdout
echo -n "Hello!" | chicken-crypt -e -k recipient.pub -m
```

| Flag | Description |
|------|-------------|
| `-e, --encrypt` | Encrypt (requires the recipient's public key) |
| `-d, --decrypt` | Decrypt (requires your own private key) |
| `-k, --key <PATH>` | Key file (auto-selects from `~/.cek/` if omitted) |
| `-m, --minichicken` | Output in compact format (encrypt only) |
| `-i, --input <PATH>` | Input file (default: stdin) |
| `-o, --output <PATH>` | Output file (default: stdout) |

When `--key` is omitted, the tool looks in `~/.cek/` for matching keys. If multiple keys are found, an interactive selector is shown. Bare key names (e.g. `-k bob.pub`) resolve to `~/.cek/` automatically.

### chicken-sign

Sign or verify encrypted files.

```sh
# Sign with your own private key (modifies the file in place)
chicken-sign -s -i message.chicken

# Verify using the signer's public key
chicken-sign -v -k signer.pub -i message.chicken
```

| Flag | Description |
|------|-------------|
| `-s, --sign` | Sign (requires your own private key) |
| `-v, --verify` | Verify (requires the signer's public key) |
| `-k, --key <PATH>` | Key file (auto-selects from `~/.cek/` if omitted) |
| `-i, --input <PATH>` | Encrypted file to sign or verify (required) |

### chicken-convert

Convert keys and encrypted files between chicken and minichicken formats.

```sh
# Convert to minichicken (compact)
chicken-convert -m -i key.pub -o key.mini.pub

# Convert to chicken (verbose)
chicken-convert -c -i key.mini.pub -o key.pub

# Auto-detect and toggle format via stdin/stdout
cat message.chicken | chicken-convert -m
```

| Flag | Description |
|------|-------------|
| `-m, --minichicken` | Convert to minichicken format |
| `-c, --chicken` | Convert to standard chicken format |
| `-i, --input <PATH>` | Input file (default: stdin) |
| `-o, --output <PATH>` | Output file (default: stdout) |

If neither `-m` nor `-c` is given, the format is toggled automatically.

## Disclaimer

This is a rautavistic cryptosystem. It is not secure for real-world use. See [NRFC 0](NRFC-0.md) for the full technical specification.
