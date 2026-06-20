use cek::cli::*;
use cek::*;
use clap::Parser;
use std::process;

/// chicken-crypt: encrypt or decrypt data using chicken-format keys.
#[derive(Parser, Debug)]
#[command(
    name = "chicken-crypt",
    about = "Encrypt or decrypt data using chicken-format keys"
)]
struct Args {
    /// Encrypt mode (requires the recipient's public key).
    #[arg(short = 'e', long = "encrypt")]
    encrypt: bool,

    /// Decrypt mode (requires your own private key).
    #[arg(short = 'd', long = "decrypt")]
    decrypt: bool,

    /// Path to key file. If omitted, auto-selects from ~/.cek/.
    /// For encryption, provide the recipient's .pub key.
    /// For decryption, provide your own .cek key.
    #[arg(short = 'k', long = "key")]
    key: Option<String>,

    /// Output in minichicken format (only relevant when encrypting).
    #[arg(short = 'm', long = "minichicken")]
    minichicken: bool,

    /// Input file. If omitted, read from stdin.
    #[arg(short = 'i', long = "input")]
    input: Option<String>,

    /// Output file. If omitted, write to stdout.
    #[arg(short = 'o', long = "output")]
    output: Option<String>,
}

fn main() {
    let args = Args::parse();

    match (args.encrypt, args.decrypt) {
        (false, false) => {
            eprintln!("error: a mode is required: use --encrypt or --decrypt");
            process::exit(1);
        }
        (true, true) => {
            eprintln!("error: --encrypt and --decrypt are mutually exclusive");
            process::exit(1);
        }
        (true, false) => {
            let key_path =
                resolve_key_for_mode(&args.key, "pub", "encryption (recipient's public key)");
            let key = read_key(&key_path);
            if key.key_type == KeyType::Private {
                eprintln!(
                    "error: encryption requires the recipient's public key, but got a private key"
                );
                process::exit(1);
            }
            let bytes = read_input_bytes(&args.input);
            let cipher = encrypt(&bytes, &key);
            let text = cipher.to_chicken_format(args.minichicken);
            write_output(&args.output, text.as_bytes());
        }
        (false, true) => {
            let key_path = resolve_key_for_mode(&args.key, "cek", "decryption (your private key)");
            let key = read_key(&key_path);
            if key.key_type == KeyType::Public {
                eprintln!("error: decryption requires your own private key, but got a public key");
                process::exit(1);
            }
            let text = read_input_text(&args.input);
            let cipher = match CipherData::from_chicken_format(&text) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: failed to parse encrypted input: {e}");
                    process::exit(1);
                }
            };
            if cipher.owner != key.owner {
                eprintln!(
                    "error: key owner '{}' does not match ciphertext owner '{}'",
                    key.owner, cipher.owner
                );
                process::exit(1);
            }
            let bytes = match decrypt(&cipher, &key) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            };
            write_output(&args.output, &bytes);
        }
    }
}
