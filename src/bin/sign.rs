use cek::cli::*;
use cek::*;
use clap::Parser;
use std::fs;
use std::process;

/// chicken-sign: sign or verify encrypted data using chicken-format keys.
#[derive(Parser, Debug)]
#[command(
    name = "chicken-sign",
    about = "Sign or verify encrypted data using chicken-format keys"
)]
struct Args {
    /// Sign mode (requires your own private key).
    #[arg(short = 's', long = "sign")]
    sign: bool,

    /// Verify mode (requires the signer's public key).
    #[arg(short = 'v', long = "verify")]
    verify: bool,

    /// Path to key file. If omitted, auto-selects from ~/.cek/.
    /// For signing, provide your own .cek key.
    /// For verification, provide the signer's .pub key.
    #[arg(short = 'k', long = "key")]
    key: Option<String>,

    /// Input file (the encrypted .chick file to sign or verify).
    #[arg(short = 'i', long = "input")]
    input: String,
}

fn is_minichicken(text: &str) -> bool {
    let first_token = text.split_whitespace().next().unwrap_or("");
    first_token != "chicken"
}

fn main() {
    let args = Args::parse();

    match (args.sign, args.verify) {
        (false, false) => {
            eprintln!("error: a mode is required: use --sign or --verify");
            process::exit(1);
        }
        (true, true) => {
            eprintln!("error: --sign and --verify are mutually exclusive");
            process::exit(1);
        }
        (true, false) => {
            let key_path = resolve_key_for_mode(&args.key, "cek", "signing (your private key)");
            let key = read_key(&key_path);
            if key.key_type == KeyType::Public {
                eprintln!("error: signing requires your own private key, but got a public key");
                process::exit(1);
            }
            let text = read_input_text(&Some(args.input.clone()));
            let minichicken = is_minichicken(&text);
            let cipher = match CipherData::from_chicken_format(&text) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: failed to parse encrypted input: {e}");
                    process::exit(1);
                }
            };
            let signed = sign(&cipher, &key);
            let output = signed.to_chicken_format(minichicken);
            if let Err(e) = fs::write(&args.input, output) {
                eprintln!("error: failed to write signed file {}: {e}", args.input);
                process::exit(1);
            }
            eprintln!("Signed '{}' with key '{}'.", args.input, key.owner);
        }
        (false, true) => {
            let key_path = resolve_key_for_mode(&args.key, "pub", "verification (signer's public key)");
            let key = read_key(&key_path);
            if key.key_type == KeyType::Private {
                eprintln!("error: verification requires the signer's public key, but got a private key");
                process::exit(1);
            }
            let text = read_input_text(&Some(args.input.clone()));
            let cipher = match CipherData::from_chicken_format(&text) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: failed to parse encrypted input: {e}");
                    process::exit(1);
                }
            };
            if cipher.signature.is_none() {
                eprintln!("error: file is not signed");
                process::exit(1);
            }
            match verify(&cipher, &key) {
                Ok(()) => {
                    eprintln!("Signature OK: signed by '{}'.", key.owner);
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            }
        }
    }
}
