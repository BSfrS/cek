use cek::cli::*;
use cek::*;
use clap::{CommandFactory, Parser};
use std::io::IsTerminal;
use std::process;

/// chicken-convert: convert keys and encrypted files between chicken and minichicken formats.
#[derive(Parser, Debug)]
#[command(
    name = "chicken-convert",
    about = "Convert keys and encrypted files between chicken and minichicken formats"
)]
struct Args {
    /// Convert to minichicken format.
    #[arg(short = 'm', long = "minichicken")]
    minichicken: bool,

    /// Convert to standard chicken format.
    #[arg(short = 'c', long = "chicken")]
    chicken: bool,

    /// Input file. If omitted, read from stdin.
    #[arg(short = 'i', long = "input")]
    input: Option<String>,

    /// Output file. If omitted, write to stdout.
    #[arg(short = 'o', long = "output")]
    output: Option<String>,
}

fn is_minichicken(text: &str) -> bool {
    let first_token = text.split_whitespace().next().unwrap_or("");
    first_token != "chicken"
}

fn main() {
    let args = Args::parse();

    if args.input.is_none() && std::io::stdin().is_terminal() {
        Args::command().print_help().ok();
        eprintln!();
        process::exit(1);
    }

    if args.minichicken && args.chicken {
        eprintln!("error: --minichicken and --chicken are mutually exclusive");
        process::exit(1);
    }

    let text = read_input_text(&args.input);
    let to_mini = if args.minichicken {
        true
    } else if args.chicken {
        false
    } else {
        !is_minichicken(&text)
    };

    let output = if let Ok(key) = KeyFile::from_chicken_format(&text) {
        let label = if to_mini { "minichicken" } else { "chicken" };
        let kind = match key.key_type {
            KeyType::Public => "public key",
            KeyType::Private => "private key",
        };
        eprintln!("Converting {kind} for '{}' to {label} format.", key.owner);
        key.to_chicken_format(to_mini)
    } else if let Ok(cipher) = CipherData::from_chicken_format(&text) {
        let label = if to_mini { "minichicken" } else { "chicken" };
        let signed = if cipher.signature.is_some() {
            "signed "
        } else {
            ""
        };
        eprintln!(
            "Converting {signed}ciphertext for '{}' to {label} format.",
            cipher.owner
        );
        cipher.to_chicken_format(to_mini)
    } else {
        eprintln!("error: input is not a valid chicken key or ciphertext file");
        process::exit(1);
    };

    write_output(&args.output, output.as_bytes());
}
