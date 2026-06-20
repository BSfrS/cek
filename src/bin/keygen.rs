use cek::*;
use clap::Parser;
use std::fs;
use std::io::{self, BufRead, Write};
use std::process;

/// chicken-keygen: generate key pairs in the Chicken format.
#[derive(Parser, Debug)]
#[command(
    name = "chicken-keygen",
    about = "Generate key pairs in the Chicken format"
)]
struct Args {
    /// Owner name (e.g., cluckmaster)
    #[arg(short = 'c', long = "chicken")]
    chicken: String,

    /// Use minichicken format (single-line). Default is standard multi-line chicken format.
    #[arg(short = 'm', long = "minichicken")]
    minichicken: bool,

    /// Total key strength in bits.
    #[arg(short = 'b', long = "bits", default_value_t = 1024, value_parser = clap::value_parser!(u32).range(256..=4096))]
    bits: u32,

    /// Output path for public key. Default: ~/.cek/<owner>.pub
    #[arg(long = "pubout")]
    pubout: Option<String>,

    /// Output path for private key. Default: ~/.cek/<owner>.cek
    #[arg(long = "out")]
    out: Option<String>,

    /// Overwrite existing key files without prompting.
    #[arg(short = 'f', long = "force")]
    force: bool,
}

fn main() {
    let args = Args::parse();

    let pub_out = resolve_key_path(
        &args
            .pubout
            .unwrap_or_else(|| format!("{}.pub", args.chicken)),
    );
    let key_out = resolve_key_path(&args.out.unwrap_or_else(|| format!("{}.cek", args.chicken)));

    if !args.force {
        let mut existing = Vec::new();
        if pub_out.exists() {
            existing.push(pub_out.display().to_string());
        }
        if key_out.exists() {
            existing.push(key_out.display().to_string());
        }
        if !existing.is_empty() {
            eprint!(
                "warning: {} already exist(s). Overwrite? [y/N] ",
                existing.join(" and ")
            );
            io::stderr().flush().ok();
            let mut answer = String::new();
            if io::stdin().lock().read_line(&mut answer).is_err()
                || !answer.trim().eq_ignore_ascii_case("y")
            {
                eprintln!("Aborted.");
                process::exit(1);
            }
        }
    }

    let (public_key, private_key) = generate_keys(&args.chicken, args.bits);

    let public_text = public_key.to_chicken_format(args.minichicken);
    let private_text = private_key.to_chicken_format(args.minichicken);

    if let Some(parent) = pub_out.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!(
                "error: failed to create directory {}: {e}",
                parent.display()
            );
            process::exit(1);
        }
    }

    if let Err(e) = fs::write(&pub_out, public_text) {
        eprintln!(
            "error: failed to write public key to {}: {e}",
            pub_out.display()
        );
        process::exit(1);
    }
    if let Err(e) = fs::write(&key_out, private_text) {
        eprintln!(
            "error: failed to write private key to {}: {e}",
            key_out.display()
        );
        process::exit(1);
    }

    let pairs = public_key.pairs.len();
    eprintln!("Generated {pairs} key pair(s) for '{}'.", args.chicken);
    eprintln!("  public key  -> {}", pub_out.display());
    eprintln!("  private key -> {}", key_out.display());
}
