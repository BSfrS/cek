use cek::cli::*;
use cek::*;
use clap::Parser;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process;

/// chicken-keygen: generate key pairs in the Chicken format.
#[derive(Parser, Debug)]
#[command(
    name = "chicken-keygen",
    about = "Generate key pairs in the Chicken format"
)]
struct Args {
    /// Owner name (e.g., cluckmaster)
    #[arg(short = 'c', long = "chicken", required_unless_present_any = ["add_password", "remove_password"])]
    chicken: Option<String>,

    /// Use minichicken format (single-line). Default is standard multi-line chicken format.
    #[arg(short = 'm', long = "minichicken")]
    minichicken: bool,

    /// Total key strength in bits.
    #[arg(short = 'b', long = "bits", default_value_t = 1024, value_parser = clap::value_parser!(u32).range(256..=4096))]
    bits: u32,

    /// Output directory for key files. Default: ~/.cek/
    #[arg(long = "out")]
    out: Option<String>,

    /// Overwrite existing key files without prompting.
    #[arg(short = 'f', long = "force")]
    force: bool,

    /// Protect the new private key with a password.
    #[arg(short = 'p', long = "password")]
    password: bool,

    /// Add password protection to an existing private key (skips key generation).
    #[arg(short = 'a', long = "add-password")]
    add_password: bool,

    /// Remove password protection from an existing private key (skips key generation).
    #[arg(short = 'r', long = "remove-password")]
    remove_password: bool,

    /// Private key file (used with --add-password / --remove-password; interactive if omitted).
    #[arg(short = 'k', long = "key")]
    key: Option<String>,
}

fn main() {
    let args = Args::parse();

    if args.add_password {
        let key_path = resolve_key_for_mode(&args.key, "cek", "password protection");
        let raw = match fs::read_to_string(&key_path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: failed to read {}: {e}", key_path.display());
                process::exit(1);
            }
        };
        let to_mini = is_minichicken_format(&raw);
        let key = read_key(&key_path);
        if key.key_type != KeyType::Private {
            eprintln!("error: can only add password protection to a private key");
            process::exit(1);
        }
        let password = read_password_confirmed();
        let text = key.to_protected_chicken_format(&password, to_mini);
        if let Err(e) = fs::write(&key_path, &text) {
            eprintln!(
                "error: failed to write key file {}: {e}",
                key_path.display()
            );
            process::exit(1);
        }
        eprintln!("Password protection added to {}.", key_path.display());
        return;
    }

    if args.remove_password {
        let key_path = resolve_key_for_mode(&args.key, "cek", "password removal");
        let raw = match fs::read_to_string(&key_path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: failed to read {}: {e}", key_path.display());
                process::exit(1);
            }
        };
        if !is_password_protected(&raw) {
            eprintln!(
                "error: {} is not password-protected",
                key_path.display()
            );
            process::exit(1);
        }
        let to_mini = is_minichicken_format(&raw);
        let key = read_key(&key_path);
        let text = key.to_chicken_format(to_mini);
        if let Err(e) = fs::write(&key_path, &text) {
            eprintln!(
                "error: failed to write key file {}: {e}",
                key_path.display()
            );
            process::exit(1);
        }
        eprintln!("Password protection removed from {}.", key_path.display());
        return;
    }

    let owner = args.chicken.as_deref().unwrap();

    let out_dir = match &args.out {
        Some(dir) => PathBuf::from(dir),
        None => {
            let mut d = dirs::home_dir().expect("cannot determine home directory");
            d.push(".cek");
            d
        }
    };
    let pub_out = out_dir.join(format!("{owner}.pub"));
    let key_out = out_dir.join(format!("{owner}.cek"));

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

    let (public_key, private_key) = generate_keys(owner, args.bits);

    let public_text = public_key.to_chicken_format(args.minichicken);
    let private_text = if args.password {
        let pw = read_password_confirmed();
        private_key.to_protected_chicken_format(&pw, args.minichicken)
    } else {
        private_key.to_chicken_format(args.minichicken)
    };

    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!(
            "error: failed to create directory {}: {e}",
            out_dir.display()
        );
        process::exit(1);
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
    eprintln!("Generated {pairs} key pair(s) for '{owner}'.");
    eprintln!("  public key  -> {}", pub_out.display());
    eprintln!(
        "  private key -> {}{}",
        key_out.display(),
        if args.password { " (password protected)" } else { "" }
    );
}
