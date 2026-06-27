use crate::*;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal;
use rpassword;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process;

pub fn find_keys_in_default_dir(extension: &str) -> Vec<PathBuf> {
    let mut dir = match dirs::home_dir() {
        Some(d) => d,
        None => return Vec::new(),
    };
    dir.push(".cek");

    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut keys: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == extension))
        .collect();
    keys.sort();
    keys
}

pub fn key_labels(keys: &[PathBuf]) -> Vec<String> {
    keys.iter()
        .map(|p| {
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        })
        .collect()
}

pub fn select_key_interactive(keys: &[PathBuf], mode: &str) -> PathBuf {
    let labels = key_labels(keys);

    if terminal::enable_raw_mode().is_err() {
        return select_key_fallback(keys, &labels, mode);
    }
    let _guard = RawModeGuard;

    let mut selected: usize = 0;
    let stderr = io::stderr();
    let mut handle = stderr.lock();
    write!(handle, "Select key for {mode}:\r\n").ok();
    render_list(&mut handle, &labels, selected);
    handle.flush().ok();

    loop {
        if let Ok(Event::Key(key_event)) = event::read() {
            if key_event.kind != KeyEventKind::Press {
                continue;
            }
            match key_event.code {
                KeyCode::Up => {
                    selected = selected.saturating_sub(1);
                }
                KeyCode::Down => {
                    if selected < labels.len() - 1 {
                        selected += 1;
                    }
                }
                KeyCode::Enter => {
                    clear_list(&mut handle, &labels);
                    write!(handle, "\rUsing key: {}\r\n", labels[selected]).ok();
                    handle.flush().ok();
                    drop(handle);
                    drop(_guard);
                    return keys[selected].clone();
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    clear_list(&mut handle, &labels);
                    handle.flush().ok();
                    drop(handle);
                    drop(_guard);
                    eprintln!("Aborted.");
                    process::exit(1);
                }
                KeyCode::Char('c')
                    if key_event
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL) =>
                {
                    clear_list(&mut handle, &labels);
                    handle.flush().ok();
                    drop(handle);
                    drop(_guard);
                    eprintln!("Aborted.");
                    process::exit(1);
                }
                _ => {}
            }
            clear_list(&mut handle, &labels);
            render_list(&mut handle, &labels, selected);
            handle.flush().ok();
        }
    }
}

pub fn select_key_fallback(keys: &[PathBuf], labels: &[String], mode: &str) -> PathBuf {
    eprintln!("Multiple keys available for {mode}:");
    for (i, label) in labels.iter().enumerate() {
        eprintln!("  [{}] {}", i + 1, label);
    }
    eprint!("Enter number (1-{}): ", labels.len());
    io::stderr().flush().ok();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        eprintln!("Aborted.");
        process::exit(1);
    }
    match input.trim().parse::<usize>() {
        Ok(n) if n >= 1 && n <= keys.len() => keys[n - 1].clone(),
        _ => {
            eprintln!("error: invalid selection");
            process::exit(1);
        }
    }
}

fn render_list(w: &mut impl Write, labels: &[String], selected: usize) {
    for (i, label) in labels.iter().enumerate() {
        if i == selected {
            write!(w, "  > {label}\r\n").ok();
        } else {
            write!(w, "    {label}\r\n").ok();
        }
    }
}

fn clear_list(w: &mut impl Write, labels: &[String]) {
    for _ in 0..labels.len() {
        write!(w, "\x1b[A\x1b[2K").ok();
    }
    write!(w, "\r").ok();
}

pub struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        terminal::disable_raw_mode().ok();
    }
}

pub fn resolve_key_for_mode(key_arg: &Option<String>, extension: &str, mode: &str) -> PathBuf {
    if let Some(k) = key_arg {
        return resolve_key_path(k);
    }

    let keys = find_keys_in_default_dir(extension);
    match keys.len() {
        0 => {
            eprintln!("error: no .{extension} keys found in ~/.cek/ and no --key specified");
            process::exit(1);
        }
        1 => {
            eprintln!(
                "Using key: {}",
                keys[0].file_name().unwrap_or_default().to_string_lossy()
            );
            keys[0].clone()
        }
        _ => select_key_interactive(&keys, mode),
    }
}

pub fn read_password(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_else(|e| {
        eprintln!("error: failed to read password: {e}");
        process::exit(1);
    })
}

pub fn read_password_confirmed() -> String {
    loop {
        let pw = read_password("Password: ");
        let confirm = read_password("Confirm password: ");
        if pw == confirm {
            return pw;
        }
        eprintln!("Passwords do not match, try again.");
    }
}

pub fn read_key(path: &std::path::Path) -> KeyFile {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: failed to read key file {}: {e}", path.display());
            process::exit(1);
        }
    };
    if is_password_protected(&text) {
        let password = read_password("Password: ");
        return match KeyFile::from_protected_chicken_format(&text, &password) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("error: {e}");
                process::exit(1);
            }
        };
    }
    match KeyFile::from_chicken_format(&text) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: failed to parse key file {}: {e}", path.display());
            process::exit(1);
        }
    }
}

pub fn read_input_bytes(input: &Option<String>) -> Vec<u8> {
    match input {
        Some(path) => match fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: failed to read input file {path}: {e}");
                process::exit(1);
            }
        },
        None => {
            let mut buf = Vec::new();
            if let Err(e) = io::stdin().read_to_end(&mut buf) {
                eprintln!("error: failed to read from stdin: {e}");
                process::exit(1);
            }
            buf
        }
    }
}

pub fn read_input_text(input: &Option<String>) -> String {
    match input {
        Some(path) => match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: failed to read input file {path}: {e}");
                process::exit(1);
            }
        },
        None => {
            let mut buf = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut buf) {
                eprintln!("error: failed to read from stdin: {e}");
                process::exit(1);
            }
            buf
        }
    }
}

pub fn write_output(output: &Option<String>, bytes: &[u8]) {
    match output {
        Some(path) => {
            if let Err(e) = fs::write(path, bytes) {
                eprintln!("error: failed to write output file {path}: {e}");
                process::exit(1);
            }
        }
        None => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            if let Err(e) = handle.write_all(bytes) {
                eprintln!("error: failed to write to stdout: {e}");
                process::exit(1);
            }
            if let Err(e) = handle.flush() {
                eprintln!("error: failed to flush stdout: {e}");
                process::exit(1);
            }
        }
    }
}
