//! Arxia CLI tool.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("keygen") => {
            let out_path =
                parse_out_path(&args).unwrap_or_else(|| PathBuf::from("arxia_keypair.json"));
            let mut stdout = std::io::stdout().lock();
            if let Err(e) = cmd_keygen_to(&mut stdout, &out_path) {
                eprintln!("keygen failed: {}", e);
                std::process::exit(1);
            }
        }
        Some("did") => cmd_did(),
        Some("help") | Some("--help") | Some("-h") => print_help(),
        _ => print_help(),
    }
}

fn parse_out_path(args: &[String]) -> Option<PathBuf> {
    for (i, a) in args.iter().enumerate() {
        if let Some(rest) = a.strip_prefix("--out=") {
            return Some(PathBuf::from(rest));
        }
        if a == "--out" {
            return args.get(i + 1).map(PathBuf::from);
        }
    }
    None
}

/// Generate a new Ed25519 keypair.
///
/// The private key is written to `out_path` (mode 0600 on Unix). Only the
/// public key is emitted on `stdout`. This function never writes the
/// private-key material to `stdout` — see
/// `test_keygen_does_not_write_private_key_to_stdout`, the CRIT-001
/// regression guard.
fn cmd_keygen_to<W: Write>(stdout: &mut W, out_path: &Path) -> std::io::Result<()> {
    let (signing_key, verifying_key) = arxia_crypto::generate_keypair();
    let public_hex = hex::encode(verifying_key.as_bytes());
    let private_hex = hex::encode(signing_key.to_bytes());

    write_secret_keypair(out_path, &public_hex, &private_hex)?;

    writeln!(stdout, "Public key:  {}", public_hex)?;
    writeln!(
        stdout,
        "Private key: written to {} (not shown on stdout)",
        out_path.display()
    )?;
    writeln!(stdout)?;
    writeln!(
        stdout,
        "IMPORTANT: keep {} secret. Back it up offline.",
        out_path.display()
    )?;
    writeln!(stdout, "Never share it or commit it to version control.")?;

    Ok(())
}

fn write_secret_keypair(path: &Path, public_hex: &str, private_hex: &str) -> std::io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(path)?;
    writeln!(f, "{{")?;
    writeln!(f, "  \"public_key\":  \"{}\",", public_hex)?;
    writeln!(f, "  \"private_key\": \"{}\"", private_hex)?;
    writeln!(f, "}}")?;
    f.flush()?;
    Ok(())
}

fn cmd_did() {
    let (_, verifying_key) = arxia_crypto::generate_keypair();
    let did = arxia_did::ArxiaDid::from_public_key(&verifying_key.to_bytes());
    println!("DID: {}", did);
}

fn print_help() {
    println!("arxia-cli - Arxia command-line interface");
    println!();
    println!("USAGE:");
    println!("  arxia-cli <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("  keygen [--out=PATH]   Generate a new Ed25519 keypair.");
    println!("                        Private key is written to PATH");
    println!("                        (default: arxia_keypair.json), mode 0600 on Unix.");
    println!("                        Only the public key is printed on stdout.");
    println!("  did                   Generate a new DID.");
    println!("  help                  Print this help message.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_tmp_path(suffix: &str) -> PathBuf {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        base.join(format!("arxia-cli-test-{}-{}-{}", pid, nanos, suffix))
    }

    /// CRIT-001 regression guard: the private key must never appear on stdout.
    #[test]
    fn test_keygen_does_not_write_private_key_to_stdout() {
        let out = unique_tmp_path("no-leak.json");
        let _ = std::fs::remove_file(&out);

        let mut buf: Vec<u8> = Vec::new();
        cmd_keygen_to(&mut buf, &out).expect("keygen should succeed");

        let stdout = String::from_utf8(buf).expect("stdout is valid utf-8");
        let file = std::fs::read_to_string(&out).expect("key file must exist");
        let _ = std::fs::remove_file(&out);

        let priv_hex = file
            .lines()
            .find(|l| l.contains("\"private_key\""))
            .and_then(|l| l.split('"').nth(3))
            .expect("file must contain private_key field");
        assert_eq!(
            priv_hex.len(),
            64,
            "ed25519 seed is 32 bytes -> 64 hex chars, got {}",
            priv_hex.len()
        );
        let pub_hex = file
            .lines()
            .find(|l| l.contains("\"public_key\""))
            .and_then(|l| l.split('"').nth(3))
            .expect("file must contain public_key field");

        assert!(
            !stdout.contains(priv_hex),
            "stdout must NOT contain the private key hex. stdout was:\n{}",
            stdout
        );

        // Defensive: every 64-hex (or longer) contiguous run on stdout MUST be
        // the public key. Anything else is a potential leak in an unexpected
        // format (e.g. concatenated hex, different casing, etc.).
        for tok in stdout.split(|c: char| !c.is_ascii_hexdigit()) {
            if tok.len() >= 64 {
                assert_eq!(
                    tok, pub_hex,
                    "stdout contains a 64-hex-or-longer token that is NOT the \
                     public key. That's a potential private-key leak in an \
                     unexpected format. Token: {}\nstdout was:\n{}",
                    tok, stdout
                );
            }
        }
    }

    #[test]
    fn test_keygen_writes_public_and_private_to_file() {
        let out = unique_tmp_path("both-fields.json");
        let _ = std::fs::remove_file(&out);

        let mut buf: Vec<u8> = Vec::new();
        cmd_keygen_to(&mut buf, &out).expect("keygen");
        let file = std::fs::read_to_string(&out).expect("file");
        let _ = std::fs::remove_file(&out);

        assert!(file.contains("\"public_key\""));
        assert!(file.contains("\"private_key\""));
        for line in file.lines() {
            if line.contains("\"public_key\"") || line.contains("\"private_key\"") {
                let val = line.split('"').nth(3).expect("value");
                assert_eq!(val.len(), 64, "both keys are 32 bytes = 64 hex");
                assert!(
                    val.chars().all(|c| c.is_ascii_hexdigit()),
                    "value must be pure hex: {}",
                    val
                );
            }
        }
    }

    #[test]
    fn test_keygen_refuses_to_overwrite_existing_file() {
        let out = unique_tmp_path("existing.json");
        std::fs::write(&out, "pre-existing secret").expect("pre-write");

        let mut buf: Vec<u8> = Vec::new();
        let res = cmd_keygen_to(&mut buf, &out);

        let leftover = std::fs::read_to_string(&out).ok();
        let _ = std::fs::remove_file(&out);

        assert!(
            res.is_err(),
            "keygen must refuse to overwrite -- silently clobbering an \
             existing keyfile would destroy the user's only copy. Got Ok."
        );
        assert_eq!(
            leftover.as_deref(),
            Some("pre-existing secret"),
            "existing file contents must be preserved after a refused keygen"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_keygen_sets_file_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let out = unique_tmp_path("perms.json");
        let _ = std::fs::remove_file(&out);

        let mut buf: Vec<u8> = Vec::new();
        cmd_keygen_to(&mut buf, &out).expect("keygen");
        let md = std::fs::metadata(&out).expect("metadata");
        let _ = std::fs::remove_file(&out);

        let mode = md.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "private key file must be mode 0600 on Unix; got {:o}",
            mode
        );
    }

    #[test]
    fn test_keygen_stdout_shows_public_key_and_references_output_path() {
        let out = unique_tmp_path("stdout-content.json");
        let _ = std::fs::remove_file(&out);

        let mut buf: Vec<u8> = Vec::new();
        cmd_keygen_to(&mut buf, &out).expect("keygen");
        let stdout = String::from_utf8(buf).expect("utf-8");
        let file = std::fs::read_to_string(&out).expect("file");
        let _ = std::fs::remove_file(&out);

        let pub_hex = file
            .lines()
            .find(|l| l.contains("\"public_key\""))
            .and_then(|l| l.split('"').nth(3))
            .expect("public_key in file");

        assert!(
            stdout.contains(pub_hex),
            "public key must be printed on stdout (it's not a secret). \
             stdout:\n{}",
            stdout
        );
        let path_str = out.display().to_string();
        let name_str = out.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            stdout.contains(&path_str) || stdout.contains(&name_str),
            "stdout must reference the output file path. stdout:\n{}",
            stdout
        );
    }

    #[test]
    fn test_parse_out_path_all_forms() {
        assert_eq!(
            parse_out_path(&[
                "arxia-cli".to_string(),
                "keygen".to_string(),
                "--out=/tmp/k.json".to_string()
            ]),
            Some(PathBuf::from("/tmp/k.json")),
            "equals form"
        );
        assert_eq!(
            parse_out_path(&[
                "arxia-cli".to_string(),
                "keygen".to_string(),
                "--out".to_string(),
                "/tmp/k.json".to_string()
            ]),
            Some(PathBuf::from("/tmp/k.json")),
            "space form"
        );
        assert_eq!(
            parse_out_path(&["arxia-cli".to_string(), "keygen".to_string()]),
            None,
            "absent"
        );
    }
}
