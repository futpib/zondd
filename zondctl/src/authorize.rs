use anyhow::{Context, Result, ensure};
use clap::Args;
use fs2::FileExt;
use libzond::{config::Config, paths};
use similar::TextDiff;
use std::{
    fs::{self, File, OpenOptions},
    io::{IsTerminal, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Args)]
pub struct Options {
    /// A single OpenSSH public key file (never a private key).
    public_key: PathBuf,
    /// Existing policy principal; the built-in policy provides "default".
    #[arg(long, default_value = "default")]
    principal: String,
    #[arg(long, default_value_os_t = paths::home_dir().join(".ssh/authorized_keys"))]
    authorized_keys: PathBuf,
    #[arg(long, default_value_os_t = paths::config_path())]
    config: PathBuf,
    /// Absolute receiver binary path; defaults to zondd beside this zondctl.
    #[arg(long)]
    zondd: Option<PathBuf>,
}

#[derive(PartialEq)]
struct Snapshot {
    text: String,
    identity: Option<(u64, u64, u32)>,
}

fn snapshot(path: &Path) -> Result<Snapshot> {
    paths::trusted_location(path)?;
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Snapshot {
                text: String::new(),
                identity: None,
            });
        }
        Err(error) => return Err(error.into()),
    };
    ensure!(
        meta.is_file() && meta.uid() == paths::current_uid(),
        "authorized_keys must be a regular file owned by this user"
    );
    ensure!(
        meta.nlink() == 1,
        "authorized_keys has multiple hard links; edit it manually"
    );
    let mut text = String::new();
    File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_string(&mut text)?;
    ensure!(text.len() <= 1024 * 1024, "authorized_keys exceeds 1 MiB");
    ensure!(
        !text
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t'),
        "control characters in authorized_keys; edit it manually"
    );
    Ok(Snapshot {
        text,
        identity: Some((meta.dev(), meta.ino(), meta.mode())),
    })
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

// Options can contain quoted spaces. Only the first three fields are needed to identify a key.
fn fields(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut start = None;
    for (i, c) in line.char_indices() {
        if !quoted && !escaped && c.is_whitespace() {
            if let Some(start) = start.take() {
                fields.push(&line[start..i]);
                if fields.len() == 3 {
                    return fields;
                }
            }
        } else {
            start.get_or_insert(i);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = !quoted;
            }
        }
    }
    if let Some(start) = start {
        fields.push(&line[start..]);
    }
    fields
}

pub async fn run(options: &Options) -> Result<u8> {
    ensure!(
        std::io::stdin().is_terminal(),
        "authorize-key requires an interactive terminal to approve the diff"
    );
    ensure!(
        libzond::config::valid_name(&options.principal) && options.principal != "admin",
        "invalid caller principal"
    );
    let config_path = std::path::absolute(&options.config)?;
    let config_text = libzond::config::read(&config_path)?;
    let config = Config::parse(&config_text)?;
    ensure!(
        config.principals.contains_key(&options.principal),
        "principal {:?} is not configured; add it to the policy first",
        options.principal
    );
    let binary = options
        .zondd
        .clone()
        .unwrap_or(std::env::current_exe()?.with_file_name("zondd"));
    ensure!(binary.is_absolute(), "--zondd must be an absolute path");
    paths::trusted_path(&binary)?;
    ensure!(
        binary.is_file() && fs::metadata(&binary)?.mode() & 0o111 != 0,
        "zondd is not executable"
    );
    let binary = binary.to_str().context("zondd path must be UTF-8")?;
    let runtime = config
        .runtime_dir
        .to_str()
        .context("runtime path must be UTF-8")?;
    ensure!(
        !binary.chars().chain(runtime.chars()).any(char::is_control),
        "control character in bridge path"
    );
    let mut public = String::new();
    File::open(&options.public_key)
        .context("read public key")?
        .take(64 * 1024 + 1)
        .read_to_string(&mut public)?;
    ensure!(public.len() <= 64 * 1024, "public key exceeds 64 KiB");
    let public = public.trim();
    ensure!(
        !public.chars().any(char::is_control),
        "expected one public key line without control characters"
    );
    let key: Vec<_> = public.split_whitespace().collect();
    ensure!(
        key.len() >= 2
            && (key[0].starts_with("ssh-")
                || key[0].starts_with("ecdsa-")
                || key[0].starts_with("sk-")),
        "expected an OpenSSH public key without authorized_keys options"
    );
    ensure!(
        !key[0].contains("-cert-"),
        "use the plain public key, not an SSH certificate"
    );
    let mut key_file = tempfile::NamedTempFile::new()?;
    writeln!(key_file, "{} {}", key[0], key[1])?;
    let check = Command::new("ssh-keygen")
        .args(["-l", "-f"])
        .arg(key_file.path())
        .output()
        .context("ssh-keygen is required to validate the public key")?;
    ensure!(check.status.success(), "invalid SSH public key");
    let command = format!(
        "{} bridge --runtime-dir {} --principal {}",
        quote(binary),
        quote(runtime),
        quote(&options.principal)
    );
    let command = command.replace('"', "\\\"");
    let entry = format!("restrict,command=\"{command}\" {public}\n");
    let path = std::path::absolute(&options.authorized_keys)?;
    let before = snapshot(&path)?;
    let mut after = String::new();
    let mut installed = false;
    for line in before.text.split_inclusive('\n') {
        let parts = fields(line.trim());
        let plain = parts.first() == Some(&key[0]) && parts.get(1) == Some(&key[1]);
        let with_options = parts.get(1) == Some(&key[0]) && parts.get(2) == Some(&key[1]);
        if plain || with_options {
            ensure!(
                !with_options || line.trim_end() == entry.trim_end(),
                "this key already has SSH options; merge those restrictions manually to avoid losing them"
            );
            if !installed {
                after.push_str(&entry);
                installed = true;
            }
        } else {
            after.push_str(line);
        }
    }
    if !installed {
        if !after.is_empty() && !after.ends_with('\n') {
            after.push('\n');
        }
        after.push_str(&entry);
    }
    if before.text == after {
        println!("Key is already configured; no changes.");
        return Ok(0);
    }
    println!(
        "Caller: {}\nKey: {}",
        options.principal,
        String::from_utf8_lossy(&check.stdout).trim()
    );
    println!(
        "This key will accept only the zondd protocol. Keep a separate normal SSH login for management."
    );
    let label = path.to_string_lossy();
    print!(
        "{}",
        TextDiff::from_lines(&before.text, &after)
            .unified_diff()
            .header(&label, &label)
    );
    print!("Apply this authorized_keys change? [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        println!("Not applied.");
        return Ok(0);
    }
    ensure!(
        libzond::config::read(&config_path)? == config_text,
        "policy changed during review; run authorize-key again"
    );
    let parent = path.parent().context("authorized_keys has no parent")?;
    paths::create_private_dir_all(parent)?;
    let lock_path = path.with_extension("zondd.lock");
    paths::trusted_location(&lock_path)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)?;
    lock.lock_exclusive()?;
    ensure!(
        snapshot(&path)? == before,
        "authorized_keys changed during review; run authorize-key again"
    );
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file().set_permissions(fs::Permissions::from_mode(
        before.identity.map_or(0o600, |(_, _, mode)| mode & 0o777),
    ))?;
    file.write_all(after.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(&path)?;
    File::open(parent)?.sync_all()?;
    println!("Updated {}. sshd does not need a restart.", path.display());
    if let Ok(mut client) = libzondctl::Client::local(&config.runtime_dir.join("admin.sock")).await
    {
        let result = client.request(libzond::Request::Audit {
            action: "authorize_key".into(),
            detail: serde_json::json!({"path":path,"principal":options.principal,"fingerprint":String::from_utf8_lossy(&check.stdout).trim()}),
        }).await;
        if !matches!(result, Ok(libzond::Event::Audited)) {
            eprintln!("Key installed, but could not record management action: {result:?}");
        }
    }
    Ok(0)
}
