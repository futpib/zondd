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
    /// A single OpenSSH public key line or a file containing one (never a private key).
    #[arg(value_name = "KEY_OR_FILE")]
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

#[derive(Args)]
pub struct RevokeOptions {
    /// An OpenSSH public key line or file; omit with --all.
    #[arg(
        value_name = "KEY_OR_FILE",
        required_unless_present = "all",
        conflicts_with = "all"
    )]
    public_key: Option<PathBuf>,
    /// Remove every zondd-managed key entry in the selected file.
    #[arg(long)]
    all: bool,
    #[arg(long, default_value_os_t = paths::home_dir().join(".ssh/authorized_keys"))]
    authorized_keys: PathBuf,
}

#[derive(PartialEq)]
struct Snapshot {
    text: String,
    identity: Option<(u64, u64, u32)>,
}

struct PublicKey {
    text: String,
    kind: String,
    blob: String,
    fingerprint: String,
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

fn caller_setup() {
    println!(
        "Next, on the caller machine, save this receiver and the matching private key:\n  zondctl --host USER@HOST --identity /path/to/caller connections add NAME\nUse the receiver's Unix user for USER and its address for HOST. For Iroh, use its endpoint ID as HOST and add --iroh before connections.\nThen: zondctl --host NAME permissions\nList saved receivers: zondctl connections"
    );
}

fn simple_word(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
}

fn compact_command(binary: &str, runtime: &Path, principal: &str) -> Option<String> {
    let runtime = runtime.to_str()?;
    if !binary.ends_with("/zondd") || !simple_word(binary) || !simple_word(runtime) {
        return None;
    }
    let default_runtime = PathBuf::from(format!("/run/user/{}/zondd", paths::current_uid()));
    let mut command = format!("{binary} bridge");
    if runtime != default_runtime.to_str()? || paths::runtime_dir() != default_runtime {
        command.push_str(&format!(" --runtime-dir {runtime}"));
    }
    if principal != "default" {
        command.push_str(&format!(" --principal {principal}"));
    }
    Some(command)
}

fn key_type(field: &str) -> bool {
    field.starts_with("ssh-") || field.starts_with("ecdsa-") || field.starts_with("sk-")
}

fn looks_like_public_key(value: &str) -> bool {
    let mut fields = value.split_whitespace();
    fields.next().is_some_and(key_type) && fields.next().is_some()
}

fn load_public_key(input: &Path) -> Result<PublicKey> {
    let public = if let Some(value) = input.to_str().filter(|value| looks_like_public_key(value)) {
        value.to_owned()
    } else {
        let mut public = String::new();
        File::open(input)
            .context("read public key")?
            .take(64 * 1024 + 1)
            .read_to_string(&mut public)?;
        public
    };
    ensure!(public.len() <= 64 * 1024, "public key exceeds 64 KiB");
    let public = public.trim();
    ensure!(
        !public.chars().any(char::is_control),
        "expected one public key line without control characters"
    );
    let key: Vec<_> = public.split_whitespace().collect();
    ensure!(
        key.len() >= 2 && key_type(key[0]),
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
    Ok(PublicKey {
        text: public.to_owned(),
        kind: key[0].to_owned(),
        blob: key[1].to_owned(),
        fingerprint: String::from_utf8_lossy(&check.stdout).trim().to_owned(),
    })
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

fn managed_entry_key(line: &str) -> Option<(&str, &str)> {
    let parts = fields(line.trim());
    let options = parts.first()?;
    let command = options
        .strip_prefix("restrict,command=\"")?
        .strip_suffix('"')?;
    let command = if let Some((command, fingerprint)) = command.rsplit_once(" --key-fingerprint ") {
        if !fingerprint.starts_with("SHA256:") || fingerprint.len() != 50 {
            return None;
        }
        command
    } else {
        command
    };
    let current = command
        .split_once(" bridge --runtime-dir '")
        .and_then(|(program, rest)| {
            let (runtime, principal) = rest.rsplit_once("' --principal '")?;
            let principal = principal.strip_suffix('\'')?;
            (program.starts_with("'/")
                && program.ends_with('\'')
                && runtime.starts_with('/')
                && libzond::config::valid_name(principal))
            .then_some(())
        });
    let legacy = command
        .split_once(" bridge --principal ")
        .is_some_and(|(program, principal)| {
            program.starts_with('/')
                && program.ends_with("/zondd")
                && libzond::config::valid_name(principal)
        });
    let compact = {
        let parts: Vec<_> = command.split(' ').collect();
        let (program, args) = parts.split_first()?;
        program.starts_with('/')
            && program.ends_with("/zondd")
            && simple_word(program)
            && match *args {
                ["bridge"] => true,
                ["bridge", "--principal", principal] => libzond::config::valid_name(principal),
                ["bridge", "--runtime-dir", runtime] => {
                    runtime.starts_with('/') && simple_word(runtime)
                }
                ["bridge", "--runtime-dir", runtime, "--principal", principal] => {
                    runtime.starts_with('/')
                        && simple_word(runtime)
                        && libzond::config::valid_name(principal)
                }
                _ => false,
            }
    };
    if current.is_none() && !legacy && !compact {
        return None;
    }
    let kind = *parts.get(1)?;
    let blob = *parts.get(2)?;
    (key_type(kind) && !blob.is_empty()).then_some((kind, blob))
}

fn confirm_change(path: &Path, before: &str, after: &str) -> Result<bool> {
    let label = path.to_string_lossy();
    print!(
        "{}",
        TextDiff::from_lines(before, after)
            .unified_diff()
            .header(&label, &label)
    );
    print!("Apply this authorized_keys change? [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        println!("Not applied.");
        return Ok(false);
    }
    Ok(true)
}

fn persist_change(path: &Path, before: &Snapshot, after: &str) -> Result<()> {
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
        snapshot(path)? == *before,
        "authorized_keys changed during review; run the command again"
    );
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file().set_permissions(fs::Permissions::from_mode(
        before.identity.map_or(0o600, |(_, _, mode)| mode & 0o777),
    ))?;
    file.write_all(after.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    File::open(parent)?.sync_all()?;
    println!("Updated {}. sshd does not need a restart.", path.display());
    Ok(())
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
    let public = load_public_key(&options.public_key)?;
    let command =
        compact_command(binary, &config.runtime_dir, &options.principal).unwrap_or_else(|| {
            format!(
                "{} bridge --runtime-dir {} --principal {}",
                quote(binary),
                quote(runtime),
                quote(&options.principal)
            )
        });
    let fingerprint = public
        .fingerprint
        .split_whitespace()
        .nth(1)
        .context("missing public key fingerprint")?;
    let command = format!("{command} --key-fingerprint {fingerprint}").replace('"', "\\\"");
    let entry = format!("restrict,command=\"{command}\" {}\n", public.text);
    let path = std::path::absolute(&options.authorized_keys)?;
    let before = snapshot(&path)?;
    let mut after = String::new();
    let mut installed = false;
    for line in before.text.split_inclusive('\n') {
        let parts = fields(line.trim());
        let plain = parts.first() == Some(&public.kind.as_str())
            && parts.get(1) == Some(&public.blob.as_str());
        let with_options = parts.get(1) == Some(&public.kind.as_str())
            && parts.get(2) == Some(&public.blob.as_str());
        if plain || with_options {
            ensure!(
                !with_options
                    || line.trim_end() == entry.trim_end()
                    || managed_entry_key(line) == Some((&*public.kind, &*public.blob)),
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
        caller_setup();
        return Ok(0);
    }
    println!("Caller: {}\nKey: {}", options.principal, public.fingerprint);
    println!(
        "This key will accept only the zondd protocol. Keep a separate normal SSH login for management."
    );
    if !confirm_change(&path, &before.text, &after)? {
        return Ok(0);
    }
    ensure!(
        libzond::config::read(&config_path)? == config_text,
        "policy changed during review; run authorize-key again"
    );
    persist_change(&path, &before, &after)?;
    if let Ok(client) = libzondctl::Client::local(&config.runtime_dir.join("admin.sock")).await {
        let mut client =
            client.with_client_info(Some(libzond::ClientInfo::current("zondctl")), None);
        let result = client.request(libzond::Request::Audit {
            action: "authorize_key".into(),
            detail: serde_json::json!({"path":path,"principal":options.principal,"fingerprint":public.fingerprint}),
        }).await;
        if !matches!(result, Ok(libzond::Event::Audited)) {
            eprintln!("Key installed, but could not record management action: {result:?}");
        }
    }
    caller_setup();
    Ok(0)
}

pub async fn revoke(options: &RevokeOptions, runtime_dir: &Path) -> Result<u8> {
    ensure!(
        std::io::stdin().is_terminal(),
        "revoke-key requires an interactive terminal to approve the diff"
    );
    let public = options
        .public_key
        .as_deref()
        .map(load_public_key)
        .transpose()?;
    let path = std::path::absolute(&options.authorized_keys)?;
    let before = snapshot(&path)?;
    let mut after = String::new();
    let mut removed = 0;
    for line in before.text.split_inclusive('\n') {
        let matches = managed_entry_key(line).is_some_and(|(kind, blob)| {
            options.all
                || public
                    .as_ref()
                    .is_some_and(|key| key.kind == kind && key.blob == blob)
        });
        if matches {
            removed += 1;
        } else {
            after.push_str(line);
        }
    }
    if removed == 0 {
        println!("No matching zondd-managed keys; no changes.");
        return Ok(0);
    }
    println!("Removing {removed} zondd-managed key entry(s).");
    if !confirm_change(&path, &before.text, &after)? {
        return Ok(0);
    }
    persist_change(&path, &before, &after)?;
    if let Ok(client) = libzondctl::Client::local(&runtime_dir.join("admin.sock")).await {
        let mut client =
            client.with_client_info(Some(libzond::ClientInfo::current("zondctl")), None);
        let result = client
            .request(libzond::Request::Audit {
                action: if options.all {
                    "revoke_all_keys".into()
                } else {
                    "revoke_key".into()
                },
                detail: serde_json::json!({"path": path, "count": removed, "fingerprint": public.map(|key| key.fingerprint)}),
            })
            .await;
        if !matches!(result, Ok(libzond::Event::Audited)) {
            eprintln!("Key removed, but could not record management action: {result:?}");
        }
    }
    Ok(0)
}
