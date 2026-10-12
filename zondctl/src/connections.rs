use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use libzond::paths;
use libzondctl::SshOptions;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
};

#[derive(Subcommand)]
pub enum Action {
    /// Save the explicit --host, --identity, --port and --iroh settings as an SSH config.
    Add { name: String },
    /// Remove a saved connection; the receiver's key authorization is unchanged.
    Remove { name: String },
}

pub fn quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.:@%=".contains(&b))
    {
        value.into()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn path(name: &str) -> Result<PathBuf> {
    ensure!(
        libzond::config::valid_name(name) && !name.starts_with('-'),
        "connection names must contain only letters, digits, underscores or hyphens and cannot start with '-'"
    );
    Ok(paths::connections_dir().join(format!("{name}.conf")))
}

pub fn saved(name: &str) -> Result<Option<PathBuf>> {
    if !libzond::config::valid_name(name) || name.starts_with('-') {
        return Ok(None);
    }
    let path = path(name)?;
    match fs::symlink_metadata(&path) {
        Ok(meta) => {
            paths::trusted_path(&path)?;
            ensure!(
                meta.is_file(),
                "connection must be a regular file: {}",
                path.display()
            );
            Ok(Some(path))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn ssh_value(value: &str) -> Result<String> {
    ensure!(
        !value.chars().any(char::is_control),
        "SSH values cannot contain control characters"
    );
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn absolute_path(path: &Path) -> Result<String> {
    let path = std::path::absolute(path)?;
    let value = path.to_str().context("SSH paths must be UTF-8")?;
    ensure!(
        !value.contains(['%', '*', '?', '[', '$']),
        "SSH paths cannot contain expansion characters"
    );
    ssh_value(value)
}

pub fn add(name: &str, options: &SshOptions) -> Result<PathBuf> {
    let path = path(name)?;
    let (user, host) = options
        .host
        .rsplit_once('@')
        .map_or((None, options.host.as_str()), |(u, h)| (Some(u), h));
    ensure!(
        !host.is_empty()
            && !host.starts_with('-')
            && options
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._:@[]".contains(&b)),
        "use a receiver hostname, address or user@address"
    );
    if options.iroh {
        ensure!(
            host.len() == 64 && host.bytes().all(|b| b.is_ascii_hexdigit()),
            "--iroh requires a 64-hex endpoint ID"
        );
    }
    let mut text = format!(
        "# Saved by zondctl; standard OpenSSH configuration.\nHost {name}\n    HostName {}\n",
        ssh_value(host)?
    );
    if let Some(user) = user {
        ensure!(
            !user.is_empty() && !user.contains('@'),
            "invalid SSH username"
        );
        text.push_str(&format!("    User {}\n", ssh_value(user)?));
    }
    if let Some(identity) = &options.identity {
        text.push_str(&format!(
            "    IdentityFile {}\n    IdentitiesOnly yes\n",
            absolute_path(identity)?
        ));
    }
    if let Some(port) = options.port {
        text.push_str(&format!("    Port {port}\n"));
    }
    if options.iroh {
        text.push_str("    ProxyCommand iroh-ssh proxy %h\n");
    }
    // Apply ordinary SSH defaults after the saved receiver's explicit settings.
    text.push_str("Host *\n");
    if let Some(config) = &options.config {
        ensure!(
            std::path::absolute(config)? != std::path::absolute(&path)?,
            "connection cannot include itself"
        );
        text.push_str(&format!("    Include {}\n", absolute_path(config)?));
    } else {
        text.push_str(&format!(
            "    Include {}\n    Include /etc/ssh/ssh_config\n",
            absolute_path(&paths::home_dir().join(".ssh/config"))?
        ));
    }
    paths::create_private_dir_all(&paths::connections_dir())?;
    paths::trusted_location(&path)?;
    let mut file = tempfile::NamedTempFile::new_in(paths::connections_dir())?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(text.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist_noclobber(&path).with_context(|| {
        format!("save connection {name}; remove the existing connection first to replace it")
    })?;
    Ok(path)
}

pub fn remove(name: &str) -> Result<()> {
    let path = saved(name)?.with_context(|| format!("unknown saved connection {name}"))?;
    fs::remove_file(path)?;
    Ok(())
}

pub fn names() -> Result<Vec<String>> {
    let dir = paths::connections_dir();
    if !dir.try_exists()? {
        return Ok(Vec::new());
    }
    paths::trusted_path(&dir)?;
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().is_some_and(|ext| ext == "conf") {
            let name = entry
                .path()
                .file_stem()
                .context("connection has no name")?
                .to_string_lossy()
                .into_owned();
            saved(&name)?.context("invalid saved connection name")?;
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

#[derive(Serialize)]
pub struct Description {
    pub receiver: String,
    pub destination: String,
    pub transport: String,
    pub role: &'static str,
    pub identities: Vec<String>,
    pub port: String,
    pub ssh_config: Option<PathBuf>,
    pub proxy: Option<String>,
}

pub async fn describe(options: &SshOptions) -> Result<Description> {
    let mut command = options.command()?;
    let output = command
        .arg("-G")
        .arg(&options.host)
        .stdin(Stdio::null())
        .output()
        .await
        .context("resolve SSH configuration")?;
    ensure!(
        output.status.success(),
        "cannot resolve SSH configuration: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let text = String::from_utf8(output.stdout)?;
    let mut values = BTreeMap::new();
    let mut identities = Vec::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(' ') {
            if key == "identityfile" {
                identities.push(value.to_owned());
            }
            values.insert(key, value);
        }
    }
    let proxy = values
        .get("proxycommand")
        .or_else(|| values.get("proxyjump"))
        .filter(|v| **v != "none")
        .map(|s| (*s).to_owned());
    Ok(Description {
        receiver: options.host.clone(),
        destination: format!(
            "{}@{}",
            values.get("user").context("SSH did not resolve user")?,
            values
                .get("hostname")
                .context("SSH did not resolve hostname")?
        ),
        transport: if proxy.as_ref().is_some_and(|p| p.contains("iroh-ssh")) {
            "Iroh SSH"
        } else if proxy.is_some() {
            "SSH proxy"
        } else {
            "SSH"
        }
        .into(),
        role: "caller (principal selected by receiver)",
        identities,
        port: values
            .get("port")
            .context("SSH did not resolve port")?
            .to_string(),
        ssh_config: options.config.clone(),
        proxy,
    })
}
