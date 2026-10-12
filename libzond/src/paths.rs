use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
};

pub fn current_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and has no memory safety requirements.
    unsafe { libc::geteuid() }
}

pub fn config_path() -> PathBuf {
    dirs::config_dir()
        .expect("could not determine the user's config directory")
        .join("zondd/config.toml")
}

pub fn connections_dir() -> PathBuf {
    dirs::config_dir()
        .expect("could not determine the user's config directory")
        .join("zondctl/connections")
}

/// Shared by daemon, bridge, and reviewer, including SSH sessions without XDG vars.
pub fn runtime_dir() -> PathBuf {
    if let Some(path) = dirs::runtime_dir() {
        return path.join("zondd");
    }
    let uid = current_uid();
    let login_runtime = PathBuf::from(format!("/run/user/{uid}"));
    if login_runtime.is_dir() {
        return login_runtime.join("zondd");
    }
    std::env::temp_dir().join(format!("zondd-{uid}"))
}

pub fn trusted_path(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "trusted path must be absolute");
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor)
            .with_context(|| format!("inspect {}", ancestor.display()))?;
        ensure!(
            !meta.file_type().is_symlink(),
            "symlink in trusted path {}",
            ancestor.display()
        );
        ensure!(
            meta.uid() == current_uid() || meta.uid() == 0,
            "{} is owned by another user",
            ancestor.display()
        );
        // In a sticky root-owned ancestor such as /tmp, other users cannot replace our child.
        let sticky_parent =
            ancestor != path && meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o1000 != 0;
        ensure!(
            meta.mode() & 0o022 == 0 || sticky_parent,
            "{} is writable by other users",
            ancestor.display()
        );
    }
    Ok(())
}

/// Check the nearest existing ancestor without following symlinks through missing paths.
pub fn trusted_location(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "trusted path must be absolute");
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => return trusted_path(ancestor),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    anyhow::bail!("no existing ancestor")
}

pub fn create_private_dir_all(path: &Path) -> Result<()> {
    trusted_location(path)?;
    if !path.try_exists()? {
        create_private_dir_all(path.parent().context("directory has no parent")?)?;
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    trusted_path(path)?;
    ensure!(path.is_dir(), "expected a directory: {}", path.display());
    Ok(())
}

pub fn home_dir() -> PathBuf {
    dirs::home_dir().expect("could not determine the user's home directory")
}
