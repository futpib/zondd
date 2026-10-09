use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};
use tokio::net::UnixListener;

pub use libzond::paths::trusted_path;

pub struct Runtime {
    _lock: File,
    sockets: Vec<PathBuf>,
}

impl Runtime {
    pub fn create(path: &Path) -> Result<Self> {
        trusted_path(path.parent().context("runtime_dir has no parent")?)?;
        if !path.exists() {
            fs::create_dir(path)?;
        }
        trusted_path(path)?;
        ensure!(
            fs::symlink_metadata(path)?.uid() == libzond::paths::current_uid(),
            "runtime directory must belong to the daemon user"
        );
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path.join("daemon.lock"))?;
        ensure!(
            // SAFETY: lock owns this valid file descriptor; flock does not retain Rust pointers.
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another zondd owns this runtime directory"
        );
        Ok(Self {
            _lock: lock,
            sockets: Vec::new(),
        })
    }

    pub fn listen(&mut self, path: PathBuf) -> Result<UnixListener> {
        if path.exists() {
            fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        self.sockets.push(path.clone());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    pub fn add(&mut self, path: PathBuf) -> Result<UnixListener> {
        let listener = UnixListener::bind(&path)?;
        self.sockets.push(path.clone());
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            let _ = self.remove(&path);
            return Err(error.into());
        }
        Ok(listener)
    }

    pub fn remove(&mut self, path: &Path) -> Result<()> {
        fs::remove_file(path)?;
        self.sockets.retain(|p| p != path);
        Ok(())
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        for path in &self.sockets {
            let _ = fs::remove_file(path);
        }
    }
}
