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
            meta.uid() == libzond::paths::current_uid() || meta.uid() == 0,
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
}

impl Drop for Runtime {
    fn drop(&mut self) {
        for path in &self.sockets {
            let _ = fs::remove_file(path);
        }
    }
}
