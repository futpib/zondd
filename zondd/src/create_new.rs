//! Stage directory output under a pinned parent and publish without replacing an entry.
use anyhow::{Context, Result, ensure};
use libzond::rules::ResolvedRequirement;
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

fn cstr(value: &OsStr) -> Result<CString> {
    Ok(CString::new(value.as_bytes())?)
}

fn open_dir_at(parent: &File, name: &OsStr) -> Result<File> {
    let name = cstr(name)?;
    // SAFETY: parent is owned and name is NUL terminated; openat returns a new descriptor.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("open directory without symlinks");
    }
    // SAFETY: a successful openat returned a new descriptor owned by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn directory(path: &Path) -> Result<File> {
    libzond::config::validate_cwd(path)?;
    let mut dir = File::open("/")?;
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        if let Component::Normal(name) = component {
            dir = open_dir_at(&dir, name).with_context(|| format!("inspect {}", path.display()))?;
        }
        let meta = dir.metadata()?;
        ensure!(
            meta.uid() == 0 || meta.uid() == libzond::paths::current_uid(),
            "directory belongs to another user"
        );
        let sticky_parent =
            components.peek().is_some() && meta.uid() == 0 && meta.mode() & 0o1000 != 0;
        ensure!(
            meta.mode() & 0o022 == 0 || sticky_parent,
            "directory is writable by other users"
        );
    }
    Ok(dir)
}

fn absent(parent: &File, name: &OsStr) -> Result<()> {
    let name = cstr(name)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid directory fd, C string, and writable stat storage; it is not read on failure.
    let rc = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    ensure!(rc != 0, "destination already exists");
    let error = io::Error::last_os_error();
    ensure!(
        error.kind() == io::ErrorKind::NotFound,
        "cannot inspect destination: {error}"
    );
    Ok(())
}

pub fn check(requirements: &[ResolvedRequirement]) -> Result<()> {
    for requirement in requirements {
        match requirement.kind.as_str() {
            "is-dir" => {
                directory(&requirement.path)
                    .with_context(|| format!("require is-dir {}", requirement.path.display()))?;
            }
            "absent" => {
                let parent = directory(
                    requirement
                        .path
                        .parent()
                        .context("absent check needs a child path")?,
                )?;
                absent(
                    &parent,
                    requirement
                        .path
                        .file_name()
                        .context("absent check needs a child path")?,
                )
                .with_context(|| format!("require absent {}", requirement.path.display()))?;
            }
            _ => anyhow::bail!("unsupported rule check"),
        }
    }
    Ok(())
}

pub struct Staging {
    parent: File,
    directory: File,
    name: String,
    destination: CString,
    path: PathBuf,
}

impl Staging {
    pub fn new(destination: &Path) -> Result<Self> {
        let parent = directory(
            destination
                .parent()
                .context("create-new-dir needs a child path")?,
        )?;
        let destination = destination
            .file_name()
            .context("create-new-dir needs a child path")?;
        absent(&parent, destination)?;
        let name = format!(".zondd-new-{}", uuid::Uuid::new_v4());
        let c_name = CString::new(name.as_str())?;
        // SAFETY: parent owns a live directory descriptor and c_name is NUL terminated.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error()).context("create staging directory");
        }
        let directory = match open_dir_at(&parent, OsStr::new(&name)) {
            Ok(dir) => dir,
            Err(error) => {
                // SAFETY: these identify only the just-created empty staging directory.
                unsafe {
                    libc::unlinkat(parent.as_raw_fd(), c_name.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(error);
            }
        };
        let path = PathBuf::from(format!(
            "/proc/{}/fd/{}/output",
            std::process::id(),
            directory.as_raw_fd()
        ));
        Ok(Self {
            parent,
            directory,
            name,
            destination: cstr(destination)?,
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn publish(&self) -> Result<()> {
        // Opening the output rejects symlinks and ensures this effect only publishes directories.
        let _output = open_dir_at(&self.directory, OsStr::new("output"))
            .context("command did not create an output directory")?;
        let output = c"output";
        // SAFETY: both directory descriptors are owned, names are NUL terminated, and
        // RENAME_NOREPLACE makes any existing file, directory or symlink a hard failure.
        let rc = unsafe {
            libc::renameat2(
                self.directory.as_raw_fd(),
                output.as_ptr(),
                self.parent.as_raw_fd(),
                self.destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error())
                .context("create-new-dir publication failed; destination was not replaced");
        }
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let path = PathBuf::from(format!(
            "/proc/{}/fd/{}/{}",
            std::process::id(),
            self.parent.as_raw_fd(),
            self.name
        ));
        // Do not remove a replacement entry if another same-user process renamed staging.
        if let (Ok(actual), Ok(expected)) =
            (std::fs::symlink_metadata(&path), self.directory.metadata())
            && actual.dev() == expected.dev()
            && actual.ino() == expected.ino()
            && let Err(error) = std::fs::remove_dir_all(&path)
        {
            tracing::warn!(%error, path=%path.display(), "could not remove rule staging directory");
        }
    }
}
