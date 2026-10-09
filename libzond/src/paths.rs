use std::path::PathBuf;

pub fn current_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and has no memory safety requirements.
    unsafe { libc::geteuid() }
}

pub fn config_path() -> PathBuf {
    dirs::config_dir()
        .expect("could not determine the user's config directory")
        .join("zondd/config.toml")
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
