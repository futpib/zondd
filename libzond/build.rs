use std::{env, path::Path, process::Command};

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn git_commit(root: &Path) -> Option<String> {
    let repository = git(root, &["rev-parse", "--show-toplevel"])?;
    if Path::new(&repository).canonicalize().ok()? != root.canonicalize().ok()? {
        return None;
    }
    for name in ["HEAD", "refs", "packed-refs"] {
        let path = root.join(git(root, &["rev-parse", "--git-path", name])?);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    git(root, &["rev-parse", "--verify", "HEAD"])
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ZONDD_GIT_COMMIT");
    let manifest = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let root = Path::new(&manifest).parent().unwrap();
    let git_dir = root.join(".git");
    if git_dir.is_file() || !git_dir.exists() {
        println!("cargo:rerun-if-changed={}", git_dir.display());
    }
    let commit = env::var("ZONDD_GIT_COMMIT")
        .ok()
        .or_else(|| git_commit(root));
    let revision = match commit {
        Some(commit) => {
            assert!(
                matches!(commit.len(), 40 | 64)
                    && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "ZONDD_GIT_COMMIT must be a full Git commit hash"
            );
            commit[..12].to_ascii_lowercase()
        }
        None => "unknown commit".into(),
    };
    println!(
        "cargo:rustc-env=ZONDD_BUILD_VERSION={} ({revision})",
        env::var("CARGO_PKG_VERSION").unwrap()
    );
}
