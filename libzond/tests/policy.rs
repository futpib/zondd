use libzond::{
    Command, Envelope, Request,
    config::{Config, Decision},
    wire,
};
use tokio::io::{AsyncWriteExt, BufReader};

const POLICY: &str = r#"
runtime_dir = "/run/zondd"
[principals.test]
cwd = "/tmp"
allow_exec = true
default = "ask"
operations = ["service"]
[[principals.test.rules]]
program = "/usr/bin/printf"
args = ["%s", "hello"]
decision = "allow"
[[principals.test.rules]]
program = "/bin/sh"
decision = "deny"
[operations.service]
program = "/usr/bin/systemctl"
fixed_args = ["is-active", "--"]
arguments = [{ name = "service", choices = ["example.service"] }]
decision = "allow"
"#;

#[test]
fn defaults_require_review_and_explicit_policies_keep_their_boundaries() {
    for text in ["".to_owned(), libzond::config::default_policy()] {
        let c = Config::parse(&text).unwrap();
        assert!(c.approvals.enabled);
        let p = &c.principals["default"];
        assert!(p.allow_exec);
        assert_eq!(
            p.decision(&Command {
                program: "/bin/sh".into(),
                args: vec![]
            }),
            Decision::Ask
        );
        assert!(c.operations.is_empty());
    }
    let c = Config::parse("[principals.closed]\ncwd = \"/\"").unwrap();
    assert!(c.approvals.enabled);
    assert!(!c.principals.contains_key("default"));
    assert!(!c.principals["closed"].allow_exec);
    assert_eq!(c.principals["closed"].default, Decision::Deny);
    assert!(Config::parse("[principals]").unwrap().principals.is_empty());
}

#[test]
fn exact_argv_and_explicit_shell_denial() {
    let c = Config::parse(POLICY).unwrap();
    let p = &c.principals["test"];
    let cmd = |program: &str, args: &[&str]| Command {
        program: program.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
    };
    assert_eq!(
        p.decision(&cmd("/usr/bin/printf", &["%s", "hello"])),
        Decision::Allow
    );
    assert_eq!(
        p.decision(&cmd("/usr/bin/printf", &["%s", "hello; id"])),
        Decision::Ask
    );
    assert_eq!(
        p.decision(&cmd("/usr/bin/printf", &["%s", "hello", "extra"])),
        Decision::Ask
    );
    assert_eq!(
        p.decision(&cmd("/bin/sh", &["-c", "echo hello"])),
        Decision::Deny
    );
    assert_eq!(p.decision(&cmd("/bin/sh", &[])), Decision::Deny);
}

#[test]
fn operation_arguments_are_closed_and_positional() {
    let c = Config::parse(POLICY).unwrap();
    let p = &c.principals["test"];
    let (cmd, decision) = c
        .operation(p, "service", &["example.service".into()])
        .unwrap();
    assert_eq!(cmd.args, ["is-active", "--", "example.service"]);
    assert_eq!(decision, Decision::Allow);
    assert!(c.operation(p, "service", &["--system".into()]).is_err());
    assert!(c.operation(p, "service", &[]).is_err());
    assert!(c.operation(p, "other", &[]).is_err());
}

#[test]
fn invalid_trust_boundaries_and_unknown_fields_are_rejected() {
    for (from, to) in [
        ("[principals.test]", "[principals.test]\nbridge_uid = 1001"),
        ("[principals.test]", "[principals.test]\nrun_uid = 1002"),
        ("[principals.test]", "[principals.test]\nrun_gid = 1002"),
        ("[principals.test]", "admin_uid = 1000\n[principals.test]"),
        ("principals.test", "principals.admin"),
        ("allow_exec = true", "allow_exce = true"),
    ] {
        assert!(Config::parse(&POLICY.replace(from, to)).is_err(), "{to}");
    }
    let spoof = r#"{"version":1,"id":1,"body":{"method":"run","principal":"admin","command":{"program":"/bin/true"}}}"#;
    assert!(serde_json::from_str::<Envelope<Request>>(spoof).is_err());
}

#[tokio::test]
async fn framing_handles_split_utf8_and_multiple_frames() {
    let (mut tx, rx) = tokio::io::duplex(1);
    let writer = tokio::spawn(async move {
        for byte in "\"λ🦀\"\n42\n".as_bytes() {
            tx.write_all(&[*byte]).await.unwrap();
        }
    });
    let mut read = BufReader::with_capacity(1, rx);
    assert_eq!(
        wire::read::<String>(&mut read, 32).await.unwrap().unwrap(),
        "λ🦀"
    );
    assert_eq!(wire::read::<u32>(&mut read, 32).await.unwrap(), Some(42));
    assert_eq!(wire::read::<u32>(&mut read, 32).await.unwrap(), None);
    writer.await.unwrap();
}

#[tokio::test]
async fn framing_rejects_overflow_and_truncated_json() {
    for (input, limit) in [(b"12345\n".as_slice(), 4), (b"12345".as_slice(), 64)] {
        assert!(
            wire::read::<u32>(&mut BufReader::new(input), limit)
                .await
                .is_err()
        );
    }
}
