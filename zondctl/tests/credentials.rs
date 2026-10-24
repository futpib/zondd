use libzondtest::{
    TestEnv, command, decoded,
    nix::{
        libc,
        pty::openpty,
        sys::termios::{LocalFlags, tcgetattr},
        unistd::setsid,
    },
    read_until,
    serde_json::json,
    wait_for,
};
use std::{
    fs::File,
    io::Write,
    os::unix::process::CommandExt,
    process::{Child, Command},
};

struct Terminal {
    child: Child,
    master: File,
}

impl Terminal {
    fn spawn(command: &mut Command) -> Self {
        let pty = openpty(None, None).unwrap();
        let slave = File::from(pty.slave);
        command
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave);
        // SAFETY: the child only establishes a session and controlling terminal.
        unsafe {
            command.pre_exec(|| {
                setsid()?;
                if libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Self {
            child: command.spawn().unwrap(),
            master: File::from(pty.master),
        }
    }

    fn exit_code(&mut self) -> i32 {
        let mut status = None;
        wait_for(|| {
            status = self.child.try_wait().unwrap();
            status.is_some()
        });
        status.unwrap().code().unwrap()
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn credential_and_review_display_the_selected_prompt_without_echoing_passwords() {
    let env = TestEnv::new();
    let prompt = "[sudo] password for futpib: \x1b[2J";
    let (mut caller, approval) =
        env.pending(command(env.probe.to_str().unwrap(), &["askpass", prompt]));
    env.resolve(&approval, true);
    let mut previous_id = String::new();
    for (review, password) in [(false, "test-password-one"), (true, "test-password-two")] {
        let mut challenge = None;
        wait_for(|| {
            challenge = env.request("admin", json!({"method":"pending"}))["credentials"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["challenge_id"].as_str() != Some(&previous_id))
                .cloned();
            challenge.is_some()
        });
        let challenge = challenge.unwrap();
        previous_id = challenge["challenge_id"].as_str().unwrap().to_owned();
        let mut cli = env.cli();
        if review {
            cli.arg("review");
        } else {
            cli.args(["credential", &previous_id]);
        }
        let mut terminal = Terminal::spawn(&mut cli);
        if review {
            read_until(&mut terminal.master, b"quit [q]: ");
            terminal.master.write_all(b"p\n").unwrap();
        }
        let shown = read_until(
            &mut terminal.master,
            b"[sudo] password for futpib: \\u{1b}[2J",
        );
        assert!(
            !shown.contains(&0x1b),
            "terminal control sequence was emitted"
        );
        wait_for(|| {
            !tcgetattr(&terminal.master)
                .unwrap()
                .local_flags
                .contains(LocalFlags::ECHO)
        });
        writeln!(terminal.master, "{password}").unwrap();
        let response = read_until(&mut terminal.master, b"credential_answered");
        assert!(!String::from_utf8_lossy(&response).contains(password));
        if !review {
            assert_eq!(terminal.exit_code(), 0);
        }
    }
    let done = caller.event();
    assert_eq!(done["type"], "completed", "{done}");
    assert_eq!(decoded(&done, "stdout"), b"two prompts answered\n");
}

#[test]
fn stale_credential_is_rejected_before_reading_a_password() {
    let env = TestEnv::new();
    let mut terminal = Terminal::spawn(env.cli().args(["credential", "not-pending"]));
    let response = read_until(&mut terminal.master, b"credential not pending");
    assert!(!String::from_utf8_lossy(&response).contains("Sudo password:"));
    assert_eq!(terminal.exit_code(), 125);
}
