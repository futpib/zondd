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
    fs::{self, File, Permissions},
    io::Write,
    os::unix::{fs::PermissionsExt, process::CommandExt},
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

    fn answer(&mut self, prompt: &[u8], value: &str) -> Vec<u8> {
        let shown = read_until(&mut self.master, prompt);
        wait_for(|| {
            !tcgetattr(&self.master)
                .unwrap()
                .local_flags
                .contains(LocalFlags::ECHO)
        });
        writeln!(self.master, "{value}").unwrap();
        shown
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

#[test]
fn application_forms_accept_menu_numbers_and_retry_only_invalid_fields_privately() {
    use libzond::{
        SecretString,
        credential::{Event, Request},
    };
    use libzondctl::credential::Client;

    let env = TestEnv::new();
    let key = "a".repeat(64);
    fs::write(&env.config, format!("{}\n[credential_recipients.service]\nlabel = 'Independent service'\nkey_sha256 = {:?}\nfield_ids = ['password', 'action', 'optional']\norigins = ['https://example.test']\n", env.policy, libzond::config::revision(&key))).unwrap();
    fs::set_permissions(&env.config, Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let mut client = Client::connect(&env.runtime.join("credential.sock"), "service", SecretString(key)).await.unwrap();
        for (review, choices, input, expected, selected) in [
            (false, vec!["1: here", "2: here\x1b[2J", "3: OK"], "3", "3: OK", None),
            (true, vec!["1: here", "2: here", "3: OK"], "3: OK", "3: OK", None),
            (false, vec!["2", "1", "3"], "1", "2", None),
            (true, vec!["ibg.Fri.xml", "ibg.Thu.xml", "Reset Default Settings"], "", "ibg.Fri.xml", Some(0)),
        ] {
            let form: Request = serde_json::from_value(json!({
                "method":"challenge", "origin":"https://example.test", "prompt":"Test form\nSecond line\x1b[2J",
                "fields":[
                    {"id":"password", "label":"Password", "kind":"secret"},
                    {"id":"action", "label":"Gateway action", "kind":"choice", "choices":choices, "selected_index":selected},
                    {"id":"optional", "label":"Optional", "kind":"choice", "choices":["One"], "required":false, "selected_index":selected}
                ]
            })).unwrap();
            client.send(form).await.unwrap();
            let Event::Opened { challenge_id } = client.receive().await.unwrap().body else { panic!("expected opened"); };
            let mut cli = env.cli();
            if review { cli.arg("review"); }
            else { cli.args(["interaction", &challenge_id]); }
            let mut terminal = Terminal::spawn(&mut cli);
            let mut shown = Vec::new();
            if review {
                shown.extend(read_until(&mut terminal.master, b"quit [q]: "));
                assert!(String::from_utf8_lossy(&shown).contains("Test form\r\nSecond line"));
                terminal.master.write_all(b"a\n").unwrap();
            }
            shown.extend(terminal.answer(b"Password (input hidden): ", "test-private-password"));
            let action_prompt: &[u8] = if selected.is_some() { b"Choose 1-3 (Enter keeps 1): " } else { b"Choose 1-3: " };
            if selected.is_none() { shown.extend(terminal.answer(action_prompt, "")); }
            shown.extend(terminal.answer(action_prompt, "test-private-invalid-choice"));
            shown.extend(terminal.answer(action_prompt, "0"));
            shown.extend(terminal.answer(action_prompt, "4"));
            shown.extend(terminal.answer(action_prompt, input));
            if selected.is_some() {
                shown.extend(terminal.answer(b"Choose 1-1 (Enter keeps 1): ", "0"));
            } else {
                shown.extend(terminal.answer(b"Choose 1-1 (Enter skips): ", ""));
            }
            shown.extend(read_until(&mut terminal.master, b"credential_answered"));
            assert!(!shown.contains(&0x1b), "terminal control sequence was emitted");
            let shown = String::from_utf8(shown).unwrap();
            assert!(shown.contains("[3]"));
            assert!(!shown.contains("[3] 3: OK"));
            assert!(!shown.contains("Application-supplied form:"));
            assert!(!shown.contains("\"fields\""));
            if selected.is_some() { assert!(shown.contains("[1] ibg.Fri.xml (current)")); }
            assert!(shown.contains("Invalid answer:"));
            assert!(!shown.contains("test-private-password"));
            assert!(!shown.contains("test-private-invalid-choice"));
            let Event::Answered { values: Some(values), .. } = client.receive().await.unwrap().body else { panic!("expected answer"); };
            assert_eq!(values["password"].0, "test-private-password");
            assert_eq!(values["action"].0, expected);
            assert_eq!(values["optional"].0, "");
            client.send(Request::Result { challenge_id, outcome: "succeeded".into() }).await.unwrap();
            assert!(matches!(client.receive().await.unwrap().body, Event::Recorded { .. }));
            if !review { assert_eq!(terminal.exit_code(), 0); }
        }
    });
    let audit = env
        .request("admin", json!({"method":"actions","limit":100}))
        .to_string();
    let logs = fs::read_to_string(env.dir.path().join("daemon.log")).unwrap();
    for text in [audit, logs] {
        assert!(!text.contains("test-private-password"));
        assert!(!text.contains("test-private-invalid-choice"));
    }
}
