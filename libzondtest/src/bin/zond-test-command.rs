//! Real subprocess payloads for credential, byte transport, and cancellation tests.
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    time::Duration,
};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args[1].as_str() {
        "adapter" => {
            let listener = std::os::unix::net::UnixListener::bind(&args[2]).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut incoming = stream.try_clone().unwrap();
            let send = std::thread::spawn(move || {
                std::io::copy(&mut std::io::stdin(), &mut stream).unwrap();
            });
            std::io::copy(&mut incoming, &mut std::io::stdout()).unwrap();
            let _ = send;
        }
        "interaction" => {
            use serde_json::{Value, json};
            let mut input = BufReader::new(std::io::stdin());
            let mut read = || -> Value {
                let mut line = String::new();
                input.read_line(&mut line).unwrap();
                serde_json::from_str(&line).unwrap()
            };
            assert_eq!(read()["type"], "ready");
            println!(
                "{}",
                json!({"method":"challenge", "prompt":"Sign in to the test application", "fields":[{"id":"username","label":"Username","kind":"text"},{"id":"password","label":"Password","kind":"secret"}], "context":{"site":"https://example.test"}})
            );
            let opened = read();
            let answer = read();
            assert_eq!(answer["values"]["username"], "test-user");
            assert!(answer["values"]["password"] == "test-application-password");
            println!(
                "{}",
                json!({"method":"result","challenge_id":opened["challenge_id"],"outcome":"succeeded"})
            );
            assert_eq!(read()["type"], "recorded");
            println!("{}", json!({"method":"status","state":"ready"}));
            assert_eq!(read()["type"], "recorded");
            std::thread::sleep(Duration::from_secs(120));
        }
        "approval" => {
            let mut socket = UnixStream::connect(&args[2]).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            writeln!(
                socket,
                "{}",
                serde_json::json!({"version":1,"id":1,"body":{"method":"pending"}})
            )
            .unwrap();
            let mut line = String::new();
            BufReader::new(&mut socket).read_line(&mut line).unwrap();
            let response: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(response["body"]["type"], "queue");
            println!("approval accessible");
        }
        "identity" => {
            use nix::unistd::{Gid, Uid, getgroups};
            println!(
                "{}",
                serde_json::json!({"uid":Uid::effective().as_raw(), "gid":Gid::effective().as_raw(), "groups":getgroups().unwrap().iter().map(|g| g.as_raw()).collect::<Vec<_>>()})
            );
        }
        "bytes" => {
            std::io::stdout().write_all(&[0, 255]).unwrap();
            std::io::stderr().write_all(b"err").unwrap();
            std::process::exit(7);
        }
        "create_new_gate" => {
            let output = std::path::Path::new(&args[2]);
            std::fs::create_dir(output).unwrap();
            std::fs::write(output.join("payload"), "new output").unwrap();
            std::fs::write(&args[3], &args[2]).unwrap();
            std::io::Read::read_to_end(
                &mut std::fs::File::open(&args[4]).unwrap(),
                &mut Vec::new(),
            )
            .unwrap();
            if args[5] == "fail" {
                std::process::exit(7);
            }
        }
        "sleep" => {
            std::fs::write(&args[2], std::process::id().to_string()).unwrap();
            std::thread::sleep(Duration::from_secs(30));
        }
        "stream" | "stream_gate" => {
            println!("early");
            std::io::stdout().flush().unwrap();
            if args[1] == "stream_gate" {
                std::io::Read::read_to_end(
                    &mut std::fs::File::open(&args[2]).unwrap(),
                    &mut Vec::new(),
                )
                .unwrap();
            } else {
                std::thread::sleep(Duration::from_secs(3));
            }
            eprintln!("late");
        }
        "large" => {
            std::io::stdout().write_all(&vec![b'x'; 2048]).unwrap();
        }
        "streamlarge" => {
            println!("early");
            std::io::stdout().flush().unwrap();
            std::thread::sleep(Duration::from_secs(3));
            std::io::stdout().write_all(&vec![b'x'; 2048]).unwrap();
        }
        "askpass" | "askpass_slow" => {
            use std::process::Command;
            // SAFETY: prctl reads the calling process's no-new-privileges bit.
            let flag = unsafe { nix::libc::prctl(nix::libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
            assert_eq!(flag, 0);
            let helper = std::env::var("SUDO_ASKPASS").unwrap();
            for (index, expected) in ["test-password-one", "test-password-two"]
                .into_iter()
                .enumerate()
            {
                if args[1] == "askpass_slow" && index == 1 {
                    std::thread::sleep(Duration::from_secs(3));
                }
                let reply = Command::new(&helper)
                    .arg("Password for sudo:")
                    .output()
                    .unwrap();
                assert!(reply.status.success(), "askpass failed");
                assert!(
                    reply.stdout == format!("{expected}\n").as_bytes(),
                    "unexpected askpass response"
                );
            }
            println!("two prompts answered");
        }
        "no_new_privs" => {
            // SAFETY: prctl reads the calling process's no-new-privileges bit.
            let flag = unsafe { nix::libc::prctl(nix::libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
            println!("{flag}");
        }
        _ => panic!("unknown probe"),
    }
}
