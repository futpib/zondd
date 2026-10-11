//! Real subprocess payloads for credential, byte transport, and cancellation tests.
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    time::Duration,
};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args[1].as_str() {
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
        "sleep" => {
            std::fs::write(&args[2], std::process::id().to_string()).unwrap();
            std::thread::sleep(Duration::from_secs(30));
        }
        "stream" => {
            println!("early");
            std::io::stdout().flush().unwrap();
            std::thread::sleep(Duration::from_secs(3));
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
