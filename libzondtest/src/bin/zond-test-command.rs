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
        _ => panic!("unknown probe"),
    }
}
