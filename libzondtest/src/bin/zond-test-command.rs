//! Real subprocess payloads for credential, byte transport, and cancellation tests.
use std::{io::Write, os::unix::net::UnixStream, time::Duration};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args[1].as_str() {
        "socket" => {
            let error = UnixStream::connect(&args[2]).expect_err("control socket was accessible");
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            println!("permission denied");
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
