# zondd for Android

A focused controller for your zondd user daemon: approvals, policy editing, and
systemd user-service controls. GPL-3.0-or-later; see [LICENSE](../LICENSE).

## Connect

1. Install current `zondd`, `zondctl`, and the user service on the receiving host
   using the [receiver instructions](../readme.md#configure-the-receiver).
2. Add a connection in the app. Enter a hostname/IP and SSH port, or enable Iroh
   and enter your existing iroh-ssh server's 64-hex endpoint ID.
3. Use the Unix account running zondd and a normal SSH private key or password.
   Paste an existing PEM/OpenSSH private key and its passphrase if encrypted.
   This key must have ordinary SSH access; a restricted caller key cannot manage
   zondd. Credentials are saved using Android encrypted storage; backups are disabled.
4. Verify the SSH server fingerprint on first connection. The app pins it for
   the destination and rejects changes, including over Iroh. To rotate a key,
   verify the new fingerprint out of band and use **Forget host key** first.
5. Tap **Approve once** or **Reject** on an exact command request. The caller
   remains connected while waiting and receives command output or rejection.

Advanced connection settings select the remote `zondctl` executable (default
`.cargo/bin/zondctl`, relative to the SSH user's home), config file, runtime
directory, and custom Iroh relay URLs. The executable is a path/name, not a shell
command; each argument is quoted separately. SSH login banners on stdout or
startup scripts that change the login working directory can interfere; use an
absolute executable path for the latter.

The approval screen polls every two seconds while foregrounded. There is no
background notification service. Closing the controller does not reject callers;
they remain pending until their existing deadline, disconnection, or a decision.
Expired/disconnected requests cannot be approved. All decisions apply once.
Policy saves validate and check for concurrent edits, then atomically replace the
file. Restart the user service to apply changes; restart/stop cancel active work.

## Architecture

Flutter provides the UI and `dartssh2` provides SSH authentication and exec
channels. A small Rust FFI adapter calls the existing `futpib/iroh-ssh` bridge
library to obtain a loopback TCP port. SSH runs through that tunnel unchanged.
The dependency is pinned by revision; tunnel and authentication implementations
are not copied from slopd or iroh-ssh-android. Unlike slopd's separate Iroh endpoint
allowlist, management authority here comes from the normal SSH account.

The SSH session invokes `zondctl control` for each management request. No new
network port, root service, or custom network authentication is required. The
app intentionally has the same rights as that login's general-purpose shell.

## Build

Requires Flutter (tested with 3.44.1/Dart 3.12.1), Rust, Android SDK, JDK 17,
NDK 28.2.13676358, and `cargo-ndk`. The app supports Android API 24+ on ARM64 and
x86-64. Gradle builds the native adapter automatically, with its committed lockfile.

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk --locked
flutter pub get
flutter analyze
flutter test
flutter build apk --debug --target-platform android-arm64,android-x64
```

Set `ANDROID_HOME` to the SDK and optionally `ANDROID_NDK_HOME` to a different
compatible NDK. `scripts/build-native.sh` can build just the adapter. The default
APK is a development build. The release build also uses development signing
until you supply your own signing configuration; it is not a published release.

## Real Android end-to-end test

Start an Android emulator. From the Rust workspace root:

```sh
cargo build --workspace --bins
FLUTTER=/path/to/flutter ZONDD_ANDROID_DEVICE=emulator-5554 \
  cargo test -p zondctl --test android -- --ignored --nocapture
```

The Rust test owns an isolated user daemon, an OpenSSH server, ephemeral caller
and management keys, and an Iroh server. The Flutter integration test exercises
actual Android SSH and native Iroh connections, taps approval/rejection buttons,
checks caller results, validates/saves configuration, rejects stale saves and
invalid policy, rejects untrusted host keys and restricted management keys, and
reads service state. It does not start/stop your installed service. The fixture
uses the emulator's `10.0.2.2` host gateway; physical devices need another route.

Ephemeral fixture credentials are embedded in the test APK. Never distribute
that APK; build the normal `lib/main.dart` app again afterward. Rust drop guards
terminate fixture processes and remove their keys and files, including on test
failure. Tests do not edit installed services or authorized keys.
