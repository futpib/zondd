# zondd for Android

A focused controller for your zondd user daemon: approvals, policy editing, and
systemd user-service controls. GPL-3.0-or-later; see [LICENSE](../LICENSE).

[<img src="https://raw.githubusercontent.com/ImranR98/Obtainium/main/assets/graphics/badge_obtainium.png" height="80" alt="Get it on Obtainium">](https://apps.obtainium.imranr.dev/redirect?r=obtainium://add/https://github.com/futpib/zondd)

## Obtainium and APK downloads

Once the first Android release is published, open the badge above or add
`https://github.com/futpib/zondd` in Obtainium. Use the release-title filter
`^Android ` to track Android releases if the repository also publishes daemon
releases. Choose `app-release.apk` for a universal ARM64/x86-64 installation,
or `app-arm64-v8a-release.apk` / `app-x86_64-release.apk` for a smaller download.
Each file installs independently. Keep the same APK filename when updating;
Flutter adds architecture-specific version-code offsets to per-ABI builds.
Obtainium handles update checks and Android's installation confirmation.

The **Build Android APK** workflow is manually triggered and publishes signed
APKs plus `SHA256SUMS` to GitHub Releases. Tags start with `android-`; the build
number increases from the highest published Android release. Release builds use
the same application ID, `io.github.futpib.zondd_control`, and must always use
the same signing key. Earlier development APKs use a different key and must be
uninstalled before installing the first release, which removes their local data.

Before the first release, publish the source repository and configure GitHub
Actions secrets `KEYSTORE_BASE64` (the base64-encoded persistent keystore) and
`KEYSTORE_PASSWORD`. The key alias defaults to `release`; set `KEY_ALIAS` if
different, and `KEY_PASSWORD` if the key password differs from the store password.
Create and back up a dedicated keystore outside the repository, for example:

```sh
umask 077
keytool -genkeypair -keystore "$HOME/zondd-release.jks" -storetype JKS \
  -alias release -keyalg RSA -keysize 3072 -validity 10000
base64 -w0 "$HOME/zondd-release.jks" | gh secret set KEYSTORE_BASE64 --repo futpib/zondd
gh secret set KEYSTORE_PASSWORD --repo futpib/zondd
```

Then run **Actions → Build Android APK → Run workflow**. Missing signing
credentials fail the release build; no temporary or debug key is substituted.
Do not delete the latest Android release or replace the signing key between
updates. Both would break the version/signature continuity Obtainium relies on.

## Connect

1. Install current `zondd`, `zondctl`, and the user service on the receiving host
   using the [receiver instructions](../readme.md#configure-the-receiver). No policy
   file is needed: the built-in caller requires manual approval for every command.
2. Open **SSH keys**. Import a PEM/OpenSSH private key from a file or paste it,
   including its passphrase if encrypted. Or generate an Ed25519 key and copy
   its public key to the server. Identities are reusable across connections.
3. Select **SSH** or **Iroh**, enter `user@host[:port]` or
   `user@<64-hex-endpoint-id>`, choose a key, and connect. IPv6 addresses use
   `user@[address]:port`. Successful quick connections are saved automatically.
   **Connection options** also supports passwords, display names, and custom paths.
   Use the Unix account running zondd and an ordinary SSH identity; a restricted
   caller key cannot manage zondd. Keys and passwords are encrypted in Android
   storage; backups are disabled. Existing inline profile keys migrate to the
   shared key store without changing SSH host-key pins.
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
file. **Save & apply** then reloads that exact saved revision without restarting.
Running commands finish. Waiting requests are re-evaluated: unchanged approvals
keep their ID/expiry, newly allowed commands run, and newly denied requests are
rejected. Changed commands or working directories require fresh review. Invalid reloads leave the active policy intact. If saving
succeeds but applying fails, **Apply now** retries the saved revision; refresh
before applying if another editor changed the file. A stopped daemon loads the
saved policy when started. Changing `runtime_dir` still requires a restart.
Restart/stop cancel active work.
The policy overview shows the saved callers, ordered rules, and named operations.
**Edit TOML** keeps validation and saving visible while editing; unsaved drafts
survive tab changes, validation errors, and stale-save errors. Command arguments
in approvals are individually JSON-quoted so boundaries and control characters
remain visible; the display is not a shell command to copy and execute.

The **History** tab keeps every request outcome, including rejection, denial,
expiry, cancellation and interruption. Details show command/context, output,
exit status and approval events. **Run again** creates a new request through the
current policy and never reuses an approval. It remains owned by the daemon if
you close the app. **Activity** shows the persistent daemon action log. Both lists
support loading earlier entries, and history survives service restarts.

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
compatible NDK. `scripts/build-native.sh` can build just the adapter. Debug builds
need no release credentials. To reproduce the release APKs locally, export
`KEYSTORE_PATH` (an absolute path) and `KEYSTORE_PASSWORD`, with optional
`KEY_ALIAS` and `KEY_PASSWORD`, then run:

```sh
bash scripts/build-release.sh 0.1.0 2 /tmp/zondd-release-apks
```

The helper builds the normal `lib/main.dart` app for both supported architectures,
then builds each standalone architecture APK and writes `SHA256SUMS`. Choose a
version code higher than previous releases. `FLUTTER` can select a Flutter binary.

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
It also generates and imports keys through the UI, saves a connection, reviews
policy details, corrects a validation error, and checks unsaved-edit prompts.

To run the same tests and capture each screen and dialog using actual `adb`
screenshots (requires Python 3 and `adb` on PATH):

```sh
FLUTTER=/path/to/flutter python3 android-app/scripts/capture-screenshots.py \
  --device emulator-5554 --output /tmp/zondd-screenshots
```

Ephemeral fixture credentials are embedded in the test APK. Never distribute
that APK; build the normal `lib/main.dart` app again afterward. Rust drop guards
terminate fixture processes and remove their keys and files, including on test
failure. Tests do not edit installed services or authorized keys.
