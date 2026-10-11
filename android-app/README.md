# zond for Android

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

Iroh connections use the same pinned bridge as `iroh-ssh-android`:
`futpib/iroh-ssh` at `f7e04ea411b198a334d118675de5e015ae527dae`
(`iroh-ssh` 0.2.12, Iroh 1.3.0). The receiving Iroh SSH server must use a
compatible wire version; CI tests the server built from this same revision.
Plain SSH connections do not depend on Iroh versions.

1. Install current `zondd`, `zondctl`, and the user service on the receiving host
   using the [receiver instructions](../readme.md#configure-the-receiver). No policy
   file is needed: the built-in caller requires manual approval for every command.
2. Open **SSH keys**. Import a PEM/OpenSSH private key from a file, paste it, or scan its QR code,
   including its passphrase if encrypted. Or generate an Ed25519 key and copy
   its public key to the server. Identities are reusable across connections.
   **Add from OpenKeychain** selects a key from an installed OpenKeychain-compatible
   provider. Only its reference and public key are saved in zond; signing stays
   with the provider. Choose that identity for either SSH or Iroh and approve
   provider prompts when connecting. Removing it from zond leaves the provider's
   key intact. RSA keys use SHA-256 signatures; Ed25519 and ECDSA are also supported
   when the provider supports them.
3. Select **SSH** or **Iroh**, enter `user@host[:port]` or
   `user@<64-hex-endpoint-id>`, optionally choose a key, and connect. IPv6 addresses use
   `user@[address]:port`. Successful quick connections are saved automatically.
   Choose **Password / no SSH key** to connect without an identity, even when
   keys are stored. The app asks only for authentication methods offered by the
   server, supports expired-password changes, and displays keyboard-interactive
   prompts and instructions, including verification codes and push approvals. Cancel returns to
   the connection list; rejected answers can be retried. Prompted answers are
   never saved. **Connection options** supports an optional saved password,
   display names, and custom paths. Leave the password blank to ask each time.
   Leaving edited connection options asks whether to discard unsaved changes.
   Use the Unix account running zondd and an ordinary SSH identity; a restricted
   caller key cannot manage zondd. Keys and passwords are encrypted in Android
   storage; backups are disabled. Existing inline profile keys migrate to the
   shared key store without changing SSH host-key pins.
4. Verify the SSH server fingerprint on first connection. The app pins it for
   the destination and rejects changes, including over Iroh. To rotate a key,
   verify the new fingerprint out of band and use **Forget host key** first.
5. Tap **Approve once** or **Reject** on an exact command request. The caller
   remains connected while waiting and receives command output or rejection.
   **Reusable rule proposal** cards show the complete typed rule, resolved
   executable, working directory, and parameter constraints. **Approve rule**
   grants repeated invocations for the selected lifetime; it defaults to one
   hour. **Caller rules** shows collapsed summaries with caller, status, and
   lifetime. Search names, callers, status, or any rule content, then expand a
   matching entry to inspect its definition or revoke its grant. See
   [caller rule syntax and semantics](../readme.md#propose-reusable-typed-rules).

Rule explanations come from the daemon as a versioned plain-text review document,
bound to the approval digest. Android renders its sections and fields generically,
so new daemon types, checks and effects using that format do not require an app
update. Unknown, incomplete or missing review formats show the complete proposal
JSON as YAML in the approval card, with approval and lifetime selection still
available. Known formats also offer **Rule details (YAML)**. The fallback preserves
all fields and scalar types, including nested definitions and escaped control
characters. Rejection and revocation remain available in either view.

**Policy** searches caller and operation names, commands, directories, and their
other configuration fields. Entries start collapsed and retain their expansion
while filtering. **Saved connections** and **SSH keys** search their public labels,
addresses, transports, providers, and fingerprints; credentials are excluded.
**History** searches requests and activity across the daemon's stored pages,
including command arguments, callers, status, reasons, and action details. Keep
the query while using **Load earlier** to page through matches. This history
search requires updated `zondd` and `zondctl` on the receiver. Command output is
available in request details but is not included in the summary search.

QR scan buttons are available beside connection targets (including quick connect),
private keys, passphrases, passwords, and relay URLs. Scan with the camera or choose
a QR image from the gallery. The decoded text fills the field for review; it does
not save or connect automatically. Cancelling leaves the field unchanged. Private
keys retain their line breaks, and passwords/passphrases retain whitespace.

Advanced connection settings select the remote `zondctl` executable (default
`zondctl`, resolved through the remote shell's `PATH`), config file, runtime
directory, and custom Iroh relay URLs. The executable is a path/name, not a shell
command; each argument is quoted separately. SSH login banners on stdout or
startup scripts that change the login working directory can interfere; use an
absolute executable path for the latter.

If the SSH connection drops, the app automatically opens a new SSH session (and
Iroh tunnel when applicable). Retries start after one second and back off to at
most 30 seconds while the app is visible; returning to the app retries immediately.
The same host-key checks and authentication prompts apply. Cancelling authentication,
a rejected identity, or a host-key error pauses automatic retries until you tap
**Reconnect**. You can still reconnect manually or leave a reconnecting screen.

Reconnection keeps your current screen, rule filters, and unsaved policy edits.
Pending approvals, service status, rules, and history refresh after recovery.
Actions are never replayed automatically: if a connection failed during an approval,
save, or command, check its state before trying that action again. Policy recovery
reads the saved server revision without replacing your draft. If a save succeeded
but its reply was lost, subsequent edits can be saved normally. If someone else
changed the server policy, **Save & apply** shows that version and asks before
replacing it; cancelling preserves your draft.

Unreadable saved-connection entries do not hide usable connections. Their raw
records remain encrypted and are preserved when you save other connections. If
the whole store cannot be read, saving is disabled; **Retry loading connections**
tries again without overwriting it.

**Cancel key import** stops an OpenKeychain import while waiting for the provider.
Provider operations time out after two minutes and can be retried. Cancellation
and timeouts release service bindings and pending interactions; late replies
cannot finish a cancelled import.

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
survive tab changes, validation errors, and stale-save errors. Structured data in approvals, password challenges, policy summaries, history and
activity is displayed as YAML. Commands show an explicit executable and argument
list, preserving argument boundaries, scalar types and visible control characters.
In policy rules, `args: null` means any arguments; `args: []` means no arguments.
Command output remains the original text, and the policy editor uses TOML.

The **History** tab keeps every request outcome, including rejection, denial,
expiry, cancellation and interruption. Details show command/context, output,
exit status and approval events. **Run again** creates a new request through the
current policy and never reuses an approval. It remains owned by the daemon if
you close the app. **Activity** shows the persistent daemon action log. Both lists
support loading earlier entries, and history survives service restarts.

## Architecture

The local `vendor/dartssh2` dependency retains version 4.1.0 with one documented
patch: discover the server's authentication methods before requesting credentials.

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

Install Python Paramiko (`python3-paramiko` on Ubuntu), or set `PYTHON` to a
Python interpreter with Paramiko installed. The authentication fixture listens
only on loopback and runs the real control helper after authenticating.

Start an Android emulator. From the Rust workspace root:

```sh
cargo build --workspace --bins
FLUTTER=/path/to/flutter ZONDD_ANDROID_DEVICE=emulator-5554 \
  cargo test -p zondctl --test android -- --ignored --nocapture
```

Set `ZONDD_ANDROID_TEST=integration_test/rules_test.dart` to run only reusable
rule review and revocation over SSH and Iroh. That test verifies caller-visible
status, invalid parameter rejection, successful directory publication, and
refusal to replace an existing destination.

External adapter repositories can set `ZONDD_ANDROID_TEST` to an absolute Dart
test path. The harness creates and cleans up a temporary entrypoint inside this
app's `integration_test` directory so Flutter runs it on the selected device. Set
`ZONDD_ANDROID_EXTRA_FIXTURE=/path/to/fixture.json` to add application-specific
fields to the test's `ZONDD_FIXTURE` object. Built-in connection fields cannot
be replaced. Optional `forbiddenLogValues` lists nonempty dummy credential
strings to check against the daemon log and SQLite files after the test;
`additionalLogFiles` lists absolute paths to application logs to check too.
External repositories own their adapter setup, fixtures, and cleanup.

For external signing, install OpenKeychain on a disposable emulator, add a test
key there, and export its **OpenSSH public key** to a host file. Run the same
command with `ZONDD_ANDROID_EXTERNAL_PUBLIC_KEY=/path/to/test-key.pub`. This
selects the external-key test, authorizes that public key on the disposable SSH
server, and exercises signing over both SSH and Iroh. Select the matching key
and approve access in the real provider UI when prompted. The test never reads
the provider's private key. Ordinary CI runs the unattended suite without this
environment variable.

The Rust test owns an isolated user daemon, an OpenSSH server, ephemeral caller
and management keys, and an Iroh server built from `native/Cargo.lock`. It uses
the same Iroh SSH library as the app; no separately installed Iroh CLI is needed.
The authentication tests exercise password entry, cancellation, rejected-answer
retry, stale saved passwords, expired-password changes, keyless multi-round
keyboard-interactive challenges, and cancellable push-approval instructions
through the normal app UI over both SSH and Iroh. They also check connection
editing and that the real authentication timeout dismisses host trust without
saving a pin. Policy repair is tested after writing malformed TOML types directly
to the remote configuration file. The other Flutter integration
tests exercise
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

For reusable rule review, grant lifetime, YAML details, and revocation:

```sh
ZONDD_ANDROID_TEST=integration_test/rule_screenshots_test.dart \
FLUTTER=/path/to/flutter python3 android-app/scripts/capture-screenshots.py \
  --device emulator-5554 --output /tmp/zondd-rule-screenshots
```

This submits the `clone-futpib` rule to the isolated daemon and approves and
revokes it without invoking a clone. The final two screens use an explicitly
labeled future-format fixture in the production approval widget to demonstrate
the YAML fallback and enabled approval controls.

To exercise QR import through real camera frames, start a disposable emulator
with `-camera-back virtualscene`, install `qrencode` and Python Pillow
(`qrencode python3-pil` on Ubuntu), then run:

```sh
FLUTTER=/path/to/flutter python3 android-app/scripts/test-qr.py --device emulator-5554
```

This scans targets, passwords, relay URLs, a generated private key, and a
passphrase, verifies whitespace and cancellation, and imports the scanned key
through the UI. It restores stored identities and the camera pose, resets the
wall poster, and deletes temporary QR images. CI runs both emulator suites.

Ephemeral fixture credentials are embedded in the test APK. Never distribute
that APK; build the normal `lib/main.dart` app again afterward. Rust drop guards
terminate fixture processes and remove their keys and files, including on test
failure. Tests do not edit installed services or authorized keys.

Android bridge recovery tests use a simulated provider to exercise stalled binding,
late binder replies, cancellation, deadlines, and provider death on the emulator:

```sh
cd android
./gradlew connectedDebugAndroidTest
```

These tests do not require a real OpenKeychain key. The external-signing test above
remains the check for real provider interoperability.
