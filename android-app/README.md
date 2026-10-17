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

Before the first release, publish the source repository and configure the GitHub
Actions secret `KEYSTORE_BASE64` with the base64-encoded persistent keystore.
The workflow uses the `release` key alias and `android` for both passwords,
matching the existing `iroh-ssh-android` release keystore. Keep a backup of the
keystore outside the repository. To create a dedicated key with those values:

```sh
umask 077
keytool -genkeypair -keystore "$HOME/zondd-release.jks" -storetype JKS \
  -alias release -keyalg RSA -keysize 3072 -validity 10000
base64 -w0 "$HOME/zondd-release.jks" | gh secret set KEYSTORE_BASE64 --repo futpib/zondd
```

Enter `android` for the store and key passwords when `keytool` prompts.

Then run **Actions → Build Android APK → Run workflow**. Missing signing
credentials fail the release build; no temporary or debug key is substituted.
Do not delete the latest Android release or replace the signing key between
updates. Both would break the version/signature continuity Obtainium relies on.

## Saved credentials

Sudo password and application credential dialogs offer **Save credentials on
this device** with a **1 hour** default. Choose 15 minutes, 8 hours or **Forever**,
or turn off saving for that response. Saving and each **Use saved credentials**
operation require strong biometric authentication on Android 11 or newer.
Devices without suitable enrolled biometrics can still enter and send answers
manually. Reuse fills the form for review; sending remains a separate action.

Values are encrypted with AES-GCM using Android Keystore keys that require
authentication for each operation and are invalidated by biometric enrollment
changes. Expiry and credential identity are authenticated with the encrypted
record. Expired records and their keys are removed when checked; timed records
also use a monotonic deadline within the same device boot. Saved values are
never added to receiver history or audit exports.

Matching includes the verified SSH destination and host key, Unix account,
receiver config/runtime paths, selected management executable, and the
authentication context. Sudo values also
bind the caller, exact command, operation and prompt. Application values bind
the registered recipient and configuration revision, UID, provider origin,
complete form and context, and selected choice/confirmation values. Process,
session, request and challenge IDs may change without changing the credential
identity. An entered username must match the saved username; editing an account
field clears a reused password. OTPs, confirmation/choice answers, unknown field
types and fields named as verification codes are never saved. Changed or expired
requests, reconnection and backgrounding during unlock prevent reuse.

Open **Saved credentials** from the connection list or receiver toolbar to see
recipient, purpose, fields and lifetime, remove one entry, or remove all entries.
This screen never decrypts or displays saved answers. SSH connection passwords
and imported keys remain separate from this credential vault.

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
   keys are stored. Quick connect selects a key automatically only when one is
   saved. **Connection options** can save an ordered list of keys for a server
   that requires more than one identity. The app asks only for authentication
   methods offered by the server, supports expired-password changes, and displays keyboard-interactive
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
   **Reusable rule proposal** cards show the exact rule source received by the
   daemon as selectable, monospaced text, followed by the resolved executable,
   working directory, and parameter constraints. **Approve rule**
   grants repeated invocations for the selected lifetime; it defaults to one
   hour. **Caller rules** shows collapsed summaries with caller, status, and
   lifetime. The default **Current** filter shows active rules first, followed by
   pending proposals. Choose **History** for previous rules, or **All** to search
   both current and historical entries. Search names, callers, status, or any
   rule content, then expand a
   matching entry to read its source and definition or revoke its grant. See
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
you close the app. **Activity** groups related events into linked timelines.
**Group related events** switches to individual events; **Include reads** reveals
recorded access events. Request details show recorded submitter/reviewer evidence
and activity in chronological order. Configuration and service intents link to
their outcomes; a management intent without a terminal event shows that its
outcome has not been recorded. Credential events distinguish a response
queued by the broker from an application's report of success or failure.
Both lists support loading earlier entries, and history survives service restarts.

Activity is checked against checkpoints held in this phone's secure storage.
Changed events, missing events, rollback or replacement produce a visible error,
preserve the previous checkpoint and block further signed decisions. Older
receivers are labeled unverified; imported history displays its migration boundary.
Management changes made through the helper are recorded even while the daemon is
unavailable. Local device receipts are saved before sending, so a lost reply can
leave an explicit decision with an unknown outcome.

**Export audit history** opens Android's document saver and writes the complete
verified range, checkpoint and signed receipts. `zondctl verify-audit FILE`
checks the saved bytes and signatures; add `--checkpoint EARLIER_EXPORT` to check
against a separately retained anchor. A device signature proves possession of
its audit key, not who held the phone or whether an external action succeeded.
The receiver still controls its own reports and can omit unobserved events.
The first observation establishes a baseline. Removing app data loses the phone
anchor; keep earlier exports separately when needed. See the main
[audit documentation](../readme.md#request-history-and-action-log) for the exact
trust boundary.

Local rule types are receiver-defined. Approval cards show aliases, enum values,
integer and text constraints, and every correlated choice row; the app submits
only the reviewed proposal ID and digest. Integer bounds remain exact decimal
strings in YAML and audit data. The app does not parse rule source or choose
values on the caller's behalf. See the main [rule language documentation](../readme.md#propose-reusable-typed-rules)
for local types, choice projections and home expansion.

## Architecture

Flutter provides the UI and `dartssh2` provides SSH authentication and exec
channels. A small Rust FFI adapter calls the existing `futpib/iroh-ssh` bridge
library to obtain a loopback TCP port. SSH runs through that tunnel unchanged.
The shared `openkeychain_ssh` Flutter plugin handles Android key providers.
The dependency is pinned by revision; tunnel and authentication implementations
are not copied from slopd or iroh-ssh-android. Unlike slopd's separate Iroh endpoint
allowlist, management authority here comes from the normal SSH account.

The SSH session invokes `zondctl control` for each management request. No new
network port, root service, or custom network authentication is required. The
app intentionally has the same rights as that login's general-purpose shell.

## Build

Requires Flutter 3.47.5 (Dart 3.13.4), Rust, Android SDK, JDK 25,
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

The biometric vault has a separate device test. Use an isolated, read-only
Android 11+ emulator with fingerprint 1 enrolled, and run `adb -s DEVICE root`
before starting. In one terminal, from `android-app`, run:

```sh
python3 scripts/credential-vault-driver.py --device emulator-5584 \
  --log /tmp/zond-vault-test.log
```

In another terminal, run:

```sh
flutter test integration_test/saved_credentials_test.dart -d emulator-5584 \
  --reporter expanded > /tmp/zond-vault-test.log 2>&1
```

The driver supplies real fingerprint events, cancels a prompt, backgrounds the
app, inspects encrypted storage, and advances/restores the emulator's clock to
check expiry. Test-mode handshakes live only in the integration test; the normal
app has no authentication bypass or test vault.

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
