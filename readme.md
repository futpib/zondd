# zondd

SSH-authenticated operations with exact command allowlists, named operations,
and an optional local approval queue. Linux, Rust, GPL-3.0-or-later.

[<img src="https://raw.githubusercontent.com/ImranR98/Obtainium/main/assets/graphics/badge_obtainium.png" height="80" alt="Get the Android controller on Obtainium">](https://apps.obtainium.imranr.dev/redirect?r=obtainium://add/https://github.com/futpib/zondd)

The Android controller's [Obtainium setup and release instructions](android-app/README.md#obtainium-and-apk-downloads)
cover installation and updates. Downloads become available after the first Android release is published.

Keep your existing OpenSSH server and iroh-ssh forwarding. OpenSSH authenticates
the key; its fixed `authorized_keys` command bridges a versioned protocol to
zondd. Both endpoints are included. No additional network listener or SSH server
implementation is needed.

```text
zondctl → ssh [→ iroh-ssh proxy] → sshd → zondd bridge
                                              ↓ principal Unix socket
                                         zondd serve → command as the same user
                                              ↑ separate admin Unix socket
                                         zondctl review
```

The workspace follows slopd's shared-library/daemon/client split:

- `libzond`: wire types, bounded framing, policy and operation schemas.
- `libzondctl`: asynchronous Unix-socket and OpenSSH client.
- `zondd`: user daemon and forced-command bridge.
- `zondctl`: sending CLI and local approval interface.
- `libzondtest`: shared isolated process fixtures and a Rust subprocess probe,
  following slopd's `libsloptest` pattern.

## Build and test

```sh
cargo build --workspace --bins
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

Named Rust integration tests live in `zondd/tests/integration.rs` and
`zondctl/tests/integration.rs`, with shared fixtures in `libzondtest`.
The normal suite starts real user daemons, tests approval through a PTY,
and verifies that commands retain the user's UID, GID, supplementary groups,
and local approval authority. Run it as your normal user, without sudo.

Additional integration tests have explicit `#[ignore]` reasons because they
require OpenSSH client/server, Iroh connectivity, or a running systemd user
manager. After building the binaries, select them with Cargo:

```sh
# Real OpenSSH transport tests:
cargo test -p zondctl --test integration -- --ignored --skip iroh_ssh --skip trusted_management
# Also exercise the installed Iroh transport and real discovery:
cargo test -p zondctl --test integration -- --ignored
# Start and stop an isolated instance of the shipped systemd user service:
cargo test -p zondd --test integration shipped_user_service -- --ignored
```

Fixtures create private temporary directories under the user's home (so SSH
StrictModes can remain enabled), ephemeral keys, and isolated loopback sshd
processes running as the current user. Drop guards clean up processes and files
on success and assertion failures, and print logs on failure. The systemd test
uses a uniquely named temporary unit and runtime directory, and removes both.
Tests do not change your installed services or authorized keys. Iroh tests
check pipe EOF after completion to catch orphaned proxy processes.

## Continuous integration and releases

GitHub Actions runs these workflows on pull requests and pushes to `master`:

- **CI**: Rust formatting, Clippy, unit/integration tests, real SSH and key
  enrollment, the systemd user service, and Linux archive builds on x86-64 and
  ARM64; Flutter formatting, analysis and widget tests; workflow and shell linting.
- **Transport and Android E2E**: real Iroh caller/management tests and the Android
  controller tests on an API 35 emulator, including native builds for both app
  architectures. This also runs weekly and can be started manually. It uses
  public Iroh discovery/relays, so network failures fail the transport job.
- **Dependency audit**: RustSec checks for both Rust lockfiles when they change,
  weekly, or on manual dispatch. Dependabot proposes weekly updates for Rust,
  Flutter and GitHub Actions dependencies.

Tests run as the runner's ordinary user. CI installs test prerequisites and
starts that user's systemd manager; the daemon and approval tests do not run as
root. Android E2E uses disposable fixture keys and does not upload its test APK.
The Iroh CLI is pinned separately from the Android bridge library: the CLI
needs upstream support for `proxy` and `server --key-dir`. The E2E tests check
interoperability between those two revisions.

**Release Linux binaries** runs when a `vMAJOR.MINOR.PATCH` tag is pushed, or when
manually dispatched against such a tag. The version must match the Rust workspace
version. It tests and packages x86-64 and ARM64 Linux binaries, the user service,
license, documentation and optional policy example, then publishes both archives
and `SHA256SUMS`. Builds use Ubuntu 24.04 and require glibc 2.39 or newer.
For a local native build, run `scripts/package-linux.sh 0.1.0 /tmp/zondd-dist`.
Extract the archive, install `bin/zondd` and `bin/zondctl` into `~/.cargo/bin`, and
follow the user-service setup below. No policy file is installed automatically.

**Build Android APK** remains the manual signed Android release workflow. Linux
releases do not replace Android as the repository's latest release; Obtainium
users can also filter release titles with `^Android `.

## Configure the receiver

On Arch Linux, install the [`zondd-git`](https://aur.archlinux.org/packages/zondd-git)
package from the AUR:

```sh
yay -S zondd-git
```

The package installs `zondd` and `zondctl` in `/usr/bin`, the systemd user
service in `/usr/lib/systemd/user`, and the example policy in
`/usr/share/doc/zondd`. To check the configuration and start the user service:

```sh
zondd check
systemctl --user daemon-reload
systemctl --user enable --now zondd.service
```

The package service uses `/usr/bin/zondd serve`. If migrating from a Cargo
installation, remove your old `~/.config/systemd/user/zondd.service` copy so
it no longer overrides the packaged unit, then reload the user manager and
restart the service. Keep any intentional local customizations as drop-ins.

For a Cargo installation, install the binaries and
[zondd.service](zondd.service) as a **user service**:

```sh
cargo install --locked --path zondd
cargo install --locked --path zondctl
mkdir -p ~/.config/systemd/user
cp zondd.service ~/.config/systemd/user/zondd.service
zondd check
systemctl --user daemon-reload
systemctl --user enable --now zondd.service
```

No policy file is required. Without one, the built-in `default` principal
accepts command requests with **nothing automatically allowed**: every valid
command waits for one-time approval, expires after five minutes, and runs in
the user's home directory only after approval. No named operations are enabled.
The daemon creates its private history storage, but does not create a policy file.

Approvals are enabled by default. Setting `[approvals] enabled = false` makes
`ask` requests reject immediately; explicit `allow` rules still run and explicit
`deny` rules remain hard denials. It never enables unrestricted SSH access.

A policy file is optional customization. The Android policy editor shows editable
built-in settings when the file is missing; saving creates the file. An omitted
`principals` section uses the built-in principal. Explicit principal tables replace
it, and `[principals]` with no entries disables every caller. Existing explicit
principals retain their default-deny behavior unless `default = "ask"` is set.
Malformed, unreadable, or untrusted files cause errors instead of falling back.
For a richer example, see [config.example.toml](config.example.toml).

The unit runs `%h/.cargo/bin/zondd serve`, installs into `default.target`, and
uses a private runtime directory. To run in the foreground, use `zondd serve`.
Config defaults to `$XDG_CONFIG_HOME/zondd/config.toml` (normally
`~/.config/zondd/config.toml`); sockets default to `$XDG_RUNTIME_DIR/zondd`.
When an SSH session lacks `XDG_RUNTIME_DIR`, the bridge uses `/run/user/<uid>/zondd`
if available, otherwise a private `zondd-<uid>` directory in the temporary
directory. The daemon and CLI use the same resolution. `--config`,
`--runtime-dir`, and the config's optional `runtime_dir` support explicit paths.

Daemon, execution, and approval all use the same Unix account. There are no
`admin_uid`, `bridge_uid`, `run_uid`, or `run_gid` settings; remove these fields
from older configurations. Commands inherit the daemon's UID, GID, and groups.
Config and its ancestors must be owned by that user or root and protected from
other users' writes. The runtime directory belongs to the daemon user (0700),
and sockets are owner-only (0600); trusted paths reject symlinks.

Enroll a caller public key on the receiver, as the daemon's Unix user:

```sh
zondctl authorize-key /path/to/caller.pub
# To select a principal already defined in a custom policy:
zondctl authorize-key /path/to/caller.pub --principal automation
```

The helper validates the key with `ssh-keygen`, prints a unified diff of
`~/.ssh/authorized_keys`, and asks **Apply this authorized_keys change? [y/N]**.
It requires an interactive terminal; through SSH, use a normal login with `ssh -t`.
Declining leaves the target untouched. Acceptance atomically installs a restricted
forced-command entry; sshd needs no restart. Ordinary entries for the same key
are converted, including duplicates. Unrelated keys and comments are preserved.
A key already carrying different SSH options is refused so existing restrictions
are not silently lost. Concurrent changes during review abort the write.

Options include `--authorized-keys PATH`, `--config PATH`, and `--zondd /absolute/path`.
The binary defaults to `zondd` beside the running `zondctl`; the runtime directory
comes from the selected policy/environment. Only authorized_keys is changed;
the selected principal must already exist, or be the built-in `default`.
Enrollment is logged when the daemon is reachable. Keep a separate ordinary SSH
key for management. For manual installation, the equivalent entry is:

```text
restrict,command="/home/alice/.cargo/bin/zondd bridge --principal default" ssh-ed25519 AAAA... caller-key
```

For a custom runtime directory, add `--runtime-dir /absolute/path` to the fixed
command. `restrict` disables forwarding, PTYs, agent/X11 forwarding and user
SSH rc execution for that key. The bridge rejects nonempty
`SSH_ORIGINAL_COMMAND`; the caller opens a session without a shell command and
writes protocol frames. Other keys can retain their normal SSH access.

The forced command binds the key to a principal socket; the daemon also checks
the local peer UID. The remote protocol cannot select another principal or
invoke approval methods. Local code running as the daemon user has that user's
full authority, including approval. This also applies to programs authorized
to run as that user. Use separate Unix accounts and separate user daemons when
OS-level isolation between users is needed.

## Apply policy changes

After editing the config, run `zondctl reload` as the daemon user. It waits for
validation and reports the applied revision or an error. The Android app's
**Save & apply** does the same over ordinary SSH or SSH through Iroh.
`systemctl --user reload zondd` sends SIGHUP; check the journal for its result.

Reload reads the original startup config path, validates it, and prepares any
new principal sockets before atomically replacing the active policy. Invalid
configurations, untrusted files, and socket conflicts leave the active policy
and approval queue intact. Rules, operations, principals, approval settings,
and limits take effect without restarting. Changing `runtime_dir` requires a
restart. `zondctl status` includes the active config's SHA-256 revision.

Commands already admitted keep running with their original policy and limits.
Reload re-evaluates waiting requests without disconnecting their callers:

- Requests that still need approval keep their approval ID and original expiry.
- Newly allowed requests execute using the new policy and limits, waiting for
  capacity if necessary. Their original expiry still applies.
- Newly denied requests, removed principals/operations, and requests needing
  disabled approvals are rejected with the specific reason.
- A changed executable, argv, or working directory requires fresh review, even
  if the new rule allows it. The caller receives another `pending` event with a
  new approval ID and the same request ID/deadline. Old approvals cannot apply.

Reload, review decisions, and execution admission share the same lock. A denial
can supersede an approval that is still waiting for capacity. Lower limits do
not kill admitted commands. Removing a principal closes its listening socket
while existing callers receive their outcomes. Reload requires admin authority.

## Send operations

```sh
zondctl --host alice@server --identity ~/.ssh/caller exec /usr/bin/uptime
# With the built-in policy this waits for approval; review with zondctl review.
zondctl --host alice@server --identity ~/.ssh/monitor operations
zondctl --host alice@server --identity ~/.ssh/monitor invoke service-status slopd.service
```

`--port` and `--ssh-config` select an alternate sshd port or SSH configuration.
Normal host-key verification applies. The client disables PTYs, forwarding,
connection sharing and configured remote commands for its own session.

For an existing Iroh SSH server forwarding to sshd:

```sh
zondctl --iroh --host alice@<64-hex-endpoint-id> \
  --identity ~/.ssh/monitor invoke service-status slopd.service
```

This runs OpenSSH with `ProxyCommand=iroh-ssh proxy %h`. For a custom Iroh proxy
configuration, put it in your SSH config and use `--host` without `--iroh`.

Local callers select the same policy principal without SSH:

```sh
zondctl --principal automation exec /usr/bin/uptime
zondctl --principal monitor invoke service-status slopd.service
# An explicit --socket /path/to/PRINCIPAL.sock also works.
```

## Inspect caller permissions

Use the same caller key or local principal that will submit the operation:

```sh
zondctl --host alice@server --identity ~/.ssh/caller permissions
zondctl --host alice@server --identity ~/.ssh/caller check exec /usr/bin/uptime
zondctl --principal monitor check invoke service-status slopd.service
zondctl --principal default --json check exec /usr/bin/id -u
```

These commands also work with `--iroh`. `permissions` returns only the
authenticated principal's policy: its working directory, `allow_exec`, default
decision, ordered command rules, and assigned named operations with executable,
fixed arguments, argument choices, and decisions. It also includes the active
policy revision, approval settings, and execution limits. Other principals and
unassigned operations are not exposed. Rules are first-match-wins; `args: null`
matches any arguments, while `args: []` matches no arguments. If `allow_exec` is
false, raw commands are denied regardless of rules. Operation decisions are
independent of raw-command rules.

`check exec` and `check invoke` use the execution policy evaluator, without
executing, creating request history, or adding an approval request. The daemon
still audits the query. The response includes `decision` (`allow`, `ask`, or
`deny`), `policy_decision`, a reason, the resolved command when valid, working
directory, and policy revision. With approvals disabled, a configured `ask`
produces effective `deny`; malformed commands and unauthorized operations also
produce `deny`. A successful check returns CLI exit status 0 for all three
decisions; use `--json` and inspect `check.decision` in scripts.

Checks describe the current policy, not a reservation or an execution guarantee.
Submission evaluates the policy again; queue capacity, executable availability,
and runtime failures are not tested. With no policy file, the built-in `default`
principal reports `ask` for valid commands. Local use requires `--principal`
or a principal `--socket`; the admin endpoint has no caller identity.

## Policy and approval

Raw `exec` requires `allow_exec = true`. Rules match the literal absolute
program path and, when `args` is present, the complete argv vector. Rules are
ordered; the first match wins. Omitting `args` permits the rule to match every
argument vector for that program. No shell quoting, glob, regex, path
canonicalization, or command-prefix matching is performed.

`allow` executes immediately; `deny` rejects immediately; `ask` blocks pending
one-time review when approvals are enabled, otherwise it rejects. Set
`default = "ask"` to queue commands that lack an allow/deny rule. A hard denial
cannot be overridden by approval. Approvals are disabled by default.

Operation-only principals have `allow_exec = false` and a list of allowed
operation names. Each operation fixes the executable and leading arguments;
the caller supplies exactly one value for each positional `arguments` entry,
chosen from that entry's explicit `choices`. Operation decisions are separate
from raw-exec rules. There is no template expansion or implicit shell.

On the receiving machine, as the same user who runs the commands (no sudo):

```sh
zondctl pending
zondctl approve <approval-id>
zondctl deny <approval-id>
zondctl review
zondctl status
```

`review` displays the principal, exact argv, expiry and request ID, with terminal
control characters escaped, and asks for approve/deny/skip/quit. Approval is
bound to that one immutable request, consumed once, and never adds a permanent
allowlist rule. A full queue rejects new requests. Expiry, client disconnect,
or daemon restart cancels pending requests. Admin connections
have separate capacity so pending remote requests cannot block review.
Restarting or stopping the daemon also cancels active work.

Commands have null stdin, no PTY, and a configured working directory. Their
environment starts with `PATH=/usr/bin:/bin`, `HOME=<cwd>`, and `LANG=C.UTF-8`,
then inherits the daemon's `HOME`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`,
`XDG_CONFIG_HOME`, `XDG_DATA_HOME`, and `XDG_CACHE_HOME` when set. This lets user
operations reach their own files and session bus; callers cannot supply environment
variables through the protocol.
Stdout/stderr are collected under a combined byte limit and returned when the
command finishes. The CLI reproduces those bytes and the command's exit status;
rejection uses 126 and protocol/infrastructure failures use 125. `--json` prints
all protocol events instead. Request bodies and decisions are logged to stderr;
avoid passing secrets in argv if those logs are retained.

## Request history and action log

The daemon records every execution request, including policy rejections, manual
approvals/denials, expiration, disconnection, execution failures and results.
History retains exact input, resolved executable/argv, working directory, output,
exit status and action timestamps. SQLite storage is private (0600), survives
restarts, and is scoped to the config: `config.toml` uses the adjacent
`config.history.sqlite3` database. Its WAL/SHM files belong with that database;
use SQLite backup tooling for a consistent live backup. History is retained
until explicitly removed by the account owner. Unfinished records on startup
are marked interrupted; they are never automatically replayed.

```sh
zondctl history --limit 30
zondctl request REQUEST_ID
zondctl retry REQUEST_ID
zondctl actions --limit 50
zondctl actions --request-id REQUEST_ID
```

History and activity use descending sequence cursors (`--before`) for paging.
The Android **History** tab includes all outcomes, request details, output,
approval events, daemon activity and **Run again**. Run again submits the original
structured request as a new request under the same principal's current policy;
operation arguments are validated/expanded again and past approvals never carry
over. Its `retry_of` points to the original. The daemon owns this new request,
so closing the controller does not cancel it. Requests that still need permission
appear in Approvals and can also be reviewed from their history details.

The persistent action log covers lifecycle, requests, policy evaluations,
reloads, reviews, execution and protocol errors. The management helper reports
config/service actions when the daemon is reachable; ordinary external file
edits and actions performed while it is stopped are outside daemon logging.
Actions are also emitted through tracing to stderr/the user service journal.
History, retry and activity are available only on the admin endpoint.

## Android management

[The Android app](android-app/README.md) connects through a **normal SSH login**
as the daemon user, directly or through your existing iroh-ssh server. Give its
key ordinary SSH access, without a forced caller command. It can review and
approve/reject requests, read/validate/save/apply policy, and start/stop/restart the
systemd user service. SSH host keys are verified on both transports.

The app invokes `zondctl control` through SSH exec. This helper exposes trusted
management on stdin/stdout and talks to the local admin socket; it does not add
another daemon listener or a separate Iroh identity allowlist. It works locally
as well:

```sh
printf '%s\n' '{"version":1,"method":"pending"}' | zondctl control
printf '%s\n' '{"version":1,"method":"pending"}' | ssh alice@server .cargo/bin/zondctl control
```

One newline-terminated JSON request per process, with `version: 1` and `method`.
Responses are `{ "version": 1, "ok": true, "result": ... }` or
`{ "version": 1, "ok": false, "error": "..." }` (exit 125). The helper exits
without requiring stdin EOF. Methods:

- `pending`, `status`, `resolve` (`approval_id`, `approve`): local admin requests.
- `history` (`before`, `limit`), `request_detail` (`request_id`), `retry`
  (`request_id`), `actions` (`before`, `limit`, optional `request_id`): history,
  results, resubmission and the persistent action log.
- `read_config`: returns `path`, `content`, SHA-256 `revision`.
- `validate_config` (`content`): parse and validate without saving.
- `save_config` (`content`, `revision`): validate, check the current revision,
  atomically replace with mode 0600. Concurrent helper saves are serialized;
  stale edits fail. External editors do not participate in the helper's lock.
- `reload_config` (`revision`): apply that saved revision through the admin
  socket. Returns `revision` and counts for retained, newly allowed, refreshed,
  and cancelled approvals after applying; stale
  revisions fail. A lost connection can leave the result unknown; check `status`
  before retrying. Reloading the same revision is harmless.
- `service` (`action`: `status`, `start`, `stop`, `restart`): `systemctl --user`
  for `zondd.service`. Restarting applies saved policy and cancels active work.

Control requests are limited to 1 MiB; configuration content to 512 KiB.
`zondctl --runtime-dir PATH control --config FILE` supports custom installations.
Service actions always operate on the installed `zondd.service`; a custom config
path does not change that unit's ExecStart. Reload always reads the daemon's
startup config path and checks the supplied revision. Saving alone leaves the
active policy unchanged until reload or startup. The policy editor works even
when the daemon is stopped.

The management login intentionally retains general-purpose SSH privileges.
Restricted caller keys cannot invoke this helper. Local processes running as
the daemon user already have equivalent authority.

## Security scope

This is authorization for the requested top-level executable and argv. It is
not a shell/interpreter sandbox or a recursive Bash/JavaScript policy engine.
Allowing an interpreter, a writable executable, a script that changes after
review, or an executable with arbitrary command/file-loading options grants
whatever that program can do as the daemon user. A deny rule for `/bin/sh`
does not match another shell path. Prefer named operations with trusted
executables/scripts and explicit argument choices for narrow capabilities.

Commands have `no_new_privs`, a 077 umask and disabled core dumps.
There are limits on frame size, connections, queue size, running
commands, wall time and collected output. Disconnect and timeout kill the
command process group. A deliberately hostile descendant can escape its
process group; there is no per-request cgroup, filesystem or network sandbox.
The supplied systemd user service cleans its entire cgroup on shutdown.
Treat these distinctions as part of configuring
what an approved command is allowed to do.

## Protocol version 1

One UTF-8 JSON object followed by LF per frame. Requests use an envelope:

```json
{"version":1,"id":1,"body":{"method":"run","command":{"program":"/usr/bin/uptime","args":[]}}}
```

Or a named operation:

```json
{"version":1,"id":1,"body":{"method":"invoke","operation":"service-status","args":["slopd.service"]}}
```

Each connection carries **one request**. Keep its writing side open until the
terminal response; EOF or additional request bytes cancel it. Responses echo
the version and ID. An optional `pending` event precedes one terminal event:
`completed`, `rejected`, `error`, `operations`, `permissions`, `checked`,
`queue`, `resolved`, or `status`.
`completed.stdout` and `.stderr` are base64 strings so arbitrary output bytes
survive JSON transport; `code` or `signal` describes termination.

Principal methods: `run`, `invoke`, `list_operations`, `permissions`, `check`.
The `check` body wraps a `run` or `invoke` as `input`, for example:

```json
{"version":1,"id":1,"body":{"method":"check","input":{"method":"run","command":{"program":"/usr/bin/uptime","args":[]}}}}
```

Neither introspection method accepts a principal selector. Local admin methods:
`pending`, `resolve` (`approval_id`, boolean `approve`), `status`. Neither
endpoint accepts the other endpoint's methods. Request types reject unknown
fields. Requests are limited to 64 KiB including LF; responses to 4 MiB. The
first request must arrive within ten seconds. Oversized/malformed requests or
unsupported protocol versions close the connection without execution. A queue
or operation listing exceeding the response limit returns an error.

## License

Copyright (C) 2026 zondd contributors.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. Distributed without any warranty. See [LICENSE](LICENSE).
