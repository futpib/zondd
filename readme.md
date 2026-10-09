# zondd

SSH-authenticated operations with exact command allowlists, named operations,
and an optional local approval queue. Linux, Rust, GPL-3.0-or-later.

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
cargo test -p zondctl --test integration -- --ignored --skip iroh_ssh
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

## Configure the receiver

Install the binaries and [zondd.service](zondd.service) as a **user service**:

```sh
cargo install --locked --path zondd
cargo install --locked --path zondctl
mkdir -p ~/.config/zondd ~/.config/systemd/user
cp config.example.toml ~/.config/zondd/config.toml
cp zondd.service ~/.config/systemd/user/zondd.service
# Edit ~/.config/zondd/config.toml for your operations and working directories.
zondd check
systemctl --user daemon-reload
systemctl --user enable --now zondd.service
```

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

Bind selected keys in that account's `authorized_keys` to fixed principals.
Use the actual absolute path to your installed binary:

```text
restrict,command="/home/alice/.cargo/bin/zondd bridge --principal automation" ssh-ed25519 AAAA... automation-key
restrict,command="/home/alice/.cargo/bin/zondd bridge --principal monitor" ssh-ed25519 AAAA... monitor-key
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

## Send operations

```sh
zondctl --host alice@server --identity ~/.ssh/automation exec /usr/bin/uptime
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

Local execution is also possible via an explicitly selected principal socket:

```sh
zondctl --socket "$XDG_RUNTIME_DIR/zondd/automation.sock" exec /usr/bin/uptime
```

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
or daemon restart cancels pending requests. Admin connections have separate
capacity so pending remote requests cannot block review. Policy is loaded at
startup; restart to apply changes, which also cancels active work.

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
`completed`, `rejected`, `error`, `operations`, `queue`, `resolved`, or `status`.
`completed.stdout` and `.stderr` are base64 strings so arbitrary output bytes
survive JSON transport; `code` or `signal` describes termination.

Principal methods: `run`, `invoke`, `list_operations`. Local admin methods:
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
