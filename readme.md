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
                                         zondd serve → unprivileged command
                                              ↑ separate admin Unix socket
                                         zondctl review
```

The workspace follows slopd's shared-library/daemon/client split:

- `libzond`: wire types, bounded framing, policy and operation schemas.
- `libzondctl`: asynchronous Unix-socket and OpenSSH client.
- `zondd`: root daemon and forced-command bridge.
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

Named integration tests live in `zondd/tests/integration.rs` and
`zondctl/tests/integration.rs`. Tests that need root have explicit `#[ignore]`
reasons and are reported as ignored by ordinary `cargo test`; missing
prerequisites fail when those tests are selected. The unprivileged protocol,
policy, CLI argument, and harness cleanup tests run normally.

Build the binaries first as your normal user, as above. On x86_64 Linux, use
Cargo's runner to elevate only the test executables, keeping Cargo and build
artifacts under your normal account:

```sh
# Daemon, real sshd, CLI, and PTY tests; no Iroh connectivity required.
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -n' \
  cargo test --workspace -- --ignored --skip iroh_ssh

# All privileged tests, including the installed Iroh transport and discovery.
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -n' \
  cargo test --workspace -- --ignored
```

For another target, replace the runner variable's target triple with your
`rustc -vV` host triple, uppercased with underscores. The tests require Linux,
OpenSSH client/server, an existing non-root login account (taken from
`SUDO_UID`), and the `nobody` account. When executing tests directly as root,
set `ZONDD_TEST_BRIDGE_USER` to the intended non-root login account.

Each fixture creates temporary keys, configuration, binaries and sockets
beneath `/run`, starts its own daemon and, where needed, an isolated sshd on a
loopback port. Rust drop guards clean up processes and files on success and
assertion failures, and print daemon logs on failure. Tests do not edit
accounts, installed services, SSH configuration, or authorized keys. Iroh
tests additionally require `iroh-ssh` and working discovery/relay connectivity.
They check pipe EOF after completion to catch orphaned proxy processes.

## Configure the receiver

Build release binaries and install `zondd` and `zondctl` into `/usr/local/bin`
as root-owned executables. Adapt [config.example.toml](config.example.toml),
install it as `/etc/zondd/config.toml`, then validate it:

```sh
zondd check --config /etc/zondd/config.toml
sudo zondd serve --config /etc/zondd/config.toml
```

For service management, install [zondd.service](zondd.service) as a system
service. The daemon starts as root and drops supplementary groups, GID, and UID
for each execution; commands cannot run as root. Configuration, its ancestors,
and the runtime directory must be root-owned and protected from other users'
writes. Symlinks in these paths are rejected.

Use dedicated bridge accounts with a real shell so sshd can launch the forced
command. Their `bridge_uid` values must match the SSH login accounts. Execution
accounts (`run_uid`/`run_gid`) must be separate from every bridge UID and from
the approval UID. Give execution accounts only the filesystem/service access
their operations require. Set up each configured `cwd` yourself; zondd does not
create accounts or work directories.

In the appropriate bridge account's `authorized_keys`, bind each selected key
to a fixed principal:

```text
restrict,command="/usr/local/bin/zondd bridge --principal automation" ssh-ed25519 AAAA... automation-key
restrict,command="/usr/local/bin/zondd bridge --principal monitor" ssh-ed25519 AAAA... monitor-key
```

These example principals use different SSH accounts in the example config.
For a non-default runtime directory, add `--runtime-dir /absolute/path` to the
fixed command. `restrict` disables forwarding, PTY allocation, agent/X11
forwarding, and user SSH rc execution for that key. Protect the accounts' shell
startup files and authorized keys, disable password login for these accounts,
and do not grant them an unrestricted login through another key. The bridge
rejects nonempty `SSH_ORIGINAL_COMMAND`; clients start a session without a shell
command and write only protocol frames.

The daemon trusts the principal socket and kernel peer UID, never a principal
name submitted in the protocol. Multiple keys can map to one principal. If
several principals share a bridge UID, local code running as that UID can access
all of those principals' sockets. Use separate bridge UIDs where local isolation
between principals matters. Root and the configured admin UID are trusted to
approve commands; approved commands run as their configured execution UID.

## Send operations

```sh
zondctl --host zond-automation@server --identity ~/.ssh/automation exec /usr/bin/uptime
zondctl --host zond-monitor@server --identity ~/.ssh/monitor operations
zondctl --host zond-monitor@server --identity ~/.ssh/monitor invoke service-status sshd.service
```

`--port` and `--ssh-config` select an alternate sshd port or SSH configuration.
Normal host-key verification applies. The client disables PTYs, forwarding,
connection sharing and configured remote commands for its own session.

For an existing Iroh SSH server forwarding to sshd:

```sh
zondctl --iroh --host zond-monitor@<64-hex-endpoint-id> \
  --identity ~/.ssh/monitor invoke service-status sshd.service
```

This runs OpenSSH with `ProxyCommand=iroh-ssh proxy %h`. For a custom Iroh proxy
configuration, put it in your SSH config and use `--host` without `--iroh`.

Local execution is also possible via an explicitly selected principal socket:

```sh
zondctl --socket /run/zondd/automation.sock exec /usr/bin/uptime
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

On the receiving machine:

```sh
sudo zondctl pending
sudo zondctl approve <approval-id>
sudo zondctl deny <approval-id>
sudo zondctl review
sudo zondctl status
```

`review` displays the principal, exact argv, expiry and request ID, with terminal
control characters escaped, and asks for approve/deny/skip/quit. Approval is
bound to that one immutable request, consumed once, and never adds a permanent
allowlist rule. A full queue rejects new requests. Expiry, client disconnect,
or daemon restart cancels pending requests. Admin connections have separate
capacity so pending remote requests cannot block review. Policy is loaded at
startup; restart to apply changes, which also cancels active work.

Commands have null stdin, no PTY, a configured working directory, and a cleared
environment containing only `PATH=/usr/bin:/bin`, `HOME=<cwd>`, and `LANG=C.UTF-8`.
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
whatever that program can do as the execution UID. A deny rule for `/bin/sh`
does not match another shell path. Prefer named operations with root-owned
executables/scripts and explicit argument choices for narrow capabilities.

Commands have `no_new_privs`, no supplementary groups, a 077 umask and disabled
core dumps. There are limits on frame size, connections, queue size, running
commands, wall time and collected output. Disconnect and timeout kill the
command process group. A deliberately hostile descendant can escape its
process group; there is no per-request cgroup, filesystem or network sandbox.
Execution accounts also share whatever resources their OS permissions allow;
use separate execution UIDs where needed. The supplied systemd service cleans
its entire cgroup on shutdown. Treat these distinctions as part of configuring
what an approved command is allowed to do.

## Protocol version 1

One UTF-8 JSON object followed by LF per frame. Requests use an envelope:

```json
{"version":1,"id":1,"body":{"method":"run","command":{"program":"/usr/bin/uptime","args":[]}}}
```

Or a named operation:

```json
{"version":1,"id":1,"body":{"method":"invoke","operation":"service-status","args":["sshd.service"]}}
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
