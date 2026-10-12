# Credentials for independent applications

Applications own their processes, jobs, logs, sessions and credential storage.
Run them under systemd or another supervisor. Zondd brokers transient human input:
it authenticates a registered recipient, queues a form for Android/CLI review,
delivers the answer to that connection, and records metadata and outcomes.
Starting, stopping, reloading or upgrading zondd does not start, stop or retry an
application. No application unit should require or bind its lifecycle to zondd.

Applications should load their own local credentials first and connect only when
values are missing. Request only missing fields, retain existing local values,
and treat invalid credentials as an authentication failure. Prompting, retrying
provider jobs, rate-limit cooldowns and persisting answers are application decisions.

## Recipient registration

```toml
[credential_recipients.example]
label = "My application"
key_sha256 = "REPLACE_WITH_SHA256_OF_CONNECTION_KEY"
field_ids = ["username", "password", "otp"]
origins = ["https://example.test"]
```

Provision a distinct, random connection identity for each recipient, separately
from provider credentials. For example, in a private directory:

```sh
umask 077
openssl rand -hex 32 > example.key
# Hash the 64 ASCII hex characters, excluding the file's final newline.
python3 -c 'import hashlib,pathlib; print(hashlib.sha256(pathlib.Path("example.key").read_text().strip().encode()).hexdigest())'
```

Put the digest in trusted zondd configuration. Keep the key private and load it
from a file, optionally provisioned using systemd
[LoadCredential](https://github.com/systemd/systemd/blob/main/docs/CREDENTIALS.md).
Never put the key or provider answers in process arguments or environment values.
The Rust client's `read_key` checks trusted paths, ownership, file permissions,
size and syntax. The wire key is exactly 64 lowercase hexadecimal characters.

The endpoint is `credential.sock` in zondd's private runtime directory (directory
0700, socket 0600). Linux
[SO_PEERCRED](https://man7.org/linux/man-pages/man7/unix.7.html) supplies the
connecting UID/PID. V1 requires the daemon UID **and** possession of the selected
recipient's private connection key. A name, UID or executable/interpreter path
alone does not authenticate a recipient. A connection selects its recipient once;
subsequent frames cannot override it. Keys cannot be shared between registrations.

This identifies a provisioned connection key, not verified systemd-unit membership,
a measured executable, a browser tab, or the process that ultimately consumes the
values. A process able to read another application's key can impersonate it.
Processes with the daemon user's unrestricted access already have admin authority;
this API does not isolate hostile programs sharing that account. Root, socket
passing and compromised authorized clients are also outside that boundary.
Use OS isolation when the deployment requires stronger separation.

Trusted review shows the configured name/label, authenticated UID/PID, session ID,
configuration revision and permitted provider origin. Application prompt, fields
and context remain explicitly application-supplied. Origins are exact canonical
HTTP(S) origins: no path, user info, query, fragment or redundant default port.
Each request must select a registered origin and only registered field IDs. This
validates declared scope; browser clients must verify the actual origin/frame
again before filling any values.

## Public protocol v1

The [published JSON schema](credential-api-v1.schema.json) and
[public Rust types](../libzond/src/credential.rs) describe the wire format.
Every frame is one UTF-8 JSON object followed by LF. Requests and responses use
`version`, `id`, and `body`; IDs are positive u64 integers, strictly increasing
within a connection. There is one active connection and one outstanding form per
recipient. Different recipients, including those in one process, use separate
connections. A session is never resumed or transferred.

Authenticate within ten seconds:

```json
{"version":1,"id":1,"body":{"method":"authenticate","recipient":"example","key":"<64 lowercase hex characters>"}}
{"version":1,"id":1,"body":{"type":"ready","session_id":"generated-by-zondd"}}
```

Open a form:

```json
{"version":1,"id":2,"body":{"method":"challenge","origin":"https://example.test","prompt":"Sign in","fields":[{"id":"password","label":"Password","kind":"secret"}],"context":{"step":"login"},"timeout_secs":300}}
{"version":1,"id":2,"body":{"type":"opened","challenge_id":"generated-by-zondd"}}
{"version":1,"id":2,"body":{"type":"answered","challenge_id":"generated-by-zondd","status":"answered","values":{"password":"..."}}}
{"version":1,"id":3,"body":{"method":"result","challenge_id":"generated-by-zondd","outcome":"succeeded"}}
{"version":1,"id":3,"body":{"type":"recorded","challenge_id":"generated-by-zondd"}}
```

The asynchronous answer echoes the opening frame's ID and challenge ID. All other
responses echo their initiating frame's ID. After an answer with values, report
`succeeded`, `failed` or `cancelled` before opening another form. Password/OTP and
encrypted-key/passphrase steps use fresh challenges on the same connection.

A rejection, expiry or withdrawal sends `answered` with `values: null` and
`status: rejected`, `expired` or `withdrawn`. No result is required for a null
answer. A withdrawal uses `method: withdraw` and `challenge_id`, receives
`recorded`, then the null answer using the original challenge request ID. Clients
must handle asynchronous frames while waiting for command acknowledgments.

If an answer wins the withdrawal race, withdraw returns `error` with code
`answer_delivered`. Discard those values and report `cancelled`. Withdrawal cannot
recall bytes already sent. The reference client's `withdraw_and_discard` drains
both frames in either order, drops values and records cancellation when required.
It is for opened challenges whose terminal answer has not yet been consumed.

Disconnect, daemon restart and changed/removed registrations invalidate pending
forms and unreported outcomes. The audit records `disconnected`, `interrupted`, or
`recipient_changed`; a closed channel cannot deliver a terminal frame. Clients
must treat EOF as failure of the outstanding credential step. Reconnect creates
a fresh session, has no pending form and never replays answers. Changes affecting
a recipient close its connection synchronously during reload; unrelated policy
changes preserve it. A connected session retains its opening configuration
revision for review. Values already received remain the application's responsibility.

Limits: 16 recipients, 16 pending forms globally, 32 accepted API connections,
1–16 fields, 1–86400 seconds per form (default 300), 64 KiB per request and 128 KiB per response including LF,
4096-byte prompts and answer values, 8192-byte serialized context, 32 choices per
field. Writes time out after five seconds; slow clients must reconnect. Idle
sessions remain open. Parse/size errors close the connection without logging the
frame. Unknown top-level/envelope attributes are rejected. Repeated/decreasing
IDs or unsupported versions after authentication return `invalid_frame` and close.
The JSON schema describes structure; byte lengths, ordering and authorization
also require these runtime checks.

Fields use `id`, `label`, `kind`, optional `required` (default true), optional
`choices`, and arbitrary extra metadata retained for review. Native review
controls support `text`, `secret`, `password`, `otp`, `choice`, and `confirmation`;
unfamiliar kinds use masked text with YAML review. Values are strings; required
fields cannot be empty, choices constrain nonempty values, confirmation accepts
`yes` or `no`, and answers cannot contain NUL, CR or LF.

Error frames contain only a stable `code`, never input or secret values:

- `authentication_failed`: unknown identity, wrong key or invalid authentication;
  closes the connection without identifying which check failed.
- `unsupported_version`: unsupported handshake version; closes the connection.
- `busy`: recipient already connected, or a form already pending.
- `origin_not_allowed`, `field_not_allowed`, `invalid_challenge`: denied scope or
  invalid form/timeout; no form opens.
- `result_required`: report the delivered answer's outcome first.
- `unknown_challenge`: absent, consumed or another session's challenge.
- `answer_delivered`: withdrawal lost the race; discard and report cancellation.
- `invalid_outcome`, `already_authenticated`, `invalid_frame`, `session_closed`:
  invalid outcome, attempt to change identity, invalid envelope or stale session.
- `queue_full`, `unavailable`: capacity or storage failure; the application decides
  whether and when to open a new request.

## Reference client and review

[libzondctl::credential](../libzondctl/src/credential.rs) provides `Client::connect`,
`send`, cancellation-safe `receive`, `withdraw_and_discard`, and `read_key`.
Keep the returned frame ID and `opened.challenge_id` with the application job.
Dropping the client closes both socket halves and withdraws pending input. A
cancelled/failed send requires dropping the connection; do not replay it.
`SecretString` masks Debug output and zeroes values when dropped. Drop answers
promptly after use; avoid copying them into ordinary strings or error messages.
The broker is transient input transport, not a credential vault.

```sh
zondctl pending
zondctl interaction CHALLENGE_ID          # all terminal input is hidden
zondctl interaction CHALLENGE_ID --reject
zondctl review
```

Android and the existing administrative SSH/Iroh controls review and answer the
same forms. `pending.recipients` reports only `idle`, `waiting`, or
`answer_delivered`. There is no application availability/status or retry command.
Restricted command callers cannot request or answer credentials through their
command endpoint and do not implicitly receive connection keys.

Answers, including usernames, are excluded from status, audit history, argv,
environment and daemon logs. Audit retains registered context, field IDs, expiry,
challenge/session IDs, terminal events and outcomes. It excludes application
prompts, context and answer values. Application logs and secret disposal remain
with the application.

## Migrating existing pipe adapters

The old `[credential_adapters]` configuration is removed and fails validation;
move supervision into an independent service and register a recipient above.
The v1 pipe request/form/outcome protocol remains supported by the service-side
`zondctl credential-adapter` bridge and the existing
[Python pipe client](python/zond_interaction.py). The
[IB Gateway adapter](https://github.com/futpib/ibkr-tws-http/tree/master/adapters/ibgateway)
can use this bridge without zondd owning Gateway's process.

For example, a systemd **user** service can wrap an existing adapter:

```ini
[Service]
LoadCredential=identity:/home/me/.config/my-application/example.key
ExecStart=/home/me/.cargo/bin/zondctl credential-adapter --recipient example --key-file %d/identity --origin https://example.test -- /absolute/path/to/adapter
Restart=on-failure
```

The wrapper starts its child independently and connects lazily when a form is
needed. Broker downtime sends an error for a new form or a null `interrupted`
answer for an outstanding form; it does not restart or kill the child. A later
new challenge opens a fresh connection. Legacy `status` requests receive a local
acknowledgment and are not published in zondd. Retry notifications are removed.
Adapter stderr stays private/discarded; application logs belong to its service.
The wrapper cleans up its child process group on its own exit. An old adapter
that exits on broker errors should be updated to fail the affected login/job and
continue supervising its application. Native API clients need no wrapper.
