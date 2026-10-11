# Application credentials and human input

A **credential adapter** is a configured program launched by zondd. It translates
an application's login or other human-input flow into forms reviewed in Android
or `zondctl review`. The broker and Android renderer are application-neutral.
The [IB Gateway adapter](ibgateway/readme.md) is the first integration; other
programs and browser automation can implement the same protocol.

```toml
[credential_adapters.example]
label = "My application"
program = "/absolute/path/to/adapter"
args = ["--some-fixed-option"]
cwd = "/home/me"
# Optional, trusted configuration; do not put credentials here.
# env = { APPLICATION_SETTING = "value" }
```

Validate with `zondd check`, then `zondctl reload`. Zondd starts added adapters
and stops removed or changed adapters and their process groups. Unrelated
policy edits preserve pending forms. An adapter that exits is retried after five
seconds. Adapters run with the daemon user's environment and access; these are
trusted programs. They are not caller-supplied commands or sandboxed plugins.
The bundled systemd unit also cleans up the service control group after a crash.

The daemon owns the adapter's private stdin/stdout pipes. There is no credential
request endpoint available to restricted callers and no shared bearer token.
Identity comes from the configured executable and the process session launched
by zondd. The adapter cannot supply the recipient label, origin, executable,
working directory, session ID, or challenge ID shown in the trusted review area.
The server name is the Android connection profile. Service-initiated requests
are labelled `configured service`, never attributed to a recent HTTP caller.

The application prompt, fields, and context are a separate, explicitly labelled
review area. Android shows the complete form description as YAML. Its native
controls support `text`, `secret`, `password`, `otp`, `choice`, and `confirmation`.
An unfamiliar kind uses masked text input and retains all additional field
metadata in YAML. An application-specific field kind does not require an Android
release. Changing the protocol's fundamental value types would require protocol
negotiation; v1 answers are strings.

```sh
zondctl pending
zondctl interaction CHALLENGE_ID          # terminal input is hidden
zondctl interaction CHALLENGE_ID --reject
zondctl retry-adapter ADAPTER_NAME
```

Android's Approvals screen displays forms and application status. Reject ends
the form. Retry asks an unavailable application to try again without restarting
its process. Closing a response dialog leaves the form pending. Expired,
withdrawn, changed-recipient, and disconnected requests cannot receive answers.
A lost Android connection does not cancel a service request; reconnecting reloads
the queue. No response is automatically replayed after a connection error.

## Protocol v1

Use newline-delimited JSON on the private pipes. The first broker message is:

```json
{"type":"ready","version":1,"session_id":"generated-by-zondd"}
```

The adapter submits a form without choosing its trusted identity:

```json
{"method":"challenge","prompt":"Sign in","fields":[{"id":"username","label":"Username","kind":"text"},{"id":"password","label":"Password","kind":"secret"}],"context":{"step":"login"},"timeout_secs":86400}
```

The broker responds with `{"type":"opened","challenge_id":"..."}`. Later:

```json
{"type":"answered","challenge_id":"...","status":"answered","values":{"username":"...","password":"..."}}
```

`values` is null for `rejected`, `expired`, `withdrawn`, `disconnected`, or
`interrupted`. A challenge is consumed once, and its response is delivered only
to the process session that created it. The local admin/control method is
`answer_interaction` with `challenge_id` and `values`; restricted principals
cannot answer forms.

There is at most one pending form per adapter. After receiving values, report
the application's outcome for that step before submitting another form:

```json
{"method":"result","challenge_id":"...","outcome":"succeeded"}
{"method":"status","state":"ready"}
```

Both receive `{"type":"recorded"}`. Outcomes are `succeeded`, `failed`, or
`cancelled`. Statuses are `starting`, `waiting`, `working`, `ready`, `unavailable`,
and `failed`; they describe the adapter's reported application state. Multi-step
logins can report a step's result and then request another form. Only report
`ready` when the whole application is ready.

Withdraw a still-pending form with
`{"method":"withdraw","challenge_id":"..."}`. The broker acknowledges it
with `recorded`, then sends `answered` with null values and status `withdrawn`.
Withdrawal racing a human response cannot recall values already delivered;
recheck that the original application session is still valid before using them,
and report `cancelled` if it is not. Operator Retry delivers `{"type":"retry"}`.
Adapters must handle unsolicited answers (including expiry) and retries while
monitoring their application's state. Closing the channel withdraws pending
forms; exit when the broker closes the channel and clean up owned subprocesses.

Limits: 16 configured adapters, 1 pending form each, 1–16 fields per form,
1–86400 seconds per challenge, 64 KiB request frames, 4096-byte prompts and
answer fields, and 8192-byte context. Field IDs are unique ASCII names;
`required` defaults to true. `choices` restricts accepted string values and
`confirmation` accepts `yes` or `no`. Answers cannot contain NUL, CR, or LF.
Extra field attributes are retained for review; unknown top-level request
attributes are rejected. Malformed frames terminate the adapter session without
logging their contents. Other invalid requests receive a generic error.

## Secret handling and audit

All answers, including ordinary text fields, are treated as secrets in daemon
storage and debugging. Values stay in memory and go directly to the adapter.
They are not placed in argv, environment variables, files, daemon history,
application status, or caller output. The broker does not retain a password
vault. An adapter necessarily sees the supplied values and must not log or echo
them. Its stdout is exclusively protocol; stderr is discarded.

Audit records retain configured recipient context, challenge and session IDs,
field IDs, expiry, answer/reject/withdraw/interrupt events, and reported outcomes.
They omit answers and application-supplied prompts/context. A restart records
unfinished challenges and outcomes as interrupted; it does not restore secrets
or replay an answer. Credential files and application settings written by the
application itself remain under that application's control.

## Writing another adapter

Any language that can read/write JSON lines works. A small blocking Python
client is provided in [python/zond_interaction.py](python/zond_interaction.py).
For a straightforward sequential login:

```python
from zond_interaction import Broker

broker = Broker()
challenge = broker.challenge(
    "Sign in to the configured application",
    [{"id": "password", "label": "Password", "kind": "secret"}],
    context={"step": "login"},
)
values = broker.answer(challenge)
if values is not None:
    try:
        application.submit_password(values["password"])
        broker.result(challenge, "succeeded")
    finally:
        values.clear()
```

Long-running integrations should use `send`/`receive` with their own event loop
to watch the application and withdraw stale forms. `receive` exposes retry
notifications. Application-specific success detection and multi-factor handling
belong in the adapter.

For a future browser adapter, register a fixed automation program with configured
sites, connect it to a specific browser context/tab, and verify the page origin
and frame again immediately before filling a field. A page-supplied URL belongs
in application context; it is not a trusted recipient label or authorization to
send a password anywhere. The same forms can collect usernames, passwords,
verification codes, choices, or confirmation. This implementation supplies the
broker and protocol, not a browser extension or arbitrary-site login automation.
