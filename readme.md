# zond

Typed permissions for AI agents on Linux.

Give agents scoped access to your machines, with human approval when they need
more authority. Review requests from Android or the CLI: approve one command,
grant a reusable rule for a limited time, or allow it until revoked.
The receiving machine enforces the permissions—a small human-in-the-loop layer
for agent tools.

<p>
<img src="fastlane/metadata/android/en-US/images/phoneScreenshots/1.png" width="200" alt="Review a system upgrade request">
<img src="fastlane/metadata/android/en-US/images/phoneScreenshots/2.png" width="200" alt="Review a typed rule for cloning repositories">
<img src="fastlane/metadata/android/en-US/images/phoneScreenshots/3.png" width="200" alt="Answer a sudo password challenge">
</p>

## How it works

1. An agent connects with an SSH key restricted to the zond bridge.
2. It requests a command or proposes a rule describing the access it needs.
3. You review the resolved command, constraints, working directory, and privileges.
   The receiver checks each invocation against the approved permissions.

`zondd` runs on the receiving machine, `zondctl` is the caller and administration
CLI, and the Android app handles review and credentials. Transport uses your
existing OpenSSH server, optionally reached through [iroh-ssh](https://github.com/futpib/iroh-ssh).
The default policy asks for approval on every valid command request.

## Rule language

Rules describe one command, typed parameters, and optional preconditions. For
example, an agent can propose permission to clone repositories:

```text
rule clone-futpib(repo: repository-name) {
  require is-directory "~/code"
  create-new-directory "~/code/$repo" as dest {
    run git clone -- "https://github.com/futpib/$repo.git" "$dest"
  }
}
```

`repository-name` excludes path separators and leading hyphens. The clone is
staged privately and published only on success, without replacing an existing
destination. After approval, the agent can invoke `clone-futpib zondd`.

Local types narrow the permitted inputs:

```text
type service = enumeration(values=(api, worker))
type lines = integer(minimum_inclusive=1, maximum_exclusive=501)

rule logs(service: service, lines: lines) {
  run journalctl --user "--unit=${service}.service" "--lines=$lines" --no-pager
}
```

This accepts `logs api 100`, but rejects unknown services and counts outside
1–500. Types also support regex-constrained text and `choice` definitions that
bind several arguments to one approved combination.

Variables expand into argument values once; there is no implicit shell, globbing,
or command substitution. A rule's executable is fixed when proposed. Privilege
escalation must be requested explicitly with `run --sudo` and remains subject
to sudoers.

An approval binds the exact definition to its proposing principal. Grants can
expire or be revoked; running jobs can be followed or cancelled separately.
Requests, decisions, and outcomes are recorded in the audit history.

See the [rule reference](docs/reference.md#propose-reusable-typed-rules) and
[example rules](examples/rules) for the full syntax and semantics.

## Scope

Zond authorizes the top-level executable and its arguments. An approved program
still has the receiving Unix account's file and network access, and can run child
processes. Its configuration and scripts matter too. Use a separate account or
an OS sandbox when you need isolation.

## Get zond

- **Linux:** [`zondd-git` on AUR](https://aur.archlinux.org/packages/zondd-git) or
  [release archives](https://github.com/futpib/zondd/releases).
- **Android:** [APK downloads and Obtainium](android-app/README.md#obtainium-and-apk-downloads).
- **Documentation:** [receiver setup](docs/reference.md#configure-the-receiver),
  [CLI and policy reference](docs/reference.md), and
  [application credentials](adapters/readme.md).
- **Development:** [build and tests](docs/reference.md#build-and-test).

GPL-3.0-or-later. See [LICENSE](LICENSE).
