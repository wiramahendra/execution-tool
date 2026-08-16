# execution-tool

Sandboxed tool execution for agents — filesystem, shell, and HTTP, each behind
a policy that denies by default.

```rust
use std::sync::Arc;
use execution_tool::{FileSystemTool, HttpTool, Sandbox, ToolRegistry};

let sandbox = Sandbox::new(["/srv/agent/workspace"])?;

let mut tools = ToolRegistry::new();
tools.register(Arc::new(FileSystemTool::new(sandbox)));   // read-only
tools.register(Arc::new(HttpTool::new(["api.github.com"])));
```

Every allowlist starts empty, so an unconfigured tool does nothing at all.

## What "sandboxed" means here

Each tool checks its target against an allowlist before acting: paths must
resolve inside a configured root, hosts must resolve to public addresses,
commands must be on a list.

It does **not** mean OS-level isolation. There is no seccomp filter, no
namespace, no chroot, no separate process. A tool that gets past its policy has
the parent's full privileges. If you need real isolation, run this inside
something that provides it — the sibling [`watchdog`] crate does resource
bounds and process containment, and composes with this.

[`watchdog`]: https://github.com/wiramahendra/watchdog

## SSRF protection

This is the part that took the most care. When an agent chooses its own URLs,
the target that matters is the cloud metadata endpoint at `169.254.169.254`,
which hands out instance credentials to anything inside the instance that asks.

Naive URL validation does not stop it. Each of these defeats a check that looks
reasonable, and `tests/escapes.rs` asserts each one is refused:

| attempt | why a simple check misses it |
|---|---|
| `https://169.254.169.254/` | a literal blocklist catches this one address and nothing else |
| `https://[::ffff:169.254.169.254]/` | IPv4-mapped IPv6 is the same address, spelled differently |
| `https://[2002:a9fe:a9fe::1]/` | 6to4 embeds an arbitrary IPv4 address in an IPv6 one |
| `https://example.com@169.254.169.254/` | the host is the metadata endpoint; parsers that split on `@` read `example.com` |
| `https://metadata.evil.com/` | a public-looking name with a private A record |
| `https://ok.com/` → 302 → metadata | the redirect is a request nobody validated |
| DNS answers public to the checker, private to the client | validation and connection resolve separately |

The last two cannot be handled by URL inspection at all, so `HttpTool` refuses
redirects outright and pins the connection to the addresses that were actually
validated (`resolve_to_addrs`) rather than re-resolving the name.

Ports are an allowlist (`443`, `8443`), not a blocklist, because an agent that
can pick arbitrary ports can map its own network through timing differences
even when every address check holds.

The host allowlist is also checked **before** any DNS lookup. Resolving first
turns every rejected request into a lookup for whatever hostname the agent
supplied, and a hostname is an excellent channel for getting data out of a
network that blocks everything else.

## The shell tool is not a sandbox

Read this before enabling it.

An allowlist decides *which binary* runs. It does not decide what that binary
does, and for most real binaries the arguments decide that entirely:

```text
allow /usr/bin/find  →  find / -exec sh -c '…' \;
allow /usr/bin/git   →  git --exec-path=/tmp/evil status
allow /usr/bin/tar   →  tar --to-command=/tmp/evil -xf …
```

Each is an allowlisted binary reaching arbitrary execution through its own
documented options. `ArgumentPolicy` is the control that matters:

```rust
use execution_tool::{ArgumentPolicy, ShellTool, shell::AllowedCommand};

ShellTool::new(vec![
    // Safe by construction.
    AllowedCommand::new("/usr/bin/uptime"),

    // Only these exact invocations.
    AllowedCommand::new("/usr/bin/git")
        .with_arguments(ArgumentPolicy::Exact(vec![vec!["status".into()]])),

    // Positionals but no options — blocks the shapes above.
    AllowedCommand::new("/usr/bin/wc")
        .with_arguments(ArgumentPolicy::NoFlags),
]);
```

It defaults to `ArgumentPolicy::None`. Programs must be absolute paths, so
whoever controls `PATH` does not get to choose the binary. No shell is invoked,
so `;`, `|`, and `$(…)` in arguments are inert.

## Output is redacted by default

A tool result travels further than the call that produced it — into a
transcript, a log line, a trace span, sometimes an evidence record. If the
result carries file contents, every one of those becomes a copy.

So `ToolOutcome` splits them. `summary` is structured, bounded, and safe to log:

```json
{"operation":"read","bytes":20,"sha256":"6e459f…","truncated":false,
 "content_redacted":true,"redaction_policy_version":"execution-tool-redaction-v1"}
```

The bytes live in `content`, which is `None` unless the tool produced a payload
and is omitted entirely from the serialized form. Logging an outcome is
therefore the safe thing as well as the easy thing. HTTP response headers pass
through an allowlist, so `set-cookie` and `authorization` never reach a log.

## What this fixes

The code this was extracted from had a well-built destination policy and a
badly-built sandbox. Both filesystem escapes below were confirmed by running
them before the rewrite:

- **String prefixes were treated as path prefixes.** A root of `/tmp/safe`
  admitted `/tmp/safe_evil/…` — a sibling directory sharing a textual prefix.
  `Path::starts_with` compares whole components; `str::starts_with` does not.
- **`..` was rejected textually and paths were otherwise trusted.** A symlink at
  `/tmp/safe/link -> /etc` made `/tmp/safe/link/passwd` legal by inspection and
  an arbitrary read in practice. Everything canonicalizes now.
- **The shell allowlist covered the binary and not its arguments**, which for
  most binaries is no restriction at all. Hence `ArgumentPolicy`.
- **Programs resolved through `PATH`.** Absolute paths only now.
- **A timed-out child was never killed** — `tokio::time::timeout` dropped the
  future and left the process running. `kill_on_drop` now.
- **stdout, stderr, response bodies, and file reads were unbounded.** All capped,
  with truncation reported.
- **A hand-rolled DNS fallback** queried `1.1.1.1` over UDP without verifying
  the response transaction ID — spoofable off-path, in the middle of the check
  it was part of. Removed; resolution failure now fails closed.
- **Missing address ranges**: 6to4 relay, IETF protocol assignments, reserved
  `240/4`, Teredo, IPv4-compatible IPv6.

Dropped from the extraction: a database tool that forwarded inserts to a
specific internal HTTP gateway. It was a client for one service rather than a
general capability.

## Honest limits

- **TOCTOU.** Containment is checked at resolve time and used a moment later. A
  symlink swapped in between wins. Closing it needs `openat2` with
  `RESOLVE_BENEATH` on Linux or a separate mount namespace; neither is portable
  and neither is here.
- **`ArgumentPolicy::NoFlags` is a heuristic**, not a guarantee. A binary that
  treats a bare positional as a script name is still fully exploitable.
- **No isolation.** Repeating it because it matters: this is policy, not a
  sandbox in the kernel sense.
- **The HTTP tool trusts your allowlist.** If you allowlist a host that
  redirects or proxies, you have allowlisted wherever it points.

## Testing

```sh
cargo test                  # 77 unit tests
cargo test --test escapes   # 12 attack regressions
cargo run --example agent_tools
```

`tests/escapes.rs` is written as attacks rather than assertions, because that is
how they were found and the shape is the part worth keeping.

## Status

`0.1.0`. The API will move before `1.0`. MIT.
