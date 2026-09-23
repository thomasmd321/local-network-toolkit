# Testing & CI

```
pip install -r requirements-dev.txt
pytest
```

Unit tests mock nearly all network/subprocess calls (a handful instead use
a real loopback socket this same machine both opens and connects to), so
the full suite runs without any real *external* network access or
elevated privileges.

A GitHub Actions workflow (`.github/workflows/tests.yml`) runs the same
suite on every push and pull request, across Python 3.9–3.12.

## How the CI workflow was created

For a while, the test suite only ever ran when someone remembered to type
`pytest` — nothing caught a regression automatically, so one could land
without anyone noticing until the next manual run. `.github/workflows/tests.yml`
closed that gap: a single job, `pytest`, that does three things per Python
version in its matrix:

1. **`actions/checkout@v4` + `actions/setup-python@v5`** — check out the
   repo and install the requested Python version.
2. **Compile-check every script** — a plain `python -m py_compile` over
   every `.py` file in the repo (both scanners and every standalone
   tool), catching a syntax error or a bad import immediately, before
   even running a single test.
3. **`pytest -v`** — the full suite.

It runs on **Python 3.9 through 3.12** (`fail-fast: false`, so one
version failing doesn't cancel the others mid-run) since the project's
own code deliberately avoids anything newer-than-3.9-only (no `X | Y`
union syntax, no `match` statements, no stdlib `tomllib`, which is why
[[Config Profiles|Config-Profiles]] uses INI via `configparser` instead
of TOML) — the matrix is what actually proves that claim, rather than
just asserting it in a comment. The job needs nothing beyond
`requirements-dev.txt` (just `pytest`) — no `scapy`/`psutil`, no real
network access, no elevated privileges — the same "mock the network,
verify the logic for real" design the test suite itself already follows
(see below), so `ubuntu-latest` with a bare Python install is enough.

Verified before ever being trusted: the actual suite was run locally
under Python 3.10 and 3.12 first (this project's own development sandbox
defaults to 3.11), confirming both passed, before relying on the CI
matrix to do the same thing automatically going forward.

## How to start/trigger it

The workflow's own trigger conditions are:

```yaml
on:
  push:
    branches: ["**"]
  pull_request:
    branches: ["**"]
  workflow_dispatch: {}
```

`branches: ["**"]` means **every** branch, not just `main` — so CI is
never something you have to remember to "turn on": it runs automatically
the moment you either

- **push a commit to any branch** on GitHub (`git push origin your-branch`), or
- **open a pull request** (updating an existing PR re-triggers it too).

There's also a manual "Run workflow" button (`workflow_dispatch: {}`) for
starting a run with no code change at all — the `{}` means it takes no
inputs, just a plain trigger. Use it from:

```
# GitHub CLI, if you have it:
gh workflow run tests.yml

# or in a browser:
https://github.com/thomasmd321/local-network-toolkit/actions/workflows/tests.yml
# → "Run workflow" dropdown, pick a branch, click "Run workflow"
```

To watch a run once it's started (whichever way it was triggered):

```
# GitHub CLI, if you have it:
gh run list --workflow=tests.yml
gh run watch

# or just open, in a browser:
https://github.com/thomasmd321/local-network-toolkit/actions
```

To re-run CI on a commit without changing any code (e.g. to confirm a
flaky failure), open that run in the Actions tab and use its "Re-run
jobs" button — that re-runs the existing commit's workflow rather than
needing a new push or a fresh `workflow_dispatch`.

## What's mocked vs. verified for real

This project leans heavily on real, unmocked verification wherever the
sandbox allows it — a real loopback socket, a real fake broker/server
thread, a real hand-built packet — rather than trusting a mock alone for
anything wire-format-sensitive. Where a tool genuinely can't be verified
against real hardware/network conditions in this project's own development
environment (no scapy privileges, no UPnP gateway, no Wi-Fi hardware, no
`traceroute` binary), that's called out explicitly as a **known
limitation** on that tool's own wiki page rather than left implicit — see
[[Troubleshooting]] for the full list.

Examples of the real-verification approach:
- [[LAN Throughput|LAN-Throughput]]: every test uses real, unmocked
  sockets — two genuinely separate processes talking over real loopback
  TCP.
- [[DHCP Monitor|DHCP-Monitor]] and [[DNS Check|DNS-Check]]: the
  socket-receive loop / wire-format client is verified against a real,
  unmocked UDP socket.
- [[UPnP Audit|UPnP-Audit]]: verified against a real, unmocked simulated
  gateway (a genuine SSDP responder plus a genuine HTTP server), though
  never a real router.
- MQTT (see [[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]]):
  a real fake MQTT broker over a real loopback socket confirms the actual
  wire bytes `publish_mqtt()` sends, including Last Will bits and TLS
  socket wrapping.

## See also

- [[Troubleshooting]]
