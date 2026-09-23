# Shell Completion

`completions.bash` adds bash tab-completion for every script's flag names
(30+ for the two scanners, fewer for the smaller tools, but still easy to
half-remember). Source it from your `~/.bashrc`:

```
source /path/to/local-network-toolkit/completions.bash
```

It only completes flag *names*, not their arguments (a subnet, a port
list, a file path), and only fires for a direct invocation matching a
script's own name (`./network_scanner.py`, or the bare name if it's on
PATH — `chmod +x` is already set on every script in this repo).

**`python3 network_scanner.py <TAB>` does NOT trigger it** — bash keys
completion off the first word of the command line, which is `python3` in
that case, not the script. Put this repo's directory on your `PATH` (or
symlink the scripts somewhere already on it) to get completion for the
common `python3 network_scanner.py` form too, by invoking the bare name
instead.

Static, not generated from argparse at runtime — each script's flags are
listed by hand in `completions.bash`, cross-checked against each script's
actual `--help` output, so it can in principle drift out of sync if a flag
changes without updating that file too. No new runtime dependency either
way, unlike wiring up `argcomplete`.

## See also

- [[Getting Started|Getting-Started]]
