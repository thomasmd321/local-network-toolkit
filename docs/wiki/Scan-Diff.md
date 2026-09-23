# Scan Diff (`scan_diff.py`)

Compares two files saved with `--output` (see [[Exporting Results &
History|Exporting-Results-and-History]]) and reports what changed between
them — devices added, devices that disappeared, and per-field changes (a
different port, hostname, banner, etc.) on devices present in both. It's
the same NEW/missing/CHG comparison the scanners do against their own
known-devices registry, just applied to two snapshots on disk instead.

```
python scan_diff.py old.json new.json
python scan_diff.py before.csv after.csv
```

Either file can be JSON or CSV (independently — comparing a CSV export
against a JSON one works fine), and they don't need to come from the same
script: fields the two scanners don't share (`mac`/`vendor` are
desktop-only, `banner` is mobile-only) are still compared whenever both
files happen to have them. `_normalize_device()` coerces CSV's
string-typed `port`/`risky_ports` back to the same shape JSON already has,
so a device unchanged in substance never shows as "changed" just because
one file was CSV.

A device is matched across the two files by MAC when present, falling
back to IP — the same identity rule `network_scanner.py`'s own
known-devices tracking uses. Output reuses the same green/dim/yellow color
language as NEW/missing/CHG elsewhere in this project.

## See also

- [[Exporting Results & History|Exporting-Results-and-History]]
- [[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]] — the live, registry-based equivalent of this file-based diff
