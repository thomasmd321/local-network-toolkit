# Exporting Results & History

Applies to both [[Network Scanner|Network-Scanner]] and [[Mobile Network
Scanner|Mobile-Network-Scanner]].

## Exporting a single scan

Both scripts can save a scan's results to a file with `--output FILE`,
independent of the known-devices registry — useful for feeding results
into another tool, diffing two scans by hand, or just keeping a record.
The format is chosen by the extension: `.csv` writes CSV, anything else
(typically `.json`) writes JSON.

```
python network_scanner.py --output scan.json
python network_scanner.py --output scan.csv
python mobile_network_scanner.py --output scan.json
```

Each run overwrites `FILE` with that scan's results — a snapshot of the
latest scan, not an appended history log. A CSV's `risky_ports` column is
`;`-separated (e.g. `23;445`) since a CSV cell can't hold a real list; the
JSON export keeps it as a proper array.

## Scan history log

`--log-history FILE` appends every scan's results to `FILE` as one JSON
line per run (`{"timestamp": "...", "devices": [...]}`), instead of
overwriting it like `--output` does — useful under `--watch` for keeping a
record of what the network looked like over time (each line parses
independently, so you don't need to load the whole file to read one
entry).

```
python network_scanner.py --watch 300 --log-history history.jsonl
python mobile_network_scanner.py --log-history history.jsonl
```

The file is capped at 200 entries by default (oldest dropped first) so it
doesn't grow forever under a long-running `--watch`; override with
`--history-max-entries N`.

```
python network_scanner.py --watch 300 --log-history history.jsonl --history-max-entries 1000
```

## Diffing two saved scans

Two files saved with `--output` above can be compared directly with the
standalone [[Scan Diff|Scan-Diff]] tool — see that page for details.

## See also

- [[Scan Diff|Scan-Diff]]
- [[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]] — the registry's own NEW/CHG/missing tracking, a different (ongoing, not snapshot-to-snapshot) way of answering "what changed"
