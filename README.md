# Domain Probe

`domain_probe.py` is an asyncio-based reconnaissance helper for finding domains or webservers that are configured identically, typically phishing kits or malware infrastructure, using a similar URL pattern. The tool expands `FUZZ` placeholders from a wordlist, brute-forces wildcard characters (`?`) from a configurable character space, and reports matches only when the response status codes and starting bytes align with user-defined criteria (defaults target `50 4B 03 04`, the APK/ZIP magic). Optional modules perform DNS pre-checks, full payload downloads, CSV logging, and config file loading for repeatable scans.

## Features
- Concurrent DNS resolution (`--resolve-first`) with customizable concurrency and per-lookup timeout
- Asynchronous HTTP range probing with adjustable headers and timeout
- FUZZ placeholders sourced from newline-delimited files
- Flexible wildcard keyspace via `--wildcard-space` (ranges and literal tokens)
- Optional CSV export (`--csv`) capturing timestamps, status codes, and error details
- Optional payload archival (`--download-dir`) using open-ended range reads
- Early-exit or full keyspace traversal control (`--stop-on-match`)
- Custom header injection (`--custom-header`), match-bytes/status tuning, and reusable config files (`--config`)

## Installation
Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```
python domain_probe.py [OPTIONS] URL_PATTERN
```

### Core arguments
- `URL_PATTERN`: Supports `FUZZ` tokens (replaced by wordlist values) and `?` wildcards. For example, running `domain_probe.py 'https://FUZZ.???.example.net/payload.bin' -w names.txt --wildcard-space 'a-z'` enumerates every value in `names.txt` (e.g., `cdn`, `files`) combined with all three-letter permutations from `a` through `z`, producing URLs such as `https://cdn.abc.example.net/payload.bin` or `https://files.xyz.example.net/payload.bin`.
- `-w, --wordlist PATH`: Newline-delimited list used to replace `FUZZ`.
- `--wildcard-space SPEC`: Character/token set for `?`. Examples: `a-z` (default), `0-9a-z`, `foo,bar`, `a,k,z,5-8,10`.
- `-c, --concurrency N`: HTTP worker count (default 8). Use higher values for larger scans.
- `--limit N`: Upper bound on HTTP requests (helpful for enormous keyspaces).

### Header, match, and transport options
- `--custom-header "Header: Value"`: Inject arbitrary headers (including custom `User-Agent`). Provide multiple times (default adds `Range: bytes=0-4`).
- `--match-bytes HEX`: Hex-encoded prefix required for a match (default `504b0304`).
- `--match-status CODE`: Acceptable HTTP statuses; repeat for multiple (default accepts 200/206).
- `--timeout SECONDS`: HTTP request timeout.
- `--insecure`: Disable TLS verification for targets with broken certs.

### DNS and workflow controls
- DNS pre-checks are enabled by default. Adjust with:
  - `--no-resolve-first`: Skip DNS checks (faster, but you’ll see connection errors).
  - `--resolve-concurrency N`: Parallel lookups (default 32).
  - `--dns-timeout SECONDS`: Per-lookup timeout (default 2s).
- `--stop-on-match`: Exit once the first fingerprint match is confirmed; omit to exhaust the keyspace.

### Output helpers
- `--csv FILE`: Save every probe (including DNS skips) to CSV with timestamps.
- `--download-dir DIR`: On each match, request `bytes=0-` and save the payload to `DIR` using a slugged filename plus timestamp.
- `--verbose`: Reveal per-request miss logs and DNS skips; omit for concise summaries.

### Examples
Check a single host (default APK-style bytes):
```bash
python domain_probe.py 'https://static.example.net/releases/kit.bin' \
  --custom-header 'Range: bytes=0-4'
```

Brute-force three-letter subdomains plus FUZZ tokens while exporting results:
```bash
python domain_probe.py 'https://FUZZ.???.example.net/dropper.bin' \
  -w fuzz.txt --wildcard-space 'a-z' --csv scans/example.csv \
  --custom-header 'Range: bytes=0-4' --verbose
```
If `fuzz.txt` contains values like `cdn` and `static`, this pattern will enumerate combinations such as `https://cdn.abc.example.net/dropper.bin` and `https://static.xyz.example.net/dropper.bin`, where `abc`/`xyz` iterate through every permutation described by `???` and the wildcard space.

Full alphanumeric wildcard plus downloads:
```bash
python domain_probe.py 'https://cdn.?-assets.example.net/installers/FUZZ.bin' \
  --wildcard-space '0-9a-z' --download-dir artifacts \
  --custom-header 'Range: bytes=0-4'
```
Here the single `?` before `-assets` cycles through the entire alphanumeric keyspace, while `FUZZ` pulls concrete filenames from the supplied wordlist—ideal when a kit reuses predictable naming conventions.

### Configuration files
Supply `--config scan.cfg` to reuse a set of flags. The file is parsed line-by-line (comments start with `#`) using normal CLI syntax:

```
# scan.cfg
--wildcard-space 0-9a-z
--custom-header "Range: bytes=0-4"
--match-status 206
--match-status 200
--resolve-concurrency 64
--dns-timeout 1.0
--csv logs/example.csv
```

Invoke with:

```bash
python domain_probe.py --config scan.cfg 'https://FUZZ.???.example.net/dropper.bin' -w fuzz.txt
```

## Output summary
Each run prints:
```
Matched hosts:
- https://static.example.net/releases/kit.bin (status=206)
Enumerated 26 URLs (DNS ok=1, failed=25); issued 1 HTTP probes, 1 matched.
```
This reflects total permutations, DNS resolution results, HTTP attempts, and fingerprint-confirmed matches.

## Notes
- CSV rows include DNS skip reasons (`dns_timeout`, `dns_error`, etc.) to diagnose why a host was skipped.
- `--download-dir` naming prevents overwrites between runs by combining the URL slug and UTC timestamp.
- Increase both `--concurrency` and `--resolve-concurrency` for very large keyspaces, but watch for upstream rate limits.
