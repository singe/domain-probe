# Domain Probe

`domain_probe.py` is an asyncio-based reconnaissance helper for finding domains or webservers that are configured identically, typically phishing kits or malware infrastructure, using flexible URL patterns. The tool expands named wildcard spaces such as `{sub}` or `{payloads}` (with `{}` as shorthand for the default space), generates every permutation of those keyspaces, and reports matches only when the response status codes and starting bytes align with user-defined criteria (defaults target `50 4B 03 04`, the APK/ZIP magic). Optional modules perform DNS pre-checks, full payload downloads, CSV logging, and config file loading for repeatable scans.

## Features
- Concurrent DNS resolution (`--resolve-first`) with customizable concurrency and per-lookup timeout
- Asynchronous HTTP range probing with adjustable headers and timeout
- Named wildcard spaces referenced as `{space}` (default `{}` plus any number of named spaces)
- Flexible wildcard keyspaces via `-W/--wildcard-space` or inline specs (ranges, literals, `@file` tokens)
- Dry-run mode (`--list-candidates`) to print generated URLs without probing
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
- `URL_PATTERN`: Use `{space}` placeholders to mark where tokens expand. `{}` references the default space, `{name}` references a named space defined via `-W`, and inline specs like `{a-z,0-9}` work without prior definition.
- `-W, --wildcard-space SPACE`: Define wildcard spaces. Format `[-W name=]spec` (names may contain letters/digits/underscores) where `spec` supports comma-separated literals, ranges (`a-z`, `0-9`, `aa-zz`, `00-99`), multiple ranges per definition, or `@file` to load newline-delimited tokens.
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
- `--list-candidates`: Print every expanded URL (respecting `--limit` if set to a positive number) and exit without DNS/HTTP requests—useful for verifying space definitions.

### Defining wildcard spaces
- **Default space (`{}`):** Provide at least one `-W` flag without a name (e.g., `-W a-z,0-9`) to define the default keyspace that `{}` references inside the URL pattern.
- **Named spaces (`{name}`):** Give `-W name=spec` to define reusable keyspaces—`spec` accepts ranges/literals or `@file` to load newline-delimited values. Example: `-W payloads=@payloads.txt` + `{payloads}` inside the pattern.
- **Inline specs:** For quick one-offs, embed the spec directly: `https://{a-z}{a-z}{a-z}.example.net/{0-9}{0-9}/payload.bin` or `https://cdn.{@hosts.txt}/kit.bin`. 
- **Literal question marks:** Because `?` used to be a wildcard, literal question marks must now be percent-encoded (use `%3F`) or handled via a space that emits the `?` character.

### Examples
Probe every three-letter subdomain using inline specs while logging to CSV:
```bash
python domain_probe.py 'https://{a-z}{a-z}{a-z}.example.net/dropper.bin' \
  --csv scans/example.csv --custom-header 'Range: bytes=0-4'
```

Preview the exact URLs that a pattern will generate without sending requests:
```bash
python domain_probe.py -W default='null,a-z' --list-candidates \
  'https://cdn.{default}{default}.example.net/payload.bin'
```

Mix inline specs with a named file-based space for predictable payload names:
```bash
python domain_probe.py -W payloads=@payloads.txt \
  'https://cdn.{a-f0-9}{a-f0-9}.example.net/{payloads}' \
  --download-dir artifacts \
  --custom-header 'Range: bytes=0-4'
```

Combine multiple named spaces from the CLI:
```bash
python domain_probe.py \
  -W default=a-z \
  -W regions=us,za,ng \
  -W payloads=@payloads.txt \
  'https://{regions}{default}{default}.example.net/{payloads}' \
  --custom-header 'Range: bytes=0-4' --verbose
```

### Configuration files
Supply `--config scan.cfg` to reuse a set of flags. The file is parsed line-by-line (comments start with `#`) using normal CLI syntax:

```
# scan.cfg
-W default=0-9a-z
--custom-header "Range: bytes=0-4"
--match-status 206
--match-status 200
--resolve-concurrency 64
--dns-timeout 1.0
--csv logs/example.csv
```

Invoke with:

```bash
python domain_probe.py --config scan.cfg 'https://{default}{default}{default}.example.net/{@payloads.txt}'
```

## Output summary
Each run prints:
```
Matched hosts:
- https://static.example.net/{default}{default}{default}/kit.bin (status=206)
Enumerated 26 URLs (DNS ok=1, failed=25); issued 1 HTTP probes, 1 matched.
```
This reflects total permutations, DNS resolution results, HTTP attempts, and fingerprint-confirmed matches.

## Notes
- CSV rows include DNS skip reasons (`dns_timeout`, `dns_error`, etc.) to diagnose why a host was skipped.
- `--download-dir` naming prevents overwrites between runs by combining the URL slug and UTC timestamp.
- Increase both `--concurrency` and `--resolve-concurrency` for very large keyspaces, but watch for upstream rate limits.

## Wildcards Keyspace

Keyspaces, or spaces for short, are a powerful mini-grammar. At it's simplest, the default space can be referenced with `{}` in the url pattern, and the space defined with something `-W 0-9`.

Each space has a name, for example the default keyspace is called `default` and so the above example can be expanded to `-W default=0-9` and `{default}` in the URL pattern.

You can define an arbitrary number of additional named keyspaces, and reference them flexibly in the url pattern e.g. `-W alpha=a-z -W digit=0-9` and `{alpha}.{digit}.example.com` in the url pattern.

You can combine them too like so `-W alphanum=alpha,digit`.

This can also be done inline in the url pattern like `http://{alpha,digit}.example.com`.

Spaces can take a range, list or file. Ranges are defined with dashes `-`, lists are defined with commas `,`, and files are defined with the at sign `@` and file name.

Some examples of each:

* ranges: `6-8`, `b-k`, `D-L`

* lists: `foo,bar,baz`, `a,b,c`

* files: `@fuzz.txt`, `@/tmp/wordlist`

These can be combined too like so:

`0-9,a-z,A-Z`


There is a special term `null` to represent emitting nothing. For example the inline space definition:

 `foo.{a,b,1-3,null}`

would result in:
```
foo.a
foo.b
foo.1
foo.2
foo.3
foo
```

Where you can see nothing was added to the last item.

Some special range handling exists.

You can zero pad numbers like so `00-09` or `001-010`. You can also do ranges of letters like so `aa-zz` or `aaa-zzzz`, the latter can be combined like so `a-zzz` to go from the full letter keyspace of singe characters, double characters and triple characters.
