#!/usr/bin/env python3
"""Asynchronous helper to locate hosts serving identical payload fingerprints via header/range-constrained probes."""
from __future__ import annotations

import argparse
import asyncio
import csv
import itertools
import logging
import socket
import re
import shlex
import sys
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence
from urllib.parse import urlsplit

import aiohttp

DOWNLOAD_RANGE_VALUE = "bytes=0-"
DEFAULT_CUSTOM_HEADERS = ["Range: bytes=0-4"]
DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
)


@dataclass
class ProbeResult:
    url: str
    status: int | None
    matched: bool
    detail: str
    timestamp: datetime


class LimitState:
    def __init__(self, remaining: int | None) -> None:
        self.remaining = remaining
        self._lock = asyncio.Lock()
        self._exhausted = False

    async def try_acquire(self) -> bool:
        if self.remaining is None:
            return True
        async with self._lock:
            if self.remaining <= 0:
                self._exhausted = True
                return False
            self.remaining -= 1
            if self.remaining == 0:
                self._exhausted = True
            return True

    def is_exhausted(self) -> bool:
        return self._exhausted

def read_wordlist(path: Path) -> list[str]:
    if not path:
        return []
    if not path.is_file():
        raise FileNotFoundError(f"FUZZ file not found: {path}")

    values: list[str] = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            value = raw_line.strip()
            if not value or value.startswith("#"):
                continue
            values.append(value)

    if not values:
        raise ValueError(f"FUZZ file {path} did not contain any usable values")

    return values


def expand_range(start: str, end: str) -> list[str]:
    if len(start) != 1 or len(end) != 1:
        raise ValueError("Wildcard ranges must operate on single characters.")
    start_ord = ord(start)
    end_ord = ord(end)
    step = 1 if start_ord <= end_ord else -1
    return [chr(code) for code in range(start_ord, end_ord + step, step)]


def parse_wildcard_space(spec: str) -> list[str]:
    if not spec:
        raise ValueError("Wildcard space spec cannot be empty.")
    tokens: list[str] = []
    seen: set[str] = set()

    def add_token(token: str) -> None:
        if not token:
            raise ValueError("Empty wildcard token encountered.")
        if token not in seen:
            seen.add(token)
            tokens.append(token)

    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        i = 0
        length = len(chunk)
        while i < length:
            if (
                i + 2 < length
                and chunk[i + 1] == "-"
                and len(chunk[i]) == 1
                and len(chunk[i + 2]) == 1
            ):
                for val in expand_range(chunk[i], chunk[i + 2]):
                    add_token(val)
                i += 3
            else:
                j = i
                while j < length:
                    if (
                        j + 2 < length
                        and chunk[j + 1] == "-"
                        and len(chunk[j]) == 1
                        and len(chunk[j + 2]) == 1
                    ):
                        break
                    j += 1
                literal = chunk[i:j].strip()
                add_token(literal)
                i = j

    if not tokens:
        raise ValueError("No valid wildcard tokens were produced.")
    return tokens


def parse_match_bytes(spec: str) -> bytes:
    cleaned = spec.replace(" ", "")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"Match bytes must have an even number of hex digits: {spec}")
    try:
        value = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"Invalid hex string for match bytes: {spec}") from exc
    if not value:
        raise ValueError("Match bytes cannot be empty.")
    return value


def expand_question_marks(pattern: str, wildcard_tokens: Sequence[str]) -> Iterator[str]:
    positions = [idx for idx, char in enumerate(pattern) if char == "?"]
    if not positions:
        yield pattern
        return

    for combo in itertools.product(wildcard_tokens, repeat=len(positions)):
        parts: list[str] = []
        prev = 0
        for pos, replacement in zip(positions, combo):
            parts.append(pattern[prev:pos])
            parts.append(replacement)
            prev = pos + 1
        parts.append(pattern[prev:])
        yield "".join(parts)


def iter_candidate_urls(
    pattern: str,
    fuzz_values: Iterable[str],
    wildcard_tokens: Sequence[str],
) -> Iterator[str]:
    has_fuzz = "FUZZ" in pattern
    if has_fuzz and not fuzz_values:
        raise ValueError("URL pattern contains FUZZ but no wordlist was supplied")

    base_iterable: Iterable[str]
    if has_fuzz:
        base_iterable = (pattern.replace("FUZZ", value) for value in fuzz_values)
    else:
        base_iterable = [pattern]

    seen: set[str] = set()
    for base in base_iterable:
        for candidate in expand_question_marks(base, wildcard_tokens):
            if candidate in seen:
                continue
            seen.add(candidate)
            yield candidate


def parse_header_string(header: str) -> tuple[str, str]:
    if ":" not in header:
        raise ValueError(f"Invalid header format (expected 'Name: value'): {header}")
    name, value = header.split(":", 1)
    name = name.strip()
    value = value.strip()
    if not name:
        raise ValueError(f"Header name missing in: {header}")
    if not value:
        raise ValueError(f"Header value missing in: {header}")
    return name, value


def build_headers(custom_headers: Sequence[tuple[str, str]], user_agent: str) -> dict[str, str]:
    headers = {
        "User-Agent": user_agent,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
    }
    for name, value in custom_headers:
        headers[name] = value
    return headers


def prepare_download_headers(custom_headers: Sequence[tuple[str, str]]) -> list[tuple[str, str]]:
    replaced = False
    updated: list[tuple[str, str]] = []
    for name, value in custom_headers:
        if name.lower() == "range":
            updated.append((name, DOWNLOAD_RANGE_VALUE))
            replaced = True
        else:
            updated.append((name, value))
    if not replaced:
        updated.append(("Range", DOWNLOAD_RANGE_VALUE))
    return updated


_SAFE_CHARS = re.compile(r"[^a-zA-Z0-9]+")


def slugify_url(url: str) -> str:
    parsed = urlsplit(url)
    base = f"{parsed.netloc}{parsed.path}"
    if parsed.query:
        base = f"{base}?{parsed.query}"
    slug = _SAFE_CHARS.sub("_", base).strip("_")
    return slug or "payload"


def load_config_arguments(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    tokens: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        tokens.extend(shlex.split(stripped))
    return tokens


def _extract_config_path(argv: list[str]) -> tuple[list[str], Path | None]:
    cleaned: list[str] = []
    config_path: Path | None = None
    skip_next = False
    for idx, arg in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if arg == "--config":
            if idx + 1 >= len(argv):
                raise ValueError("--config specified without a path")
            config_path = Path(argv[idx + 1])
            skip_next = True
            continue
        if arg.startswith("--config="):
            _, value = arg.split("=", 1)
            config_path = Path(value)
            continue
        cleaned.append(arg)
    return cleaned, config_path


def _inject_config_args(parser: argparse.ArgumentParser) -> list[str]:
    argv = sys.argv[1:]
    stripped, config_path = _extract_config_path(argv)
    config_args: list[str] = []
    if config_path:
        config_args = load_config_arguments(config_path)
    return config_args + stripped


async def download_apk(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict[str, str],
    dest_dir: Path,
    logger: logging.Logger,
) -> Path | None:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = slugify_url(url)
    dest_path = dest_dir / f"{slug}_{timestamp}.apk"

    try:
        async with session.get(url, headers=headers, allow_redirects=False) as resp:
            if resp.status not in (200, 206):
                logger.warning("Download skipped for %s (status=%s)", url, resp.status)
                return None

            with dest_path.open("wb") as handle:
                async for chunk in resp.content.iter_chunked(64 * 1024):
                    handle.write(chunk)

        logger.info("Saved APK from %s to %s", url, dest_path)
        return dest_path
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        logger.warning("Failed to download %s: %s", url, exc)
        return None


def write_csv(csv_path: Path, records: list[ProbeResult]) -> None:
    if not records:
        return
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["timestamp", "url", "status", "matched", "detail"])
        for record in records:
            writer.writerow(
                [
                    record.timestamp.isoformat(),
                    record.url,
                    record.status if record.status is not None else "",
                    "true" if record.matched else "false",
                    record.detail,
                ]
            )


async def probe_once(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict[str, str],
    match_bytes: bytes,
    match_statuses: set[int] | None,
    logger: logging.Logger,
) -> ProbeResult:
    try:
        async with session.get(url, headers=headers, allow_redirects=False) as resp:
            chunk = await resp.content.read(len(match_bytes))
            status_ok = not match_statuses or resp.status in match_statuses
            matched = status_ok and chunk.startswith(match_bytes)
            detail = chunk[:4].hex() if chunk else ""
            return ProbeResult(
                url=url,
                status=resp.status,
                matched=matched,
                detail=detail,
                timestamp=datetime.now(timezone.utc),
            )
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        return ProbeResult(
            url=url,
            status=None,
            matched=False,
            detail=str(exc),
            timestamp=datetime.now(timezone.utc),
        )


async def worker(
    name: int,
    queue: asyncio.Queue[str | None],
    session: aiohttp.ClientSession,
    headers: dict[str, str],
    match_bytes: bytes,
    match_statuses: set[int] | None,
    results: list[ProbeResult],
    logger: logging.Logger,
    stats: dict[str, int],
    download_dir: Path | None,
    download_headers: dict[str, str] | None,
    csv_records: list[ProbeResult],
    stop_event: asyncio.Event | None,
) -> None:
    while True:
        url = await queue.get()
        if url is None:
            queue.task_done()
            break
        if stop_event and stop_event.is_set():
            queue.task_done()
            continue
        stats["http_attempted"] += 1
        result = await probe_once(session, url, headers, match_bytes, match_statuses, logger)
        csv_records.append(result)
        if result.matched:
            stats["matched"] += 1
            logger.info("MATCH %s (status=%s, bytes=%s)", result.url, result.status, result.detail)
            results.append(result)
            if download_dir and download_headers:
                await download_apk(session, url, download_headers, download_dir, logger)
            if stop_event:
                stop_event.set()
        else:
            if result.detail:
                logger.debug("MISS  %s (status=%s detail=%s)", result.url, result.status, result.detail)
            else:
                logger.debug("MISS  %s (status=%s)", result.url, result.status)
        queue.task_done()


async def resolver_worker(
    candidate_queue: asyncio.Queue[str | None],
    target_queue: asyncio.Queue[str | None],
    *,
    resolve_first: bool,
    resolution_cache: dict[str, bool],
    resolution_lock: asyncio.Lock,
    limit_state: LimitState,
    stop_event: asyncio.Event | None,
    logger: logging.Logger,
    csv_records: list[ProbeResult],
    stats: dict[str, int],
    dns_timeout: float,
) -> None:
    while True:
        url = await candidate_queue.get()
        if url is None:
            candidate_queue.task_done()
            break
        if stop_event and stop_event.is_set():
            candidate_queue.task_done()
            continue

        if resolve_first:
            resolves, reason = await hostname_resolves(
                url, resolution_cache, resolution_lock, timeout=dns_timeout
            )
            if not resolves:
                logger.debug("SKIP %s (hostname did not resolve)", url)
                csv_records.append(
                    ProbeResult(
                        url=url,
                        status=None,
                        matched=False,
                        detail=reason or "dns_skip",
                        timestamp=datetime.now(timezone.utc),
                    )
                )
                stats["dns_failed"] += 1
                candidate_queue.task_done()
                continue
            stats["dns_resolved"] += 1

        if stop_event and stop_event.is_set():
            candidate_queue.task_done()
            continue

        acquired = await limit_state.try_acquire()
        if not acquired:
            candidate_queue.task_done()
            continue

        await target_queue.put(url)
        candidate_queue.task_done()

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan wildcard URLs for hosts serving APK/ZIP payloads requiring Range and UA headers.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Optional config file containing CLI flags (one flag per line, comments start with '#').",
    )
    parser.add_argument(
        "url_pattern",
        help="URL containing optional FUZZ and '?' placeholders to enumerate",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        type=Path,
        help="Path to newline-delimited values used to replace FUZZ",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=8,
        help="Number of simultaneous requests (default: 8)",
    )
    parser.add_argument(
        "--wildcard-space",
        default="a-z",
        help=(
            "Tokens used when expanding '?' wildcards. Supports comma-separated literals "
            "and single-character ranges like 'a-z', '0-9', or mixed specs such as 'a,k,z,5-8'."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Maximum number of HTTP requests to issue (useful for very large permutations)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Total timeout per request in seconds",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification",
    )
    parser.add_argument(
        "--csv",
        dest="csv_path",
        type=Path,
        help="Write detailed probe results to this CSV file.",
    )
    parser.add_argument(
        "--download-dir",
        type=Path,
        help="Directory to store full APK downloads for matching hosts.",
    )
    parser.add_argument(
        "--stop-on-match",
        action="store_true",
        help="Exit early once the first positive match is found.",
    )
    parser.add_argument(
        "--no-resolve-first",
        dest="resolve_first",
        action="store_false",
        help="Skip DNS pre-checks (default performs a resolve before requesting).",
    )
    parser.add_argument(
        "--resolve-concurrency",
        type=int,
        default=32,
        help="Number of concurrent DNS lookups when --resolve-first is enabled (default: 32).",
    )
    parser.add_argument(
        "--dns-timeout",
        type=float,
        default=2.0,
        help="Seconds to wait for each DNS lookup before skipping (default: 2.0).",
    )
    parser.set_defaults(resolve_first=True)
    parser.add_argument(
        "--custom-header",
        action="append",
        dest="custom_headers",
        help="Additional header (Name: value). Default adds 'Range: bytes=0-4'. Provide multiple times as needed.",
    )
    parser.add_argument(
        "--match-bytes",
        default="504b0304",
        help="Hex-encoded byte prefix required for a match (default: 504b0304 for APK).",
    )
    parser.add_argument(
        "--match-status",
        type=int,
        action="append",
        dest="match_status",
        help="HTTP status code required for a match. Provide multiple times for multiple acceptable codes.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args(_inject_config_args(parser))
    return args


async def hostname_resolves(
    url: str,
    cache: dict[str, bool],
    lock: asyncio.Lock,
    timeout: float,
) -> tuple[bool, str | None]:
    parsed = urlsplit(url)
    host = parsed.hostname
    if not host:
        return False, "dns_invalid_host"
    if parsed.scheme == "https":
        port = parsed.port or 443
    else:
        port = parsed.port or 80
    key = f"{host}:{port}"
    async with lock:
        cached = cache.get(key)
    if cached is not None:
        return cached, None

    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=timeout)
        async with lock:
            cache[key] = True
        return True, None
    except asyncio.TimeoutError:
        async with lock:
            cache[key] = False
        return False, "dns_timeout"
    except OSError:
        async with lock:
            cache[key] = False
        return False, "dns_error"


async def run_scan(args: argparse.Namespace) -> tuple[list[ProbeResult], dict[str, int], list[ProbeResult]]:
    fuzz_values: list[str] = []
    if args.wordlist:
        fuzz_values = read_wordlist(args.wordlist)
    wildcard_tokens = parse_wildcard_space(args.wildcard_space)
    match_bytes = parse_match_bytes(args.match_bytes)
    match_statuses = set(args.match_status) if args.match_status else {200, 206}
    candidates = iter_candidate_urls(args.url_pattern, fuzz_values, wildcard_tokens)

    if args.concurrency < 1:
        raise ValueError("Concurrency must be >= 1")

    logger = logging.getLogger("apk_probe")
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(message)s",
    )

    queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=args.concurrency * 2)
    candidate_queue: asyncio.Queue[str | None] = asyncio.Queue(
        maxsize=max(1, args.resolve_concurrency * 4)
    )
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    ssl_flag = False if args.insecure else None
    connector = aiohttp.TCPConnector(ssl=ssl_flag, limit_per_host=args.concurrency)
    raw_headers = args.custom_headers or DEFAULT_CUSTOM_HEADERS.copy()
    custom_header_pairs = [parse_header_string(item) for item in raw_headers]
    headers = build_headers(custom_header_pairs, DEFAULT_UA)
    download_dir: Path | None = args.download_dir
    download_headers: dict[str, str] | None = None
    if download_dir:
        download_dir.mkdir(parents=True, exist_ok=True)
        download_pairs = prepare_download_headers(custom_header_pairs)
        download_headers = build_headers(download_pairs, DEFAULT_UA)

    results: list[ProbeResult] = []
    stats = {
        "candidates": 0,
        "dns_resolved": 0,
        "dns_failed": 0,
        "http_attempted": 0,
        "matched": 0,
    }
    csv_records: list[ProbeResult] = []
    limit_state = LimitState(args.limit)

    stop_event: asyncio.Event | None = asyncio.Event() if args.stop_on_match else None
    resolution_cache: dict[str, bool] = {}
    resolution_lock = asyncio.Lock()
    resolver_workers_count = args.resolve_concurrency if args.resolve_first else 1

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        workers = [
            asyncio.create_task(
                worker(
                    idx,
                    queue,
                    session,
                    headers,
                    match_bytes,
                    match_statuses,
                    results,
                    logger,
                    stats,
                    download_dir,
                    download_headers,
                    csv_records,
                    stop_event,
                )
            )
            for idx in range(args.concurrency)
        ]
        resolver_tasks = [
            asyncio.create_task(
                resolver_worker(
                    candidate_queue,
                    queue,
                    resolve_first=args.resolve_first,
                    resolution_cache=resolution_cache,
                    resolution_lock=resolution_lock,
                    limit_state=limit_state,
                    stop_event=stop_event,
                    logger=logger,
                    csv_records=csv_records,
                    stats=stats,
                    dns_timeout=args.dns_timeout,
                )
            )
            for _ in range(resolver_workers_count)
        ]

        async def produce_candidates() -> None:
            for url in candidates:
                if stop_event and stop_event.is_set():
                    break
                if args.limit is not None and limit_state.is_exhausted():
                    break
                stats["candidates"] += 1
                await candidate_queue.put(url)
            for _ in resolver_tasks:
                await candidate_queue.put(None)

        producer_task = asyncio.create_task(produce_candidates())
        await producer_task
        await candidate_queue.join()
        await asyncio.gather(*resolver_tasks)

        await queue.join()

        for _ in workers:
            await queue.put(None)

        await asyncio.gather(*workers)

    return results, stats, csv_records


def main() -> None:
    args = parse_args()
    try:
        results, stats, csv_records = asyncio.run(run_scan(args))
    except Exception as exc:  # pragma: no cover - top level guard
        print(f"Error: {exc}")
        raise SystemExit(1)

    if args.csv_path:
        write_csv(args.csv_path, csv_records)

    if results:
        print("\nMatched hosts:")
        for result in results:
            status = result.status if result.status is not None else "?"
            print(f"- {result.url} (status={status})")
    else:
        print("No matching hosts found.")

    if args.resolve_first:
        dns_summary = (
            f" (DNS ok={stats['dns_resolved']}, failed={stats['dns_failed']})"
        )
    else:
        dns_summary = ""
    print(
        f"Enumerated {stats['candidates']} URLs{dns_summary}; "
        f"issued {stats['http_attempted']} HTTP probes, {stats['matched']} matched."
    )


if __name__ == "__main__":
    main()
