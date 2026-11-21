#!/usr/bin/env python3
"""Polite archiver for the City of Casper, WY official website.

What it does, end to end:
  1. Fetches robots.txt per contacted host and parses Disallow, Sitemap, and
     crawl-delay rules.
  2. Fetches sitemap.xml on casperwy.gov, recursively walks any child sitemaps
     (<sitemapindex>, including .xml.gz), and inspects both direct sitemap
     document URLs and sitemap-listed casperwy.gov HTML pages for links to
     public documents.
  3. Explicitly seeds the City Council documents page
     (https://www.casperwy.gov/government/city_council/documents.php).
  4. Downloads each original document binary (PDF/DOC/DOCX/RTF/XLS/XLSX/PPT/
     PPTX/ODT/TXT/CSV) from casperwy.gov (including official redirects strictly
     within https://cms2.revize.com/revize/casperwy/) with polite sequential
     pacing, writes it under documents/ preserving path structure, hashes it
     (SHA-256), and records full provenance (original URL + final download URL)
     in manifest.json.
  5. Writes MANIFEST.md with an honest, human-readable coverage summary,
     including failed, robots-blocked, external, oversized, and pending items.

Approved host & redirect boundary:
  * Sitemap and HTML page discovery is strictly restricted to casperwy.gov.
  * Document downloads allow casperwy.gov and exact HTTPS Casper Revize storage
    paths under https://cms2.revize.com/revize/casperwy/<path> (no HTTP, no
    other revize.com subdomains, no other tenants on cms2.revize.com, and no
    '..' path traversal). Every redirect hop is validated before connection.

Usage:
  python3 collect.py                           # full run (sitemaps + pages + council seed)
  python3 collect.py --max-new 5               # bounded verification run (5 archived docs)
  python3 collect.py --max-seconds 2700        # graceful 45-minute run budget
  python3 collect.py --dry-run                 # discover URLs without downloading documents
  python3 collect.py --headline-only           # only the city-council documents page
  python3 collect.py --delay 3.0               # polite pacing (>= 3.0 seconds between hits)
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import posixpath
import re
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.robotparser import RobotFileParser

SITE = "https://www.casperwy.gov"
SITEMAP_URL = SITE + "/sitemap.xml"
HEADLINE_PAGE = SITE + "/government/city_council/documents.php"
APPROVED_REVIZE_HOST = "cms2.revize.com"
APPROVED_REVIZE_PREFIX = "/revize/casperwy/"
USER_AGENT = "casper-record-mirror/1.0 (+https://github.com/bartimoussmith-oss/casper-record-mirror)"
MIN_DELAY = 3.0
DEFAULT_DELAY = 3.0
MAX_REDIRECTS = 5
MAX_BYTES = 50 * 1024 * 1024        # 50 MiB per document; bigger files are recorded as oversized
MAX_HTML_BYTES = 5 * 1024 * 1024    # 5 MiB bound when parsing HTML pages for document links
MAX_SITEMAP_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_RUN_BYTES = 750 * 1024 * 1024  # 750 MiB new bytes per run so git push stays reliable
CHUNK_SIZE = 64 * 1024

DOC_EXTS = (
    ".pdf", ".doc", ".docx", ".rtf", ".xls", ".xlsx",
    ".ppt", ".pptx", ".odt", ".txt", ".csv",
)
IMAGE_EXTS = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp",
    ".ico", ".tif", ".tiff", ".svg",
)
NON_HTML_ASSET_EXTS = IMAGE_EXTS + (
    ".css", ".js", ".mjs", ".json", ".map",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".m4a", ".wav", ".ogg", ".webm", ".avi", ".mov",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".exe", ".msi", ".dmg", ".iso", ".apk",
    ".xml", ".rss", ".atom",
)
SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "sms:", "blob:")
REDIRECT_CODES = (301, 302, 303, 307, 308)


class ExternalRedirectError(RuntimeError):
    def __init__(self, target_url: str):
        super().__init__(f"redirected to external host: {target_url}")
        self.target_url = target_url


class RobotsDisallowedError(RuntimeError):
    def __init__(self, target_url: str):
        super().__init__(f"disallowed by robots.txt: {target_url}")
        self.target_url = target_url


class OversizedDocumentError(RuntimeError):
    def __init__(self, actual_bytes: int, limit_bytes: int, via_header: bool = False):
        qualifier = "Content-Length" if via_header else "streamed bytes"
        super().__init__(f"file too large ({qualifier}: {actual_bytes} > {limit_bytes} bytes)")
        self.actual_bytes = actual_bytes
        self.limit_bytes = limit_bytes


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_casper_host(netloc: str) -> bool:
    host = netloc.split(":", 1)[0].lower().strip(".")
    return host == "casperwy.gov" or host.endswith(".casperwy.gov")


def is_approved_revize_casper_url(url: str) -> bool:
    """Allow ONLY https://cms2.revize.com/revize/casperwy/<non-empty-path> with no '..' traversal."""
    if not url:
        return False
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme.lower() != "https":
        return False
    raw_netloc = parsed.netloc.lower()
    if "@" in raw_netloc:
        return False
    if ":" in raw_netloc:
        host, port = raw_netloc.rsplit(":", 1)
        if port != "443":
            return False
    else:
        host = raw_netloc
    host = host.strip(".")
    if host != APPROVED_REVIZE_HOST:
        return False
    unquoted_path = urllib.parse.unquote(parsed.path or "")
    raw_segments = unquoted_path.split("/")
    if ".." in raw_segments:
        return False
    norm = posixpath.normpath(unquoted_path)
    if not norm.startswith("/"):
        norm = "/" + norm
    if not norm.lower().startswith(APPROVED_REVIZE_PREFIX):
        return False
    remainder = norm[len(APPROVED_REVIZE_PREFIX):].strip("/")
    return bool(remainder)


def is_approved_robots_url(url: str) -> bool:
    """Allow /robots.txt only on casperwy.gov hosts or https://cms2.revize.com/robots.txt."""
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.path != "/robots.txt" or parsed.query:
        return False
    if is_casper_host(parsed.netloc):
        return parsed.scheme.lower() in ("http", "https")
    host = parsed.netloc.split(":", 1)[0].lower().strip(".")
    return parsed.scheme.lower() == "https" and host == APPROVED_REVIZE_HOST


def canonical_host(netloc: str) -> str:
    host = netloc.split(":", 1)[0].lower().strip(".")
    if host == "casperwy.gov":
        return "www.casperwy.gov"
    return host


def canonical_doc_relpath(url: str) -> str:
    """Return unquoted path relative to site root (stripping /revize/casperwy/ on approved Revize URLs)."""
    parsed = urllib.parse.urlsplit(url)
    unquoted = re.sub(r"/+", "/", urllib.parse.unquote(parsed.path or ""))
    if is_approved_revize_casper_url(url) and unquoted.lower().startswith(APPROVED_REVIZE_PREFIX):
        unquoted = "/" + unquoted[len(APPROVED_REVIZE_PREFIX):]
    return unquoted.lstrip("/")


def _encode_url_part(val: str, safe_chars: str) -> str:
    """Percent-encode spaces, control chars, and non-ASCII while preserving %XX."""
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        + safe_chars
    )
    out: list[str] = []
    i = 0
    n = len(val)
    while i < n:
        ch = val[i]
        if (
            ch == "%"
            and i + 2 < n
            and all(c in "0123456789ABCDEFabcdef" for c in val[i + 1 : i + 3])
        ):
            out.append(val[i : i + 3])
            i += 3
        elif ch in allowed:
            out.append(ch)
            i += 1
        else:
            out.append(urllib.parse.quote(ch, safe=""))
            i += 1
    return "".join(out)


def safe_request_url(url: str) -> str:
    """Return an HTTP-safe URL string suitable for urllib.request on Python 3.12+."""
    parsed = urllib.parse.urlsplit(url.strip())
    scheme = parsed.scheme.lower() or "https"
    raw_netloc = parsed.netloc
    if "@" in raw_netloc:
        raise ValueError(f"userinfo not permitted in URL: {url}")
    if ":" in raw_netloc:
        host_part, port_part = raw_netloc.rsplit(":", 1)
        netloc = f"{host_part.encode('idna').decode('ascii')}:{port_part}"
    else:
        netloc = raw_netloc.encode("idna").decode("ascii")
    path = _encode_url_part(parsed.path or "/", "/:@!$&'()*+,;=")
    query = _encode_url_part(parsed.query, "=:&?/+!$'()*,;")
    return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))


def has_doc_extension(url: str) -> bool:
    if not url or not re.match(r"^https?://", url, re.I):
        return False
    parsed = urllib.parse.urlsplit(url)
    path = urllib.parse.unquote(parsed.path.lower())
    if path.endswith(IMAGE_EXTS):
        return False
    return path.endswith(DOC_EXTS)


def is_document_url(url: str) -> bool:
    if not has_doc_extension(url):
        return False
    parsed = urllib.parse.urlsplit(url)
    return is_casper_host(parsed.netloc) or is_approved_revize_casper_url(url)


def is_html_candidate_url(url: str) -> bool:
    if not url or not re.match(r"^https?://", url, re.I):
        return False
    parsed = urllib.parse.urlsplit(url)
    if not is_casper_host(parsed.netloc):
        return False
    path = urllib.parse.unquote(parsed.path.lower())
    if path.endswith(DOC_EXTS) or path.endswith(NON_HTML_ASSET_EXTS):
        return False
    return True


def normalize_key(url: str) -> str:
    """Strip cache-buster query params and fragments for document deduping."""
    parsed = urllib.parse.urlsplit(url)
    if is_approved_revize_casper_url(url):
        rel = canonical_doc_relpath(url).lower()
        return f"www.casperwy.gov/{rel}"
    host = canonical_host(parsed.netloc)
    path = re.sub(r"/+", "/", urllib.parse.unquote(parsed.path)).lower()
    return f"{host}{path}"


def normalize_page_key(url: str) -> str:
    """Normalize an HTML page URL while preserving query strings that select pages."""
    parsed = urllib.parse.urlsplit(url)
    host = canonical_host(parsed.netloc)
    path = re.sub(r"/+", "/", urllib.parse.unquote(parsed.path)) or "/"
    query = urllib.parse.unquote(parsed.query)
    return f"{host}{path}?{query}" if query else f"{host}{path}"


def bucket_for(url: str) -> str:
    rel = canonical_doc_relpath(url)
    parts = [p for p in rel.split("/") if p]
    if parts and parts[0].lower() == "documents":
        parts = parts[1:]
    return parts[0] if parts else "misc"


def safe_filename(name: str, max_utf8_bytes: int = 200) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip()
    if cleaned in ("", ".", "..") or cleaned.strip(".") == "":
        return ""
    raw = cleaned.encode("utf-8")
    if len(raw) <= max_utf8_bytes:
        return cleaned
    suffix = Path(cleaned).suffix
    stem = Path(cleaned).stem
    digest = hashlib.sha256(raw).hexdigest()[:8]
    budget = max(32, max_utf8_bytes - len(suffix.encode("utf-8")) - 10)
    trimmed = stem.encode("utf-8")[:budget].decode("utf-8", "ignore").rstrip()
    return f"{trimmed}-{digest}{suffix}"


def local_path(url: str, buckets_used: dict[str, str], output_dir: str = "documents") -> str:
    """Map a document URL to a path under output_dir, preserving nesting.

    e.g. .../Documents/Government/City Council/Gaming Location Survey.pdf
         -> documents/Government/City Council/Gaming Location Survey.pdf
    """
    url_key = normalize_key(url)
    rel = canonical_doc_relpath(url)
    parts = [p for p in rel.split("/") if p and p not in (".", "..")]
    if parts and parts[0].lower() == "documents":
        parts = parts[1:]
    base_root = output_dir.strip("/") or "documents"
    if not parts:
        target = f"{base_root}/misc/document.pdf"
    else:
        folders = [safe_filename(p) or "folder" for p in parts[:-1]]
        basename = safe_filename(parts[-1]) or "document.pdf"
        folder = "/".join([base_root] + folders)
        target = f"{folder}/{basename}"
    if target not in buckets_used or buckets_used[target] == url_key:
        buckets_used[target] = url_key
        return target
    folder_part = str(Path(target).parent).replace("\\", "/")
    stem = Path(target).stem
    suffix = Path(target).suffix
    n = 2
    while True:
        candidate = f"{folder_part}/{stem}-{n}{suffix}"
        if candidate not in buckets_used or buckets_used[candidate] == url_key:
            buckets_used[candidate] = url_key
            return candidate
        n += 1


def should_requeue_external_skipped(rec: dict) -> bool:
    """Return True if a prior external_skipped record qualifies under the approved Revize Casper rule."""
    if rec.get("status") != "external_skipped":
        return False
    url = rec.get("url") or ""
    if not is_document_url(url):
        return False
    err = rec.get("error") or ""
    prefix = "redirected to external host: "
    if err.startswith(prefix):
        redirect_target = err[len(prefix):].strip()
        return is_approved_revize_casper_url(redirect_target) or is_casper_host(
            urllib.parse.urlsplit(redirect_target).netloc
        )
    return is_approved_revize_casper_url(url)


class PageLinkParser(HTMLParser):
    """Extract <base href> and candidate links from an HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_href: str | None = None
        self.raw_links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        attr_map = {k.lower(): v for k, v in attrs if k and v is not None}
        if tag_l == "base" and self.base_href is None:
            href = (attr_map.get("href") or "").strip()
            if href:
                self.base_href = href
            return
        target: str | None = None
        if tag_l in ("a", "area", "link"):
            target = attr_map.get("href")
        elif tag_l in ("iframe", "embed"):
            target = attr_map.get("src")
        elif tag_l == "object":
            target = attr_map.get("data")
        if target:
            cleaned = target.strip()
            if cleaned and not cleaned.lower().startswith(SKIP_SCHEMES) and not cleaned.startswith("#"):
                self.raw_links.append(cleaned)


def parse_float_crawl_delay(robots_text: str, user_agent: str) -> float:
    """Parse float or integer Crawl-delay rules that stdlib RobotFileParser may drop."""
    ua_token = user_agent.split("/", 1)[0].lower()
    current_agents: list[str] = []
    specific_delay = 0.0
    wildcard_delay = 0.0
    last_was_ua = False
    for raw_line in robots_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            if not line:
                current_agents = []
                last_was_ua = False
            continue
        field, value = [part.strip() for part in line.split(":", 1)]
        field_l = field.lower()
        if field_l == "user-agent":
            if not last_was_ua:
                current_agents = []
            current_agents.append(value.lower())
            last_was_ua = True
        else:
            last_was_ua = False
            if field_l == "crawl-delay":
                m = re.match(r"^([0-9]+(?:\.[0-9]+)?)", value)
                if m:
                    val = float(m.group(1))
                    if any(ua_token in ag for ag in current_agents if ag != "*"):
                        specific_delay = max(specific_delay, val)
                    elif "*" in current_agents:
                        wildcard_delay = max(wildcard_delay, val)
    return specific_delay if specific_delay > 0 else wildcard_delay


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return 3xx responses directly so PoliteClient validates & paces every redirect hop."""

    def http_error_301(self, req, fp, code, msg, headers):
        return fp

    http_error_302 = http_error_303 = http_error_307 = http_error_308 = http_error_301


class PoliteClient:
    """Single-threaded HTTP client enforcing >=3.0s pacing, per-host robots.txt/crawl-delay, and hop validation."""

    def __init__(self, base_delay: float) -> None:
        self.base_delay = max(MIN_DELAY, float(base_delay))
        self.delay = self.base_delay
        self.requests_made = 0
        self._robots_by_origin: dict[str, tuple[RobotFileParser | None, float, list[str]]] = {}
        self._opener = urllib.request.build_opener(NoRedirectHandler())

    def _origin_for(self, url: str) -> str:
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower() or "https"
        host = parsed.netloc.lower()
        if scheme == "https" and host.endswith(":443"):
            host = host[:-4]
        elif scheme == "http" and host.endswith(":80"):
            host = host[:-3]
        return f"{scheme}://{host}"

    def _is_origin_permitted(self, url: str) -> bool:
        parsed = urllib.parse.urlsplit(url)
        if is_casper_host(parsed.netloc):
            return True
        return is_approved_revize_casper_url(url) or is_approved_robots_url(url)

    def delay_for_origin(self, origin: str) -> float:
        entry = self._robots_by_origin.get(origin)
        host_delay = entry[1] if entry else 0.0
        return max(MIN_DELAY, self.base_delay, host_delay)

    def ensure_robots(self, url: str) -> list[str]:
        if not self._is_origin_permitted(url):
            return []
        origin = self._origin_for(url)
        if origin in self._robots_by_origin:
            return self._robots_by_origin[origin][2]

        # Register placeholder first so redirects during robots.txt fetch do not recurse.
        self._robots_by_origin[origin] = (None, 0.0, [])
        robots_url = f"{origin}/robots.txt"
        rp = RobotFileParser()
        sitemaps: list[str] = []
        host_delay = 0.0
        try:
            _, _, body, _, _ = self.fetch_raw(
                robots_url,
                max_bytes=1024 * 1024,
                timeout=20,
                is_robots_fetch=True,
            )
            text = body.decode("utf-8", "replace")
            rp.parse(text.splitlines())
            std_cd = rp.crawl_delay(USER_AGENT) or rp.crawl_delay("*") or 0.0
            flt_cd = parse_float_crawl_delay(text, USER_AGENT)
            host_delay = max(float(std_cd), flt_cd)
            if host_delay > self.base_delay:
                print(
                    f"[*] {robots_url} declared crawl-delay={host_delay}s; "
                    f"using {host_delay}s for {origin}"
                )
                self.delay = max(self.delay, host_delay)
            if is_casper_host(urllib.parse.urlsplit(origin).netloc):
                for sm in rp.site_maps() or []:
                    sm_clean = sm.strip()
                    if sm_clean and is_casper_host(urllib.parse.urlsplit(sm_clean).netloc):
                        sitemaps.append(sm_clean)
            self._robots_by_origin[origin] = (rp, host_delay, sitemaps)
        except Exception as exc:
            print(
                f"[!] robots.txt at {robots_url} could not be fetched ({exc}); "
                f"continuing without robots filter for {origin}"
            )
            self._robots_by_origin[origin] = (None, 0.0, [])
        return sitemaps

    def robots_allowed(self, url: str, *, allow_approved_revize: bool = False) -> bool:
        parsed = urllib.parse.urlsplit(url)
        if is_casper_host(parsed.netloc):
            pass
        elif allow_approved_revize and is_approved_revize_casper_url(url):
            pass
        else:
            return False
        self.ensure_robots(url)
        rp, _, _ = self._robots_by_origin.get(self._origin_for(url), (None, 0.0, []))
        if rp is None:
            return True
        return rp.can_fetch(USER_AGENT, safe_request_url(url))

    def _validate_target_url(
        self,
        safe_url: str,
        *,
        allow_approved_revize: bool,
        is_robots_fetch: bool,
    ) -> None:
        parsed = urllib.parse.urlsplit(safe_url)
        if is_robots_fetch:
            if not is_approved_robots_url(safe_url):
                raise ExternalRedirectError(safe_url)
            return
        if is_casper_host(parsed.netloc):
            return
        if allow_approved_revize and is_approved_revize_casper_url(safe_url):
            return
        raise ExternalRedirectError(safe_url)

    def fetch_raw(
        self,
        url: str,
        *,
        max_bytes: int,
        timeout: int = 60,
        accept: str = "*/*",
        allow_approved_revize: bool = False,
        is_robots_fetch: bool = False,
        html_only: bool = False,
    ) -> tuple[int, object, bytes, str, list[str]]:
        current_url = url
        seen_hops: set[str] = set()
        redirect_chain: list[str] = []

        for hop in range(MAX_REDIRECTS + 1):
            safe_url = safe_request_url(current_url)
            self._validate_target_url(
                safe_url,
                allow_approved_revize=allow_approved_revize,
                is_robots_fetch=is_robots_fetch,
            )
            if safe_url in seen_hops:
                raise RuntimeError(f"redirect loop detected at {safe_url}")
            seen_hops.add(safe_url)

            if not is_robots_fetch:
                if not self.robots_allowed(safe_url, allow_approved_revize=allow_approved_revize):
                    raise RobotsDisallowedError(safe_url)

            origin = self._origin_for(safe_url)
            time.sleep(self.delay_for_origin(origin))
            self.requests_made += 1

            req = urllib.request.Request(
                safe_url,
                headers={"User-Agent": USER_AGENT, "Accept": accept},
            )
            with self._opener.open(req, timeout=timeout) as resp:
                status = getattr(resp, "status", None) or resp.getcode() or 200
                headers = resp.headers

                if status in REDIRECT_CODES:
                    resp.read(4096)
                    loc = headers.get("Location")
                    if not loc:
                        raise RuntimeError(f"HTTP {status} redirect without Location header")
                    if hop >= MAX_REDIRECTS:
                        raise RuntimeError(f"exceeded max redirects ({MAX_REDIRECTS})")
                    next_url = urllib.parse.urljoin(safe_url, loc.strip())
                    next_sp = urllib.parse.urlsplit(next_url)
                    next_clean = urllib.parse.urlunsplit(
                        (next_sp.scheme, next_sp.netloc, next_sp.path, next_sp.query, "")
                    )
                    redirect_chain.append(next_clean)
                    current_url = next_clean
                    continue

                ctype = (headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
                if html_only and ctype and ctype not in ("text/html", "application/xhtml+xml"):
                    return status, headers, b"", safe_url, redirect_chain

                cl_header = headers.get("Content-Length")
                expected_len: int | None = None
                if cl_header:
                    try:
                        expected_len = int(cl_header.strip())
                    except ValueError:
                        expected_len = None
                if expected_len is not None and max_bytes > 0 and expected_len > max_bytes:
                    raise OversizedDocumentError(expected_len, max_bytes, via_header=True)

                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = resp.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                    if max_bytes > 0 and total > max_bytes:
                        raise OversizedDocumentError(total, max_bytes, via_header=False)
                    chunks.append(chunk)
                body = b"".join(chunks)

                content_enc = (headers.get("Content-Encoding") or "").strip().lower()
                if (
                    expected_len is not None
                    and content_enc in ("", "identity")
                    and len(body) < expected_len
                ):
                    raise RuntimeError(f"truncated download ({len(body)} < {expected_len} bytes)")
                return status, headers, body, safe_url, redirect_chain

        raise RuntimeError(f"exceeded max redirects ({MAX_REDIRECTS})")


def looks_like_html_error_page(content_type: str, body: bytes) -> bool:
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    head = body[:512].lstrip().lower()
    if ctype in ("text/html", "application/xhtml+xml"):
        return True
    if head.startswith((b"<!doctype html", b"<html")):
        return True
    return False


def decode_xml_bytes(body: bytes) -> str:
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    text = body.decode("utf-8-sig", "replace").lstrip()
    return text


def load_manifest(path: Path) -> dict:
    if path.exists():
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, dict) and "documents" in data:
                    return data
        except Exception as exc:
            print(f"[!] Could not read existing manifest ({exc}); starting fresh.")
    return {
        "source": {
            "site": SITE,
            "sitemap_url": SITEMAP_URL,
            "documents_page_url": HEADLINE_PAGE,
            "approved_redirect_prefix": f"https://{APPROVED_REVIZE_HOST}{APPROVED_REVIZE_PREFIX}",
        },
        "generated_at": None,
        "site_map": {
            "sitemaps_fetched": 0,
            "locs_total": 0,
            "sitemap_document_locs": 0,
            "sitemap_html_pages": 0,
            "html_pages_scanned_total": 0,
            "html_pages_scanned_this_run": 0,
            "html_pages_remaining": 0,
            "documents_found": 0,
        },
        "run_budget": {},
        "crawl_state": {
            "sweep_complete": False,
            "scanned_pages": [],
        },
        "summary": {},
        "total_archived_bytes": 0,
        "documents": [],
    }


def write_outputs(manifest: dict, manifest_path: Path, markdown_path: Path = Path("MANIFEST.md")) -> None:
    manifest.setdefault("source", {})[
        "approved_redirect_prefix"
    ] = f"https://{APPROVED_REVIZE_HOST}{APPROVED_REVIZE_PREFIX}"
    documents = sorted(manifest.get("documents", []), key=lambda d: normalize_key(d.get("url", "")))
    manifest["documents"] = documents
    manifest["generated_at"] = now_iso()

    summary: dict[str, int] = {}
    archived_bytes = 0
    for doc in documents:
        st = doc.get("status", "unknown")
        summary[st] = summary.get(st, 0) + 1
        if st == "archived":
            archived_bytes += int(doc.get("bytes", 0) or 0)
    manifest["summary"] = summary
    manifest["total_archived_bytes"] = archived_bytes

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_manifest = manifest_path.with_suffix(".json.tmp")
    with open(tmp_manifest, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    tmp_manifest.replace(manifest_path)

    sm = manifest.get("site_map", {})
    rb = manifest.get("run_budget", {})
    lines = [
        "# Casper, WY — archived documents",
        "",
        f"Generated from [casperwy.gov]({SITE}) via the site sitemaps and the "
        f"[city council documents page]({HEADLINE_PAGE}) "
        f"(approved document storage redirect scope: `https://{APPROVED_REVIZE_HOST}{APPROVED_REVIZE_PREFIX}`).",
        "",
        f"- **Sitemaps fetched:** {sm.get('sitemaps_fetched', 0)}",
        f"- **Sitemap `<loc>` entries:** {sm.get('locs_total', 0)}",
        f"- **Direct document `<loc>` entries in sitemaps:** {sm.get('sitemap_document_locs', 0)}",
        f"- **Sitemap HTML pages queued:** {sm.get('sitemap_html_pages', 0)}",
        f"- **HTML pages scanned (sweep total / this run / remaining):** "
        f"{sm.get('html_pages_scanned_total', 0)} / {sm.get('html_pages_scanned_this_run', 0)} / "
        f"{sm.get('html_pages_remaining', 0)}",
        f"- **Unique Casper documents discovered:** {sm.get('documents_found', 0)}",
        f"- **Archived documents:** {summary.get('archived', 0)} "
        f"({archived_bytes:,} bytes / {archived_bytes / 1024 / 1024:.2f} MiB)",
        f"- **Needs follow-up run to finish sweep:** {'yes' if rb.get('needs_resume') else 'no'}"
        + (f" ({rb.get('stop_reason')})" if rb.get("stop_reason") else ""),
        f"- **Archive run:** {manifest['generated_at']}",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "| --- | --- |",
    ]
    for status, count in sorted(summary.items()):
        lines.append(f"| {status} | {count} |")

    sitemap_errors = sm.get("sitemap_errors") or []
    page_errors = sm.get("page_scan_errors") or []
    if sitemap_errors or page_errors:
        lines += ["", "## Discovery issues", ""]
        for err in sitemap_errors:
            lines.append(f"- **sitemap** — {err}")
        for err in page_errors[:50]:
            lines.append(f"- **page_scan** — {err}")
        if len(page_errors) > 50:
            lines.append(f"- *(+{len(page_errors) - 50} additional page scan errors in logs)*")

    lines += ["", "## Not archived", ""]
    non_archived = [d for d in documents if d.get("status") != "archived"]
    if non_archived:
        for d in non_archived:
            lines.append(f"- **{d.get('status')}** — {d.get('url')}")
            if d.get("error"):
                lines.append(f"  - reason: {d['error']}")
    else:
        lines.append("None — every discovered Casper document in scope is archived.")

    lines += [
        "",
        "## Documents",
        "",
        "Full provenance (original city URL, final download URL, discovery source,",
        "local path, SHA-256, size, fetch time, content type) is in [`manifest.json`](manifest.json).",
        "",
    ]
    by_bucket: dict[str, list[dict]] = {}
    for d in documents:
        if d.get("status") != "archived":
            continue
        rel = (d.get("local_path") or "").strip()
        if not rel:
            continue
        parts = rel.split("/")
        bucket = parts[1] if len(parts) > 2 else "misc"
        by_bucket.setdefault(bucket, []).append(d)
    for bucket, docs in sorted(by_bucket.items()):
        bucket_bytes = sum(int(d.get("bytes", 0) or 0) for d in docs)
        lines.append(f"### {bucket} — {len(docs)} documents ({bucket_bytes / 1024 / 1024:.2f} MiB)")
        lines.append("")
        for d in sorted(docs, key=lambda x: x.get("local_path", "")):
            lines.append(f"- `{d.get('local_path')}` — {int(d.get('bytes', 0) or 0) / 1024:.1f} KiB")
        lines.append("")

    tmp_md = markdown_path.with_suffix(".md.tmp")
    with open(tmp_md, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    tmp_md.replace(markdown_path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                    help="seconds to wait between requests (minimum/default 3.0)")
    ap.add_argument("--max-bytes", type=int, default=MAX_BYTES,
                    help="per-document size cap (default 50 MiB)")
    ap.add_argument("--max-new", type=int, default=0,
                    help="stop after archiving this many NEW documents (0 = no cap)")
    ap.add_argument("--max-seconds", type=int, default=0,
                    help="graceful wall-clock budget in seconds before saving & exiting (0 = no cap)")
    ap.add_argument("--max-requests", type=int, default=0,
                    help="graceful total HTTP request cap per run (0 = no cap)")
    ap.add_argument("--max-run-bytes", type=int, default=DEFAULT_MAX_RUN_BYTES,
                    help="graceful cap on newly downloaded document bytes per run (default 750 MiB, 0 = no cap)")
    ap.add_argument("--output-dir", default="documents")
    ap.add_argument("--manifest", default="manifest.json")
    ap.add_argument("--headline-only", action="store_true",
                    help="only collect documents linked from the city-council documents page")
    ap.add_argument("--no-sitemap", action="store_true",
                    help="skip sitemaps and only use the city-council documents page")
    ap.add_argument("--no-page-scan", action="store_true",
                    help="do not scan sitemap-listed HTML pages for document links")
    ap.add_argument("--rescan-pages", action="store_true",
                    help="start a fresh HTML page scan even if an earlier sweep was partway through")
    ap.add_argument("--dry-run", action="store_true",
                    help="list discovered URLs without downloading documents")
    args = ap.parse_args(argv)

    start_mono = time.monotonic()
    interrupted_signal: list[str] = []

    def _handle_sig(signum, _frame):
        interrupted_signal.append(signal.Signals(signum).name)

    prev_sigint = signal.signal(signal.SIGINT, _handle_sig)
    prev_sigterm = signal.signal(signal.SIGTERM, _handle_sig)

    try:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = Path(args.manifest)
        markdown_path = manifest_path.with_name("MANIFEST.md")
        manifest = load_manifest(manifest_path)

        existing_docs: list[dict] = manifest.get("documents", [])
        docs_by_key: dict[str, dict] = {}
        buckets_used: dict[str, str] = {}
        discovered: dict[str, dict] = {}
        requeued_count = 0

        for rec in existing_docs:
            u = rec.get("url", "")
            if not u:
                continue
            key = normalize_key(u)
            if should_requeue_external_skipped(rec):
                rec = {
                    **rec,
                    "status": "pending",
                    "error": (
                        f"requeued under approved https://{APPROVED_REVIZE_HOST}"
                        f"{APPROVED_REVIZE_PREFIX} redirect rule"
                    ),
                }
                requeued_count += 1
            docs_by_key[key] = rec
            if rec.get("status") == "archived" and rec.get("local_path") and Path(rec["local_path"]).exists():
                buckets_used[rec["local_path"]] = key
            if is_document_url(u):
                discovered[key] = {"url": u, "source": rec.get("source", "manifest")}

        if requeued_count:
            print(
                f"[*] Requeued {requeued_count} previously external_skipped entries "
                f"qualifying under https://{APPROVED_REVIZE_HOST}{APPROVED_REVIZE_PREFIX}"
            )

        prior_state = manifest.get("crawl_state") if isinstance(manifest.get("crawl_state"), dict) else {}
        resuming_partial_sweep = (
            not args.rescan_pages
            and bool(prior_state.get("scanned_pages"))
            and not bool(prior_state.get("sweep_complete", False))
        )
        scanned_pages: set[str] = set(prior_state.get("scanned_pages", [])) if resuming_partial_sweep else set()
        if resuming_partial_sweep:
            print(f"[*] Resuming partial sweep with {len(scanned_pages)} HTML pages already scanned")

        client = PoliteClient(args.delay)
        robots_sitemaps = client.ensure_robots(SITE)

        new_count = 0
        new_bytes = 0
        skipped_count = 0
        tried_this_run: set[str] = set()
        stop_reason: str | None = None

        def check_budget() -> str | None:
            nonlocal stop_reason
            if stop_reason:
                return stop_reason
            if interrupted_signal:
                stop_reason = f"signal:{interrupted_signal[0]}"
            elif args.max_seconds and (time.monotonic() - start_mono) >= args.max_seconds:
                stop_reason = f"max_seconds_reached ({args.max_seconds}s)"
            elif args.max_requests and client.requests_made >= args.max_requests:
                stop_reason = f"max_requests_reached ({args.max_requests})"
            elif args.max_new and new_count >= args.max_new:
                stop_reason = f"max_new_reached ({args.max_new})"
            elif args.max_run_bytes and new_bytes >= args.max_run_bytes:
                stop_reason = f"max_run_bytes_reached ({args.max_run_bytes} bytes)"
            return stop_reason

        def register_candidate_url(raw_url: str, source: str, base_url: str) -> bool:
            """Return True if a new in-scope Casper document was added."""
            if not raw_url:
                return False
            cleaned = raw_url.strip().strip("\"'<>\t\r\n")
            if not cleaned or cleaned.lower().startswith(SKIP_SCHEMES) or cleaned.startswith("#"):
                return False
            resolved = urllib.parse.urljoin(base_url, cleaned)
            sp = urllib.parse.urlsplit(resolved)
            resolved = urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, sp.query, ""))
            if not re.match(r"^https?://", resolved, re.I):
                return False
            if has_doc_extension(resolved):
                key = normalize_key(resolved)
                if is_casper_host(sp.netloc) or is_approved_revize_casper_url(resolved):
                    is_new = key not in discovered
                    if is_new:
                        discovered[key] = {"url": resolved, "source": source}
                    return is_new
                # Unapproved external document link: record once without ever requesting it.
                if key not in docs_by_key:
                    docs_by_key[key] = {
                        "url": resolved,
                        "status": "external_skipped",
                        "fetched_at": now_iso(),
                        "error": "external host outside casperwy.gov scope",
                        "source": source,
                    }
            return False

        # ---- 1. Sitemap discovery (supports <sitemapindex>, child sitemaps, .xml.gz) ----
        sitemaps_fetched = 0
        locs_total = 0
        sitemap_doc_locs = 0
        sitemap_non_doc_skipped = 0
        sitemap_errors: list[str] = []
        html_pages_ordered: list[str] = []
        html_pages_seen: set[str] = set()

        if not args.no_sitemap and not args.headline_only:
            sitemap_queue: deque[str] = deque()
            visited_sitemaps: set[str] = set()
            for seed_sm in [SITEMAP_URL] + robots_sitemaps:
                sm_key = normalize_page_key(seed_sm)
                if sm_key not in visited_sitemaps:
                    visited_sitemaps.add(sm_key)
                    sitemap_queue.append(seed_sm)

            while sitemap_queue and not check_budget():
                sm_url = sitemap_queue.popleft()
                if not client.robots_allowed(sm_url, allow_approved_revize=False):
                    sitemap_errors.append(f"{sm_url}: disallowed by robots.txt")
                    continue
                print(f"[*] Fetching sitemap {sm_url}")
                try:
                    _, _, sm_bytes, final_sm_url, _ = client.fetch_raw(
                        sm_url,
                        max_bytes=MAX_SITEMAP_BYTES,
                        timeout=60,
                        accept="application/xml,text/xml,*/*;q=0.8",
                        allow_approved_revize=False,
                    )
                    sitemaps_fetched += 1
                    xml_text = decode_xml_bytes(sm_bytes)
                    root = ET.fromstring(xml_text)
                    root_tag = root.tag.lower()
                    if root_tag.endswith("sitemapindex"):
                        child_locs = [
                            el.text.strip()
                            for el in root.iter()
                            if el.tag.lower().endswith("loc") and el.text and el.text.strip()
                        ]
                        print(f"[*] Sitemap index {sm_url} listed {len(child_locs)} child sitemaps")
                        for child in child_locs:
                            child_resolved = urllib.parse.urljoin(final_sm_url, child)
                            if is_casper_host(urllib.parse.urlsplit(child_resolved).netloc):
                                c_key = normalize_page_key(child_resolved)
                                if c_key not in visited_sitemaps:
                                    visited_sitemaps.add(c_key)
                                    sitemap_queue.append(child_resolved)
                    else:
                        locs = [
                            el.text.strip()
                            for el in root.iter()
                            if el.tag.lower().endswith("loc") and el.text and el.text.strip()
                        ]
                        locs_total += len(locs)
                        sm_label = urllib.parse.urlsplit(final_sm_url).path.lstrip("/") or "sitemap.xml"
                        for loc in locs:
                            loc_resolved = urllib.parse.urljoin(final_sm_url, loc)
                            if is_document_url(loc_resolved):
                                sitemap_doc_locs += 1
                                register_candidate_url(loc_resolved, sm_label, final_sm_url)
                            elif is_html_candidate_url(loc_resolved):
                                p_key = normalize_page_key(loc_resolved)
                                if p_key not in html_pages_seen:
                                    html_pages_seen.add(p_key)
                                    html_pages_ordered.append(loc_resolved)
                            else:
                                register_candidate_url(loc_resolved, sm_label, final_sm_url)
                                sitemap_non_doc_skipped += 1
                        print(
                            f"[*] Sitemap {sm_label}: {len(locs)} URLs "
                            f"({len(discovered)} Casper documents, {len(html_pages_ordered)} HTML pages queued so far)"
                        )
                except Exception as exc:
                    msg = f"{sm_url}: {exc}"
                    print(f"[!] Sitemap fetch/parse failed ({msg})")
                    sitemap_errors.append(msg)

        # ---- Helper: scan one HTML page for document links ----
        pages_scanned_this_run = 0
        page_scan_errors: list[str] = []

        def scan_html_page(page_url: str, source_label: str) -> list[str]:
            """Fetch an HTML page on casperwy.gov politely, extract document links, never save HTML."""
            nonlocal pages_scanned_this_run
            newly_added_keys: list[str] = []
            p_key = normalize_page_key(page_url)
            if not client.robots_allowed(page_url, allow_approved_revize=False):
                print(f"[robots] Disallowed HTML page — skipping {page_url}")
                scanned_pages.add(p_key)
                return newly_added_keys
            print(f"[*] Scanning page {page_url}")
            try:
                _, headers, body, final_url, _ = client.fetch_raw(
                    page_url,
                    max_bytes=MAX_HTML_BYTES,
                    timeout=45,
                    accept="text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                    allow_approved_revize=False,
                    html_only=True,
                )
                pages_scanned_this_run += 1
                scanned_pages.add(p_key)
                scanned_pages.add(normalize_page_key(final_url))
                if not body:
                    return newly_added_keys
                charset = "utf-8"
                ctype_raw = headers.get("Content-Type") or ""
                m_cs = re.search(r"charset=([\w\-]+)", ctype_raw, re.I)
                if m_cs:
                    charset = m_cs.group(1)
                try:
                    html_text = body.decode(charset, "replace")
                except LookupError:
                    html_text = body.decode("utf-8", "replace")
                parser = PageLinkParser()
                parser.feed(html_text)
                effective_base = (
                    urllib.parse.urljoin(final_url, parser.base_href)
                    if parser.base_href
                    else final_url
                )
                before_keys = set(discovered.keys())
                for raw_href in parser.raw_links:
                    register_candidate_url(raw_href, source_label, effective_base)
                newly_added_keys = sorted(set(discovered.keys()) - before_keys)
            except Exception as exc:
                scanned_pages.add(p_key)
                err_msg = f"{page_url}: {exc}"
                print(f"[!] Page scan failed ({err_msg})")
                page_scan_errors.append(err_msg)
            return newly_added_keys

        # ---- 2. Explicit seed: City Council documents page ----
        if not check_budget():
            scan_html_page(HEADLINE_PAGE, "documents.php")
            print(f"[*] After council documents page: {len(discovered)} unique Casper documents known")

        # ---- Helper: download one discovered document ----
        checkpoint_counter = 0

        def save_checkpoint(pages_remaining_est: int) -> None:
            manifest["site_map"] = {
                "sitemaps_fetched": sitemaps_fetched,
                "locs_total": locs_total or manifest.get("site_map", {}).get("locs_total", 0),
                "sitemap_document_locs": sitemap_doc_locs,
                "sitemap_html_pages": len(html_pages_ordered),
                "sitemap_non_doc_skipped": sitemap_non_doc_skipped,
                "html_pages_scanned_total": len(scanned_pages),
                "html_pages_scanned_this_run": pages_scanned_this_run,
                "html_pages_remaining": pages_remaining_est,
                "documents_found": len(discovered),
                "sitemap_errors": sitemap_errors,
                "page_scan_errors": page_scan_errors,
            }
            manifest["documents"] = list(docs_by_key.values())
            write_outputs(manifest, manifest_path, markdown_path)

        def process_document_key(key: str, retry_failed: bool = False) -> None:
            nonlocal new_count, new_bytes, skipped_count, checkpoint_counter
            if key in tried_this_run:
                return
            entry = discovered[key]
            url = entry["url"]
            existing = docs_by_key.get(key)
            if existing:
                st = existing.get("status")
                if st == "archived" and existing.get("local_path") and Path(existing["local_path"]).exists():
                    skipped_count += 1
                    tried_this_run.add(key)
                    return
                if st in ("oversized", "external_skipped", "robots_refused"):
                    tried_this_run.add(key)
                    return
                if st == "failed" and not retry_failed:
                    return

            if check_budget():
                if key not in docs_by_key:
                    docs_by_key[key] = {
                        "url": url,
                        "status": "pending",
                        "fetched_at": now_iso(),
                        "error": f"deferred ({stop_reason})",
                        "source": entry["source"],
                    }
                return

            tried_this_run.add(key)
            if not client.robots_allowed(url, allow_approved_revize=True):
                print(f"[robots] Disallowed — skipping {url}")
                docs_by_key[key] = {
                    "url": url,
                    "status": "robots_refused",
                    "fetched_at": now_iso(),
                    "error": "disallowed by robots.txt",
                    "source": entry["source"],
                }
                return

            print(f"[*] Downloading {url}")
            try:
                _, headers, body, final_url, redirect_chain = client.fetch_raw(
                    url,
                    max_bytes=args.max_bytes,
                    timeout=90,
                    accept="*/*",
                    allow_approved_revize=True,
                )
                ctype = headers.get("Content-Type", "")
                if looks_like_html_error_page(ctype, body):
                    raise RuntimeError(f"server returned HTML ({ctype or 'html body'}) instead of original document")
                content_len = len(body)
                local = local_path(url, buckets_used, args.output_dir)
                target = Path(local)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
                record = {
                    "url": url,
                    "final_url": final_url,
                    "local_path": local,
                    "bytes": content_len,
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "content_type": ctype,
                    "status": "archived",
                    "fetched_at": now_iso(),
                    "source": entry["source"],
                }
                if redirect_chain:
                    record["redirect_chain"] = redirect_chain
                docs_by_key[key] = record
                new_count += 1
                new_bytes += content_len
            except OversizedDocumentError as exc:
                docs_by_key[key] = {
                    "url": url,
                    "status": "oversized",
                    "fetched_at": now_iso(),
                    "error": str(exc),
                    "source": entry["source"],
                }
            except RobotsDisallowedError as exc:
                docs_by_key[key] = {
                    "url": url,
                    "status": "robots_refused",
                    "fetched_at": now_iso(),
                    "error": str(exc),
                    "source": entry["source"],
                }
            except ExternalRedirectError as exc:
                docs_by_key[key] = {
                    "url": url,
                    "status": "external_skipped",
                    "fetched_at": now_iso(),
                    "error": str(exc),
                    "source": entry["source"],
                }
            except Exception as exc:
                docs_by_key[key] = {
                    "url": url,
                    "status": "failed",
                    "fetched_at": now_iso(),
                    "error": str(exc),
                    "source": entry["source"],
                }

            checkpoint_counter += 1
            if checkpoint_counter % 25 == 0 and not args.dry_run:
                rem = sum(1 for p in html_pages_ordered if normalize_page_key(p) not in scanned_pages)
                save_checkpoint(rem)

        # ---- 3. Dry-run shortcut ----
        if args.dry_run:
            if not args.headline_only and not args.no_page_scan:
                for p_url in html_pages_ordered:
                    if check_budget():
                        break
                    if normalize_page_key(p_url) in scanned_pages:
                        continue
                    rel_label = urllib.parse.urlsplit(p_url).path.lstrip("/") or "index"
                    scan_html_page(p_url, rel_label)
            for key, entry in sorted(discovered.items()):
                existing = docs_by_key.get(key)
                suffix = " [already archived]" if existing and existing.get("status") == "archived" else ""
                print(f"[dry-run] {entry['url']}{suffix}")
            return 0

        # ---- 4. Download already-discovered pending documents first ----
        for key in sorted(discovered.keys()):
            process_document_key(key, retry_failed=False)

        # ---- 5. Scan remaining sitemap HTML pages & download newly discovered documents ----
        if not args.headline_only and not args.no_page_scan:
            for p_url in html_pages_ordered:
                if check_budget():
                    break
                if normalize_page_key(p_url) in scanned_pages:
                    continue
                rel_label = urllib.parse.urlsplit(p_url).path.lstrip("/") or "index"
                new_keys = scan_html_page(p_url, rel_label)
                for key in new_keys:
                    process_document_key(key, retry_failed=False)
                checkpoint_counter += 1
                if checkpoint_counter % 25 == 0:
                    rem = sum(1 for p in html_pages_ordered if normalize_page_key(p) not in scanned_pages)
                    save_checkpoint(rem)

        # ---- 6. Retry previously failed documents if budget still remains ----
        if not check_budget():
            for key in sorted(discovered.keys()):
                if check_budget():
                    break
                process_document_key(key, retry_failed=True)

        # Ensure every discovered document has a manifest entry (mark unattempted ones as pending).
        for key, entry in sorted(discovered.items()):
            if key not in docs_by_key:
                docs_by_key[key] = {
                    "url": entry["url"],
                    "status": "pending",
                    "fetched_at": now_iso(),
                    "error": f"deferred ({stop_reason or 'not reached in run'})",
                    "source": entry["source"],
                }

        pages_remaining = (
            0
            if (args.headline_only or args.no_page_scan)
            else sum(1 for p in html_pages_ordered if normalize_page_key(p) not in scanned_pages)
        )
        pending_remaining = sum(1 for d in docs_by_key.values() if d.get("status") == "pending")
        sweep_complete = (stop_reason is None) and (pages_remaining == 0) and (pending_remaining == 0)

        manifest["site_map"] = {
            "sitemaps_fetched": sitemaps_fetched,
            "locs_total": locs_total or manifest.get("site_map", {}).get("locs_total", 0),
            "sitemap_document_locs": sitemap_doc_locs,
            "sitemap_html_pages": len(html_pages_ordered),
            "sitemap_non_doc_skipped": sitemap_non_doc_skipped,
            "html_pages_scanned_total": len(scanned_pages),
            "html_pages_scanned_this_run": pages_scanned_this_run,
            "html_pages_remaining": pages_remaining,
            "documents_found": len(discovered),
            "sitemap_errors": sitemap_errors,
            "page_scan_errors": page_scan_errors,
        }
        manifest["run_budget"] = {
            "delay_seconds": client.delay,
            "max_bytes_per_file": args.max_bytes,
            "max_seconds": args.max_seconds,
            "max_new_documents": args.max_new,
            "max_requests": args.max_requests,
            "max_run_bytes": args.max_run_bytes,
            "elapsed_seconds": round(time.monotonic() - start_mono, 1),
            "requests_made": client.requests_made,
            "requeued_external_skipped": requeued_count,
            "new_documents_archived": new_count,
            "new_bytes_archived": new_bytes,
            "skipped_already_archived": skipped_count,
            "budget_reached": stop_reason is not None,
            "stop_reason": stop_reason,
            "needs_resume": not sweep_complete,
        }
        manifest["crawl_state"] = {
            "sweep_complete": sweep_complete,
            "scanned_pages": sorted(scanned_pages),
        }
        manifest["documents"] = list(docs_by_key.values())
        write_outputs(manifest, manifest_path, markdown_path)

        print(
            f"[done] requeued={requeued_count} new={new_count} ({new_bytes / 1024 / 1024:.2f} MiB) "
            f"skipped={skipped_count} requests={client.requests_made} "
            f"pages_remaining={pages_remaining} pending_docs={pending_remaining} "
            f"needs_resume={not sweep_complete}"
        )
        print(f"[done] summary: {json.dumps(manifest['summary'], sort_keys=True)}")
        return 0
    finally:
        signal.signal(signal.SIGINT, prev_sigint)
        signal.signal(signal.SIGTERM, prev_sigterm)


if __name__ == "__main__":
    sys.exit(main())
