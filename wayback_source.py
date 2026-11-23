#!/usr/bin/env python3
"""Wayback Machine source for casper-record-mirror.

Replaces live-site discovery (sitemap.xml + HTML page scan) with the
Wayback Machine CDX index, so the target site's robots.txt is never
consulted by OUR crawler at all. Downloads come from web.archive.org,
not from casperwy.gov / cms2.revize.com.

Verified 2026-11-23 (CDX, collapse=urlkey, limit 100000):
  * casperwy.gov/*                : 23,589 unique URLs in CDX
  * casperwy.gov PDFs 2024-2026   : 4 unique URLs (documents now live on Revize)
  * cms2.revize.com/revize/casperwy/* : 3,026 unique URLs
  * Revize PDFs, all time         : 1,387 unique URLs
  * Revize PDFs, 2026             : 238 unique URLs
  * casperwy.gov/government/city_council/documents.php : 1 capture,
    2026-08-14 (24,364 bytes, status 200) -- HTML discovery via Wayback
    is therefore NOT viable; use CDX PDF enumeration instead.
  * Playback test 2026-11-23: Wayback replay of a Revize PDF
    (capture 2026-10-03, "RFP Washington Park / Fort Caspar ... Final.pdf")
    returned HTTP 200, 627,922 bytes, Content-Type application/pdf,
    valid PDF 1.7 -- replay works in practice for this target.

Robots policy -- read carefully, do NOT over-claim:
  * The Internet Archive stopped applying an origin site's robots.txt to
    Wayback crawling/display in April 2017 (general policy; US-gov/military
    first, then broader). Its Help Center still notes robots.txt may prevent
    crawling, and an explicit owner exclusion request still removes material.
  * The live Revize robots.txt is: Allow pdf/doc/docx/ppt/pptx/xml/txt,
    Disallow: / -- i.e. every non-document path is refused, which is why
    live discovery fails. Wayback nevertheless HOLDS 1,387 Revize PDF
    captures, so for PDF documents the archive is usable in practice.
  * What Wayback does NOT fix: (a) coverage gaps -- a document never
    captured by the Wayback crawler is not in CDX, and Save Page Now is
    rate-limited and may itself be blocked; (b) freshness -- the newest
    Revize PDF captures lag the live site by days to weeks; (c) legal
    clearance -- robots.txt is a technical preference, not a legal
    exemption; archived content remains third-party content under the
    Internet Archive's terms of use.
  * Consequence for E1 (robots policy): choosing the Wayback source does
    NOT require deciding to bypass robots.txt on the live site, because
    we never fetch the live site in --source wayback mode. It DOES require
    accepting that we are republishing snapshots the Archive collected
    under its own 2017 policy. That is a distinct decision; Charles must
    still approve it, but it is narrower than PR #33's blanket
    respect_robots=false for all 126 collectors.

Usage (as a module, imported by collect.py -- see the diff in the report):
    from wayback_source import enumerate_wayback_documents, wayback_url
    for rec in enumerate_wayback_documents(from_year="2024"):
        # rec: {original_url, wayback_timestamp, wayback_url, mimetype, statuscode}
        ...
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request

CDX_API = "https://web.archive.org/cdx/search/cdx"
WAYBACK_HOST = "https://web.archive.org"
USER_AGENT = "casper-record-mirror-wayback/1.0 (+https://github.com/bartimoussmith-oss/casper-record-mirror)"

# CDX URL patterns for Casper document sources. Revize is the live host
# for the documents; casperwy.gov itself holds almost no PDFs since 2024.
CDX_PATTERNS = [
    "cms2.revize.com/revize/casperwy/*",
    "casperwy.gov/*",
]

DOC_MIMETYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "text/plain",
    "text/csv",
}


def wayback_url(timestamp: str, original_url: str) -> str:
    """Replay URL that returns the archived bytes verbatim (id_ = no rewrite)."""
    return f"{WAYBACK_HOST}/web/{timestamp}id_/{original_url}"


def _cdx_query(url_pattern: str, from_year: str | None = None):
    params = {
        "url": url_pattern,
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest,length",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": "100000",
    }
    if from_year:
        params["from"] = from_year
    req = urllib.request.Request(
        CDX_API + "?" + urllib.parse.urlencode(params),
        headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=90) as r:
        rows = json.loads(r.read())
    return rows[1:]  # skip header row


def enumerate_wayback_documents(from_year: str = "2024"):
    """Yield one record per unique archived Casper document (PDF-first).

    Dedupes by original URL, keeping the NEWEST capture per URL.
    Only status-200 captures with a document mimetype or a document
    file extension are returned.
    """
    best: dict[str, dict] = {}
    for pattern in CDX_PATTERNS:
        for ts, original, status, mimetype, digest, length in _cdx_query(pattern, from_year):
            path = urllib.parse.urlsplit(original).path.lower()
            is_doc = (mimetype in DOC_MIMETYPES
                      or path.endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx",
                                        ".ppt", ".pptx", ".rtf", ".txt", ".csv", ".odt")))
            if not is_doc:
                continue
            key = original.split("?")[0].lower()
            if key not in best or ts > best[key]["wayback_timestamp"]:
                best[key] = {
                    "original_url": original,
                    "wayback_timestamp": ts,
                    "wayback_url": wayback_url(ts, original),
                    "statuscode": status,
                    "mimetype": mimetype,
                    "cdx_digest": digest,
                    "archived_bytes": int(length or 0),
                    "source": "wayback-cdx",
                }
    return sorted(best.values(), key=lambda r: r["original_url"])


def fetch_wayback_bytes(record: dict, timeout: int = 120) -> bytes:
    """Download one archived document from web.archive.org and verify
    it is not an error page: PDF magic %PDF-, or a plausible size for
    other types (Wayback error pages are small HTML)."""
    req = urllib.request.Request(record["wayback_url"], headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    if record["original_url"].lower().split("?")[0].endswith(".pdf"):
        if not data.startswith(b"%PDF-"):
            raise ValueError("Wayback replay did not return PDF bytes for "
                             + record["original_url"])
    if len(data) < 200:
        raise ValueError("Wayback replay suspiciously small (%d bytes) for %s"
                         % (len(data), record["original_url"]))
    return data


if __name__ == "__main__":
    docs = enumerate_wayback_documents(from_year="2026")
    print(f"{len(docs)} unique archived Casper documents from 2026")
    for d in docs[:10]:
        print(d["wayback_timestamp"], d["original_url"][:120])
