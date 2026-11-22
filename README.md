# casper-record-mirror
Archive of publicly accessible Casper, Wyoming municipal documents from casperwy.gov, with a sitemap-driven collection workflow and provenance manifests.

This is a **public-records mirror**, not an official City of Casper site. Every
file here was published on [casperwy.gov](https://www.casperwy.gov) for the public,
and is archived as the original binary with its source URL, download time, and
SHA-256 hash so a reader can verify provenance. Not affiliated with the City of
Casper.

## What is in this repo

- `documents/` — original public documents collected from `casperwy.gov`, path-preserved and hashed.
- `manifest.json` — machine-readable provenance, discovery counts, crawl state, and per-document status.
- `MANIFEST.md` — human-readable coverage summary generated on each run.
- `collect.py` — the polite crawler (`robots.txt`-aware, custom `User-Agent`, ≥3.0 s between requests, zero concurrency, `casperwy.gov` documents only).
- `RUN-ON-ACCESS.md` — installation provenance and operations runbook.

## Politeness contract

This is a municipal site. The crawler:

- reads and honors `robots.txt` (including `Disallow`, `Sitemap`, and `crawl-delay`) for every contacted host;
- identifies itself with a custom `User-Agent` (`casper-record-mirror/1.0`);
- waits at least 3.0 seconds between sequential requests (and honors any larger `crawl-delay` declared by a contacted host), with no concurrency;
- archives original public document binaries only — no media/images or HTML pages are stored in `documents/`;
- validates every redirect hop, allowing document downloads only from `casperwy.gov` and Casper's official Revize document-storage path prefix `https://cms2.revize.com/revize/casperwy/` (blocking all other `revize.com` hosts/tenants, non-HTTPS schemes, `..` traversal, and arbitrary external destinations);
- is resumable and idempotent (documents already archived on disk and recorded in `manifest.json` are skipped).

## Coverage & scope

See `MANIFEST.md` and `manifest.json` for exact discovery counts, archived byte totals, and bucket breakdowns.

- **In scope:** documents listed directly in `casperwy.gov` sitemaps (including `<sitemapindex>` child sitemaps), document links discovered on sitemap-listed `casperwy.gov` HTML pages, and documents linked from the City Council documents page (`https://www.casperwy.gov/government/city_council/documents.php`), including official HTTP redirects strictly under `https://cms2.revize.com/revize/casperwy/`. Unlinked files on the origin server outside sitemaps and linked pages are outside discovery scope.
- **Recorded exclusions & errors:** documents that fail (`failed`), exceed the 50 MiB per-file limit (`oversized`), are disallowed by `robots.txt` (`robots_refused`), point or redirect outside the approved Casper scope (`external_skipped`), or await a follow-up run (`pending`) are explicitly listed in `manifest.json` and `MANIFEST.md`; nothing is silently dropped.

## How it runs

The workflow in `.github/workflows/collect.yml` is manual-only
(`workflow_dispatch`). Each run:

1. fetches `robots.txt` and walks `sitemap.xml` (plus any child sitemaps),
2. scans the City Council documents page and sitemap-listed `casperwy.gov` HTML pages for document links,
3. downloads original documents politely within a 45-minute graceful budget (`--max-seconds 2700`, inside the 60-minute job timeout) and checkpoints state to `manifest.json` and `MANIFEST.md`,
4. commits `documents/`, `manifest.json`, and `MANIFEST.md` back to `main`.

If `MANIFEST.md` / `manifest.json` reports `needs_resume: true`, re-dispatch the
workflow manually to continue where the previous committed run stopped. (Note: a
hard GitHub Actions timeout or manual cancellation before the commit step does
not preserve uncommitted progress, which is why `--max-seconds 2700` stops
gracefully with headroom to commit.)

## Source & provenance

- **Site:** https://www.casperwy.gov
- **Sitemap:** https://www.casperwy.gov/sitemap.xml
- **Council documents page:** https://www.casperwy.gov/government/city_council/documents.php
- **Implementation origin:** installed from staged package in [`bartimoussmith-oss/therealwindycity`](https://github.com/bartimoussmith-oss/therealwindycity), branch `arena/98140dbd-therealwindycity` (PR [#44](https://github.com/bartimoussmith-oss/therealwindycity/pull/44)), commit `88704592a5c39f0efa038a9e3197ad705510c2e9` (see `RUN-ON-ACCESS.md` for installation notes).

## License

Content is a mirror of public records published by the City of Casper, WY.
No claim of endorsement by the City. Use freely for inspection and accountability;
re-publish specific documents from their original source for citation.
