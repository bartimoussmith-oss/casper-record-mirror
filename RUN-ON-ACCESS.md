# Casper, WY Mirror — Installation Provenance & Runbook

## Origin & traceability

This package was retrieved read-only from the staging repository and installed
at the root of [`bartimoussmith-oss/casper-record-mirror`](https://github.com/bartimoussmith-oss/casper-record-mirror):

- **Source repository:** `bartimoussmith-oss/therealwindycity` (`https://github.com/bartimoussmith-oss/therealwindycity`)
- **Source branch:** `arena/98140dbd-therealwindycity`
- **Source pull request:** [#44 — "Stage Casper, WY document mirror — crawler, workflow, runbook"](https://github.com/bartimoussmith-oss/therealwindycity/pull/44) (left untouched)
- **Source commit SHA:** `88704592a5c39f0efa038a9e3197ad705510c2e9`
- **Source staging path:** `casper-record-mirror/` (wrapper removed when installing at destination root)

### Minimal corrections applied during installation review

While preserving the staged architecture, CLI surface, 50 MiB per-file cutoff,
and strict politeness rules (≥3.0 s sequential delay, custom `User-Agent`,
`robots.txt` + `crawl-delay`, documents-only archiving), the following targeted
fixes were applied so the implementation matches its stated scope:

1. **Sitemap indexes & `.xml.gz` support:** `collect.py` now recursively walks
   `<sitemapindex>` child sitemaps on `casperwy.gov` (and `Sitemap:` entries in
   `robots.txt`), including gzipped sitemaps.
2. **Site-wide HTML page link discovery (`<base href>` aware):** Sitemap-listed
   `casperwy.gov` HTML pages are politely scanned for document links (resolving
   relative links against `<base href>` when present, or the page's own URL
   rather than hardcoding `documents.php`), while still never saving HTML pages
   or media to `documents/`.
3. **Safe URL encoding & collision tracking:** Request URLs percent-encode
   spaces/brackets/non-ASCII characters without double-encoding existing `%XX`
   sequences (preventing Python 3.12 `http.client.InvalidURL` errors on spaces),
   and `local_path` pre-populates existing archived paths on resume so collisions
   cannot overwrite prior files.
4. **Streaming size cap, soft-404 check & host boundary:** `Content-Length` and
   chunked streaming enforce the 50 MiB cap without buffering unbounded files;
   HTML soft-404 responses on document URLs are recorded as `failed`; external
   document links and external redirects are never requested and are recorded as
   `external_skipped`.
5. **Graceful run budget & true multi-run resume:** `.github/workflows/collect.yml`
   runs `python3 collect.py --delay 3.0 --max-new ... --max-seconds 2700` inside
   the 60-minute job timeout so runs exit cleanly at 45 minutes, persist
   `scanned_pages` and `pending` documents to `manifest.json` + `MANIFEST.md`,
   and commit progress. *(Note: a hard GitHub Actions runner timeout or
   cancellation before the commit step will NOT preserve uncommitted work.)*
6. **Narrowly scoped Revize Casper document-storage redirect rule:** Run #1
   (`5ead8af`) verified that 878/878 `https://www.casperwy.gov/<path>` document
   URLs redirect 1-to-1 to `https://cms2.revize.com/revize/casperwy/<path>`.
   `collect.py` validates every redirect hop and allows document downloads from
   exact `https://cms2.revize.com/revize/casperwy/<non-empty-path>` (rejecting
   HTTP, other `revize.com` hosts, other tenants on `cms2.revize.com`, `..`
   traversal, and any subsequent off-scope redirect), honors `robots.txt` and
   `crawl-delay` on each contacted host, records both `url` and `final_url` in
   provenance, and requeues qualifying prior `external_skipped` manifest entries
   without losing existing discovery state.

---

## Operating the mirror on `bartimoussmith-oss/casper-record-mirror`

### 1. Confirm workflow installation on `main`

```bash
gh api 'repos/bartimoussmith-oss/casper-record-mirror/contents/.github/workflows/collect.yml?ref=main' --jq '.sha'
```

### 2. Trigger a manual collection run

```bash
gh workflow run collect.yml \
  --repo bartimoussmith-oss/casper-record-mirror \
  --ref main
```

Or in GitHub UI: **Actions → Archive Casper WY documents → Run workflow** (on `main`).

### 3. Monitor the run

```bash
gh run list \
  --repo bartimoussmith-oss/casper-record-mirror \
  --workflow collect.yml \
  --limit 5

gh run watch <RUN_ID> \
  --repo bartimoussmith-oss/casper-record-mirror
```

### 4. Inspect coverage and check if another run is needed

After the run commits to `main`, check `MANIFEST.md` and `manifest.json`:

- `documents/` contains archived original binaries, path-preserved.
- `manifest.json` records SHA-256 hashes, byte counts, source URLs, discovery
  counts (`site_map`), run budget stats (`run_budget`), and non-archived items
  (`failed`, `oversized`, `robots_refused`, `external_skipped`, `pending`).
- If `run_budget.needs_resume` is `true` (for example, `max_seconds_reached` or
  `max_run_bytes_reached`), dispatch `collect.yml` again — it resumes from the
  committed `manifest.json` state without re-downloading archived files or
  re-scanning already-scanned pages in the active sweep.

## Politeness rules (do not weaken)

- Honors `robots.txt` (`Disallow` and `crawl-delay`, including float values).
- Waits ≥3.0 seconds between sequential requests (no concurrency).
- Uses custom `User-Agent`: `casper-record-mirror/1.0 (+https://github.com/bartimoussmith-oss/casper-record-mirror)`.
- Manual `workflow_dispatch` only — no scheduled cron or automatic triggers.
