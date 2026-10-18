# Deliverable Gate report: example-portal-docs

- **Candidate:** `20261018-161252-b142` (sha256 `0df3d6fe0611c85f…`)
- **Destination:** `github:example-client-org/portal-handover@main (private, as your-publishing-account)`
- **Audience:** Example Co. engineering team (external client)
- **Mode:** snapshot
- **Source:** `C:/Work/example-portal` at `d6720de5622c` (HEAD)
- **Working tree:** dirty, 1 changed/untracked path(s); 1 of them are NOT in the candidate (it is built from the commit)
- **Totals:** 7 file(s), 565 bytes included; 3 excluded

## Verdict: BLOCKED

At least one required check failed. This candidate cannot be approved.

| Check | Required | Result | Summary |
| --- | --- | --- | --- |
| paths | yes | **PASS** | 7 files, all inside the allowlist with no exclusion, traversal, symlink, collision or type problems. Allowlist entries matching nothing: LICENSE. |
| secrets | yes | **PASS** | gitleaks 8.30.1 (default rules, candidate config/ignores/allow-comments disregarded): no findings. Binary files are not meaningfully scanned. |
| sensitive | yes | **PASS** | no flags (built-in rules + 2 custom pattern(s) + 1 custom path rule(s); binary files not inspected). |
| links | yes | **FAIL** | 1 of 4 relative link(s)/image(s) broken in the deliverable layout. |
| provenance | yes | **FAIL** | 1 provenance problem(s) across 1 rule(s). |
| binaries | yes | **INCOMPLETE** | 2 binary file(s) were not inspected by text-based checks (secrets, sensitive patterns, links). Uninspected is not safe: review them yourself. |
| lfs | yes | **PASS** | no LFS pointers or LFS filter declarations in the candidate. |
| destination | yes | **PASS** | example-client-org/portal-handover is private, pushable by your-publishing-account; branch main does not exist yet (first publish creates it). Commit author: Your Name <you@example.com>. |
| history | yes | **PASS** | snapshot mode: the candidate is published as one new commit on the destination branch. No source commits, history, tags or refs are pushed. |

## Findings

_File names and locations only. Matched text is never reproduced._

### links: FAIL

- `README.md` → `docs/api.md` target is not in the deliverable

### provenance: FAIL

- `docs/handover-guide.pdf` stale: input docs/handover-guide.md changed since the document was generated

### binaries: INCOMPLETE

- `docs/handover-guide.pdf` uninspected binary (14 bytes)
- `docs/img/architecture.png` uninspected binary (12 bytes)

## Changes since last approved candidate

_No previous approval: everything is new._

## Included files (7)

| Path | Size | SHA-256 | From | Note |
| --- | ---: | --- | --- | --- |
| `README.md` | 142 | `db6ad2031fd3` | HEAD |  |
| `docs/handover-guide.md` | 27 | `0554afceb960` | HEAD |  |
| `docs/handover-guide.pdf` | 14 | `e73513ce04bf` | HEAD |  |
| `docs/handover-guide.pdf.provenance.json` | 281 | `fcb017cee8bb` | HEAD |  |
| `docs/img/architecture.png` | 12 | `1b56b50ac4e9` | HEAD |  |
| `docs/setup.md` | 58 | `3dab8b0a50c4` | HEAD |  |
| `src/index.js` | 31 | `3f8fd2f21718` | HEAD | working copy differs; committed version used |

## Excluded files (3)

| Path | Reason |
| --- | --- |
| `correspondence/2026-09-12-kickoff.eml` | client correspondence |
| `docs/internal/rates.md` | internal notes, not for the client |
| `notes/meeting.txt` | not in allowlist |

---

Passing checks reduce risk; they do not guarantee the deliverable contains no confidential information. INCOMPLETE means not checked, never safe.
