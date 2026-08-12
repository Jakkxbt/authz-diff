# authz-diff — Adversarial Pass (pre-public)

Date: 2026-08-12 · Reviewer: Director (independent attack)

Threat model: a user-aimed HTTP tool. The concerns are **verdict correctness**
(a false CRITICAL → bad bounty submission; a false negative → missed IDOR),
**credential handling**, and **never firing at an unintended host**. Tested
against a local mock server (IDOR endpoint, properly-authz endpoint, and a
second user's own object) plus in-process parser fuzzing.

## Findings (all CONFIRMED with PoC, all FIXED + re-attacked)

| ID | Sev | Defect | Fix |
|----|-----|--------|-----|
| F-1 | MED | `--swap` did a global `url.replace` over the whole URL incl. the authority — `--swap 10=20` rewrote `api10.example.com`→`api20.example.com` (a different, possibly out-of-scope host) and corrupted the body. | `swap_ids` splits the URL and rewrites path/query/body only; never the scheme/host/port; warns to stderr if the id also appears in the host. |
| F-2 | MED | Swap mode compared each identity's fetch of a *different* object against the owner's *original* object → cross-object body-similarity is noise → misleading MEDIUM verdicts, and the summary contradicted the printed findings. | `classify(..., swapped=True)` is status-driven: any 2xx for a swapped id is a labeled "BOLA candidate — verify"; summary now counts MEDIUMs ("N to verify by hand"). |
| F-3 | LOW | `-o` output persisted URL-embedded credentials (`?api_key=…`) in plaintext; the "safe to dump" comment was only half-true. | `_redact_url` redacts credential-ish query params in every stored/echoed URL; auth headers and bodies were already never stored. |
| F-4 | LOW | Unguarded `open(args.output,"w")` → `FileNotFoundError` traceback on a bad path. | Guarded write → clean `[!] cannot write output file` error. |

## Not a finding
- CRLF/header injection via `--identity` value is blocked by the stdlib
  (`http.client` rejects newlines in header values) — returns a clean error.

## Verification
- Core same-object cross-identity detection unchanged: clean IDOR still
  CRITICAL (unauth) + HIGH (other user) at 100% identical; properly-authz
  endpoint correctly `OK` (403 denied). Raw-request (`-r`) mode verified.
- F-1: swap keeps the host intact, rewrites only the path; warns on host-id collision.
- F-2: second user's own object now reported as a status-driven BOLA candidate to
  verify, with a self-consistent summary.
- F-3: `api_key` redacted to `REDACTED` in the `-o` JSON.
- F-4: clean error, no traceback.
- Parser fuzz (raw requests, identities, swaps — empty/garbage/oversized/control chars):
  0 uncaught crashes.

## Documented residual (inherent, not a blocker)
Body-similarity can false-positive when a target serves an identical generic
page (SPA shell / login) to every identity; the tool reports similarity so the
operator can judge. AST/semantic diffing is a future enhancement, not a ship
blocker — same honest-signature-limits posture as the other tools.
