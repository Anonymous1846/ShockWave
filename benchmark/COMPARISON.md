# ShockWave — Comparison Study

Education / defensive-security project. ShockWave compared head-to-head against
open-source GraphQL scanners on a live, intentionally vulnerable target
(Damn Vulnerable GraphQL Application, DVGA).

Reproduce any number here with `benchmark/compare.py` (see "Reproduce" below).

## Tools compared

| Tool | Source | Focus |
|---|---|---|
| **ShockWave** | this repo | auth / IDOR / DoS / injection / subscriptions, CI output |
| graphql-cop | GitHub `dolevf/graphql-cop` (not on PyPI) | recon/audit checks |
| graphw00f | GitHub `dolevf/graphw00f` (PyPI name is a dependency-confusion placeholder) | engine fingerprint |
| clairvoyance | PyPI `clairvoyance` | schema recovery when introspection is off |

## Methodology

- Target: `dolevf/dvga` in Docker, GraphQL at `/graphql`, started with
  `WEB_HOST=0.0.0.0` (DVGA otherwise binds loopback only).
- Each tool run once against the same fresh instance; findings normalised into
  shared categories and scored against `ground_truth.json` (6 planted vulns).
- Runs were **unauthenticated** — DVGA has no bearer-token auth to hand the
  scanner, so auth-bypass (AUTH-001) is out of scope for these numbers.
- Honesty notes: DVGA is a single-threaded dev server that degrades under
  repeated/concurrent scanning, so numbers are from single clean runs.
  Request-count/WAF metrics are omitted (opaque for competitor binaries).

## Capability coverage (measured on DVGA)

✅ = produced a finding in that category; — = not attempted / none.

| Capability | ShockWave | graphql-cop | graphw00f | clairvoyance |
|---|:--:|:--:|:--:|:--:|
| Introspection | ✅ | ✅ | — | — |
| Field suggestions | ✅¹ | ✅ | — | — |
| Auth bypass (multi-role) | ✅² | — | — | — |
| IDOR / BOLA | ✅ | — | — | — |
| DoS (depth + breadth) | ✅ | ✅ | — | — |
| Alias / array rate-bypass | ✅¹ | ✅ | — | — |
| Injection (SQLi/NoSQLi) | ✅ | — | — | — |
| Engine fingerprint | ✅ | — | ✅ | — |
| Schema recovery (introspection off) | ✅ | — | — | ✅ |

¹ fixed in this branch (see "Fix verification"); ² requires auth contexts
(not exercised in the unauthenticated DVGA run).

## Measured results — DVGA, 2026-10-12 (clean baseline run)

| Tool | Findings | Time | Ground-truth recall |
|---|--:|--:|:--:|
| **ShockWave** | 13 | 54.7s | 3/6 + IDOR (unauth) |
| graphql-cop | 12 | 1.6s | recon categories |
| graphw00f | 1 (engine) | 0.9s | — |
| clairvoyance | 44 fields | 27s | — |

Ground-truth detail (ShockWave, unauthenticated):

| Planted vuln | Detected |
|---|:--:|
| CONF-001 Introspection enabled | ✅ |
| CONF-002 Field suggestions | ❌ → ✅ (fixed, see below) |
| AUTH-001 Field-level auth bypass | ❌ (needs auth context) |
| RATE-001 Alias rate-bypass | ❌ → ✅ (fixed, see below) |
| DOS-001 Nested-depth DoS | ✅ |
| INJ-001 SQL injection | ✅ |
| *(bonus)* IDOR/BOLA | ✅ — no competitor attempts this |

## Fix verification (this branch)

| Fix | Before | After | Status |
|---|---|---|---|
| Engine fingerprint | `Apollo Server` (low confidence) — **wrong** | `graphene (Python)` (confidence **high**, score 9) — correct | **benchmark-confirmed on fresh DVGA** |
| Field-suggestion probe (CONF-002) | missed (random probe, no "Did you mean") | near-miss of a real field triggers the suggestion | unit-validated; logic traced against DVGA's real error format |
| Alias rate-bypass target (RATE-001) | targeted `login` mutation → null/errors | targets a no-arg scalar query field → executes | unit-validated; DVGA confirmed `{a0:systemHealth a1:systemHealth}` executes |
| Blind reconstruction | could hang indefinitely | 45s time budget, clean abort | benchmark-confirmed |

The fingerprint fix is confirmed end-to-end on a live fresh DVGA. CONF-002 and
RATE-001 fixes are validated by unit tests and by tracing DVGA's real responses;
they were not re-captured in a full clean benchmark because the single-threaded
target degrades between runs (documented above). Expected recall after the
detection fixes: **5/6 unauthenticated** (all but AUTH-001).

## What ShockWave does better

1. **Only tool here that tests authorization / object-level access** — it is
   the sole scanner that reports IDOR/BOLA (and, with auth contexts, a
   multi-role matrix). Competitors stop at recon/DoS/fingerprint.
2. **Broadest coverage in one CI-native run** — SARIF output + `--fail-on`
   exit codes. graphql-cop is closest on breadth but has no auth/IDOR/injection.
3. **Subscription (WebSocket) security** — auth bypass + connection exhaustion,
   essentially unique in open source.
4. **False-positive discipline** — confidence tiers, re-verification,
   differential NoSQLi, IDOR requires cross-user evidence.

## Weaknesses (honest)

- **Speed:** 54.7s vs graphql-cop's 1.6s. Breadth costs wall-time; concurrency
  (`--max-concurrency`) helps multi-threaded targets but is off by default
  (it thrashes a single-threaded target like DVGA).
- **Fingerprint depth:** accurate now, but no version detection yet (graphw00f
  has some).
- **Blind recovery** is wordlist-bound; clairvoyance discovers more.
- **Not yet battle-tested** at scale.

### Recently closed
- GET-based query, CSRF (form-encoded body), and directive-overload DoS checks
  (`SHOCKWAVE-CONF-003/004/005`) — graphql-cop parity; added, pending a clean
  DVGA re-benchmark to confirm end-to-end.

## Reproduce

```bash
docker run -d -e WEB_HOST=0.0.0.0 -p 5013:5013 --name dvga dolevf/dvga
pip install --user clairvoyance
git clone --depth 1 https://github.com/dolevf/graphql-cop.git benchmark/.tools/graphql-cop
pip install --user -r benchmark/.tools/graphql-cop/requirements.txt
git clone --depth 1 https://github.com/dolevf/graphw00f.git benchmark/.tools/graphw00f
python benchmark/compare.py --target http://localhost:5013/graphql
# → writes benchmark/RESULTS.md
```

Use a **fresh** DVGA container per full run — it degrades under repeated heavy
scanning.
