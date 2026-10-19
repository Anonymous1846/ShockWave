# ShockWave

ShockWave is an open-source command-line framework for automated **GraphQL API
security testing** — built for education and authorized/defensive testing.

It covers what most GraphQL scanners skip: field-level and object-level
authorization bypass (IDOR/BOLA), multi-role access-control matrices,
subscription (WebSocket) security, cross-user response diffing, injection,
denial-of-service, rate-limit bypass, schema drift, and engine fingerprinting —
with CI-native output (SARIF + exit codes).

> Use only against systems you are authorized to test.

## Why ShockWave

Measured head-to-head against the common open-source GraphQL tools on DVGA
(Damn Vulnerable GraphQL App). Full study: [`benchmark/COMPARISON.md`](benchmark/COMPARISON.md).

- **Only OSS GraphQL scanner that tests authorization.** Multi-role auth
  matrix, cross-user response diffing, and IDOR/BOLA — `graphql-cop`, `InQL`,
  `Clairvoyance`, `graphw00f` and `GraphQLmap` don't attempt object-level
  access testing. On DVGA, ShockWave is the only tool that reports IDOR.
- **Broadest coverage in one CI-native run** — auth + injection + IDOR + DoS +
  rate-bypass + subscriptions + schema-drift, emitting SARIF and `--fail-on`
  exit codes for pipelines.
- **Subscription / WebSocket security** — auth bypass + connection exhaustion,
  essentially unique in open source.
- **Lower false positives** — confidence tiers, re-verification, differential
  NoSQLi, and IDOR that requires cross-user evidence.
- **Accurate engine fingerprinting** — scored signatures over error text,
  response headers and introspection markers (benchmark-confirmed: correctly
  identifies DVGA as Graphene with high confidence).
- **Extensible** — drop in custom checks via `--plugins` without forking.

Honest scope: ShockWave trades speed for breadth (a full scan is slower than a
recon-only tool like `graphql-cop`), does not yet do manual exploitation
(use Burp/InQL), and its SSRF check is heuristic. See the comparison for the
full weaknesses list.

## Requirements

- Python **3.10+**

## Install

```bash
git clone https://github.com/Anonymous1846/ShockWave.git
cd ShockWave
pip install -e .
```

This installs the `shockwave` command. (Or run without installing via
`python -m shockwave.cli.main ...`.)

## Quick start

```bash
# Full scan, human-readable summary
shockwave scan https://target/graphql

# With two auth contexts (enables cross-user diff + IDOR + a role matrix)
shockwave scan https://target/graphql \
  --auth-a "Authorization: Bearer <low-priv>" \
  --auth-b "Authorization: Bearer <high-priv>"

# CI mode: SARIF report, fail the build on any high+ finding
shockwave scan https://target/graphql \
  --output sarif,json --fail-on high
```

Auth is any header, so cookie / API-key / session targets work too — and
`--auth-a` is repeatable to combine headers (e.g. cookie + CSRF token):

```bash
shockwave scan https://target/graphql \
  --auth-a "Cookie: session=<id>" --auth-a "X-CSRF-Token: <tok>"
```

## Commands

| Command | Purpose |
|---|---|
| `scan <url>` | Run the full security scan (or a subset via `--scope`). |
| `schema <url>` | Fetch and print the schema only (`--output json\|sdl`). |
| `matrix <url> --auth-config f.yaml` | Build the multi-role authorization matrix (HTML/JSON). |
| `diff <url>` | Compare the live schema against the cached baseline (drift: types, args, deprecations). |
| `benchmark <url>` | Run every scanner against a target and tabulate real finding counts. |

## Key options (`scan`)

| Option | Default | Description |
|---|---|---|
| `--scope` | `full` | `full\|auth\|dos\|injection\|idor\|subscription\|config\|drift` |
| `--auth-a` / `--auth-b` | — | Auth header(s); two contexts enable diff/IDOR/matrix |
| `--auth-config` | — | YAML of named auth contexts (multi-role matrix) |
| `--output` | `sarif,console` | Any of `sarif,json,markdown,matrix,console` |
| `--fail-on` | `high` | Exit 1 at/above this severity (`critical\|high\|medium\|low\|never`) |
| `--rate-limit` | `20` | Max requests/sec (`0` = unlimited) |
| `--max-concurrency` | `1` | In-flight request bound; raise for multi-threaded targets |
| `--jitter` | `0` | Random per-request delay to blend traffic |
| `--test-mutations` | off | Also fuzz/diff mutations (has side effects — disposable targets only) |
| `--plugins DIR` | — | Load custom check modules |

## What it tests

Authorization (field-level, object-level/IDOR, multi-role matrix, cross-user
diff) · Injection (error- and time-based SQLi, differential NoSQLi, path
traversal, SSRF) · DoS (nested-depth, field breadth) · Rate-limit bypass
(alias overloading, array batching) · Subscriptions (auth bypass, connection
exhaustion) · Configuration (introspection, field suggestions) · Schema drift
(type/arg/deprecation changes) · Engine fingerprinting.

## Extending with plugins

```python
# myplugin.py  ->  shockwave scan <url> --plugins ./plugins
async def run(ctx):
    async with ctx.net.client() as client:
        ...
    return [ctx.Finding(...)]   # list of ShockwaveFinding
```

Loading a plugin executes its code — only use a directory you trust.

## Benchmark / comparison

Measured against DVGA (Damn Vulnerable GraphQL App). Verified results:

- **Unique coverage:** on DVGA, ShockWave is the only scanner that reports
  IDOR/BOLA; `graphql-cop`, `graphw00f` and `Clairvoyance` don't attempt
  object-level access testing.
- **Engine fingerprint:** correctly identifies DVGA as **Graphene** with high
  confidence (benchmark-confirmed) — `graphw00f`-grade on that target.
- **Recall vs ground truth (unauthenticated):** 4/6 on a clean run
  (introspection, field-suggestions, nested-DoS, SQLi); AUTH-001 needs auth
  contexts, RATE-001 is unit-validated.

> Caveat: DVGA is single-threaded and degrades under a combined multi-tool
> scan (the competitor canary alone slowed ~40×), so trust **per-tool runs on a
> fresh container** over a combined one. Full study, methodology and the honest
> weaknesses list: [`benchmark/COMPARISON.md`](benchmark/COMPARISON.md).

`benchmark/` holds the head-to-head harness (`compare.py`) and the DVGA ground
truth. Use a **fresh** DVGA container per run.

## Contributing

Contributions welcome via pull request — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
Commits must be DCO signed-off (`git commit -s`); the owner reviews every change
via [`CODEOWNERS`](.github/CODEOWNERS), and merged contributors are credited in
[`AUTHORS`](AUTHORS).

## License

Licensed under the **Apache License 2.0** — see [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE). You may use, modify, and redistribute ShockWave freely,
provided you keep the copyright attribution and state any changes you make to
the files. Copyright 2026 Sharath Sunil.
