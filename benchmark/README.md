# ShockWave Comparison Benchmark

Runs ShockWave head-to-head against competitor GraphQL scanners on a live
target (DVGA by default), scores each against `ground_truth.json`, and writes
`RESULTS.md`.

## Tools compared

| Tool | Source | How the harness runs it |
|---|---|---|
| ShockWave | this repo | `python -m shockwave.cli.main scan` |
| graphql-cop | GitHub `dolevf/graphql-cop` (not on PyPI) | cloned to `.tools/graphql-cop` |
| graphw00f | GitHub `dolevf/graphw00f` (PyPI name is a dependency-confusion placeholder — do **not** `pip install graphw00f`) | cloned to `.tools/graphw00f` |
| clairvoyance | PyPI `clairvoyance` | `pip install --user clairvoyance` |

## Setup

1. Start Docker Desktop, then run DVGA:
   ```bash
   docker run -d -p 5013:5013 --name dvga dolevf/dvga
   ```
2. Install competitors (one-time):
   ```bash
   pip install --user clairvoyance
   git clone --depth 1 https://github.com/dolevf/graphql-cop.git benchmark/.tools/graphql-cop
   pip install --user -r benchmark/.tools/graphql-cop/requirements.txt
   git clone --depth 1 https://github.com/dolevf/graphw00f.git benchmark/.tools/graphw00f
   ```
3. Run the comparison:
   ```bash
   python benchmark/compare.py --target http://localhost:5013/graphql
   # optional auth for auth-bypass / IDOR categories:
   #   --auth-a "Authorization: Bearer <A>" --auth-b "Authorization: Bearer <B>"
   ```
4. Read `benchmark/RESULTS.md`.

## Notes / caveats

- **Auth/IDOR:** DVGA has no bearer-token auth model; its planted auth bug is
  that private pastes leak regardless of caller. Pass `--auth-a/--auth-b` only
  if your target actually uses header auth.
- **clairvoyance** recovers schemas when introspection is *off*; DVGA ships it
  *on*, so clairvoyance's value is limited there (reported as context).
- **Request-count / WAF metric** is omitted — it is opaque for competitor
  binaries, and a ShockWave-only column would be unfair.
- No live target? `python run_mock_target.py` then
  `--target http://127.0.0.1:5080` exercises the ShockWave path (competitors
  need a real engine and will report thin against the mock).
