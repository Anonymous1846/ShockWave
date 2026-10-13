#!/usr/bin/env python3
"""Head-to-head GraphQL-scanner comparison harness.

Runs ShockWave and competitor tools (graphql-cop, graphw00f, clairvoyance)
against a target (DVGA by default), scores each against ground_truth.json, and
writes benchmark/RESULTS.md.

Usage:
    python benchmark/compare.py --target http://localhost:5013/graphql
    python benchmark/compare.py --target ... --auth-a "Authorization: Bearer A" --auth-b "..."
    python benchmark/compare.py --skip-install          # don't pip-install competitors

Defensive by design: a tool that is missing, errors, or emits an unexpected
format is reported as such instead of aborting the run.
"""
import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request

# Windows consoles default to cp1252 and choke on the ✅/❌ in the report.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GROUND_TRUTH = os.path.join(HERE, "ground_truth.json")
WORDLIST = os.path.join(ROOT, "shockwave", "data", "wordlist.txt")
RESULTS = os.path.join(HERE, "RESULTS.md")

# Shared category vocabulary every tool's findings normalize into.
CATEGORIES = [
    "introspection", "suggestions", "auth_bypass", "idor",
    "dos", "rate_bypass", "injection", "fingerprint",
]

# ShockWave rule-id prefix -> category.
SHOCKWAVE_PREFIX = {
    "SHOCKWAVE-CONF-001": "introspection",
    "SHOCKWAVE-CONF-002": "suggestions",
    "SHOCKWAVE-AUTH": "auth_bypass",
    "SHOCKWAVE-IDOR": "idor",
    "SHOCKWAVE-DOS": "dos",
    "SHOCKWAVE-RATE": "rate_bypass",
    "SHOCKWAVE-INJ": "injection",
}

# graphql-cop finding titles (substring, lowercased) -> category.
COP_MAP = {
    "introspection": "introspection",
    "field suggestion": "suggestions",
    "alias": "rate_bypass",
    "batch": "rate_bypass",
    "array-based": "rate_bypass",
    "deep recursion": "dos",
    "circular": "dos",
    "directive overloading": "dos",
    "get method": "injection",      # cop's GET/CSRF -> closest shared bucket
    "post based": "injection",
}


def shourie(cmd, timeout=180):
    """Run a command, return (ok, stdout, stderr, seconds). Never raises."""
    start = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return True, p.stdout, p.stderr, time.time() - start
    except FileNotFoundError:
        return False, "", "tool not installed", time.time() - start
    except subprocess.TimeoutExpired:
        return False, "", f"timeout after {timeout}s", time.time() - start
    except Exception as e:  # noqa: BLE001 - harness must not crash
        return False, "", str(e), time.time() - start


def _module_cmd(mod):
    """Return `[python, -m, mod]` if the module is importable, else None."""
    try:
        if importlib.util.find_spec(mod) is not None:
            return [sys.executable, "-m", mod]
    except Exception:
        pass
    return None


def _competitor_cmd(name, module=None):
    """Resolve how to invoke a competitor: module first (works with --user
    installs where Scripts isn't on PATH), then a console script on PATH."""
    if module:
        cmd = _module_cmd(module)
        if cmd:
            return cmd
    exe = shutil.which(name)
    return [exe] if exe else None


GRAPHQL_COP_SCRIPT = os.path.join(HERE, ".tools", "graphql-cop", "graphql-cop.py")
# graphw00f ships only on GitHub; the PyPI name is a dependency-confusion
# placeholder, so we deliberately use the cloned repo's entrypoint.
GRAPHW00F_SCRIPT = os.path.join(HERE, ".tools", "graphw00f", "main.py")


def target_up(url):
    body = json.dumps({"query": "query { __typename }"}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status < 500
    except Exception:
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                return r.status < 500
        except Exception:
            return False


# ---- tool runners: each returns dict(name, categories:set, total:int, seconds, note) ----

def run_shockwave(url, auth_a, auth_b, tmp):
    out_dir = os.path.join(tmp, "sw")
    cmd = [sys.executable, "-m", "shockwave.cli.main", "scan", url,
           "--output", "json", "--output-dir", out_dir,
           "--fail-on", "never", "--rate-limit", "0"]
    if auth_a:
        cmd += ["--auth-a", auth_a]
    if auth_b:
        cmd += ["--auth-b", auth_b]
    ok, out, err, secs = shourie(cmd, timeout=300)
    cats, total, rule_ids = set(), 0, []
    findings_path = os.path.join(out_dir, "shockwave-findings.json")
    if os.path.exists(findings_path):
        try:
            data = json.load(open(findings_path, encoding="utf-8"))
            total = len(data)
            for f in data:
                rid = f.get("rule_id", "")
                rule_ids.append(rid)
                cat = SHOCKWAVE_PREFIX.get(rid) or next(
                    (c for p, c in SHOCKWAVE_PREFIX.items() if rid.startswith(p)), None)
                if cat:
                    cats.add(cat)
        except Exception as e:
            return dict(name="ShockWave", categories=cats, total=0, seconds=secs,
                        note=f"ran, unparsed ({e})", rule_ids=[])
    note = "" if total else (err.strip().splitlines()[-1] if err.strip() else "no findings file")
    return dict(name="ShockWave", categories=cats, total=total, seconds=secs,
                note=note, rule_ids=rule_ids)


def run_graphql_cop(url, tmp):
    base = _competitor_cmd("graphql-cop", "graphql_cop")
    if not base and os.path.exists(GRAPHQL_COP_SCRIPT):
        base = [sys.executable, GRAPHQL_COP_SCRIPT]
    if not base:
        return dict(name="graphql-cop", categories=set(), total=0, seconds=0, note="not installed")
    # Try JSON output; fall back to plain text parsing.
    for flag in (["-o", "json"], ["--format", "json"], []):
        ok, out, err, secs = shourie([*base, "-t", url, *flag], timeout=180)
        text = (out or "") + (err or "")
        cats, total = set(), 0
        parsed = None
        try:
            parsed = json.loads(out)
        except Exception:
            parsed = None
        blob = ""
        if isinstance(parsed, list):
            total = len(parsed)
            blob = json.dumps(parsed).lower()
        else:
            blob = text.lower()
            total = blob.count("[high]") + blob.count("[medium]") + blob.count("[low]")
        for needle, cat in COP_MAP.items():
            if needle in blob:
                cats.add(cat)
        if cats or total:
            return dict(name="graphql-cop", categories=cats, total=max(total, len(cats)),
                        seconds=secs, note="")
    return dict(name="graphql-cop", categories=set(), total=0, seconds=secs, note="ran, no parse")


def run_graphw00f(url):
    if not os.path.exists(GRAPHW00F_SCRIPT):
        return dict(name="graphw00f", categories=set(), total=0, seconds=0,
                    note="not cloned (git clone dolevf/graphw00f into benchmark/.tools)", engine=None)
    ok, out, err, secs = shourie([sys.executable, GRAPHW00F_SCRIPT, "-f", "-d", "-t", url], timeout=120)
    text = (out or "") + (err or "")
    m = re.search(r"Discovered GraphQL Engine:\s*\(?([^)\n]+)\)?", text)
    engine = m.group(1).strip() if m else None
    cats = {"fingerprint"} if engine else set()
    return dict(name="graphw00f", categories=cats, total=1 if engine else 0,
                seconds=secs, note="" if engine else "no engine matched", engine=engine)


def run_clairvoyance(url, tmp):
    base = _competitor_cmd("clairvoyance", "clairvoyance")
    if not base:
        return dict(name="clairvoyance", categories=set(), total=0, seconds=0,
                    note="not installed", fields=0)
    out_path = os.path.join(tmp, "clair.json")
    cmd = [*base, url, "-o", out_path]
    if os.path.exists(WORDLIST):
        cmd += ["-w", WORDLIST]
    ok, out, err, secs = shourie(cmd, timeout=240)
    fields = 0
    if os.path.exists(out_path):
        try:
            data = json.load(open(out_path, encoding="utf-8"))
            types = data.get("data", {}).get("__schema", {}).get("types", []) or data.get("__schema", {}).get("types", [])
            fields = sum(len(t.get("fields") or []) for t in types)
        except Exception:
            pass
    note = "introspection ON: blind recovery not exercised"
    return dict(name="clairvoyance", categories=set(), total=fields, seconds=secs,
                note=note, fields=fields)


def _gt_category(rule_id):
    """Map a ground-truth rule_id to its shared category (exact, then prefix)."""
    if rule_id in SHOCKWAVE_PREFIX:
        return SHOCKWAVE_PREFIX[rule_id]
    return next((c for p, c in SHOCKWAVE_PREFIX.items() if rule_id.startswith(p)), None)


def score_vs_ground_truth(shockwave_result):
    """Recall of ShockWave against the planted ground truth.

    A ground-truth item counts as detected only if ShockWave produced a finding
    in the SAME category (or the exact rule_id). Matching by category — not a
    loose rule-id prefix — stops CONF-001 from masking a missed CONF-002.
    """
    gt = json.load(open(GROUND_TRUTH, encoding="utf-8"))
    found_ids = set(shockwave_result.get("rule_ids", []))
    sw_cats = shockwave_result.get("categories", set())
    detected, missed = [], []
    for g in gt:
        rid = g["rule_id"]
        cat = _gt_category(rid)
        if rid in found_ids or (cat and cat in sw_cats):
            detected.append(rid)
        else:
            missed.append(rid)
    recall = len(detected) / len(gt) if gt else 0.0
    return gt, detected, missed, recall


def write_report(url, results, gt, detected, missed, recall, gw_engine, sw_engine):
    def cell(r, cat):
        return "✅" if cat in r["categories"] else "—"

    lines = []
    lines.append("# ShockWave Comparison Results\n")
    lines.append(f"- Target: `{url}`")
    lines.append(f"- Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("- Tools: ShockWave, graphql-cop, graphw00f, clairvoyance\n")

    lines.append("## Capability coverage\n")
    header = "| Tool | " + " | ".join(CATEGORIES) + " | total | time(s) |"
    sep = "|" + "---|" * (len(CATEGORIES) + 3)
    lines.append(header)
    lines.append(sep)
    for r in results:
        row = [r["name"]] + [cell(r, c) for c in CATEGORIES] + [str(r["total"]), f"{r['seconds']:.1f}"]
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")

    lines.append("## ShockWave recall vs ground truth\n")
    lines.append(f"**Recall: {len(detected)}/{len(gt)} = {recall*100:.0f}%**\n")
    lines.append("| Ground-truth rule | Detected |")
    lines.append("|---|---|")
    for g in gt:
        mark = "✅" if g["rule_id"] in detected else "❌"
        lines.append(f"| {g['rule_id']} — {g['rule_name']} ({g['location']}) | {mark} |")
    lines.append("")

    lines.append("## Fingerprint agreement\n")
    lines.append(f"- ShockWave: `{sw_engine or 'n/a'}`")
    lines.append(f"- graphw00f: `{gw_engine or 'n/a'}`")
    agree = "yes" if (sw_engine and gw_engine and sw_engine.split()[0].lower() in gw_engine.lower()) else "compare manually"
    lines.append(f"- Agreement: {agree}\n")

    lines.append("## Notes\n")
    for r in results:
        if r.get("note"):
            lines.append(f"- **{r['name']}**: {r['note']}")
    lines.append("- Request-count/WAF metric omitted: opaque for competitor binaries.")
    lines.append("- clairvoyance value is limited when introspection is enabled (DVGA default).")

    report = "\n".join(lines) + "\n"
    open(RESULTS, "w", encoding="utf-8").write(report)
    return report


def main():
    ap = argparse.ArgumentParser(description="GraphQL scanner comparison harness")
    ap.add_argument("--target", default="http://localhost:5013/graphql")
    ap.add_argument("--auth-a")
    ap.add_argument("--auth-b")
    ap.add_argument("--skip-install", action="store_true")
    args = ap.parse_args()

    if not args.skip_install:
        # Only these two are on PyPI; graphql-cop is GitHub-only (clone into
        # benchmark/.tools/graphql-cop). See benchmark/README.md.
        for pkg, mod in (("graphw00f", "graphw00f"), ("clairvoyance", "clairvoyance")):
            if _module_cmd(mod) is None:
                print(f"[*] installing {pkg} ...")
                subprocess.run([sys.executable, "-m", "pip", "install", "--user", pkg],
                               capture_output=True, text=True)

    if not target_up(args.target):
        print(f"[-] Target {args.target} unreachable. Start it first, e.g.:")
        print("    docker run -d -p 5013:5013 dolevf/dvga")
        print("    (or: python run_mock_target.py  then --target http://127.0.0.1:5080)")
        sys.exit(2)

    import tempfile
    tmp = tempfile.mkdtemp(prefix="gqlbench_")
    print(f"[*] Target up. Working dir: {tmp}")

    sw = run_shockwave(args.target, args.auth_a, args.auth_b, tmp)
    print(f"[+] ShockWave: {sw['total']} findings, {sw['seconds']:.1f}s")
    cop = run_graphql_cop(args.target, tmp)
    print(f"[+] graphql-cop: {cop['total']} findings, {cop['seconds']:.1f}s ({cop['note'] or 'ok'})")
    gw = run_graphw00f(args.target)
    print(f"[+] graphw00f: engine={gw.get('engine')}, {gw['seconds']:.1f}s")
    clair = run_clairvoyance(args.target, tmp)
    print(f"[+] clairvoyance: {clair.get('fields',0)} fields recovered, {clair['seconds']:.1f}s")

    results = [sw, cop, gw, clair]
    gt, detected, missed, recall = score_vs_ground_truth(sw)

    # Capture ShockWave's own fingerprint verdict (not in the JSON report) by
    # calling its engine directly, for a like-for-like compare with graphw00f.
    sw_engine = None
    try:
        import asyncio
        from shockwave.schema.fingerprint import fingerprint_engine
        eng, info = asyncio.run(fingerprint_engine(args.target))
        sw_engine = f"{eng} (confidence: {info.get('confidence')})"
    except Exception:
        sw_engine = None
    report = write_report(args.target, results, gt, detected, missed, recall,
                          gw.get("engine"), sw_engine)
    print(f"\n[*] Wrote {RESULTS}\n")
    print(report)


if __name__ == "__main__":
    main()
