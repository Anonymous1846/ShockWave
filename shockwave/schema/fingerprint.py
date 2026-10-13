import json
import os
from collections import defaultdict
from typing import Dict, Any, List, Tuple, Optional

from shockwave import net
from shockwave.schema.models import GraphQLSchema

# Resolve the absolute path to engine_matrix.json (the signature database).
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
MATRIX_PATH = os.path.join(DATA_DIR, "engine_matrix.json")

# Minimal built-in fallback so fingerprinting still works if the data file is
# missing. The JSON file is the real source of truth.
_FALLBACK_DB: Dict[str, Any] = {
    "Hasura": {
        "headers": {"x-hasura": 5},
        "extension_codes": {"validation-failed": 5, "parse-failed": 5},
        "error_substrings": {"query_root": 3},
        "introspection_types": {"query_root": 5},
    },
    "AWS AppSync": {
        "headers": {"x-amzn-requestid": 5},
        "extension_codes": {"__errortype__": 5},
    },
    "Apollo Server": {
        "extension_codes": {"graphql_parse_failed": 5, "graphql_validation_failed": 5},
        "error_substrings": {"cannot query field": 1},
    },
}

# Probe battery. Each probe is crafted so engines diverge in their error text,
# extension codes, or response headers. The *combination* of responses (scored
# against the DB) identifies the engine, rather than a single substring match.
PROBES: List[Dict[str, Any]] = [
    {"query": "query {"},                                    # syntax error
    {"query": "query { __non_existent_field_signature_probe }"},  # unknown field
    {"query": "query @skip { __typename }"},                 # misused directive
    {"query": "query { __typename(nonexistent: 1) }"},       # arg on __typename
    {"query": "query { __typename }"},                       # valid baseline (headers)
]

CONFIDENCE_HIGH = 5
CONFIDENCE_MEDIUM = 3


def load_engine_matrix() -> Dict[str, Any]:
    if os.path.exists(MATRIX_PATH):
        try:
            with open(MATRIX_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data:
                    return data
        except Exception:
            pass
    return _FALLBACK_DB


async def _collect_signals(
    url: str, req_headers: Dict[str, str]
) -> Tuple[str, str, str]:
    """Send the probe battery and return (error_blob, ext_blob, header_blob),
    all lowercased, for scoring."""
    error_parts: List[str] = []
    ext_tokens: set = set()
    resp_headers: Dict[str, str] = {}

    async with net.client() as client:
        for probe in PROBES:
            try:
                r = await client.post(url, json=probe, headers=req_headers, timeout=10)
            except Exception:
                continue
            # Capture headers once (first-seen wins) — high-signal, low-noise.
            for k, v in r.headers.items():
                resp_headers.setdefault(k.lower(), v)
            try:
                data = r.json()
            except Exception:
                continue
            for err in data.get("errors", []) or []:
                error_parts.append(str(err.get("message", "")))
                error_parts.append(str(err.get("extensions", {})))
                ext_tokens.add(str(err.get("extensions", {}).get("code")))
                ext_tokens.add(str(err.get("code")))
                ext_tokens.add(str(err.get("error")))
                if "errorType" in err:
                    ext_tokens.add("__errorType__")

    error_blob = " ".join(error_parts).lower()
    ext_blob = " ".join(ext_tokens).lower()
    header_blob = " ".join(f"{k}: {v}" for k, v in resp_headers.items()).lower()
    return error_blob, ext_blob, header_blob


def _score_engines(
    db: Dict[str, Any],
    error_blob: str,
    ext_blob: str,
    header_blob: str,
    schema: Optional[GraphQLSchema],
) -> Dict[str, int]:
    """Additive scoring: each matched signal contributes its weight to the
    candidate engine. Headers / extension codes / introspection markers carry
    high weight (low false-positive); error substrings carry low weight."""
    scores: Dict[str, int] = defaultdict(int)

    schema_type_names = set(schema.types.keys()) if schema else set()
    if schema:
        schema_type_names.add(schema.query_type or "")
        schema_type_names.add(schema.mutation_type or "")

    for engine, sig in db.items():
        for needle, w in sig.get("headers", {}).items():
            if needle.lower() in header_blob:
                scores[engine] += w
        for needle, w in sig.get("extension_codes", {}).items():
            if needle.lower() in ext_blob:
                scores[engine] += w
        for needle, w in sig.get("error_substrings", {}).items():
            if needle.lower() in error_blob:
                scores[engine] += w
        for tname, w in sig.get("introspection_types", {}).items():
            if tname in schema_type_names:
                scores[engine] += w

    return scores


def _confidence(score: int) -> str:
    if score >= CONFIDENCE_HIGH:
        return "high"
    if score >= CONFIDENCE_MEDIUM:
        return "medium"
    return "low"


async def fingerprint_engine(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    schema: Optional[GraphQLSchema] = None,
) -> Tuple[str, Dict[str, Any]]:
    """
    Fingerprint the remote GraphQL engine using a probe battery scored against
    a signature database (error text, extension codes, response headers, and —
    when ``schema`` is provided — introspection type markers).

    Returns: (engine_name, engine_details). ``engine_details`` includes the
    matched score and a confidence label.
    """
    db = load_engine_matrix()
    req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    error_blob, ext_blob, header_blob = await _collect_signals(url, req_headers)
    scores = _score_engines(db, error_blob, ext_blob, header_blob, schema)

    if not scores or max(scores.values()) == 0:
        return "Generic GraphQL Engine", {
            "versions": ["Unknown"],
            "default_introspection": "enabled",
            "confidence": "low",
            "score": 0,
        }

    best = max(scores, key=scores.get)
    best_score = scores[best]

    # Runners-up help a human see collisions / ambiguity.
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    alternatives = [f"{name} ({sc})" for name, sc in ranked[1:4] if sc > 0]

    info = dict(db.get(best, {}))
    info.update({
        "confidence": _confidence(best_score),
        "score": best_score,
        "alternatives": alternatives,
    })
    return best, info
