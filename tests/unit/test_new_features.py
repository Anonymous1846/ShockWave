"""Focused checks for the features added on top of the core scanners:
request throttle, richer schema diff, and the plugin loader."""
import asyncio
import os
import time

import pytest

from shockwave.net import Throttle
from shockwave.schema.drift import compute_schema_changes
from shockwave.schema.fingerprint import load_engine_matrix, _score_engines
from shockwave.schema.models import (
    GraphQLSchema, GraphQLType, GraphQLField, GraphQLArgument, GraphQLTypeRef,
)
from shockwave.plugins import load_plugins


def _ref(name, kind="SCALAR", required=False):
    r = GraphQLTypeRef(kind=kind, name=name)
    if required:
        return GraphQLTypeRef(kind="NON_NULL", of_type=r)
    return r


def _schema(fields):
    return GraphQLSchema(types={"Query": GraphQLType(name="Query", kind="OBJECT", fields=fields)})


def test_throttle_unlimited_is_instant():
    t = Throttle(rate_per_sec=0)
    start = time.monotonic()
    asyncio.run(t.wait())
    assert time.monotonic() - start < 0.05


def test_throttle_enforces_rate():
    t = Throttle(rate_per_sec=50)  # 20ms apart

    async def hammer():
        for _ in range(5):
            await t.wait()

    start = time.monotonic()
    asyncio.run(hammer())
    # 5 calls at 20ms min interval -> at least ~0.06s of forced spacing
    assert time.monotonic() - start >= 0.06


def test_schema_changes_detects_type_and_arg_changes():
    old = _schema([
        GraphQLField(name="user", type_ref=_ref("User", kind="OBJECT"),
                     args=[GraphQLArgument(name="id", type_ref=_ref("ID"))]),
        GraphQLField(name="legacy", type_ref=_ref("String")),
        GraphQLField(name="keep", type_ref=_ref("String")),
    ])
    new = _schema([
        GraphQLField(name="user", type_ref=_ref("Account", kind="OBJECT"),  # type changed
                     args=[GraphQLArgument(name="id", type_ref=_ref("ID", required=True))]),  # now required
        GraphQLField(name="brandNew", type_ref=_ref("String")),  # added
        GraphQLField(name="keep", type_ref=_ref("String"),
                     is_deprecated=True, deprecation_reason="use brandNew"),  # newly deprecated
    ])
    changes = compute_schema_changes(old, new)

    assert "Query.brandNew" in changes["added_fields"]
    assert "Query.legacy" in changes["removed_fields"]
    assert any("Query.user:" in c and "User" in c and "Account" in c for c in changes["type_changes"])
    assert any("Query.user: arg id now required" == c for c in changes["arg_changes"])
    assert any(c.startswith("Query.keep:") and "use brandNew" in c for c in changes["newly_deprecated"])


def test_engine_matrix_loads_and_is_populated():
    db = load_engine_matrix()
    assert isinstance(db, dict) and len(db) >= 10
    assert "Hasura" in db and "Apollo Server" in db


def test_fingerprint_scoring_picks_best_and_avoids_collision():
    db = load_engine_matrix()

    # Header signal alone should identify Hasura with high weight.
    scores = _score_engines(db, "", "", "x-hasura-role: admin", schema=None)
    assert max(scores, key=scores.get) == "Hasura"

    # Apollo extension code wins over the generic "cannot query field" substring
    # that Apollo also carries — no collision with a bare message match.
    scores = _score_engines(
        db,
        error_blob="cannot query field \"x\" on type \"query\"",
        ext_blob="graphql_validation_failed",
        header_blob="",
        schema=None,
    )
    assert max(scores, key=scores.get) == "Apollo Server"

    # Introspection type marker boosts Hasura when schema exposes query_root.
    class _S:
        types = {"query_root": object()}
        query_type = "query_root"
        mutation_type = "mutation_root"
    scores = _score_engines(db, "", "", "", schema=_S())
    assert scores.get("Hasura", 0) >= 5


def test_parse_headers_merges_and_handles_empty():
    from shockwave.cli.main import parse_headers
    assert parse_headers(()) is None
    assert parse_headers(("Cookie: s=1",)) == {"Cookie": "s=1"}
    assert parse_headers(("Cookie: s=1", "X-CSRF: tok")) == {"Cookie": "s=1", "X-CSRF": "tok"}


def test_load_plugins_finds_run(tmp_path):
    plugin = tmp_path / "my_check.py"
    plugin.write_text("async def run(ctx):\n    return []\n", encoding="utf-8")
    (tmp_path / "_skip.py").write_text("async def run(ctx):\n    return []\n", encoding="utf-8")

    runners = load_plugins(str(tmp_path))
    assert len(runners) == 1  # _skip.py is ignored
    assert asyncio.iscoroutinefunction(runners[0])
