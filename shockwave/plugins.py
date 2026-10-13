"""Minimal plugin loader so users can add custom checks without forking.

Drop a ``*.py`` file in a directory and point ``--plugins DIR`` at it. Each
plugin module exposes::

    async def run(ctx):
        async with ctx.net.client() as client:
            ...
        return [ctx.Finding(...), ...]   # list of ShockwaveFinding

SECURITY: loading a plugin imports and executes its module code in this
process. Only use a directory you control.
"""
import importlib.util
import os
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from shockwave import net
from shockwave.schema.models import GraphQLSchema
from shockwave.output.sarif_writer import ShockwaveFinding


@dataclass
class PluginContext:
    url: str
    schema: GraphQLSchema
    headers: Optional[Dict[str, str]]
    # Shared helpers for plugin authors (class attributes, not dataclass fields):
    net = net
    Finding = ShockwaveFinding


def load_plugins(path: Optional[str]) -> List[Callable]:
    """Return the ``run`` coroutine of every importable ``*.py`` in ``path``."""
    runners: List[Callable] = []
    if not path or not os.path.isdir(path):
        return runners
    for fname in sorted(os.listdir(path)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        fpath = os.path.join(path, fname)
        spec = importlib.util.spec_from_file_location(f"shockwave_plugin_{fname[:-3]}", fpath)
        if not spec or not spec.loader:
            continue
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception:
            continue
        run = getattr(mod, "run", None)
        if callable(run):
            runners.append(run)
    return runners


async def run_plugins(runners: List[Callable], ctx: PluginContext) -> List[ShockwaveFinding]:
    """Run every loaded plugin, isolating failures so one bad plugin can't
    abort the scan."""
    findings: List[ShockwaveFinding] = []
    for run in runners:
        try:
            result = await run(ctx)
        except Exception:
            continue
        if result:
            findings.extend(result)
    return findings
