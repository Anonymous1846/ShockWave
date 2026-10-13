import os
import json
import hashlib
from urllib.parse import urlparse
from typing import Dict, Any, Tuple, Set, Optional
from shockwave.schema.models import GraphQLSchema, parse_introspection

def get_cache_path(url: str, cache_dir: Optional[str] = None) -> str:
    """Computes a persistent local cache file path for the target URL."""
    if not cache_dir:
        cache_dir = os.path.expanduser("~/.cache/shockwave")
        
    os.makedirs(cache_dir, exist_ok=True)
    
    parsed = urlparse(url)
    hostname = parsed.hostname or "unknown"
    # Create MD5 of full URL to avoid collisions
    url_hash = hashlib.md5(url.encode("utf-8")).hexdigest()
    
    return os.path.join(cache_dir, f"schema_{hostname}_{url_hash}.json")

def load_cached_schema(url: str, cache_dir: Optional[str] = None) -> Optional[GraphQLSchema]:
    """Loads schema from local cache if it exists."""
    path = get_cache_path(url, cache_dir)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return parse_introspection(data)
        except Exception:
            return None
    return None

def save_schema_cache(url: str, raw_introspection: Dict[str, Any], cache_dir: Optional[str] = None) -> None:
    """Saves raw introspection json to cache."""
    path = get_cache_path(url, cache_dir)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(raw_introspection, f, indent=2)
    except Exception:
        pass

def compute_schema_diff(old_schema: Optional[GraphQLSchema], new_schema: GraphQLSchema) -> Tuple[Set[str], Set[str]]:
    """
    Compares two schemas and identifies added or removed fields.
    Returns: (added_fields, removed_fields) where fields are dot-path strings: e.g. "Query.user"
    """
    if not old_schema:
        # All fields in the new schema are considered new/added
        added = set()
        for t_name, gtype in new_schema.types.items():
            for field in gtype.fields:
                added.add(f"{t_name}.{field.name}")
        return added, set()

    old_fields = set()
    for t_name, gtype in old_schema.types.items():
        for field in gtype.fields:
            old_fields.add(f"{t_name}.{field.name}")

    new_fields = set()
    for t_name, gtype in new_schema.types.items():
        for field in gtype.fields:
            new_fields.add(f"{t_name}.{field.name}")

    added = new_fields - old_fields
    removed = old_fields - new_fields

    return added, removed


def _field_map(schema: GraphQLSchema) -> Dict[str, Any]:
    """Flatten a schema to {"Type.field": GraphQLField} for comparison."""
    out = {}
    for t_name, gtype in schema.types.items():
        for f in gtype.fields:
            out[f"{t_name}.{f.name}"] = f
    return out


def compute_schema_changes(
    old_schema: Optional[GraphQLSchema], new_schema: GraphQLSchema
) -> Dict[str, Any]:
    """Richer diff than compute_schema_diff: also reports type changes on kept
    fields and argument changes (added/removed/required-ness). Returns a dict
    with keys: added_fields, removed_fields, added_types, removed_types,
    type_changes, arg_changes. All values are sorted lists of strings.
    """
    added_f, removed_f = compute_schema_diff(old_schema, new_schema)
    result = {
        "added_fields": sorted(added_f),
        "removed_fields": sorted(removed_f),
        "added_types": [],
        "removed_types": [],
        "type_changes": [],
        "arg_changes": [],
        "newly_deprecated": [],
    }
    if not old_schema:
        result["added_types"] = sorted(new_schema.types.keys())
        result["newly_deprecated"] = sorted(
            f"{p}: {nf.deprecation_reason or 'deprecated'}"
            for p, nf in _field_map(new_schema).items() if nf.is_deprecated
        )
        return result

    result["added_types"] = sorted(set(new_schema.types) - set(old_schema.types))
    result["removed_types"] = sorted(set(old_schema.types) - set(new_schema.types))

    old_map = _field_map(old_schema)
    new_map = _field_map(new_schema)

    for path in sorted(set(old_map) & set(new_map)):
        of, nf = old_map[path], new_map[path]

        old_t = of.type_ref.to_type_string() if of.type_ref else "?"
        new_t = nf.type_ref.to_type_string() if nf.type_ref else "?"
        if old_t != new_t:
            result["type_changes"].append(f"{path}: {old_t} -> {new_t}")

        old_args = {a.name: a for a in of.args}
        new_args = {a.name: a for a in nf.args}
        for a in sorted(set(new_args) - set(old_args)):
            result["arg_changes"].append(f"{path}: +arg {a}: {new_args[a].type_ref.to_type_string()}")
        for a in sorted(set(old_args) - set(new_args)):
            result["arg_changes"].append(f"{path}: -arg {a}")
        for a in sorted(set(old_args) & set(new_args)):
            o_req = old_args[a].type_ref.is_required()
            n_req = new_args[a].type_ref.is_required()
            if o_req != n_req:
                state = "now required" if n_req else "now optional"
                result["arg_changes"].append(f"{path}: arg {a} {state}")

        # Field became deprecated since the baseline
        if nf.is_deprecated and not of.is_deprecated:
            result["newly_deprecated"].append(f"{path}: {nf.deprecation_reason or 'deprecated'}")

    result["newly_deprecated"] = sorted(result["newly_deprecated"])
    return result
