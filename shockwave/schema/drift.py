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
