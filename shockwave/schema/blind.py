import httpx
import re
import os
from typing import Dict, Any, List, Set, Optional
from shockwave.schema.models import GraphQLSchema, GraphQLType, GraphQLField, GraphQLTypeRef

# Resolve the absolute path to wordlist.txt
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
WORDLIST_PATH = os.path.join(DATA_DIR, "wordlist.txt")

def load_wordlist() -> List[str]:
    if os.path.exists(WORDLIST_PATH):
        with open(WORDLIST_PATH, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    return ["user", "users", "me", "login", "admin", "settings", "profile"]

async def send_raw_query(
    url: str,
    query: str,
    headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    async with httpx.AsyncClient(verify=False) as client:
        try:
            res = await client.post(url, json={"query": query}, headers=req_headers, timeout=10)
            return res.json()
        except Exception:
            return {}

def extract_suggestions(errors: List[Dict[str, Any]]) -> Set[str]:
    """
    Parses GraphQL error messages to find suggested field names.
    Example error message:
    "Cannot query field \"use\" on type \"Query\". Did you mean \"user\" or \"users\"?"
    """
    suggestions = set()
    for err in errors:
        msg = err.get("message", "")
        # Match pattern: Did you mean "..." or "..."
        matches = re.findall(r'Did you mean "([^"]+)"', msg)
        for match in matches:
            suggestions.add(match)
        # Handle comma-separated list suggestions
        comma_matches = re.search(r'Did you mean (.*)\?', msg)
        if comma_matches:
            for word in re.findall(r'"([^"]+)"', comma_matches.group(1)):
                suggestions.add(word)
    return suggestions

async def check_suggestions_enabled(url: str, headers: Optional[Dict[str, str]] = None) -> bool:
    """Verifies if the server returns suggestion errors."""
    res = await send_raw_query(url, "query { abcdefghijklmnop }", headers)
    errors = res.get("errors", [])
    s = extract_suggestions(errors)
    return len(s) > 0

async def blind_reconstruct(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    limit_fields: int = 50
) -> GraphQLSchema:
    """
    Brute-forces the schema using suggestions and errors to construct Query, Mutation, and types.
    """
    schema = GraphQLSchema(query_type="Query", mutation_type="Mutation", subscription_type=None)
    schema.types["Query"] = GraphQLType(name="Query", kind="OBJECT")
    schema.types["Mutation"] = GraphQLType(name="Mutation", kind="OBJECT")

    # If suggestions are not enabled, we cannot reconstruct the schema blindly in a reasonable time.
    if not await check_suggestions_enabled(url, headers):
        return schema

    wordlist = load_wordlist()
    found_query_fields = set()
    found_mutation_fields = set()

    # Step 1: Probe Query fields using suggestions
    # We query clusters of non-existent fields to trigger suggestions.
    # We can batch words like query { word1 word2 ... }
    batch_size = 10
    for i in range(0, min(len(wordlist), 100), batch_size):
        chunk = wordlist[i:i+batch_size]
        query_parts = [f"probe_{w}: {w}" for w in chunk]
        query = f"query {{ {', '.join(query_parts)} }}"
        
        res = await send_raw_query(url, query, headers)
        errors = res.get("errors", [])
        
        # Add any valid fields that didn't throw a "Cannot query field" error (i.e. valid fields)
        # Note: if a field exists, it might throw a subselection error or argument error
        # but not a "Cannot query field" error.
        invalid_fields = set()
        for err in errors:
            msg = err.get("message", "")
            match = re.search(r'Cannot query field "([^"]+)"', msg)
            if match:
                invalid_fields.add(match.group(1))

        # Check suggestions
        suggestions = extract_suggestions(errors)
        for sug in suggestions:
            found_query_fields.add(sug)

        # For fields that didn't throw "Cannot query field" but failed on other rules:
        for w in chunk:
            if w not in invalid_fields:
                found_query_fields.add(w)

    # Step 2: Probe Mutation fields
    for i in range(0, min(len(wordlist), 100), batch_size):
        chunk = wordlist[i:i+batch_size]
        mut_parts = [f"probe_{w}: {w}" for w in chunk]
        mutation = f"mutation {{ {', '.join(mut_parts)} }}"
        
        res = await send_raw_query(url, mutation, headers)
        errors = res.get("errors", [])
        
        invalid_muts = set()
        for err in errors:
            msg = err.get("message", "")
            match = re.search(r'Cannot query field "([^"]+)"', msg)
            if match:
                invalid_muts.add(match.group(1))
                
        suggestions = extract_suggestions(errors)
        for sug in suggestions:
            found_mutation_fields.add(sug)
            
        for w in chunk:
            if w not in invalid_muts:
                found_mutation_fields.add(w)

    # Clean internal names and filter fields
    found_query_fields = {f for f in found_query_fields if not f.startswith("__") and f != "probe_"}
    found_mutation_fields = {f for f in found_mutation_fields if not f.startswith("__") and f != "probe_"}

    # Build schema fields by querying sub-typename
    # e.g., query { user { __typename } } to find the returned type name.
    for q_field in list(found_query_fields)[:limit_fields]:
        # Try to fetch type name
        test_query = f"query {{ {q_field} {{ __typename }} }}"
        res = await send_raw_query(url, test_query, headers)
        
        data = res.get("data", {})
        errors = res.get("errors", [])
        
        type_name = "String"  # Default fallback
        
        if data and data.get(q_field):
            val = data[q_field]
            if isinstance(val, dict) and val.get("__typename"):
                type_name = val["__typename"]
            elif isinstance(val, list) and val and isinstance(val[0], dict) and val[0].get("__typename"):
                type_name = val[0]["__typename"]
        else:
            # Parse errors
            for err in errors:
                msg = err.get("message", "")
                # Case: must have selection of subfields
                match = re.search(r'field "([^"]+)" of type "([^"]+)"', msg)
                if match:
                    # e.g. "Field 'user' of type 'User' must have a selection" -> type_name is 'User'
                    if match.group(1) == q_field:
                        type_name = match.group(2)
                        break

        # Create type if not exists
        if type_name not in schema.types:
            schema.types[type_name] = GraphQLType(name=type_name, kind="OBJECT")

        ref = GraphQLTypeRef(kind="OBJECT" if type_name != "String" else "SCALAR", name=type_name)
        schema.types["Query"].fields.append(
            GraphQLField(name=q_field, type_ref=ref)
        )

    # Build mutations
    for m_field in list(found_mutation_fields)[:limit_fields]:
        # Try to fetch type name
        # Since mutation requires execution, we check what it returns
        # Usually mutations are objects or status fields. Let's do similar probe.
        test_mut = f"mutation {{ {m_field} {{ __typename }} }}"
        res = await send_raw_query(url, test_mut, headers)
        data = res.get("data", {})
        errors = res.get("errors", [])
        
        type_name = "String"
        if data and data.get(m_field):
            val = data[m_field]
            if isinstance(val, dict) and val.get("__typename"):
                type_name = val["__typename"]
        else:
            for err in errors:
                msg = err.get("message", "")
                match = re.search(r'field "([^"]+)" of type "([^"]+)"', msg)
                if match:
                    if match.group(1) == m_field:
                        type_name = match.group(2)
                        break

        if type_name not in schema.types:
            schema.types[type_name] = GraphQLType(name=type_name, kind="OBJECT")

        ref = GraphQLTypeRef(kind="OBJECT" if type_name != "String" else "SCALAR", name=type_name)
        schema.types["Mutation"].fields.append(
            GraphQLField(name=m_field, type_ref=ref)
        )

    return schema
