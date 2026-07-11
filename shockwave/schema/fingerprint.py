import httpx
import json
import os
from typing import Dict, Any, Tuple, Optional

# Resolve the absolute path to engine_matrix.json
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
MATRIX_PATH = os.path.join(DATA_DIR, "engine_matrix.json")

def load_engine_matrix() -> Dict[str, Any]:
    if os.path.exists(MATRIX_PATH):
        with open(MATRIX_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

async def fingerprint_engine(
    url: str,
    headers: Optional[Dict[str, str]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Fingerprints the remote GraphQL server by sending various malformed queries 
    and matching error formats against known signatures.
    Returns: (engine_name, engine_details)
    """
    matrix = load_engine_matrix()
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
        
    async with httpx.AsyncClient(verify=False) as client:
        # Test 1: Syntax error
        try:
            res1 = await client.post(url, json={"query": "query {"}, headers=req_headers, timeout=10)
            data1 = res1.json()
        except Exception:
            data1 = {}
            
        # Test 2: Field suggestion probe (non-existent field)
        try:
            res2 = await client.post(url, json={"query": "query { __non_existent_field_signature_probe }"}, headers=req_headers, timeout=10)
            data2 = res2.json()
        except Exception:
            data2 = {}

    errors1 = data1.get("errors", [])
    errors2 = data2.get("errors", [])
    
    # 1. Hasura detection
    # Hasura returns code: "validation-failed" or "parse-failed" directly under errors -> extensions or error field
    for err in errors1:
        if err.get("code") == "parse-failed" or "validation-failed" in str(err.get("code")):
            return "Hasura", matrix.get("Hasura", {})
        if "validation-failed" in str(err.get("error")):
            return "Hasura", matrix.get("Hasura", {})

    # 2. AWS AppSync detection
    # AppSync returns errorType: "ValidationError" or similar inside errors
    for err in errors1 + errors2:
        if "errorType" in err:
            return "AWS AppSync", matrix.get("AWS AppSync", {})
            
    # 3. Apollo Server detection
    # Apollo adds extensions.code (e.g. GRAPHQL_PARSE_FAILED, GRAPHQL_VALIDATION_FAILED)
    for err in errors1 + errors2:
        ext = err.get("extensions", {})
        if ext.get("code") in ("GRAPHQL_PARSE_FAILED", "GRAPHQL_VALIDATION_FAILED", "BAD_USER_INPUT"):
            return "Apollo Server", matrix.get("Apollo Server", {})
        if "INTERNAL_SERVER_ERROR" in str(ext.get("code")):
            return "Apollo Server", matrix.get("Apollo Server", {})

    # 4. GraphQL Yoga / Strawberry detection
    # Yoga/Strawberry usually has clean standard spec error formats but sometimes custom exception fields
    for err in errors1 + errors2:
        if "Strawberry" in str(err.get("message")) or "strawberry" in str(err.get("extensions")):
            return "Strawberry", matrix.get("Strawberry", {})

    # Fallback checks based on headers
    # (e.g., Server header, x-powered-by)
    # Since we can inspect the response headers of any request:
    # We will just default to "Apollo Server" if unknown because of its high popularity,
    # or return "Generic GraphQL Engine" if we can't match it.
    
    return "Generic GraphQL Engine", {
        "versions": ["Unknown"],
        "default_introspection": "enabled",
        "default_field_suggestions": "enabled",
        "known_issues": [],
        "misconfig_defaults": ["no_depth_limit"]
    }
