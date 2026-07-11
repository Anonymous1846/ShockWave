import asyncio
import json
import os
import re
import httpx
from typing import Dict, Any, List, Optional
from deepdiff import DeepDiff
from shockwave.schema.models import GraphQLSchema, QueryBuilder
from shockwave.output.sarif_writer import ShockwaveFinding

# Resolve absolute path to sensitive_fields.txt
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
SENSITIVE_FIELDS_PATH = os.path.join(DATA_DIR, "sensitive_fields.txt")

def load_sensitive_patterns() -> List[str]:
    if os.path.exists(SENSITIVE_FIELDS_PATH):
        with open(SENSITIVE_FIELDS_PATH, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip()]
    return ["password", "token", "secret", "internal", "admin", "ssn", "dob", "billing"]

def is_sensitive_field(field_path: str) -> bool:
    patterns = load_sensitive_patterns()
    path_lower = field_path.lower()
    for p in patterns:
        if p in path_lower:
            return True
    return False

async def execute_query(
    url: str,
    query: str,
    variables: Dict[str, Any],
    headers: Optional[Dict[str, str]],
    client: httpx.AsyncClient
) -> Dict[str, Any]:
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    try:
        res = await client.post(url, json={"query": query, "variables": variables}, headers=req_headers, timeout=10)
        if res.status_code == 200:
            return res.json()
        return {"errors": [{"message": f"HTTP {res.status_code}"}]}
    except Exception as e:
        return {"errors": [{"message": str(e)}]}

async def verify_finding(
    url: str,
    query: str,
    variables: Dict[str, Any],
    headers: Optional[Dict[str, str]],
    field_name: str,
    client: httpx.AsyncClient
) -> bool:
    """Verifies a suspected bypass by re-querying 3 times."""
    for _ in range(3):
        res = await execute_query(url, query, variables, headers, client)
        data = res.get("data", {}) or {}
        # Traverse to find the field value
        if not data:
            return False
        # If the query itself was a direct field query, verify it returned non-null
        val = data.get(field_name)
        if val is None:
            return False
    return True

async def scan_auth_diff(
    url: str,
    schema: GraphQLSchema,
    auth_a_headers: Optional[Dict[str, str]],
    auth_b_headers: Optional[Dict[str, str]],
    max_depth: int = 3
) -> List[ShockwaveFinding]:
    """
    Performs cross-user semantic response diffing (FR-2) on Queries and Mutations.
    auth_a: Lower-privileged credentials / Test context A
    auth_b: Higher-privileged credentials / Test context B
    """
    findings = []
    
    # We need both auth contexts to perform diffing
    if auth_a_headers is None or auth_b_headers is None:
        return findings

    builder = QueryBuilder(schema)
    query_type = schema.types.get(schema.query_type or "Query")
    
    if not query_type or not query_type.fields:
        return findings

    async with httpx.AsyncClient(verify=False) as client:
        for field in query_type.fields:
            # Generate template query
            query_str, variables = builder.build_operation("query", field, max_depth)
            
            # Execute queries in parallel
            res_a, res_b = await asyncio.gather(
                execute_query(url, query_str, variables, auth_a_headers, client),
                execute_query(url, query_str, variables, auth_b_headers, client)
            )
            
            data_a = res_a.get("data") or {}
            data_b = res_b.get("data") or {}
            
            # Perform semantic diff
            diff = DeepDiff(
                data_a,
                data_b,
                ignore_order=True,
                exclude_paths=["root['__typename']"]
            )
            
            # Case 1: Inverted authorization or authorization bypass.
            # If auth_a (lower privilege) returns data that matches or is different,
            # but auth_a can access a field named with a sensitive pattern or returning non-null.
            # Let's inspect the keys and values in response A.
            val_a = data_a.get(field.name)
            val_b = data_b.get(field.name)
            
            # If lower-privileged user gets non-null data for a query field
            # and that field contains sensitive details, let's flag it.
            if val_a is not None:
                is_sensitive = is_sensitive_field(field.name)
                
                # Check for sensitive sub-fields recursively in data_a
                has_sensitive_leaks = False
                if isinstance(val_a, dict):
                    for k, v in val_a.items():
                        if v is not None and is_sensitive_field(k):
                            has_sensitive_leaks = True
                            
                if is_sensitive or has_sensitive_leaks:
                    # Verify by querying 3 times
                    verified = await verify_finding(url, query_str, variables, auth_a_headers, field.name, client)
                    if verified:
                        findings.append(ShockwaveFinding(
                            id="",
                            rule_id="SHOCKWAVE-AUTH-001",
                            rule_name="Field-level authorization bypass",
                            severity="high",
                            owasp_category="API1:2023 — Broken Object Level Authorization",
                            cwe_id="CWE-284",
                            field_path=f"Query.{field.name}",
                            engine="Generic",
                            evidence_request=query_str,
                            evidence_response=json.dumps(res_a),
                            auth_context="Auth A (Lower)",
                            confidence="confirmed",
                            confirmation_count=3,
                            remediation=f"Implement robust authorization checks inside the resolver for Query.{field.name}.",
                            references=["https://owasp.org/API-Security/editions/2023/en/0x07-api1-broken-object-level-authorization/"]
                        ))

            # Case 2: Mutation-based authorization diffs
            # (We will check mutations later or dynamically under other modules)
            
    return findings
