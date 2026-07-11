import asyncio
import json
import httpx
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
from shockwave.schema.models import GraphQLSchema, QueryBuilder, GraphQLField
from shockwave.output.sarif_writer import ShockwaveFinding

class FieldAccess(str, Enum):
    ACCESSIBLE = "accessible"   # Non-null response received
    BLOCKED = "blocked"         # Null response or auth error
    ERROR = "error"             # Unexpected error (not auth-related)
    UNTESTED = "untested"       # Not included in this scan

@dataclass
class AuthMatrix:
    schema_hash: str
    scan_timestamp: str
    auth_contexts: List[str]       # ["admin", "user", "guest", "unauthenticated"]
    fields: Dict[str, Dict[str, FieldAccess]]

async def execute_matrix_query(
    url: str,
    query: str,
    variables: Dict[str, Any],
    headers: Optional[Dict[str, str]],
    client: httpx.AsyncClient
) -> FieldAccess:
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    try:
        res = await client.post(url, json={"query": query, "variables": variables}, headers=req_headers, timeout=10)
        if res.status_code == 401 or res.status_code == 403:
            return FieldAccess.BLOCKED
            
        data = res.json()
        if "errors" in data and not data.get("data"):
            # If there are errors and data is empty, check if it's auth-related
            err_msg = str(data["errors"]).lower()
            if any(x in err_msg for x in ("unauthorized", "forbidden", "not authenticated", "access denied", "denied")):
                return FieldAccess.BLOCKED
            return FieldAccess.ERROR
            
        # If there is data but the specific query returned null
        # We look at the first key inside data
        # e.g., data: {"user": null}
        first_key = list(data.get("data", {}).keys())[0] if data.get("data") else None
        if first_key and data["data"][first_key] is None:
            # Check if there was an error for this field
            if "errors" in data:
                err_msg = str(data["errors"]).lower()
                if any(x in err_msg for x in ("unauthorized", "forbidden", "not authenticated", "access denied", "denied")):
                    return FieldAccess.BLOCKED
            return FieldAccess.BLOCKED
            
        if data.get("data"):
            return FieldAccess.ACCESSIBLE
            
        return FieldAccess.BLOCKED
    except Exception:
        return FieldAccess.ERROR

async def generate_auth_matrix(
    url: str,
    schema: GraphQLSchema,
    contexts: List[Dict[str, Any]],  # [{"name": "admin", "headers": {...}}, ...]
    max_depth: int = 3
) -> Tuple[AuthMatrix, List[ShockwaveFinding]]:
    """
    Generates a multi-role authorization matrix (FR-3).
    Also detects inverted privilege anomalies and sensitive unauthenticated exposures.
    """
    findings = []
    builder = QueryBuilder(schema)
    query_type = schema.types.get(schema.query_type or "Query")
    
    auth_names = [ctx["name"] for ctx in contexts]
    matrix_fields = {}
    
    if not query_type or not query_type.fields:
        return AuthMatrix("", "", auth_names, {}), findings

    async with httpx.AsyncClient(verify=False) as client:
        for field in query_type.fields:
            field_path = f"Query.{field.name}"
            matrix_fields[field_path] = {}
            
            # Generate the query template
            query_str, variables = builder.build_operation("query", field, max_depth)
            
            # Query each context
            for ctx in contexts:
                ctx_name = ctx["name"]
                headers = ctx.get("headers")
                
                access = await execute_matrix_query(url, query_str, variables, headers, client)
                matrix_fields[field_path][ctx_name] = access

    # Analyze findings based on the matrix
    # Anomaly 1: Inverted Access Control
    # (Higher privilege is blocked but lower privilege is accessible)
    # Define privilege order based on context list order (first is highest, e.g. admin -> user -> guest -> unauthenticated)
    for field_path, roles_access in matrix_fields.items():
        # Check unauthenticated access to sensitive fields
        unauth_access = roles_access.get("unauthenticated")
        if unauth_access == FieldAccess.ACCESSIBLE:
            from shockwave.tests.auth_diff import is_sensitive_field
            if is_sensitive_field(field_path):
                findings.append(ShockwaveFinding(
                    id="",
                    rule_id="SHOCKWAVE-AUTH-001",
                    rule_name="Field-level authorization bypass",
                    severity="critical",
                    owasp_category="API1:2023 — Broken Object Level Authorization",
                    cwe_id="CWE-284",
                    field_path=field_path,
                    engine="Generic",
                    evidence_request=f"Sensitive field {field_path} queried anonymously",
                    evidence_response="Accessible anonymously",
                    auth_context="unauthenticated",
                    confidence="confirmed",
                    confirmation_count=1,
                    remediation=f"Restricted unauthenticated access to sensitive field {field_path} by implementing token validation.",
                    references=["https://owasp.org/API-Security/editions/2023/en/0x07-api1-broken-object-level-authorization/"]
                ))
        
        # Check inverted access controls: lower privilege is accessible, but higher is blocked.
        for idx, high_role in enumerate(auth_names):
            for low_role in auth_names[idx+1:]:
                high_access = roles_access.get(high_role)
                low_access = roles_access.get(low_role)
                
                if low_access == FieldAccess.ACCESSIBLE and high_access == FieldAccess.BLOCKED:
                    findings.append(ShockwaveFinding(
                        id="",
                        rule_id="SHOCKWAVE-AUTH-001",
                        rule_name="Field-level authorization bypass",
                        severity="medium",
                        owasp_category="API1:2023 — Broken Object Level Authorization",
                        cwe_id="CWE-284",
                        field_path=field_path,
                        engine="Generic",
                        evidence_request=f"Inverted control detected: {low_role} can access {field_path} but {high_role} is blocked.",
                        evidence_response=f"{low_role}: accessible, {high_role}: blocked",
                        auth_context=low_role,
                        confidence="confirmed",
                        confirmation_count=1,
                        remediation=f"Ensure authorization rules for {field_path} grant access hierarchically (higher roles should inherit or have explicit access).",
                        references=["https://owasp.org/API-Security/editions/2023/en/0x07-api1-broken-object-level-authorization/"]
                    ))

    import hashlib
    import time
    schema_hash = hashlib.md5(str(matrix_fields).encode()).hexdigest()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    return AuthMatrix(schema_hash, timestamp, auth_names, matrix_fields), findings
