import httpx
import uuid
import json
from typing import Dict, Any, List, Optional
from shockwave import net
from shockwave.schema.models import GraphQLSchema, QueryBuilder, GraphQLField
from shockwave.output.sarif_writer import ShockwaveFinding
from shockwave.tests.auth_diff import execute_query

async def extract_ids_from_list_query(
    url: str,
    list_field: GraphQLField,
    op_type: str,
    headers: Optional[Dict[str, str]],
    builder: QueryBuilder,
    client: httpx.AsyncClient
) -> List[str]:
    """Tries to execute a list query and harvest returned object IDs."""
    query_str, variables = builder.build_operation(op_type, list_field)
    res = await execute_query(url, query_str, variables, headers, client)
    
    ids = []
    data_val = res.get("data", {}).get(list_field.name) if res.get("data") else None
    
    if isinstance(data_val, list):
        for item in data_val:
            if isinstance(item, dict):
                # Check standard ID fields
                for k in ["id", "uuid", "key", "code"]:
                    if k in item and item[k]:
                        ids.append(str(item[k]))
                        
    return ids

async def scan_idor(
    url: str,
    schema: GraphQLSchema,
    auth_a_headers: Optional[Dict[str, str]],
    auth_b_headers: Optional[Dict[str, str]],
    max_depth: int = 3
) -> List[ShockwaveFinding]:
    """
    Performs IDOR/BOLA scanning (FR-7) on Query fields.
    """
    findings = []
    builder = QueryBuilder(schema)
    
    q_type = schema.types.get(schema.query_type or "Query")
    if not q_type or not q_type.fields:
        return findings

    # Look for list fields vs singular detail fields
    list_fields = []
    detail_fields = []
    
    for f in q_type.fields:
        has_id_arg = any(arg.type_ref.get_deep_name().upper() in ["ID", "INT", "STRING"] for arg in f.args)
        if has_id_arg:
            detail_fields.append(f)
        elif f.type_ref.is_list():
            list_fields.append(f)

    async with net.client() as client:
        # Step 1: Try to harvest IDs from auth_b if available
        harvested_ids = []
        if auth_b_headers and list_fields:
            for lf in list_fields:
                try:
                    h_ids = await extract_ids_from_list_query(url, lf, "query", auth_b_headers, builder, client)
                    harvested_ids.extend(h_ids)
                except Exception:
                    pass

        # Step 2: Enumerate detail queries
        for df in detail_fields:
            # Find the ID argument
            id_arg = None
            for arg in df.args:
                if arg.type_ref.get_deep_name().upper() in ["ID", "INT", "STRING"]:
                    id_arg = arg
                    break
                    
            if not id_arg:
                continue
                
            var_name = f"{df.name}_{id_arg.name}"
            
            # Formulate IDs to test
            test_ids = []
            
            # If we harvested IDs from user B, use them! (Testing cross-user BOLA)
            if harvested_ids:
                test_ids.extend(harvested_ids[:5])
            else:
                # Fallback: simple sequential enumeration
                # We start with "1" or "2"
                test_ids.extend(["1", "2", "3", "100", "101"])
                # Add a couple of random UUIDs to test response behavior
                test_ids.extend([str(uuid.uuid4()) for _ in range(2)])

            # Query each candidate ID with auth_a credentials.
            # To avoid false positives we distinguish three cases:
            #   1. Cross-user: A reads an ID harvested from B      -> confirmed BOLA
            #   2. Unauthenticated: no creds read a detail object  -> confirmed BOLA
            #   3. Sequential walk: authed A reads >=2 DISTINCT objects by guessing
            #      IDs. A single hit may just be A's own object, so one is not enough.
            flagged = False
            distinct_objects = {}  # serialized_object -> tid (dedup identical/empty payloads)

            for tid in test_ids:
                query_str, variables = builder.build_operation("query", df, max_depth)
                variables[var_name] = tid

                res = await execute_query(url, query_str, variables, auth_a_headers, client)
                data_val = res.get("data", {}).get(df.name) if res.get("data") else None
                if not (res.get("data") and data_val is not None):
                    continue

                # Case 1 & 2: high-confidence, flag immediately.
                reason = None
                if harvested_ids and tid in harvested_ids:
                    reason = f"Accessed Auth B's object ID '{tid}' using Auth A's credentials"
                elif not auth_a_headers:
                    reason = f"Unauthenticated access to detail object ID '{tid}'"

                if reason:
                    findings.append(ShockwaveFinding(
                        id="",
                        rule_id="SHOCKWAVE-IDOR-001",
                        rule_name="Object-level authorization bypass",
                        severity="high",
                        owasp_category="API1:2023 — Broken Object Level Authorization",
                        cwe_id="CWE-639",
                        field_path=f"Query.{df.name}",
                        engine="Generic",
                        evidence_request=query_str + f"\nVariables: {json.dumps(variables)}\n{reason}",
                        evidence_response=json.dumps(res)[:500],
                        auth_context="unauthenticated" if not auth_a_headers else "Auth A (Lower)",
                        confidence="confirmed",
                        confirmation_count=1,
                        remediation=f"Verify the caller owns or may view the resource for ID '{tid}' before resolving Query.{df.name}.",
                        references=["https://owasp.org/API-Security/editions/2023/en/0x07-api1-broken-object-level-authorization/"]
                    ))
                    flagged = True
                    break  # One finding per field path

                # Case 3: record distinct object payloads for post-loop analysis.
                serialized = json.dumps(data_val, sort_keys=True)
                distinct_objects.setdefault(serialized, tid)

            # Case 3 verdict: >=2 distinct objects reachable by ID guessing under
            # an authenticated session with no harvested IDs = likely missing
            # ownership check (walkable), reported as medium/likely for review.
            if not flagged and not harvested_ids and auth_a_headers and len(distinct_objects) >= 2:
                sample_ids = list(distinct_objects.values())[:3]
                findings.append(ShockwaveFinding(
                    id="",
                    rule_id="SHOCKWAVE-IDOR-001",
                    rule_name="Object-level authorization bypass",
                    severity="medium",
                    owasp_category="API1:2023 — Broken Object Level Authorization",
                    cwe_id="CWE-639",
                    field_path=f"Query.{df.name}",
                    engine="Generic",
                    evidence_request=f"Query.{df.name} returned {len(distinct_objects)} distinct objects for guessed IDs {sample_ids} under one session",
                    evidence_response="Multiple distinct objects reachable by sequential ID enumeration",
                    auth_context="Auth A (Lower)",
                    confidence="likely",
                    confirmation_count=1,
                    remediation=f"Confirm manually that Query.{df.name} enforces per-object ownership; sequential IDs should not expose other users' objects.",
                    references=["https://owasp.org/API-Security/editions/2023/en/0x07-api1-broken-object-level-authorization/"]
                ))

    return findings
