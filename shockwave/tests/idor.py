import httpx
import uuid
import json
from typing import Dict, Any, List, Optional
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

    async with httpx.AsyncClient(verify=False) as client:
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

            # Query with auth_a credentials
            for tid in test_ids:
                query_str, variables = builder.build_operation("query", df, max_depth)
                variables[var_name] = tid
                
                # Check if auth_a is allowed to query this ID
                res = await execute_query(url, query_str, variables, auth_a_headers, client)
                data_val = res.get("data", {}).get(df.name) if res.get("data") else None
                
                # BOLA check: if response contains data for an ID belonging to B (if harvested)
                # or general successful access of sequential IDs that aren't authenticated-owned.
                if res.get("data") and data_val is not None:
                    # To be a BOLA, the resource accessed must return non-null
                    # and if we queried a cross-user harvested ID
                    is_bola = False
                    reason = ""
                    
                    if harvested_ids and tid in harvested_ids:
                        is_bola = True
                        reason = f"Accessed Auth B's object ID: {tid} using Auth A's credentials"
                    elif not auth_a_headers:
                        # Unauthenticated user accessing detail resources
                        is_bola = True
                        reason = f"Unauthenticated access to detail object ID: {tid}"
                    else:
                        # Authenticated access to arbitrary sequential IDs
                        is_bola = True
                        reason = f"Accessed sequential detail object ID: {tid} without ownership validation check"

                    if is_bola:
                        findings.append(ShockwaveFinding(
                            id="",
                            rule_id="SHOCKWAVE-IDOR-001",
                            rule_name="Object-level authorization bypass",
                            severity="high",
                            owasp_category="API1:2023 — Broken Object Level Authorization",
                            cwe_id="CWE-639",
                            field_path=f"Query.{df.name}",
                            engine="Generic",
                            evidence_request=query_str + f"\nVariables: {json.dumps(variables)}",
                            evidence_response=json.dumps(res)[:500],
                            auth_context="Auth A (Lower)",
                            confidence="confirmed",
                            confirmation_count=1,
                            remediation=f"Verify that the authenticated user owns or has explicit permission to view the resource represented by ID '{tid}' before executing the query.",
                            references=["https://owasp.org/API-Security/editions/2023/en/0x07-api1-broken-object-level-authorization/"]
                        ))
                        break # Only report one IDOR finding per field path to avoid spam

    return findings
