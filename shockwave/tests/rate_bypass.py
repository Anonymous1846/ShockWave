import httpx
import json
from typing import Dict, Any, List, Optional, Tuple
from shockwave.schema.models import GraphQLSchema
from shockwave.output.sarif_writer import ShockwaveFinding

AUTH_MUTATION_PATTERNS = ["login", "signin", "authenticate", "verifyotp", "resetpassword", "changepassword", "requestpasswordreset"]

def find_target_field(schema: GraphQLSchema) -> Tuple[str, str, Dict[str, Any]]:
    """
    Finds a suitable authentication mutation or query to target.
    Returns (operation_type, field_name, sample_arguments)
    """
    # 1. Search in Mutations
    mutation_type = schema.types.get(schema.mutation_type or "Mutation")
    if mutation_type and mutation_type.fields:
        for field in mutation_type.fields:
            if any(p in field.name.lower() for p in AUTH_MUTATION_PATTERNS):
                # Generate simple args: email/password or default
                args = {}
                for arg in field.args:
                    args[arg.name] = "test@example.com" if "email" in arg.name.lower() else "wrong_pass"
                return "mutation", field.name, args

    # 2. Check for any mutation
    if mutation_type and mutation_type.fields:
        field = mutation_type.fields[0]
        args = {arg.name: "test" for arg in field.args}
        return "mutation", field.name, args

    # 3. Fallback to a Query field
    query_type = schema.types.get(schema.query_type or "Query")
    if query_type and query_type.fields:
        for field in query_type.fields:
            if any(p in field.name.lower() for p in AUTH_MUTATION_PATTERNS):
                return "query", field.name, {}
        return "query", query_type.fields[0].name, {}

    return "query", "__typename", {}

def build_aliased_query(
    op_type: str,
    field_name: str,
    args: Dict[str, Any],
    batch_size: int
) -> str:
    """
    Builds a query with many aliased calls to the same field.
    Example:
    mutation {
      a001: login(username: "x") { token }
      a002: login(username: "x") { token }
    }
    """
    arg_str = ""
    if args:
        # Convert dictionary to GraphQL argument format
        # e.g., username: "x", password: "y"
        parts = []
        for k, v in args.items():
            # JSON serialization is close enough to GraphQL syntax for basic types
            parts.append(f"{k}: {json.dumps(v)}")
        arg_str = f"({', '.join(parts)})"

    lines = []
    for i in range(batch_size):
        lines.append(f"  a{i:04d}: {field_name}{arg_str}")
        
    return f"{op_type} {{\n" + "\n".join(lines) + "\n}"

async def scan_rate_bypass(
    url: str,
    schema: GraphQLSchema,
    headers: Optional[Dict[str, str]] = None,
    batch_size: int = 500
) -> List[ShockwaveFinding]:
    """
    Tests if the server is vulnerable to alias-based and array-based rate-limit bypasses (FR-5).
    """
    findings = []
    op_type, field_name, args = find_target_field(schema)
    
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
        
    async with httpx.AsyncClient(verify=False) as client:
        # Test 1: Alias-based rate limiting bypass
        # We try with the specified batch size (default 500)
        query = build_aliased_query(op_type, field_name, args, batch_size)
        
        try:
            res = await client.post(url, json={"query": query}, headers=req_headers, timeout=20)
            res_data = res.json()
            
            # Check if execution was successful and returned multiple alias responses
            if res.status_code == 200 and "data" in res_data:
                data_keys = res_data.get("data", {}).keys()
                # If we get a response key for each alias, it executed them all
                if len(data_keys) >= batch_size - 10:  # Allow some wiggle room
                    findings.append(ShockwaveFinding(
                        id="",
                        rule_id="SHOCKWAVE-RATE-001",
                        rule_name="Alias-based rate limit bypass",
                        severity="high",
                        owasp_category="API4:2023 — Unrestricted Resource Consumption",
                        cwe_id="CWE-307",
                        field_path=f"{op_type.capitalize()}.{field_name}",
                        engine="Generic",
                        evidence_request=query[:200] + f"\n... [truncated {batch_size} aliases] ...",
                        evidence_response=f"Executed {len(data_keys)} operations in a single HTTP request successfully.",
                        auth_context="No Auth" if not headers else "Provided Auth",
                        confidence="confirmed",
                        confirmation_count=1,
                        remediation=f"Limit the maximum number of aliases or fields executed per request (e.g. max 50).",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#alias-overloading"]
                    ))
        except Exception:
            pass

        # Test 2: Array-based batching rate limiting bypass (FR-5.5)
        # We send an array of query objects
        array_batch_size = 100
        single_payload = {"query": f"{op_type} {{ {field_name} }}"}
        array_payload = [single_payload for _ in range(array_batch_size)]
        
        try:
            res_arr = await client.post(url, json=array_payload, headers=req_headers, timeout=20)
            res_arr_data = res_arr.json()
            
            if res_arr.status_code == 200 and isinstance(res_arr_data, list) and len(res_arr_data) == array_batch_size:
                findings.append(ShockwaveFinding(
                    id="",
                    rule_id="SHOCKWAVE-RATE-002",
                    rule_name="Array batching rate limit bypass",
                    severity="high",
                    owasp_category="API4:2023 — Unrestricted Resource Consumption",
                    cwe_id="CWE-307",
                    field_path=f"{op_type.capitalize()}.{field_name}",
                    engine="Generic",
                    evidence_request=f"POST {url} with list of {array_batch_size} operations",
                    evidence_response=f"Server executed array of size {len(res_arr_data)} returning HTTP 200.",
                    auth_context="No Auth" if not headers else "Provided Auth",
                    confidence="confirmed",
                    confirmation_count=1,
                    remediation="Disable HTTP request batching or enforce rate limiting on individual operations inside the batch.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#batching-attacks"]
                ))
        except Exception:
            pass

    return findings
