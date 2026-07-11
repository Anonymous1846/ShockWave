import httpx
import time
from typing import Dict, Any, List, Tuple, Set, Optional
from shockwave.schema.models import GraphQLSchema, GraphQLType, GraphQLField
from shockwave.output.sarif_writer import ShockwaveFinding

def find_cycles(schema: GraphQLSchema) -> List[Tuple[List[str], List[str]]]:
    """
    Finds cycles in the schema type graph using DFS.
    Returns a list of cycles, each represented as a tuple: (prefix_fields, loop_fields).
    """
    cycles = []
    path_types = []
    path_fields = []

    def dfs(type_name: str):
        gtype = schema.get_type(type_name)
        if not gtype or gtype.kind != "OBJECT":
            return
            
        path_types.append(type_name)
        
        for field in gtype.fields:
            field_deep_type = field.type_ref.get_deep_name()
            
            if field_deep_type in path_types:
                # Cycle found!
                start_idx = path_types.index(field_deep_type)
                prefix = path_fields[:start_idx]
                loop = path_fields[start_idx:] + [field.name]
                cycles.append((prefix, loop))
                continue
                
            path_fields.append(field.name)
            dfs(field_deep_type)
            path_fields.pop()
            
        path_types.pop()

    if schema.query_type in schema.types:
        dfs(schema.query_type)
        
    return cycles

def build_nested_query(cycle: Tuple[List[str], List[str]], depth: int) -> str:
    """
    Generates a nested recursive query string based on a prefix and loop.
    Example:
    Query -> user -> friends -> user -> friends ...
    """
    prefix, loop = cycle
    if not loop:
        return "query { __typename }"
        
    query_parts = []
    indent = ""
    
    # 1. Output prefix fields
    for field in prefix:
        query_parts.append(f"{indent}{field} {{")
        indent += "  "
        
    # 2. Output loop fields repeatedly until we satisfy depth
    # Total depth of query matches the target depth parameter.
    # Note: depth includes prefix depth.
    loop_depth = max(1, depth - len(prefix))
    for d in range(loop_depth):
        f_name = loop[d % len(loop)]
        query_parts.append(f"{indent}{f_name} {{")
        indent += "  "
        
    query_parts.append(f"{indent}__typename")
    
    # 3. Close all brackets
    total_brackets = len(prefix) + loop_depth
    for d in range(total_brackets):
        indent = indent[:-2]
        query_parts.append(f"{indent}}}")
        
    return "query {\n" + "\n".join(query_parts) + "\n}"

def calculate_complexity(depth: int, field_count_per_level: int = 2) -> int:
    """
    complexity_estimate = sum of (2^depth_level * field_count) per nesting level.
    """
    total = 0
    for level in range(1, depth + 1):
        total += (2 ** level) * field_count_per_level
    return total

async def scan_dos(
    url: str,
    schema: GraphQLSchema,
    headers: Optional[Dict[str, str]] = None
) -> List[ShockwaveFinding]:
    """
    Runs DoS testing by sending recursive queries at varying depths (FR-4).
    Also performs breadth checks.
    """
    findings = []
    cycles = find_cycles(schema)
    if not cycles:
        return findings

    # Use the first detected cycle for scanning
    cycle = cycles[0]
    depths = [5, 10, 15, 20, 50]
    
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
        
    async with httpx.AsyncClient(verify=False) as client:
        last_duration = 0.0
        
        for d in depths:
            query = build_nested_query(cycle, d)
            complexity = calculate_complexity(d)
            
            # Send recursive query
            start_time = time.time()
            try:
                res = await client.post(url, json={"query": query}, headers=req_headers, timeout=35)
                duration = time.time() - start_time
                status = res.status_code
                res_data = res.json()
            except httpx.TimeoutException:
                duration = 30.0
                status = 504
                res_data = {"error": "Timeout"}
            except Exception as e:
                duration = 0.0
                status = 500
                res_data = {"error": str(e)}

            # Finding conditions
            is_dos = False
            reproduce_details = f"Depth {d} queried. Time: {duration:.2f}s."
            
            # Check 1: Server times out or errors
            if status >= 500 or "errors" in res_data and not res_data.get("data"):
                # If it's a validation error that blocks depth, this is GOOD (prevented DoS)
                msg = str(res_data.get("errors", "")).lower()
                if "depth" in msg or "complexity" in msg or "limit" in msg:
                    # Server successfully blocked the DoS, skip
                    break
                else:
                    is_dos = True
            
            # Check 2: Exponential growth (N vs N-5)
            # e.g. depth 10 takes 3x depth 5
            if d > 5 and last_duration > 0.1 and duration >= 3.0 * last_duration:
                is_dos = True
                
            # Check 3: Too slow
            if duration > 15.0:
                is_dos = True

            if is_dos:
                findings.append(ShockwaveFinding(
                    id="",
                    rule_id="SHOCKWAVE-DOS-001",
                    rule_name="Nested query depth DoS",
                    severity="high",
                    owasp_category="API4:2023 — Unrestricted Resource Consumption",
                    cwe_id="CWE-400",
                    field_path=f"Query.{cycle[0][0] if cycle[0] else cycle[1][0]}",
                    engine="Generic",
                    evidence_request=query,
                    evidence_response=f"Status: {status}\nTime taken: {duration:.2f} seconds\nComplexity: {complexity}\nResponse: {str(res_data)[:200]}",
                    auth_context="No Auth" if not headers else "Provided Auth",
                    confidence="confirmed",
                    confirmation_count=1,
                    remediation=f"Configure query depth limiting in the GraphQL gateway (e.g. max depth 10).",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#depth-limiting"]
                ))
                break  # Stop to avoid crashing the server completely
                
            last_duration = duration

        # Breadth DoS Probe (FR-4.5)
        # Query 200 fields at the same level
        # We can construct a query with 200 __typename fields or alias lookups
        breadth_fields = []
        for idx in range(250):
            breadth_fields.append(f"alias_{idx}: __typename")
            
        breadth_query = "query {\n  " + "\n  ".join(breadth_fields) + "\n}"
        try:
            res_breadth = await client.post(url, json={"query": breadth_query}, headers=req_headers, timeout=10)
            res_data_b = res_breadth.json()
            if res_breadth.status_code == 200 and "data" in res_data_b:
                # If successfully executed 250 fields, check if depth limit exists
                findings.append(ShockwaveFinding(
                    id="",
                    rule_id="SHOCKWAVE-DOS-002",
                    rule_name="Excessive field breadth DoS",
                    severity="medium",
                    owasp_category="API4:2023 — Unrestricted Resource Consumption",
                    cwe_id="CWE-400",
                    field_path="Query",
                    engine="Generic",
                    evidence_request=breadth_query[:200] + "\n... [truncated 250 fields] ...",
                    evidence_response=f"Executed successfully. Return keys count: {len(res_data_b.get('data', {}))}",
                    auth_context="No Auth" if not headers else "Provided Auth",
                    confidence="confirmed",
                    confirmation_count=1,
                    remediation="Implement query complexity analysis or a field limit rules processor (e.g., maximum 50 fields per query).",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#query-cost-analysis"]
                ))
        except Exception:
            pass

    return findings
