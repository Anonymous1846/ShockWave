import httpx
import json
import time
from typing import Dict, Any, List, Optional, Tuple
from shockwave.schema.models import GraphQLSchema, QueryBuilder, GraphQLField
from shockwave.output.sarif_writer import ShockwaveFinding

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\\' OR \\'1\\'=\\'1",
    "\" OR \"1\"=\"1",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1"
]

SQL_ERROR_SIGNATURES = [
    "sql syntax", "ora-", "pg_", "mysql_", "sqlite", "mariadb", 
    "postgre", "database error", "driver error", "syntax error near"
]

NOSQLI_PAYLOADS = [
    {"$gt": ""},
    {"$ne": None},
    "{\"$gt\": \"\"}"
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//etc/passwd",
    "..\\..\\..\\windows\\win.ini"
]

async def execute_fuzz_query(
    url: str,
    query: str,
    variables: Dict[str, Any],
    headers: Optional[Dict[str, str]],
    client: httpx.AsyncClient
) -> Tuple[int, Dict[str, Any], float]:
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    start = time.time()
    try:
        res = await client.post(url, json={"query": query, "variables": variables}, headers=req_headers, timeout=10)
        elapsed = time.time() - start
        return res.status_code, res.json(), elapsed
    except Exception as e:
        return 500, {"errors": [{"message": str(e)}]}, time.time() - start

async def scan_injection(
    url: str,
    schema: GraphQLSchema,
    headers: Optional[Dict[str, str]] = None,
    collaborator_url: Optional[str] = None
) -> List[ShockwaveFinding]:
    """
    Fuzzes Query/Mutation arguments for SQLi, NoSQLi, Path Traversal, and SSRF (FR-6).
    """
    findings = []
    builder = QueryBuilder(schema)
    
    # Collect all queries and mutations
    entrypoints = []
    q_type = schema.types.get(schema.query_type or "Query")
    if q_type:
        entrypoints.extend([("query", f) for f in q_type.fields])
    m_type = schema.types.get(schema.mutation_type or "Mutation")
    if m_type:
        entrypoints.extend([("mutation", f) for f in m_type.fields])

    async with httpx.AsyncClient(verify=False) as client:
        for op_type, field in entrypoints:
            # Only test fields that have arguments
            if not field.args:
                continue
                
            for arg in field.args:
                arg_type = arg.type_ref.get_deep_name().upper()
                
                # Check for SSRF triggers (FR-6.4)
                is_url_arg = any(x in arg.name.lower() for x in ["url", "endpoint", "webhook", "callback", "redirect", "destination"])
                if is_url_arg and collaborator_url:
                    query_str, variables = builder.build_operation(op_type, field)
                    # Insert collaborator URL
                    var_name = f"{field.name}_{arg.name}"
                    variables[var_name] = collaborator_url
                    
                    status, res_data, _ = await execute_fuzz_query(url, query_str, variables, headers, client)
                    # SSRF is confirmed if we hit the collaborator.
                    # Since we can't check the collaborator DNS server here, we flag it as likely/possible SSRF.
                    findings.append(ShockwaveFinding(
                        id="",
                        rule_id="SHOCKWAVE-INJ-003",
                        rule_name="SSRF via GraphQL mutation URL argument",
                        severity="high",
                        owasp_category="API7:2023 — Server Side Request Forgery",
                        cwe_id="CWE-918",
                        field_path=f"{op_type.capitalize()}.{field.name}.{arg.name}",
                        engine="Generic",
                        evidence_request=f"Variable {var_name} set to {collaborator_url}",
                        evidence_response=f"Status: {status}\nResponse: {str(res_data)[:200]}",
                        auth_context="No Auth" if not headers else "Provided Auth",
                        confidence="likely",
                        confirmation_count=1,
                        remediation="Validate URL inputs against a strict whitelist and route requests through a proxy with restricted egress.",
                        references=["https://owasp.org/API-Security/editions/2023/en/0x0d-api7-server-side-request-forgery/"]
                    ))
                
                # Fuzz strings and IDs
                if "STRING" in arg_type or "ID" in arg_type:
                    var_name = f"{field.name}_{arg.name}"
                    
                    # 1. SQLi Tests
                    for payload in SQLI_PAYLOADS:
                        query_str, variables = builder.build_operation(op_type, field)
                        variables[var_name] = payload
                        
                        status, res_data, elapsed = await execute_fuzz_query(url, query_str, variables, headers, client)
                        errors = res_data.get("errors", [])
                        
                        # Detect by error messages
                        has_sqli_err = False
                        for err in errors:
                            msg = err.get("message", "").lower()
                            if any(sig in msg for sig in SQL_ERROR_SIGNATURES):
                                has_sqli_err = True
                                break
                                
                        if has_sqli_err:
                            findings.append(ShockwaveFinding(
                                id="",
                                rule_id="SHOCKWAVE-INJ-001",
                                rule_name="SQL injection via GraphQL argument",
                                severity="critical",
                                owasp_category="API3:2023 — Server-Side Request Forgery",  # Actually injection is usually API3 in OWASP API top 10
                                cwe_id="CWE-89",
                                field_path=f"{op_type.capitalize()}.{field.name}.{arg.name}",
                                engine="Generic",
                                evidence_request=query_str + f"\nVariables: {json.dumps(variables)}",
                                evidence_response=json.dumps(res_data)[:500],
                                auth_context="No Auth" if not headers else "Provided Auth",
                                confidence="confirmed",
                                confirmation_count=1,
                                remediation="Ensure raw inputs are parameterized using ORM query tools or prepared statements rather than raw string concatenation.",
                                references=["https://owasp.org/www-community/attacks/SQL_Injection"]
                            ))
                            break # No need to run more SQLi payloads for this arg
                    
                    # 2. NoSQLi Tests (MongoDB)
                    for payload in NOSQLI_PAYLOADS:
                        query_str, variables = builder.build_operation(op_type, field)
                        variables[var_name] = payload
                        
                        status, res_data, _ = await execute_fuzz_query(url, query_str, variables, headers, client)
                        errors = res_data.get("errors", [])
                        
                        # NoSQLi error signature or success when sending object type where string is expected
                        # Check if response returned valid non-empty list of data or bypass error messages
                        # For a NoSQL injection, sending {"$gt": ""} might return users that shouldn't be matched
                        data_val = res_data.get("data", {}).get(field.name) if res_data.get("data") else None
                        if status == 200 and data_val is not None and len(str(data_val)) > 10:
                            findings.append(ShockwaveFinding(
                                id="",
                                rule_id="SHOCKWAVE-INJ-002",
                                rule_name="NoSQL injection via GraphQL argument",
                                severity="high",
                                owasp_category="API3:2023 — Server-Side Request Forgery",
                                cwe_id="CWE-943",
                                field_path=f"{op_type.capitalize()}.{field.name}.{arg.name}",
                                engine="Generic",
                                evidence_request=query_str + f"\nVariables: {json.dumps(variables)}",
                                evidence_response=json.dumps(res_data)[:500],
                                auth_context="No Auth" if not headers else "Provided Auth",
                                confidence="likely",
                                confirmation_count=1,
                                remediation="Ensure NoSQL database queries sanitize inputs or validate strict schemas rather than passing raw JSON objects.",
                                references=["https://owasp.org/www-section/resources/articles/NOSQL_Injection_in_MongoDB"]
                            ))
                            break

                    # 3. Path Traversal Tests
                    is_file_arg = any(x in arg.name.lower() for x in ["file", "path", "attachment", "document", "upload"])
                    if is_file_arg:
                        for payload in PATH_TRAVERSAL_PAYLOADS:
                            query_str, variables = builder.build_operation(op_type, field)
                            variables[var_name] = payload
                            
                            status, res_data, _ = await execute_fuzz_query(url, query_str, variables, headers, client)
                            # Traversal is confirmed if response contains system file markers (e.g. root:x:0:0 or [fonts])
                            resp_str = str(res_data)
                            if "root:x:0:0" in resp_str or "[boot loader]" in resp_str or "[fonts]" in resp_str:
                                findings.append(ShockwaveFinding(
                                    id="",
                                    rule_id="SHOCKWAVE-INJ-004",  # Path traversal rule
                                    rule_name="Path traversal via GraphQL argument",
                                    severity="critical",
                                    owasp_category="API3:2023 — Server-Side Request Forgery",
                                    cwe_id="CWE-22",
                                    field_path=f"{op_type.capitalize()}.{field.name}.{arg.name}",
                                    engine="Generic",
                                    evidence_request=query_str + f"\nVariables: {json.dumps(variables)}",
                                    evidence_response=json.dumps(res_data)[:500],
                                    auth_context="No Auth" if not headers else "Provided Auth",
                                    confidence="confirmed",
                                    confirmation_count=1,
                                    remediation="Sanitize path arguments, validate filename patterns, and ensure lookups stay within predefined directories.",
                                    references=["https://owasp.org/www-community/attacks/Path_Traversal"]
                                ))
                                break

    return findings
