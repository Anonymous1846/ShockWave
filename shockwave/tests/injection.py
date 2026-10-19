import asyncio
import httpx
import json
import time
from typing import Dict, Any, List, Optional, Tuple
from shockwave import net
from shockwave.schema.models import GraphQLSchema, QueryBuilder, GraphQLField
from shockwave.output.sarif_writer import ShockwaveFinding

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1' OR '1'='1",
    "\" OR \"1\"=\"1",
]

SQL_ERROR_SIGNATURES = [
    "sql syntax", "ora-", "pg_", "mysql_", "sqlite", "mariadb",
    "postgre", "database error", "driver error", "syntax error near"
]

# Time-based (blind) SQLi. The backend sleeps DELAY_SECONDS if the input reaches
# a SQL engine unparameterized; we detect the induced latency instead of an error
# string, catching blind injection that error-based checks miss. {D} = delay.
TIME_DELAY_SECONDS = 5
TIME_BASED_SQLI_PAYLOADS = [
    "1' AND SLEEP({D})-- -",              # MySQL / MariaDB
    "1'||pg_sleep({D})-- -",              # PostgreSQL
    "1' AND 1=(SELECT 1 FROM pg_sleep({D}))-- -",
    "1'; WAITFOR DELAY '0:0:{D}'-- -",    # MSSQL
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

def _boolean_blind_hit(true_val, false_val) -> bool:
    """Boolean-blind SQLi signal: the TRUE condition returned data and the
    FALSE condition returned something different (typically null/empty)."""
    return true_val is not None and true_val != false_val


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
    collaborator_url: Optional[str] = None,
    test_mutations: bool = False
) -> List[ShockwaveFinding]:
    """
    Fuzzes argument values for SQLi, NoSQLi, Path Traversal, and SSRF (FR-6).

    Query fields only by default. Mutations are fuzzed only when
    ``test_mutations`` is set: blindly sending payloads to mutations is slow
    (e.g. an importPaste/SSRF arg stalls on an outbound fetch) and unsafe (a
    deletePaste/systemUpdate mutation mutates or destroys data).
    """
    findings = []
    builder = QueryBuilder(schema)

    # Collect entrypoints — queries always, mutations only if opted in.
    entrypoints = []
    q_type = schema.types.get(schema.query_type or "Query")
    if q_type:
        entrypoints.extend([("query", f) for f in q_type.fields])
    if test_mutations:
        m_type = schema.types.get(schema.mutation_type or "Mutation")
        if m_type:
            entrypoints.extend([("mutation", f) for f in m_type.fields])

    async with net.client() as client:
        async def fuzz_field(op_type, field):
            out = []
            # Only test fields that have arguments
            if not field.args:
                return out

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
                    out.append(ShockwaveFinding(
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
                    
                    # 1. SQLi Tests (error-based)
                    sqli_found = False
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
                            sqli_found = True
                            out.append(ShockwaveFinding(
                                id="",
                                rule_id="SHOCKWAVE-INJ-001",
                                rule_name="SQL injection via GraphQL argument",
                                severity="critical",
                                owasp_category="API3:2023 — Injection",
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

                    # 1b. Time-based blind SQLi (only if error-based found nothing).
                    # Establish a baseline latency, then send a delay payload; a
                    # response that takes ~DELAY longer confirms injection without
                    # any error string. Confirm with a second request to rule out
                    # a one-off slow response.
                    if not sqli_found:
                        baseline_q, baseline_v = builder.build_operation(op_type, field)
                        baseline_v[var_name] = "1"
                        _, _, baseline_elapsed = await execute_fuzz_query(url, baseline_q, baseline_v, headers, client)
                        threshold = baseline_elapsed + TIME_DELAY_SECONDS * 0.6

                        for tpl in TIME_BASED_SQLI_PAYLOADS:
                            payload = tpl.format(D=TIME_DELAY_SECONDS)
                            q_str, variables = builder.build_operation(op_type, field)
                            variables[var_name] = payload
                            _, _, delayed = await execute_fuzz_query(url, q_str, variables, headers, client)
                            if delayed < threshold:
                                continue
                            # Re-confirm the delay before reporting.
                            _, _, delayed2 = await execute_fuzz_query(url, q_str, variables, headers, client)
                            if delayed2 < threshold:
                                continue
                            out.append(ShockwaveFinding(
                                id="",
                                rule_id="SHOCKWAVE-INJ-001",
                                rule_name="Time-based blind SQL injection via GraphQL argument",
                                severity="critical",
                                owasp_category="API3:2023 — Injection",
                                cwe_id="CWE-89",
                                field_path=f"{op_type.capitalize()}.{field.name}.{arg.name}",
                                engine="Generic",
                                evidence_request=q_str + f"\nVariables: {json.dumps(variables)}",
                                evidence_response=(
                                    f"Baseline {baseline_elapsed:.2f}s; delay payload {delayed:.2f}s / {delayed2:.2f}s "
                                    f"(threshold {threshold:.2f}s). Induced latency indicates blind SQLi."
                                ),
                                auth_context="No Auth" if not headers else "Provided Auth",
                                confidence="likely",
                                confirmation_count=2,
                                remediation="Parameterize all database inputs; a controllable response delay proves the argument reaches the SQL engine unsanitized.",
                                references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"]
                            ))
                            sqli_found = True
                            break

                    # 1c. Boolean-based blind SQLi (engine-agnostic — works on
                    # SQLite etc. that have no sleep primitive for time-based).
                    # A TRUE condition returns the row; a FALSE one does not.
                    if not sqli_found:
                        t_q, t_v = builder.build_operation(op_type, field)
                        t_v[var_name] = "1' AND '1'='1"
                        f_q, f_v = builder.build_operation(op_type, field)
                        f_v[var_name] = "1' AND '1'='2"
                        _, t_res, _ = await execute_fuzz_query(url, t_q, t_v, headers, client)
                        _, f_res, _ = await execute_fuzz_query(url, f_q, f_v, headers, client)
                        t_val = t_res.get("data", {}).get(field.name) if t_res.get("data") else None
                        f_val = f_res.get("data", {}).get(field.name) if f_res.get("data") else None
                        if _boolean_blind_hit(t_val, f_val):
                            out.append(ShockwaveFinding(
                                id="", rule_id="SHOCKWAVE-INJ-001",
                                rule_name="Boolean-based blind SQL injection via GraphQL argument",
                                severity="critical", owasp_category="API3:2023 — Injection",
                                cwe_id="CWE-89",
                                field_path=f"{op_type.capitalize()}.{field.name}.{arg.name}",
                                engine="Generic",
                                evidence_request=f"TRUE: {json.dumps(t_v)}\nFALSE: {json.dumps(f_v)}",
                                evidence_response="TRUE condition returned data; FALSE condition did not — input alters the WHERE clause.",
                                auth_context="No Auth" if not headers else "Provided Auth",
                                confidence="likely", confirmation_count=1,
                                remediation="Parameterize database inputs; a response that depends on an injected boolean condition proves the argument reaches the SQL engine unsanitized.",
                                references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"]
                            ))
                            sqli_found = True

                    # 2. NoSQLi Tests (MongoDB) — differential detection.
                    # Baseline with the benign sample value, then inject an
                    # operator object ({"$gt":""} etc). A real NoSQLi makes the
                    # operator return data the benign value did not (filter
                    # bypass), which is far less noisy than a length heuristic.
                    base_q, base_v = builder.build_operation(op_type, field)
                    _, base_res, _ = await execute_fuzz_query(url, base_q, base_v, headers, client)
                    base_val = base_res.get("data", {}).get(field.name) if base_res.get("data") else None

                    for payload in NOSQLI_PAYLOADS:
                        query_str, variables = builder.build_operation(op_type, field)
                        variables[var_name] = payload

                        status, res_data, _ = await execute_fuzz_query(url, query_str, variables, headers, client)
                        data_val = res_data.get("data", {}).get(field.name) if res_data.get("data") else None

                        # Flag when the operator payload returns data that the
                        # benign request did not (new data, or a larger result set).
                        bypassed = False
                        if status == 200 and data_val is not None:
                            if base_val is None:
                                bypassed = True
                            elif isinstance(data_val, list) and isinstance(base_val, list) and len(data_val) > len(base_val):
                                bypassed = True
                            elif data_val != base_val and not isinstance(data_val, list):
                                bypassed = True

                        if bypassed:
                            out.append(ShockwaveFinding(
                                id="",
                                rule_id="SHOCKWAVE-INJ-002",
                                rule_name="NoSQL injection via GraphQL argument",
                                severity="high",
                                owasp_category="API3:2023 — Injection",
                                cwe_id="CWE-943",
                                field_path=f"{op_type.capitalize()}.{field.name}.{arg.name}",
                                engine="Generic",
                                evidence_request=query_str + f"\nVariables: {json.dumps(variables)}",
                                evidence_response=(
                                    "Operator payload returned data the benign value did not.\n"
                                    + json.dumps(res_data)[:400]
                                ),
                                auth_context="No Auth" if not headers else "Provided Auth",
                                confidence="likely",
                                confirmation_count=1,
                                remediation="Ensure NoSQL database queries sanitize inputs or validate strict schemas rather than passing raw JSON objects.",
                                references=["https://owasp.org/www-community/attacks/Testing_for_NoSQL_injection"]
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
                                out.append(ShockwaveFinding(
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
            return out

        # Fuzz every entrypoint concurrently; net._semaphore bounds in-flight
        # requests so this stays WAF-friendly while cutting wall-time.
        results = await asyncio.gather(*[fuzz_field(op, fld) for op, fld in entrypoints])
        for r in results:
            findings.extend(r)

    return findings
