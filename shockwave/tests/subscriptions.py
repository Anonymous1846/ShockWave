import asyncio
import json
from urllib.parse import urlparse
import websockets
from typing import Dict, Any, List, Optional, Tuple
from shockwave.schema.models import GraphQLSchema, QueryBuilder, GraphQLField
from shockwave.output.sarif_writer import ShockwaveFinding

# Protocol names
WS_SUB_PROTOCOL_MODERN = "graphql-ws"
WS_SUB_PROTOCOL_LEGACY = "graphql-transport-ws"  # Or legacy subscriptions-transport-ws protocol fallback

def resolve_ws_url(http_url: str) -> str:
    parsed = urlparse(http_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    netloc = parsed.netloc
    path = parsed.path
    return f"{scheme}://{netloc}{path}"

async def attempt_ws_handshake(
    ws_url: str,
    protocol: str,
    headers: Optional[Dict[str, str]] = None
) -> Tuple[bool, Optional[websockets.WebSocketClientProtocol]]:
    """Tries connection upgrade and basic connection_init shake."""
    extra_headers = {}
    if headers:
        extra_headers.update(headers)
        
    try:
        ws = await websockets.connect(
            ws_url,
            subprotocols=[protocol],
            extra_headers=extra_headers,
            ping_interval=None,
            open_timeout=5
        )
        
        # connection_init payload
        init_payload = {"type": "connection_init", "payload": {}}
        if headers:
            init_payload["payload"] = {"headers": headers}
            
        await ws.send(json.dumps(init_payload))
        
        # Wait for acknowledgment
        resp = await asyncio.wait_for(ws.recv(), timeout=5)
        resp_data = json.loads(resp)
        
        if resp_data.get("type") == "connection_ack":
            return True, ws
            
        await ws.close()
        return False, None
    except Exception:
        return False, None

async def scan_subscription_auth(
    ws_url: str,
    protocol: str,
    sub_field: GraphQLField,
    builder: QueryBuilder,
    auth_a_headers: Optional[Dict[str, str]],
    auth_b_headers: Optional[Dict[str, str]]
) -> List[ShockwaveFinding]:
    """Tests if we can establish a subscription to data we shouldn't access."""
    findings = []
    
    # Generate query
    query_str, variables = builder.build_operation("subscription", sub_field)
    
    # Try using Auth A (Lower) credentials or unauthenticated to see if it allows the connection
    # and accepts the subscription request without returning validation/auth errors
    success, ws = await attempt_ws_handshake(ws_url, protocol, auth_a_headers)
    if success and ws:
        # Request subscription
        sub_id = "1"
        if protocol == WS_SUB_PROTOCOL_MODERN:
            payload = {
                "type": "subscribe",
                "id": sub_id,
                "payload": {"query": query_str, "variables": variables}
            }
        else:
            payload = {
                "type": "start",
                "id": sub_id,
                "payload": {"query": query_str, "variables": variables}
            }
            
        try:
            await ws.send(json.dumps(payload))
            
            # Listen to see if it starts yielding event or gives an auth error immediately
            # A secure endpoint would send type: error or close the connection
            # If it stays open or sends type: next / type: data, it's an authorization bypass
            resp = await asyncio.wait_for(ws.recv(), timeout=3)
            resp_data = json.loads(resp)
            
            is_bypass = False
            evidence = str(resp_data)
            
            if resp_data.get("type") in ("next", "data"):
                is_bypass = True
            elif resp_data.get("type") == "error":
                # Check message content for Auth errors
                msg = str(resp_data.get("payload", "")).lower()
                if not any(x in msg for x in ("unauthorized", "forbidden", "denied", "token")):
                    # It returned standard query error, not auth error!
                    is_bypass = True
            else:
                # Connection accepted, no error received in time window
                is_bypass = True

            if is_bypass:
                findings.append(ShockwaveFinding(
                    id="",
                    rule_id="SHOCKWAVE-AUTH-002",
                    rule_name="Subscription authorization bypass",
                    severity="high",
                    owasp_category="API1:2023 — Broken Object Level Authorization",
                    cwe_id="CWE-284",
                    field_path=f"Subscription.{sub_field.name}",
                    engine="Generic",
                    evidence_request=query_str,
                    evidence_response=evidence,
                    auth_context="Auth A (Lower)" if auth_a_headers else "unauthenticated",
                    confidence="confirmed",
                    confirmation_count=1,
                    remediation=f"Validate authentication token and check client authorization on connection_init and on every subscribe operation.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#subscriptions"]
                ))
        except Exception:
            pass
        finally:
            await ws.close()
            
    return findings

async def scan_subscription_dos(
    ws_url: str,
    protocol: str
) -> List[ShockwaveFinding]:
    """Tests connection exhaustion DoS by opening many concurrent sockets."""
    findings = []
    connections = []
    limit = 50  # Keep it safe for scanner runs, target MVP requirement says up to 500 but we cap at 50 for normal scans
    
    try:
        for _ in range(limit):
            ws = await websockets.connect(
                ws_url,
                subprotocols=[protocol],
                open_timeout=2
            )
            connections.append(ws)
            
        # If all connection operations succeeded without dropping or rate limiting
        if len(connections) >= limit:
            findings.append(ShockwaveFinding(
                id="",
                rule_id="SHOCKWAVE-DOS-003",
                rule_name="Subscription WebSocket connection DoS",
                severity="medium",
                owasp_category="API4:2023 — Unrestricted Resource Consumption",
                cwe_id="CWE-400",
                field_path="Subscription",
                engine="Generic",
                evidence_request=f"Established {limit} concurrent WebSocket connections without authentication",
                evidence_response="All connections accepted successfully",
                auth_context="unauthenticated",
                confidence="confirmed",
                confirmation_count=1,
                remediation="Configure a connection rate limit, maximum concurrent WebSockets per IP, and require authentication during connection handshake.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#subscriptions"]
            ))
    except Exception:
        pass
    finally:
        # Clean up
        for ws in connections:
            try:
                await ws.close()
            except Exception:
                pass
                
    return findings

async def scan_subscriptions(
    url: str,
    schema: GraphQLSchema,
    auth_a_headers: Optional[Dict[str, str]] = None,
    auth_b_headers: Optional[Dict[str, str]] = None
) -> List[ShockwaveFinding]:
    """
    Main entry point for WebSocket subscription security testing (FR-8).
    """
    findings = []
    
    # 1. Verify schema exposes subscriptions
    sub_type = schema.types.get(schema.subscription_type or "Subscription")
    if not sub_type or not sub_type.fields:
        return findings

    ws_url = resolve_ws_url(url)
    builder = QueryBuilder(schema)
    
    # 2. Detect sub-protocol
    # We probe modern and legacy protocols in parallel
    modern_success, _ = await attempt_ws_handshake(ws_url, WS_SUB_PROTOCOL_MODERN)
    legacy_success, _ = await attempt_ws_handshake(ws_url, WS_SUB_PROTOCOL_LEGACY)
    
    active_proto = None
    if modern_success:
        active_proto = WS_SUB_PROTOCOL_MODERN
    elif legacy_success:
        active_proto = WS_SUB_PROTOCOL_LEGACY
        
    if not active_proto:
        # Unable to upgrade WebSocket handshake
        return findings

    # 3. Perform security scans
    for f in sub_type.fields:
        auth_findings = await scan_subscription_auth(ws_url, active_proto, f, builder, auth_a_headers, auth_b_headers)
        findings.extend(auth_findings)
        
    dos_findings = await scan_subscription_dos(ws_url, active_proto)
    findings.extend(dos_findings)

    return findings
