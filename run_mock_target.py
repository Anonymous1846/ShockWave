import asyncio
import sys
import os

# Ensure the project directory is in sys.path so we can import the test mock definitions
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tests.unit.test_mock_server import mock_http_server, mock_ws_server

async def main():
    http_port = 5080
    ws_port = 5081
    host = "127.0.0.1"

    print("====================================================")
    print("      ShockWave Vulnerable Mock Target Server")
    print("====================================================")
    print(f"[*] Starting vulnerable GraphQL HTTP server on: http://{host}:{http_port}")
    print(f"[*] Starting vulnerable GraphQL WS server on:   ws://{host}:{ws_port}")
    print("")
    print("This server mocks multiple API vulnerabilities, including:")
    print("  - Introspection and Field Suggestions Enabled")
    print("  - BOLA / IDOR on Query.paste and Query.pastes")
    print("  - Field-level Access Bypass on secretNotes / internalNotes")
    print("  - Query depth/breadth resource exhaustion (DoS)")
    print("  - SQL / NoSQL Injection payloads on query arguments")
    print("  - WebSocket connection limits bypass and event eavesdropping")
    print("")
    print("To test the scanner against this target, open a new terminal and run:")
    print(f"  python -m shockwave.cli.main scan http://{host}:{http_port}")
    print("")
    print("[*] Server running... Press Ctrl+C to stop.")
    print("====================================================")

    shutdown_evt = asyncio.Event()

    try:
        await asyncio.gather(
            mock_http_server(host, http_port, shutdown_evt),
            mock_ws_server(host, ws_port, shutdown_evt)
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping server...")
    finally:
        shutdown_evt.set()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Shutdown completed.")
