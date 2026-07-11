import httpx
from typing import Dict, Any, Optional
from shockwave.schema.models import GraphQLSchema, parse_introspection

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type {
            ...TypeRef
          }
          defaultValue
        }
        type {
          ...TypeRef
        }
      }
      inputFields {
        name
        description
        type {
          ...TypeRef
        }
        defaultValue
      }
      enumValues(includeDeprecated: true) {
        name
        description
      }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
"""

async def run_introspection(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30
) -> Dict[str, Any]:
    """Sends a GraphQL Introspection query to the target url and returns raw JSON response."""
    payload = {"query": INTROSPECTION_QUERY}
    
    # Standard headers for GraphQL requests
    req_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    if headers:
        req_headers.update(headers)
        
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(
            url,
            json=payload,
            headers=req_headers,
            timeout=timeout
        )
        response.raise_for_status()
        return response.json()

async def fetch_schema(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30
) -> GraphQLSchema:
    """Fetches and parses the schema from the target GraphQL endpoint."""
    raw_data = await run_introspection(url, headers, timeout)
    return parse_introspection(raw_data)
