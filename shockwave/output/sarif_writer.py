import json
import uuid
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

@dataclass
class ShockwaveFinding:
    id: str                        # UUID, unique per finding instance
    rule_id: str                   # e.g. "SHOCKWAVE-AUTH-001"
    rule_name: str                 # e.g. "Field-level authorization bypass"
    severity: str                  # "critical" | "high" | "medium" | "low" | "info"
    owasp_category: str            # e.g. "API1:2023 — Broken Object Level Authorization"
    cwe_id: Optional[str]          # e.g. "CWE-284"
    field_path: str                # e.g. "Query.user.internalNotes"
    engine: str                    # e.g. "Apollo Server 3.x"
    evidence_request: str          # The exact GraphQL query or mutation sent
    evidence_response: str         # The response that confirms the finding
    auth_context: Optional[str]    # Which auth context produced the finding
    confidence: str                # "confirmed" | "likely" | "possible"
    confirmation_count: int        # How many times reproduced (>=3 for confirmed)
    remediation: str               # Specific fix guidance for this finding type
    references: List[str]          # Links to OWASP, CVEs, writeups

def map_severity_to_sarif(sev: str) -> str:
    """Maps custom severities to SARIF level values."""
    m = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note"
    }
    return m.get(sev.lower(), "warning")

def build_sarif_report(findings: List[ShockwaveFinding], target_url: str) -> Dict[str, Any]:
    """Generates a schema-compliant SARIF 2.1.0 JSON report."""
    
    # Establish rule definitions
    rules_map = {}
    for f in findings:
        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.rule_name},
                "fullDescription": {"text": f.remediation},
                "helpUri": f.references[0] if f.references else "",
                "properties": {
                    "cwe": f.cwe_id,
                    "owasp": f.owasp_category
                }
            }

    results = []
    for f in findings:
        finding_id = f.id or str(uuid.uuid4())
        results.append({
            "ruleId": f.rule_id,
            "message": {
                "text": f"Vulnerability detected on field '{f.field_path}' under context '{f.auth_context}'."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target_url,
                        },
                        "region": {
                            "startLine": 1,
                            "charOffset": 0
                        }
                    },
                    "logicalLocations": [
                        {
                            "fullyQualifiedName": f.field_path,
                            "kind": "member"
                        }
                    ]
                }
            ],
            "properties": {
                "evidence_request": f.evidence_request,
                "evidence_response": f.evidence_response,
                "confidence": f.confidence,
                "confirmation_count": f.confirmation_count,
                "remediation": f.remediation,
                "severity": f.severity,
                "finding_id": finding_id
            },
            "level": map_severity_to_sarif(f.severity)
        })

    sarif_format = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "shockwave",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/shockwave-security/shockwave",
                        "rules": list(rules_map.values())
                    }
                },
                "results": results
            }
        ]
    }
    
    return sarif_format
