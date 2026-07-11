import json
import os
import dataclasses
from typing import List
from shockwave.output.sarif_writer import ShockwaveFinding

def write_json_report(findings: List[ShockwaveFinding], output_dir: str) -> None:
    """Dumps raw finding objects to JSON file in output directory."""
    os.makedirs(output_dir, exist_ok=True)
    
    findings_data = [dataclasses.asdict(f) for f in findings]
    
    path = os.path.join(output_dir, "shockwave-findings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings_data, f, indent=2)
