import json
from pathlib import Path
from sentinelgate.policy import PolicyResult

def generate_sarif_report(results: list[PolicyResult], output_path: Path):
    rules = [
        {
            "id": "SG001",
            "name": "HallucinatedPackage",
            "shortDescription": {"text": "Nonexistent or hallucinated package dependency"},
            "defaultConfiguration": {"level": "error"}
        },
        {
            "id": "SG002",
            "name": "SlopsquattedPackage",
            "shortDescription": {"text": "High risk package with missing provenance or suspicious age"},
            "defaultConfiguration": {"level": "error"}
        }
    ]

    sarif_results = []
    for res in results:
        if res.allowed:
            continue

        rule_id = "SG001" if not res.provenance.exists else "SG002"
        sarif_results.append({
            "ruleId": rule_id,
            "message": {
                "text": f"Package '{res.provenance.name}' blocked: {', '.join(res.provenance.flags)}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "dependencies"},
                    "region": {"startLine": 1}
                }
            }]
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SentinelGate",
                    "version": "0.1.0",
                    "rules": rules
                }
            },
            "results": sarif_results
        }]
    }

    output_path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
