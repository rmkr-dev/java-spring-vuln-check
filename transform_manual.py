"""Map vulnerability CSV data to InfraGuard POST /api/v1/ingest body.

Expected keys: project_id, repo_name, vulnerabilities[] (OSV-shaped entries with raw).
Matches infraguard/action/infraguard-scan/transform.py for the same API contract.
"""
import argparse
import csv
import json
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Transform CVE CSV into InfraGuard ingest payload."
    )
    parser.add_argument("--input", required=True, help="Path to input CSV file")
    parser.add_argument("--output", required=True, help="Path to write InfraGuard ingest JSON")
    parser.add_argument("--project-id", required=True, help="InfraGuard project ID")
    parser.add_argument("--repo-name", required=True, help="Source repository name")
    return parser.parse_args()


def _normalize_vuln(row: dict) -> dict:
    cve_id = row.get("cve_id", "")
    desc = row.get("description_en", "")

    # Map the first available CVSS vector to the OSV "severity" structure
    severities = []
    if row.get("cvss_v31_vector"):
        severities.append({"type": "CVSS_V3", "score": row.get("cvss_v31_vector")})
    elif row.get("cvss_v30_vector"):
        severities.append({"type": "CVSS_V3", "score": row.get("cvss_v30_vector")})
    elif row.get("cvss_v2_vector"):
        severities.append({"type": "CVSS_V2", "score": row.get("cvss_v2_vector")})

    return {
        "id": cve_id,
        # Truncate summary if it's too long, use the full text for details
        "summary": (desc[:137] + "...") if len(desc) > 140 else desc,
        "details": desc,
        "aliases": [],
        "severity": severities,
        "affected": [],
        "references": [],
        "database_specific": {
            "published": row.get("published"),
            "last_modified": row.get("last_modified"),
            "vuln_status": row.get("vuln_status"),
            "cwe_ids": row.get("cwe_ids"),
            "cvss_v31_base_score": row.get("cvss_v31_base_score"),
            "cvss_v2_base_score": row.get("cvss_v2_base_score"),
            "references_count": row.get("references_count"),
            "cpe_match_count": row.get("cpe_match_count")
        },
        "raw": row, # Attach the raw CSV row to fulfill the backend contract
    }


def main() -> None:
    args = _parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    vulnerabilities = []
    
    # Parse the CSV file and normalize each row
    with open(input_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vulnerabilities.append(_normalize_vuln(row))

    payload = {
        "project_id": args.project_id,
        "repo_name": args.repo_name,
        "vulnerabilities": vulnerabilities,
    }
    output_path.write_text(json.dumps(payload), encoding="utf-8")


if __name__ == "__main__":
    main()
