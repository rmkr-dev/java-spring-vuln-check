"""Map vulnerability CSV data, enrich via OSV API, to InfraGuard POST /api/v1/ingest body."""
import argparse
import csv
import json
import urllib.request
import urllib.error
from pathlib import Path

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Transform and enrich CVE CSV into InfraGuard ingest payload."
    )
    parser.add_argument("--input", required=True, help="Path to input CSV file")
    parser.add_argument("--output", required=True, help="Path to write InfraGuard ingest JSON")
    parser.add_argument("--project-id", required=True, help="InfraGuard project ID")
    parser.add_argument("--repo-name", required=True, help="Source repository name")
    return parser.parse_args()

def fetch_osv_data(cve_id: str) -> dict | None:
    """Fetch the official OSV record for a given CVE ID."""
    if not cve_id:
        return None
        
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                return json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        # 404 simply means OSV doesn't have a record for this specific CVE ID
        if e.code != 404:
            print(f"Warning: HTTP {e.code} while fetching OSV data for {cve_id}")
    except Exception as e:
        print(f"Warning: Failed to fetch OSV data for {cve_id}: {e}")
    
    return None

def _normalize_vuln(row: dict) -> dict:
    cve_id = row.get("cve_id") or row.get("CVE_ID") or row.get("id") or ""
    cve_id = cve_id.strip()
    cvss_score = row.get("cvss_v31_base_score", "").strip()

    # Attempt to fetch rich data from OSV
    osv_record = fetch_osv_data(cve_id)

    if osv_record:
        # ENRICHMENT PATH: Use OSV data, append our specific requirements
        osv_record["cvss_score"] = cvss_score 
        
        if "database_specific" not in osv_record:
            osv_record["database_specific"] = {}
            
        osv_record["database_specific"]["csv_enrichment"] = {
            "published": row.get("published"),
            "last_modified": row.get("last_modified"),
            "vuln_status": row.get("vuln_status"),
            "cwe_ids": row.get("cwe_ids"),
            "cvss_v31_base_score": row.get("cvss_v31_base_score"),
            "cvss_v2_base_score": row.get("cvss_v2_base_score"),
            "references_count": row.get("references_count"),
            "cpe_match_count": row.get("cpe_match_count")
        }
        osv_record["raw_csv_row"] = row
        return osv_record

    # FALLBACK PATH: If OSV doesn't have it, manually map it from the CSV
    desc = row.get("description_en") or row.get("Description") or ""
    severities = []
    if row.get("cvss_v31_vector"):
        severities.append({"type": "CVSS_V3", "score": row.get("cvss_v31_vector")})
    elif row.get("cvss_v30_vector"):
        severities.append({"type": "CVSS_V3", "score": row.get("cvss_v30_vector")})
    elif row.get("cvss_v2_vector"):
        severities.append({"type": "CVSS_V2", "score": row.get("cvss_v2_vector")})

    return {
        "id": cve_id,
        "cvss_score": cvss_score,
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
        "raw_csv_row": row, 
    }

def main() -> None:
    args = _parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    vulnerabilities = []
    
    # Using 'utf-8-sig' safely handles the hidden BOM (\ufeff) character
    print(f"Reading CSV from {input_path} and querying OSV API...")
    with open(input_path, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # MANDATORY: Skip row if cvss_v31_base_score is empty
            cvss_v31_base_score = row.get("cvss_v31_base_score", "").strip()
            if not cvss_v31_base_score:
                continue
                
            enriched_vuln = _normalize_vuln(row)
            vulnerabilities.append(enriched_vuln)
            
            # Print a little status pip to show it's working
            print(f"Processed {enriched_vuln.get('id')} - Extracted CVSS: {enriched_vuln.get('cvss_score')}")

    payload = {
        "project_id": args.project_id,
        "repo_name": args.repo_name,
        "vulnerabilities": vulnerabilities,
    }
    
    print(f"Saving enriched payload to {output_path}...")
    output_path.write_text(json.dumps(payload), encoding="utf-8")

if __name__ == "__main__":
    main()
