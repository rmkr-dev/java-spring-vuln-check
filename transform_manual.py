"""Map OSV API vulnerabilities to InfraGuard, requiring a valid CVSS Score."""
import argparse
import json
import time
import os
import requests
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from cvss import CVSS2, CVSS3, CVSS4


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ytd", required=True, help="Date filter in YYYY-MM-DD")
    parser.add_argument("--output", required=True, help="Path to write InfraGuard ingest JSON")
    parser.add_argument("--project-id", required=True, help="InfraGuard project ID")
    parser.add_argument("--repo-name", required=True, help="Source repository name")
    return parser.parse_args()


def calculate_cvss_from_vector(vector: str, cvss_type: str) -> float | None:
    """Uses the cvss library to compute the base score from an OSV vector string."""
    try:
        if cvss_type == "CVSS_V3":
            return CVSS3(vector).scores()[0]
        elif cvss_type == "CVSS_V4":
            return CVSS4(vector).scores()[0]
        elif cvss_type == "CVSS_V2":
            return CVSS2(vector).scores()[0]
    except Exception:
        pass
    return None


def fetch_nvd_fallback_score(cve_id: str) -> float | None:
    """Fallback to NVD API if OSV lacks CVSS data. Uses API key if available."""
    if not cve_id.startswith("CVE-"):
        return None
        
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {}
    
    # Read the token mapped from GitHub Secrets
    nvd_token = os.environ.get("NVD_TOKEN")
    
    if nvd_token:
        headers["apiKey"] = nvd_token
        # Rate limit with key: 50 requests per 30 seconds (~1.6 req/sec)
        time.sleep(0.7) 
    else:
        # Rate limit without key: 5 requests per 30 seconds (~0.16 req/sec)
        time.sleep(6.5)

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            vuls = data.get("vulnerabilities", [])
            if vuls:
                metrics = vuls[0].get("cve", {}).get("metrics", {})
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics:
                        return metrics[key][0].get("cvssData", {}).get("baseScore")
        elif resp.status_code == 403:
            # 403 usually means rate limit exceeded on NVD
            print(f"Warning: Hit NVD rate limit for {cve_id}.")
    except Exception:
        pass
    return None


def process_vulnerability(vuln_id: str) -> dict | None:
    """Fetches, scores, and normalizes a single vulnerability. Returns None if skipped."""
    osv_url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
    osv_data = None
    cvss_score = None

    # 1. Fetch from OSV Primary API
    for _ in range(3):
        try:
            resp = requests.get(osv_url, timeout=10)
            if resp.status_code == 200:
                osv_data = resp.json()
                break
            elif resp.status_code == 404:
                break
        except requests.exceptions.RequestException:
            time.sleep(1)

    # 2. Extract and Calculate Score from OSV
    if osv_data and "severity" in osv_data:
        for sev in osv_data["severity"]:
            score = calculate_cvss_from_vector(sev.get("score", ""), sev.get("type", ""))
            if score is not None:
                cvss_score = score
                break

    # 3. Fallback to NVD if OSV missed it
    if cvss_score is None:
        cvss_score = fetch_nvd_fallback_score(vuln_id)

    # 4. STRICT REQUIREMENT: Skip if no CVSS score is found anywhere
    if cvss_score is None:
        return None

    # 5. Normalize (Create a base OSV shell if OSV was 404 but NVD had it)
    if not osv_data:
        osv_data = {
            "id": vuln_id,
            "summary": f"Vulnerability {vuln_id}",
            "details": "Details fetched from fallback source due to OSV miss.",
            "severity": [],
            "affected": []
        }

    return {
        "id": osv_data.get("id", vuln_id),
        "cvss_score": cvss_score,  
        "summary": osv_data.get("summary"),
        "details": osv_data.get("details"),
        "aliases": osv_data.get("aliases", []),
        "severity": osv_data.get("severity", []),
        "affected": osv_data.get("affected", []),
        "references": osv_data.get("references", []),
        "database_specific": osv_data.get("database_specific", {}),
        "raw": osv_data,
    }


def main() -> None:
    args = _parse_args()
    output_path = Path(args.output)

    try:
        ytd_date = datetime.strptime(args.ytd, "%Y-%m-%d").date()
    except ValueError:
        print(f"Error: Invalid YTD format '{args.ytd}'. Expected YYYY-MM-DD.")
        exit(1)

    csv_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
    vuln_ids = set()

    print(f"Streaming modified_id.csv to find vulnerabilities modified since {args.ytd}...")
    try:
        req = requests.get(csv_url, stream=True)
        for line in req.iter_lines(decode_unicode=True):
            if not line:
                continue
            
            row = line.split(',')
            if len(row) < 2:
                continue
                
            mod_time_str = row[0]
            try:
                mod_date = datetime.strptime(mod_time_str[:10], "%Y-%m-%d").date()
            except ValueError:
                continue
            
            if mod_date >= ytd_date:
                vuln_id = row[1].split("/")[-1]
                vuln_ids.add(vuln_id)
            else:
                break
    except Exception as e:
        print(f"Failed to fetch or parse modified_id.csv: {e}")
        exit(1)

    print(f"Found {len(vuln_ids)} unique vulnerability IDs since {args.ytd}.")
    
    if not vuln_ids:
        payload = {"project_id": args.project_id, "repo_name": args.repo_name, "vulnerabilities": []}
        output_path.write_text(json.dumps(payload), encoding="utf-8")
        return

    vulnerabilities = []
    skipped_count = 0
    
    print("Fetching records and calculating CVSS scores concurrently...")
    
    # Kept to 10 workers to manage concurrency and rate limiting smoothly
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_id = {executor.submit(process_vulnerability, vid): vid for vid in vuln_ids}
        
        count = 0
        for future in as_completed(future_to_id):
            count += 1
            if count % 100 == 0:
                print(f"Processed {count} / {len(vuln_ids)} records...")
            
            record = future.result()
            if record:
                vulnerabilities.append(record)
            else:
                skipped_count += 1

    print(f"Successfully enriched {len(vulnerabilities)} vulnerabilities.")
    print(f"Skipped {skipped_count} vulnerabilities due to missing CVSS scores.")

    payload = {
        "project_id": args.project_id,
        "repo_name": args.repo_name,
        "vulnerabilities": vulnerabilities,
    }
    
    output_path.write_text(json.dumps(payload), encoding="utf-8")

if __name__ == "__main__":
    main()
