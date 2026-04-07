"""Map OSV API vulnerabilities to InfraGuard POST /api/v1/ingest body based on YTD filter.

Expected keys: project_id, repo_name, vulnerabilities[] (OSV-shaped entries with raw).
"""
import argparse
import json
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch OSV vulnerabilities since YTD and transform for InfraGuard."
    )
    parser.add_argument("--ytd", required=True, help="Date filter in YYYY-MM-DD")
    parser.add_argument("--output", required=True, help="Path to write InfraGuard ingest JSON")
    parser.add_argument("--project-id", required=True, help="InfraGuard project ID")
    parser.add_argument("--repo-name", required=True, help="Source repository name")
    return parser.parse_args()


def fetch_osv_record(vuln_id: str) -> dict | None:
    """Fetch the official OSV record for a given ID, with basic retries."""
    url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
    req = urllib.request.Request(url)
    
    # Simple retry loop to handle momentary API latency/timeouts seamlessly
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None  # If it doesn't exist on API for some reason, skip
        except Exception:
            pass  # Retry on network timeout/errors
    return None


def _normalize_vuln(vuln: dict) -> dict:
    """Map raw OSV JSON structure natively matching OSV-Scanner standard output."""
    aliases = vuln.get("aliases", [])
    return {
        "id": vuln.get("id", ""),
        "summary": vuln.get("summary"),
        "details": vuln.get("details"),
        "aliases": aliases,
        "severity": vuln.get("severity", []),
        "affected": vuln.get("affected", []),
        "references": vuln.get("references", []),
        "database_specific": vuln.get("database_specific", {}),
        "raw": vuln,
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
    req = urllib.request.Request(csv_url)
    
    try:
        with urllib.request.urlopen(req) as response:
            for line in response:
                decoded_line = line.decode('utf-8').strip()
                if not decoded_line:
                    continue
                
                row = decoded_line.split(',')
                if len(row) < 2:
                    continue
                
                # First column is ISO datetime, e.g., 2024-08-15T00:05:00Z
                mod_time_str = row[0]
                try:
                    mod_date = datetime.strptime(mod_time_str[:10], "%Y-%m-%d").date()
                except ValueError:
                    continue
                
                if mod_date >= ytd_date:
                    # Second column is Ecosystem/ID. We only need the ID portion.
                    vuln_id = row[1].split("/")[-1]
                    vuln_ids.add(vuln_id)
                else:
                    # The CSV is sorted in reverse chronological order.
                    # Once we hit an older date, we can safely stop streaming.
                    break
    except Exception as e:
        print(f"Failed to fetch or parse modified_id.csv from OSV GCS bucket: {e}")
        exit(1)

    print(f"Found {len(vuln_ids)} unique vulnerabilities since {args.ytd}.")
    
    if not vuln_ids:
        print("No updates found. Exiting gracefully.")
        # Create an empty template so the rest of the pipeline doesn't break
        payload = {"project_id": args.project_id, "repo_name": args.repo_name, "vulnerabilities": []}
        output_path.write_text(json.dumps(payload), encoding="utf-8")
        return

    vulnerabilities = []
    
    print("Fetching full OSV records from the API concurrently...")
    
    # Threading speeds up API calls significantly compared to fetching one-by-one
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_id = {executor.submit(fetch_osv_record, vid): vid for vid in vuln_ids}
        
        count = 0
        for future in as_completed(future_to_id):
            count += 1
            if count % 100 == 0:
                print(f"Processed {count} / {len(vuln_ids)} records...")
            
            record = future.result()
            if record:
                vulnerabilities.append(_normalize_vuln(record))

    print(f"Successfully normalized {len(vulnerabilities)} full vulnerability records.")

    payload = {
        "project_id": args.project_id,
        "repo_name": args.repo_name,
        "vulnerabilities": vulnerabilities,
    }
    
    output_path.write_text(json.dumps(payload), encoding="utf-8")
    print(f"Enriched JSON payload saved to {output_path}")

if __name__ == "__main__":
    main()
