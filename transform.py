import json
import argparse
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--repo-name", default="unknown")
    args = parser.parse_args()

    input_path = Path(args.input)
    
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        data = {"results": []}

    # FIX: OSV returns a list when using --recursive or --experimental-all-packages
    # We normalize it into a 'results' list for the loop below
    if isinstance(data, list):
        results = data
    else:
        results = data.get("results", [])

    transformed = {
        "projectId": args.project_id,
        "repository": args.repo_name,
        "scanType": "OSV_JAVA",
        "vulnerabilities": []
    }

    for result in results:
        # Check if the result has packages (some results might be empty)
        packages = result.get("packages", [])
        for pkg in packages:
            p_info = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []):
                transformed["vulnerabilities"].append({
                    "id": vuln.get("id"),
                    "package": p_info.get("name"),
                    "version": p_info.get("version"),
                    "ecosystem": p_info.get("ecosystem"),
                    "summary": vuln.get("summary", "No summary provided"),
                    "severity": vuln.get("database_specific", {}).get("severity", "UNKNOWN")
                })

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(transformed, f, indent=2)
    
    print(f"Successfully transformed {len(transformed['vulnerabilities'])} vulnerabilities.")

if __name__ == "__main__":
    main()
