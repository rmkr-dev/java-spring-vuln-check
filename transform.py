import json
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--repo-name", default="unknown")
    args = parser.parse_args()

    input_path = Path(args.input)
    
    if not input_path.exists() or input_path.stat().st_size == 0:
        data = {"results": []}
    else:
        with open(input_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {"results": []}

    # OSV output normalization
    if isinstance(data, list):
        results = data
    elif isinstance(data, dict):
        results = data.get("results", [])
    else:
        results = []

    transformed = {
        "projectId": args.project_id,
        "repository": args.repo_name,
        "scanType": "OSV_JAVA",
        "vulnerabilities": []
    }

    for result in results:
        for pkg in result.get("packages", []):
            p_info = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []):
                transformed["vulnerabilities"].append({
                    "id": vuln.get("id"),
                    "package": p_info.get("name"),
                    "version": p_info.get("version"),
                    "ecosystem": p_info.get("ecosystem"),
                    "summary": vuln.get("summary", "No summary"),
                    "severity": vuln.get("database_specific", {}).get("severity", "UNKNOWN")
                })

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(transformed, f, indent=2)
    print(f"Transformed {len(transformed['vulnerabilities'])} vulnerabilities.")

if __name__ == "__main__":
    main()
