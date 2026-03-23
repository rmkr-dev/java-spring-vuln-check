import argparse
import json
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Transform OSV scanner JSON into InfraGuard ingest payload."
    )
    parser.add_argument("--input", required=True, help="Path to osv-scanner output JSON")
    parser.add_argument("--output", required=True, help="Path to write InfraGuard ingest JSON")
    parser.add_argument("--project-id", required=True, help="InfraGuard project ID")
    parser.add_argument("--repo-name", required=True, help="Source repository name")
    return parser.parse_args()


def _normalize_vuln(vuln: dict) -> dict:
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
    input_path = Path(args.input)
    output_path = Path(args.output)

    raw = json.loads(input_path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        results = raw
    else:
        results = raw.get("results", [])
    vulnerabilities: list[dict] = []
    for result in results:
        for pkg in result.get("packages", []):
            for vuln in pkg.get("vulnerabilities", []):
                vulnerabilities.append(_normalize_vuln(vuln))

    payload = {
        "project_id": args.project_id,
        "repo_name": args.repo_name,
        "vulnerabilities": vulnerabilities,
    }
    output_path.write_text(json.dumps(payload), encoding="utf-8")


if __name__ == "__main__":
    main()
