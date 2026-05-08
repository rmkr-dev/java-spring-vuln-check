"""Map OSV scanner JSON to InfraGuard POST /api/v1/ingest body.

Expected keys: project_id, repo_name, vulnerabilities[] (OSV-shaped entries with raw).
Matches infraguard/action/infraguard-scan/transform.py for the same API contract.

Scanner output is filtered to the first ten ``cve_id`` values from
``2026-05-08T16-19_export.csv`` (project vulnerability export). All other findings
are dropped so InfraGuard ingests only this demo allowlist.
"""
import argparse
import json
from pathlib import Path

# First 10 CVE rows (by report order) in 2026-05-08T16-19_export.csv - keep only these.
ALLOWED_CVE_IDS_IN_ORDER: tuple[str, ...] = (
    "CVE-2021-44228",
    "CVE-2021-45046",
    "CVE-2022-42889",
    "CVE-2025-24813",
    "CVE-2025-31651",
    "CVE-2025-41232",
    "CVE-2025-55754",
    "CVE-2025-66614",
    "CVE-2026-22732",
    "CVE-2026-29145",
)
ALLOWED_CVE_SET = frozenset(ALLOWED_CVE_IDS_IN_ORDER)


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


def _cve_ids_from_osv_vuln(vuln: dict) -> set[str]:
    ids: set[str] = set()
    vid = vuln.get("id") or ""
    if isinstance(vid, str) and vid.startswith("CVE-"):
        ids.add(vid)
    for alias in vuln.get("aliases", []):
        if isinstance(alias, str) and alias.startswith("CVE-"):
            ids.add(alias)
    return ids


def _filter_to_allowed_vulnerabilities(vulnerabilities: list[dict]) -> list[dict]:
    """Keep at most one normalized record per allowlisted CVE (CSV order).

    The same OSV record may cover multiple allowlisted CVEs (e.g. Log4j); we emit a
    shallow copy per CVE so the ingest list lines up with the ten CVE identifiers.
    """
    chosen: dict[str, dict] = {}
    for item in vulnerabilities:
        raw = item.get("raw") or item
        matching = _cve_ids_from_osv_vuln(raw) & ALLOWED_CVE_SET
        for cve in matching:
            if cve not in chosen:
                chosen[cve] = {**item}
    return [chosen[c] for c in ALLOWED_CVE_IDS_IN_ORDER if c in chosen]


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

    vulnerabilities = _filter_to_allowed_vulnerabilities(vulnerabilities)

    payload = {
        "project_id": args.project_id,
        "repo_name": args.repo_name,
        "vulnerabilities": vulnerabilities,
    }
    output_path.write_text(json.dumps(payload), encoding="utf-8")


if __name__ == "__main__":
    main()
