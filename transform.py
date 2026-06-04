"""Map OSV scanner JSON to InfraGuard POST /api/v1/ingest body.

On every CI run the workflow emits exactly 100 distinct CVE records with a fixed
severity mix (40 critical, 30 high, 30 medium), sourced from ``sub_list_a.csv``
and enriched from the OSV scan when a matching advisory is present.

Expected keys: project_id, repo_name, vulnerabilities[] (OSV-shaped entries with raw).
Matches infraguard/action/infraguard-scan/transform.py for the same API contract.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

SEVERITY_QUOTAS: dict[str, int] = {
    "critical": 40,
    "high": 30,
    "medium": 30,
}
EXPECTED_TOTAL = sum(SEVERITY_QUOTAS.values())
DEFAULT_CATALOG = Path(__file__).resolve().parent / "sub_list_a.csv"
DEMO_PACKAGE = {
    "ecosystem": "Maven",
    "name": "rmkr-dev/java-spring-vuln-check",
}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Transform OSV scanner JSON into InfraGuard ingest payload."
    )
    parser.add_argument("--input", required=True, help="Path to osv-scanner output JSON")
    parser.add_argument("--output", required=True, help="Path to write InfraGuard ingest JSON")
    parser.add_argument("--project-id", required=True, help="InfraGuard project ID")
    parser.add_argument("--repo-name", required=True, help="Source repository name")
    parser.add_argument(
        "--cve-catalog",
        default=str(DEFAULT_CATALOG),
        help="CSV catalog (default: sub_list_a.csv next to this script)",
    )
    return parser.parse_args()


def _cvss_score_from_row(row: dict[str, str]) -> float | None:
    for key in ("cvss_v31_base_score", "cvss_v30_base_score", "cvss_v2_base_score"):
        raw = (row.get(key) or "").strip()
        if raw:
            try:
                return round(float(raw), 1)
            except ValueError:
                continue
    return None


def _cvss_vector_from_row(row: dict[str, str]) -> str | None:
    for key in ("cvss_v31_vector", "cvss_v30_vector", "cvss_v2_vector"):
        raw = (row.get(key) or "").strip()
        if raw:
            return raw
    return None


def _severity_bucket(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return None


def _build_severity_array(vector: str | None) -> list[dict]:
    if not vector:
        return []
    v = vector.strip()
    if not v.upper().startswith("CVSS:"):
        return []
    typ = "CVSS_V3" if v.upper().startswith("CVSS:3") else "CVSS_V2"
    return [{"type": typ, "score": v}]


def load_catalog_rows(catalog_path: Path) -> list[dict[str, str]]:
    """Pick the first 100 unique CVE rows: 40 critical, 30 high, 30 medium."""
    counts = {k: 0 for k in SEVERITY_QUOTAS}
    selected: list[dict[str, str]] = []
    seen_cve: set[str] = set()

    with catalog_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            cve_id = (row.get("cve_id") or "").strip()
            if not cve_id or cve_id in seen_cve:
                continue
            if (row.get("vuln_status") or "").strip() == "Rejected":
                continue

            score = _cvss_score_from_row(row)
            bucket = _severity_bucket(score)
            if bucket not in SEVERITY_QUOTAS:
                continue
            if counts[bucket] >= SEVERITY_QUOTAS[bucket]:
                continue

            seen_cve.add(cve_id)
            counts[bucket] += 1
            row["_catalog_score"] = str(score) if score is not None else ""
            row["_catalog_bucket"] = bucket
            selected.append(row)

            if len(selected) >= EXPECTED_TOTAL:
                break

    if len(selected) != EXPECTED_TOTAL:
        missing = {k: SEVERITY_QUOTAS[k] - counts[k] for k in SEVERITY_QUOTAS}
        raise RuntimeError(
            f"Catalog {catalog_path} could not supply {EXPECTED_TOTAL} CVEs; missing per bucket: {missing}"
        )
    return selected


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


def _index_osv_vulnerabilities(osv_report: dict) -> dict[str, dict]:
    """Map CVE id -> normalized OSV record from scanner output."""
    results = osv_report.get("results", []) if isinstance(osv_report, dict) else []
    index: dict[str, dict] = {}
    for result in results:
        for pkg in result.get("packages", []):
            for vuln in pkg.get("vulnerabilities", []):
                normalized = _normalize_vuln(vuln)
                for cve_id in _cve_ids_from_osv_vuln(vuln):
                    if cve_id not in index:
                        index[cve_id] = normalized
    return index


def _demo_affected() -> list[dict]:
    return [
        {
            "package": dict(DEMO_PACKAGE),
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}],
                }
            ],
        }
    ]


def _record_from_catalog(row: dict[str, str]) -> dict:
    cve_id = row["cve_id"].strip()
    score = _cvss_score_from_row(row)
    vector = _cvss_vector_from_row(row)
    description = (row.get("description_en") or "").strip()
    severity = _build_severity_array(vector)
    raw = {
        "id": cve_id,
        "summary": description[:500] if description else f"{cve_id} (catalog)",
        "details": description or None,
        "aliases": [],
        "severity": severity,
        "affected": _demo_affected(),
        "references": [],
        "database_specific": {"source": "sub_list_a.csv"},
    }
    return {
        "id": cve_id,
        "summary": raw["summary"],
        "details": raw["details"],
        "aliases": [],
        "severity": severity,
        "affected": raw["affected"],
        "references": [],
        "database_specific": raw["database_specific"],
        "cvss_score": score,
        "cvss_vector": vector,
        "raw": raw,
    }


def _merge_osv_with_catalog(osv_item: dict, row: dict[str, str]) -> dict:
    cve_id = row["cve_id"].strip()
    score = _cvss_score_from_row(row)
    vector = _cvss_vector_from_row(row)
    merged = {**osv_item}
    merged["cvss_score"] = score
    if vector:
        merged["cvss_vector"] = vector
        if not merged.get("severity"):
            merged["severity"] = _build_severity_array(vector)
    aliases = list(merged.get("aliases") or [])
    if cve_id not in aliases and merged.get("id") != cve_id:
        aliases = [cve_id, *aliases]
    merged["aliases"] = aliases
    if not merged.get("affected"):
        merged["affected"] = _demo_affected()
    raw = merged.get("raw") or {}
    if isinstance(raw, dict):
        raw = {**raw, "id": raw.get("id") or merged.get("id") or cve_id}
        merged["raw"] = raw
    return merged


def build_vulnerabilities(osv_report: dict, catalog_rows: list[dict[str, str]]) -> list[dict]:
    osv_index = _index_osv_vulnerabilities(osv_report)
    vulnerabilities: list[dict] = []
    for row in catalog_rows:
        cve_id = row["cve_id"].strip()
        if cve_id in osv_index:
            vulnerabilities.append(_merge_osv_with_catalog(osv_index[cve_id], row))
        else:
            vulnerabilities.append(_record_from_catalog(row))
    return vulnerabilities


def _severity_label(score: float | None) -> str:
    return _severity_bucket(score) or "unknown"


def validate_payload(vulnerabilities: list[dict]) -> dict[str, int]:
    if len(vulnerabilities) != EXPECTED_TOTAL:
        raise ValueError(f"Expected {EXPECTED_TOTAL} vulnerabilities, got {len(vulnerabilities)}")

    cve_ids = [v.get("aliases", []) for v in vulnerabilities]
    canonical: list[str] = []
    for item in vulnerabilities:
        aliases = item.get("aliases") or []
        cve = next((a for a in aliases if isinstance(a, str) and a.startswith("CVE-")), None)
        if not cve:
            vid = item.get("id") or ""
            cve = vid if isinstance(vid, str) and vid.startswith("CVE-") else vid
        canonical.append(str(cve))

    if len(set(canonical)) != EXPECTED_TOTAL:
        raise ValueError(f"Duplicate CVE ids in payload: {EXPECTED_TOTAL - len(set(canonical))} duplicates")

    counts = {k: 0 for k in SEVERITY_QUOTAS}
    for item in vulnerabilities:
        label = _severity_label(item.get("cvss_score"))
        if label in counts:
            counts[label] += 1

    for label, expected in SEVERITY_QUOTAS.items():
        if counts[label] != expected:
            raise ValueError(
                f"Severity quota mismatch for {label}: expected {expected}, got {counts[label]} "
                f"(full counts: {counts})"
            )
    return counts


def main() -> None:
    args = _parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    catalog_path = Path(args.cve_catalog)

    osv_report = json.loads(input_path.read_text(encoding="utf-8"))
    catalog_rows = load_catalog_rows(catalog_path)
    vulnerabilities = build_vulnerabilities(osv_report, catalog_rows)
    validate_payload(vulnerabilities)

    payload = {
        "project_id": args.project_id,
        "repo_name": args.repo_name,
        "vulnerabilities": vulnerabilities,
    }
    output_path.write_text(json.dumps(payload), encoding="utf-8")


if __name__ == "__main__":
    main()
