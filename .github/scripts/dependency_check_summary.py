"""Превращает JSON-отчёт OWASP Dependency-Check в markdown для job summary."""

import json
import sys


def vuln_ids(vulns):
    return ", ".join(v.get("name", "?") for v in vulns) or "none"


def main(path):
    print("## OWASP Dependency-Check (SCA)")
    try:
        with open(path, encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, ValueError):
        print("Report not found")
        return

    info = report.get("scanInfo", {})
    print(f"Engine version: {info.get('engineVersion', '-')}")
    print()
    print("| Dependency | Vulnerabilities | Suppressed (false positives) |")
    print("|---|---|---|")

    total = 0
    suppressed = 0
    for dep in report.get("dependencies", []):
        vulns = dep.get("vulnerabilities", [])
        hidden = dep.get("suppressedVulnerabilities", [])
        total += len(vulns)
        suppressed += len(hidden)
        print(f"| {dep.get('fileName', '-')} | {vuln_ids(vulns)} | {vuln_ids(hidden)} |")

    print()
    print(f"Total vulnerabilities: **{total}**, suppressed: {suppressed}")


if __name__ == "__main__":
    main(sys.argv[1])
