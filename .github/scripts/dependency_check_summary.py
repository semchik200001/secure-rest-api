"""Превращает JSON-отчёт OWASP Dependency-Check в markdown для job summary."""

import json
import sys


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
    print("| Dependency | Version | Vulnerabilities |")
    print("|---|---|---|")

    total = 0
    for dep in report.get("dependencies", []):
        name = dep.get("fileName", "-")
        packages = dep.get("packages") or [{}]
        version = packages[0].get("id", "-").rsplit("@", 1)[-1]
        vulns = dep.get("vulnerabilities", [])
        total += len(vulns)
        ids = ", ".join(v.get("name", "?") for v in vulns) or "none"
        print(f"| {name} | {version} | {ids} |")

    print()
    print(f"Total vulnerabilities: **{total}**")


if __name__ == "__main__":
    main(sys.argv[1])
