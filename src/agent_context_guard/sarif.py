from __future__ import annotations

from .scanner import Finding, ScanReport


LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def render_sarif(report: ScanReport, *, real_paths: bool = False) -> dict[str, object]:
    rules = [_rule(rule_id, findings) for rule_id, findings in _group_by_rule(report.findings).items()]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Agent Context Guard",
                        "informationUri": "https://github.com/zxyasfas/agent-context-guard",
                        "rules": rules,
                    }
                },
                "results": [_result(finding, real_paths=real_paths) for finding in report.findings],
            }
        ],
    }


def _group_by_rule(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.rule, []).append(finding)
    return grouped


def _rule(rule_id: str, findings: list[Finding]) -> dict[str, object]:
    first = findings[0]
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": first.message},
        "fullDescription": {"text": f"{first.kind}: {first.message}"},
        "defaultConfiguration": {"level": LEVELS[first.severity]},
        "properties": {"kind": first.kind, "severity": first.severity},
    }


def _result(finding: Finding, *, real_paths: bool) -> dict[str, object]:
    # Redacted by default, like every other output surface. real_paths is an
    # explicit opt-in for code-scanning navigability — it puts finding.raw_file
    # (which may be secret-shaped) into the uploaded SARIF.
    uri = finding.raw_file if real_paths else finding.file
    return {
        "ruleId": finding.rule,
        "level": LEVELS[finding.severity],
        "message": {"text": f"{finding.message}: {finding.preview}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column,
                    },
                }
            }
        ],
        "properties": {"kind": finding.kind, "severity": finding.severity},
    }
