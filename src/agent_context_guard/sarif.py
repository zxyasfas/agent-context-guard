from __future__ import annotations

from .scanner import Finding, ScanReport


LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def render_sarif(report: ScanReport) -> dict[str, object]:
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
                "results": [_result(finding) for finding in report.findings],
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


def _result(finding: Finding) -> dict[str, object]:
    return {
        "ruleId": finding.rule,
        "level": LEVELS[finding.severity],
        "message": {"text": f"{finding.message}: {finding.preview}"},
        "locations": [
            {
                "physicalLocation": {
                    # Unlike finding.file (redacted for report/pack output), SARIF needs
                    # the real path so code scanning can navigate to the flagged file.
                    "artifactLocation": {"uri": finding.raw_file},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column,
                    },
                }
            }
        ],
        "properties": {"kind": finding.kind, "severity": finding.severity},
    }
