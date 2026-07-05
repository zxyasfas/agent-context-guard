from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from .scanner import ScanReport, sanitize_text


def render_tree(report: ScanReport) -> str:
    rows = []
    for item in report.files:
        suffix = "" if item.text is not None else f"  # omitted: {item.omitted_reason}"
        rows.append(f"- {item.relative}{suffix}")
    return "\n".join(rows) if rows else "- (no files)"


def render_summary(report: ScanReport) -> str:
    counts: dict[str, int] = defaultdict(int)
    for finding in report.findings:
        counts[finding.severity] += 1
    if not counts:
        finding_line = "No findings."
    else:
        finding_line = ", ".join(f"{k}: {counts[k]}" for k in ["critical", "high", "medium", "low"] if counts[k])
    return (
        f"Risk: **{report.risk}**\n\n"
        f"Files scanned: **{report.files_scanned}**  \n"
        f"Files omitted: **{report.files_omitted}**  \n"
        f"Findings: **{finding_line}**"
    )


def render_findings(report: ScanReport) -> str:
    if not report.findings:
        return "No findings."
    lines = []
    for f in report.findings:
        lines.append(f"- **{f.severity}** `{f.kind}/{f.rule}` in `{f.file}:{f.line}:{f.column}` — {f.message}")
    return "\n".join(lines)


def language_for(path: str) -> str:
    suffix = Path(path).suffix.lower().lstrip(".")
    return {"py": "python", "js": "javascript", "ts": "typescript", "md": "markdown", "yml": "yaml"}.get(suffix, suffix)


def render_context_pack(report: ScanReport, *, max_total_bytes: int = 300_000) -> str:
    parts = [
        "# Safe AI Agent Context Pack",
        "",
        "Prepared by Agent Context Guard. Secrets are redacted; suspicious instructions are listed as findings, not followed.",
        "",
        "## Risk summary",
        "",
        render_summary(report),
        "",
        "## Findings",
        "",
        render_findings(report),
        "",
        "## File tree",
        "",
        render_tree(report),
        "",
        "## Files",
    ]
    used = sum(len(p.encode("utf-8")) for p in parts)
    for item in report.files:
        if item.text is None:
            continue
        safe_text = sanitize_text(item.text)
        block = (
            f"\n\n### `{item.relative}`\n\n"
            f"```{language_for(item.relative)}\n"
            f"{safe_text}\n"
            "```\n"
        )
        block_size = len(block.encode("utf-8"))
        if used + block_size > max_total_bytes:
            parts.append(f"\n\n### `{item.relative}`\n\n_omitted: max-total-bytes reached_\n")
            break
        parts.append(block)
        used += block_size
    return "\n".join(parts).rstrip() + "\n"
