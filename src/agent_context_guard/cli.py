from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .packer import render_context_pack
from .policy import SEVERITY_ORDER
from .sarif import render_sarif
from .scanner import exceeds_threshold, scan_path, scan_text_input


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acg",
        description="Scan and pack repositories for safe AI-agent context.",
    )
    parser.add_argument("--version", action="version", version=f"agent-context-guard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a path and optionally write a safe context pack")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument("--pack", help="write a safe Markdown context pack")
    scan.add_argument("--sarif", help="write SARIF results for code scanning tools")
    scan.add_argument("--json", action="store_true", help="print machine-readable JSON")
    scan.add_argument("--fail-on", choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get), help="exit 2 if this severity or above is present")
    scan.add_argument("--exclude", action="append", default=[], help="glob/name to exclude; can be repeated")
    scan.add_argument("--max-file-bytes", type=int, default=64_000, help="omit files larger than this many bytes")
    scan.add_argument("--max-total-bytes", type=int, default=300_000, help="maximum size of generated context pack")
    return parser


def print_human(report) -> None:
    print(f"Risk: {report.risk}")
    print(f"Files scanned: {report.files_scanned}")
    print(f"Files omitted: {report.files_omitted}")
    if report.findings:
        print("Findings:")
        for f in report.findings:
            print(f"  [{f.severity}] {f.kind}/{f.rule} {f.file}:{f.line}:{f.column} - {f.message}")
    else:
        print("Findings: none")


def run_scan(args: argparse.Namespace) -> int:
    if args.path == "-":
        report = scan_text_input(sys.stdin.read())
    else:
        report = scan_path(args.path, excludes=args.exclude, max_file_bytes=args.max_file_bytes)
    if args.pack:
        Path(args.pack).write_text(render_context_pack(report, max_total_bytes=args.max_total_bytes), encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(render_sarif(report), ensure_ascii=False, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print_human(report)
        if args.pack:
            print(f"Pack written: {args.pack}")
        if args.sarif:
            print(f"SARIF written: {args.sarif}")
    return 2 if exceeds_threshold(report, args.fail_on) else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return run_scan(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    parser.error("unknown command")
    return 1
