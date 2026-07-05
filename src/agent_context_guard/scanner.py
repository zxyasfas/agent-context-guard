from __future__ import annotations

from dataclasses import asdict, dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable

from .policy import ALL_RULES, DEFAULT_EXCLUDES, PROMPT_INJECTION_RULES, SECRET_RULES, SEVERITY_ORDER, TEXT_EXTENSIONS


@dataclass(frozen=True)
class Finding:
    severity: str
    kind: str
    rule: str
    file: str
    line: int
    column: int
    message: str
    preview: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class ScannedFile:
    path: Path
    relative: str
    text: str | None
    omitted_reason: str | None = None
    size: int = 0


@dataclass
class ScanReport:
    root: Path
    files: list[ScannedFile]
    findings: list[Finding]

    @property
    def files_scanned(self) -> int:
        return sum(1 for f in self.files if f.text is not None)

    @property
    def files_omitted(self) -> int:
        return sum(1 for f in self.files if f.text is None)

    @property
    def risk(self) -> str:
        if not self.findings:
            return "clean"
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])

    def to_dict(self) -> dict[str, object]:
        return {
            "risk": self.risk,
            "files_scanned": self.files_scanned,
            "files_omitted": self.files_omitted,
            "findings": [f.to_dict() for f in self.findings],
        }


def should_exclude(path: Path, patterns: Iterable[str]) -> bool:
    parts = set(path.parts)
    if parts & DEFAULT_EXCLUDES:
        return True
    text = path.as_posix()
    return any(fnmatch(text, p) or fnmatch(path.name, p) for p in patterns)


def looks_binary(data: bytes) -> bool:
    if b"\0" in data:
        return True
    if not data:
        return False
    sample = data[:2048]
    non_text = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return non_text / len(sample) > 0.15


def is_probably_text(path: Path, data: bytes) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS or path.name in {"Dockerfile", "Makefile", "LICENSE", "README"}:
        return not looks_binary(data)
    return not looks_binary(data)


def line_col(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    last_newline = text.rfind("\n", 0, index)
    col = index + 1 if last_newline < 0 else index - last_newline
    return line, col


def preview(text: str, start: int, end: int) -> str:
    lo = max(0, start - 36)
    hi = min(len(text), end + 36)
    chunk = text[lo:hi].replace("\n", " ")
    return " ".join(chunk.split())


def scan_text(relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ALL_RULES:
        for match in rule.pattern.finditer(text):
            line, col = line_col(text, match.start())
            findings.append(
                Finding(
                    severity=rule.severity,
                    kind=rule.kind,
                    rule=rule.name,
                    file=relative,
                    line=line,
                    column=col,
                    message=rule.message,
                    preview=f"<REDACTED:{rule.name}>" if rule.kind == "secret" else preview(text, match.start(), match.end()),
                )
            )
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line, f.column, f.rule))
    return findings


def redact_text(text: str) -> str:
    redacted = text
    for rule in SECRET_RULES:
        redacted = rule.pattern.sub(f"<REDACTED:{rule.name}>", redacted)
    return redacted


def sanitize_text(text: str) -> str:
    sanitized = redact_text(text)
    for rule in PROMPT_INJECTION_RULES:
        sanitized = rule.pattern.sub(f"<FLAGGED_PROMPT_INJECTION:{rule.name}>", sanitized)
    return sanitized


def iter_files(root: Path, excludes: Iterable[str]) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and not should_exclude(path.relative_to(root), excludes):
            yield path


def scan_path(
    root: Path | str,
    *,
    excludes: Iterable[str] = (),
    max_file_bytes: int = 64_000,
) -> ScanReport:
    root_path = Path(root).resolve()
    files: list[ScannedFile] = []
    findings: list[Finding] = []
    base = root_path if root_path.is_dir() else root_path.parent

    for path in iter_files(root_path, excludes):
        relative = path.relative_to(base).as_posix()
        size = path.stat().st_size
        if size > max_file_bytes:
            files.append(ScannedFile(path, relative, None, f"large file ({size} bytes)", size))
            continue
        data = path.read_bytes()
        if not is_probably_text(path, data):
            files.append(ScannedFile(path, relative, None, "binary or non-text file", size))
            continue
        text = data.decode("utf-8", errors="replace")
        files.append(ScannedFile(path, relative, text, None, size))
        findings.extend(scan_text(relative, text))

    return ScanReport(root_path, files, findings)


def scan_text_input(text: str, *, name: str = "<stdin>") -> ScanReport:
    pseudo = Path(name)
    scanned = ScannedFile(pseudo, name, text, None, len(text.encode("utf-8")))
    return ScanReport(pseudo, [scanned], scan_text(name, text))


def exceeds_threshold(report: ScanReport, threshold: str | None) -> bool:
    if not threshold:
        return False
    threshold_rank = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[f.severity] >= threshold_rank for f in report.findings)
