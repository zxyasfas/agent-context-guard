from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Rule:
    name: str
    kind: str
    severity: str
    pattern: re.Pattern[str]
    message: str


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

SECRET_RULES: tuple[Rule, ...] = (
    Rule("openrouter_key", "secret", "critical", re.compile(r"sk-or-v1-[A-Za-z0-9_-]{20,}"), "OpenRouter API key"),
    Rule("anthropic_key", "secret", "critical", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "Anthropic API key"),
    Rule("openai_key", "secret", "critical", re.compile(r"sk-(?!or-v1-|ant-)[A-Za-z0-9_-]{20,}"), "OpenAI-style API key"),
    Rule("github_token", "secret", "critical", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}"), "GitHub token"),
    Rule("aws_access_key", "secret", "critical", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    Rule("slack_token", "secret", "critical", re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"), "Slack token"),
    Rule(
        "private_key",
        "secret",
        "critical",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)?PRIVATE KEY-----"
            r".*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "Private key block",
    ),
    Rule("jwt_like_token", "secret", "medium", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT-like token"),
)

PROMPT_INJECTION_RULES: tuple[Rule, ...] = (
    Rule(
        "ignore_previous_instructions",
        "prompt_injection",
        "high",
        re.compile(
            r"(?:ignore|disregard)\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)\s+instructions"
            r"|(?:ignore|disregard)\s+(?:all\s+)?the\s+instructions\s+above"
            r"|forget\s+(?:everything|all)\s+you(?:\s+were|\s+have\s+been|'ve\s+been)\s+told",
            re.I,
        ),
        "Attempts to override prior instructions",
    ),
    Rule("reveal_system_prompt", "prompt_injection", "high", re.compile(r"(reveal|print|dump|show).{0,40}(system|developer) prompt", re.I), "Attempts to reveal hidden prompts"),
    Rule("exfiltrate_secrets", "prompt_injection", "high", re.compile(r"(exfiltrate|send|upload|post).{0,60}(secret|token|api key|credential)", re.I), "Attempts to exfiltrate secrets"),
    Rule("agent_role_override", "prompt_injection", "medium", re.compile(r"you are now (?:dan|developer|system|root|admin)|act as (?:system|developer|root)", re.I), "Attempts to change the agent role"),
    Rule("dangerous_shell_instruction", "prompt_injection", "medium", re.compile(r"(curl|wget).{0,80}(\$\{|SECRET|TOKEN|KEY|credential)|rm -rf /", re.I), "Suspicious shell/network instruction"),
)

ALL_RULES: tuple[Rule, ...] = SECRET_RULES + PROMPT_INJECTION_RULES

DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".next",
    ".turbo",
}

TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cfg",
    ".conf",
    ".cpp",
    ".css",
    ".csv",
    ".dockerfile",
    ".env",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".lock",
    ".md",
    ".mdx",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
