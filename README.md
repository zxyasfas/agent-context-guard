# Agent Context Guard

Scan local context before it is handed to an AI agent.

The tool checks files for likely secrets and hostile instructions, then writes a Markdown bundle with risky spans replaced. It is meant to run before copying a repo, issue, README, or log into an agent workflow.

```bash
pipx install agent-context-guard
acg scan . --pack safe-context.md --fail-on high
```

`promptfence` is installed as a shorter alias:

```bash
promptfence scan . --pack safe-context.md --fail-on high
```

## quick demo

```bash
acg scan examples/unsafe_repo --pack /tmp/safe-context.md --json
```

Example result:

```json
{
  "risk": "critical",
  "files_scanned": 3,
  "findings": [
    {"severity": "critical", "kind": "secret", "file": "examples/unsafe_repo/app.py", "rule": "openai_key"},
    {"severity": "high", "kind": "prompt_injection", "file": "examples/unsafe_repo/README.md", "rule": "ignore_previous_instructions"}
  ]
}
```

The generated pack keeps normal context and rewrites matched spans:

```text
client = OpenAI(api_key="<REDACTED:openai_key>")
<FLAGGED_PROMPT_INJECTION:ignore_previous_instructions>
```

## what it checks

Secrets:

- OpenAI, OpenRouter, Anthropic, GitHub, AWS and Slack tokens
- private key blocks
- JWT-like strings

Prompt injection patterns:

- instruction override text
- requests to reveal system or developer prompts
- requests to send or upload credentials
- role override text
- suspicious shell or network instructions

Packing behavior:

- includes a file tree and risk summary
- redacts secrets inline
- flags prompt injection text inline
- skips large or binary files
- supports JSON, SARIF and CI exit codes

## usage

```bash
acg scan PATH [options]
```

Common commands:

```bash
# scan and write a safe Markdown pack
acg scan . --pack safe-context.md

# fail CI if any high or critical finding appears
acg scan . --fail-on high

# JSON for scripts
acg scan . --json

# SARIF for code scanning tools
acg scan . --sarif acg.sarif

# SARIF with real (unredacted) file paths, for code-scanning navigability;
# a secret-shaped filename or directory will appear as-is in the SARIF output
acg scan . --sarif acg.sarif --sarif-real-paths

# scan piped text
curl -L https://example.com/issue.md | promptfence scan - --fail-on high

# keep the pack small
acg scan . --pack safe-context.md --max-file-bytes 12000 --max-total-bytes 180000

# skip noisy paths
acg scan . --exclude node_modules --exclude dist --exclude "*.lock"
```

## exit codes

- `0`: no finding at or above the selected threshold
- `2`: threshold exceeded
- `1`: runtime error

## GitHub code scanning

The repository includes `.github/workflows/context-guard.yml`. It writes `acg.sarif` and uploads it to GitHub code scanning.

To use the same pattern in another repo:

```yaml
name: context guard
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install .
      - id: scan
        run: |
          set +e
          acg scan . --sarif acg.sarif --fail-on high
          code=$?
          echo "exit_code=$code" >> "$GITHUB_OUTPUT"
          exit 0
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: acg.sarif
      - if: steps.scan.outputs.exit_code != '0'
        run: exit 1
```

## limits

This is a local preflight check. It uses rules, not a sandbox or model. Treat a clean report as a useful signal, not proof that the context is safe.

`benchmarks/` has a small labeled corpus and a runner that shows what the injection rules catch and miss, including false positives and obfuscation the regex does not handle. On the current corpus it catches 9 of 20 attacks; `benchmarks/README.md` has the breakdown.

## development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e . pytest
pytest -q
acg scan examples/unsafe_repo --pack /tmp/safe-context.md --json
```

## license

MIT
