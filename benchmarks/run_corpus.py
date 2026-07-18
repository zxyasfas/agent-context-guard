"""Run the prompt-injection rules against a labeled corpus.

Each corpus line is a JSON object with an `attack` label (ground truth) and
a `family`. This scores the prompt-injection rules only: a case counts as
detected if the scanner returns any prompt_injection finding. Secret rules
are out of scope here.

It prints a confusion summary, per-family detection, and the exact ids of
false negatives (attacks missed) and false positives (benign text flagged),
so the misses are visible instead of hidden behind a single accuracy number.

Usage: python benchmarks/run_corpus.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
sys.dont_write_bytecode = True

from agent_context_guard.scanner import scan_text_input  # noqa: E402

CORPUS = ROOT / "benchmarks" / "injection_corpus.jsonl"


def has_injection(text: str) -> bool:
    report = scan_text_input(text, name="corpus")
    return any(f.kind == "prompt_injection" for f in report.findings)


def main() -> int:
    cases = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]

    tp = fp = tn = fn = 0
    false_negatives: list[str] = []
    false_positives: list[str] = []
    by_family: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # [detected, total] for attacks

    for case in cases:
        detected = has_injection(case["text"])
        attack = bool(case["attack"])
        if attack:
            by_family[case["family"]][1] += 1
            if detected:
                tp += 1
                by_family[case["family"]][0] += 1
            else:
                fn += 1
                false_negatives.append(case["id"])
        else:
            if detected:
                fp += 1
                false_positives.append(case["id"])
            else:
                tn += 1

    attacks = tp + fn
    benign = tn + fp
    print(f"corpus: {len(cases)} cases ({attacks} attacks, {benign} benign)")
    print()
    print(f"detected attacks (true positive):  {tp}/{attacks}")
    print(f"missed attacks (false negative):   {fn}/{attacks}")
    print(f"flagged benign (false positive):   {fp}/{benign}")
    print(f"passed benign (true negative):     {tn}/{benign}")
    print()
    print("attack detection by family:")
    for family in sorted(by_family):
        detected, total = by_family[family]
        print(f"  {family}: {detected}/{total}")
    print()

    if false_negatives:
        print("missed (these attacks are not caught by the current rules):")
        for cid in false_negatives:
            print(f"  {cid}")
        print()
    if false_positives:
        print("false alarms (benign text flagged as injection):")
        for cid in false_positives:
            print(f"  {cid}")
        print()

    print("The rules are literal regex patterns. Paraphrases, obfuscation,")
    print("other languages and encoded payloads are expected to slip through;")
    print("the evasion cases above show where. A clean report is a signal,")
    print("not proof the context is safe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
