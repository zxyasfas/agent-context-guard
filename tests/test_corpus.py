from __future__ import annotations

import json
import unittest
from pathlib import Path

from agent_context_guard.scanner import scan_text_input

CORPUS = Path(__file__).resolve().parents[1] / "benchmarks" / "injection_corpus.jsonl"
FAMILIES = {"override", "reveal", "exfil", "role", "shell", "evasion", "benign"}


def _cases():
    return [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]


def _detected(text: str) -> bool:
    report = scan_text_input(text, name="corpus")
    return any(f.kind == "prompt_injection" for f in report.findings)


class CorpusTests(unittest.TestCase):
    def test_corpus_schema_is_valid(self):
        cases = _cases()
        self.assertGreater(len(cases), 0)
        ids = set()
        for case in cases:
            for field in ("id", "attack", "family", "text"):
                self.assertIn(field, case)
            self.assertIsInstance(case["id"], str)
            self.assertTrue(case["id"])
            self.assertIsInstance(case["attack"], bool)
            self.assertIn(case["family"], FAMILIES)
            self.assertIsInstance(case["text"], str)
            self.assertTrue(case["text"].strip())
            self.assertNotIn(case["id"], ids, f"duplicate id {case['id']}")
            ids.add(case["id"])

    def test_role_and_shell_families_are_still_caught(self):
        # these are the families the rules currently handle; this guards
        # against a regression that would silently stop catching them
        for family in ("role", "shell"):
            cases = [c for c in _cases() if c["attack"] and c["family"] == family]
            self.assertTrue(cases, f"no {family} attack cases in corpus")
            for case in cases:
                self.assertTrue(_detected(case["text"]), f"no longer caught: {case['id']}")

    def test_most_benign_sentences_are_not_flagged(self):
        benign = [c for c in _cases() if not c["attack"]]
        self.assertTrue(benign)
        clean = [c for c in benign if not _detected(c["text"])]
        self.assertGreater(len(clean), len(benign) / 2)


if __name__ == "__main__":
    unittest.main()
