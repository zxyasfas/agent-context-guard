# Injection detection benchmark

`injection_corpus.jsonl` is a small labeled set of prompt-injection and
malicious agent-instruction attempts, plus benign lookalikes. `run_corpus.py`
runs the `prompt_injection` rule group against it and reports what was caught,
what was missed, and what benign text was flagged by mistake. Secret rules are
out of scope here.

The point is not a high score. It is to show, on this labeled corpus, where a
regex-based check helps and where it does not.

```bash
python benchmarks/run_corpus.py
```

Result on 2026-07-18 (current rules):

```text
corpus: 29 cases (20 attacks, 9 benign)

detected attacks (true positive):  9/20
missed attacks (false negative):   11/20
flagged benign (false positive):   2/9
passed benign (true negative):     7/9

attack detection by family:
  evasion: 0/7
  exfil: 1/2
  override: 2/4
  reveal: 2/3
  role: 2/2
  shell: 2/2

missed (these attacks are not caught by the current rules):
  override-plain-3
  override-plain-4
  reveal-plain-3
  exfil-plain-1
  evasion-typo-1
  evasion-space-1
  evasion-synonym-1
  evasion-synonym-2
  evasion-lang-1
  evasion-b64-1
  evasion-split-1

false alarms (benign text flagged as injection):
  benign-security-1
  benign-code-1
```

## reading this

The rules catch role-override and dangerous-shell phrasings in this set, and
some direct override and reveal wording. They miss:

- paraphrases the pattern does not list (`disregard the instructions above`,
  `forget everything you were told`)
- every evasion case: letter-spacing, typo characters, synonyms, another
  language, a base64 payload, and an attack split across lines
- one exfiltration phrasing where the verb and the secret are too far apart

They also raise false alarms on two benign lines: a sentence that *describes*
prompt injection defense, and a normal function that passes a token around.
Both look like the patterns without being attacks.

So a clean report means the literal patterns did not match. It is a useful
first filter before handing context to an agent, not proof the context is
safe. For anything sensitive, read the context yourself.

## adding cases

Append a JSON line to `injection_corpus.jsonl` with `attack` (true or false),
a `family`, and the `text`. Real examples you have seen are more useful than
invented ones. If a case exposes a rule gap, that is the point — leave it in
so the miss stays visible.
