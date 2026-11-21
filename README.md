# promptshield-guard

A small, dependency-free Python toolkit that helps protect LLM applications against **prompt injection**, the #1 risk (LLM01) in the OWASP Top 10 for LLM Applications.

> **Important:** no filter can fully stop prompt injection. This library is one defensive layer. Combine it with least-privilege tool access, human approval for risky actions, and output validation.

## Features

| Module | What it does |
|---|---|
| `detector` | Rule-based scoring of text for injection signals (instruction override, prompt extraction, fake delimiters, markdown exfiltration, hidden-from-user requests). Also decodes base64 blobs. |
| `sanitizer` | NFKC normalisation, removal of zero-width / bidi / Unicode-tag characters, HTML-comment stripping, and **spotlighting** (randomised delimiters around untrusted data). |
| `guard` | Canary tokens to detect system-prompt leaks, output URL allow-listing, and a least-privilege `ToolPolicy` (allow / ask human / deny). |

## Install

```bash
git clone https://github.com/<your-username>/promptshield-guard.git
cd promptshield-guard
pip install -e ".[dev]"
```

## Quick start

```python
from promptshield import scan, spotlight, CanaryToken, validate_output, ToolPolicy

doc = open("untrusted_page.txt").read()

result = scan(doc)
if result.is_suspicious:
    print(result.summary())      # e.g. score=0.84 [override_instructions, hidden_to_user]

wrapped, note = spotlight(doc)   # put `note` in the system prompt
canary = CanaryToken()           # put canary.instruction() in the system prompt

# ... call your LLM ...

problems = validate_output(model_output, allowed_domains={"example.com"}, canary=canary)

policy = ToolPolicy(allowed={"search"}, needs_approval={"send_email"})
policy.decide("delete_files")    # -> "deny"
```

### CLI

```bash
promptshield scan_me.txt
cat email.txt | promptshield - --json
```

Exit code is `1` when the text scores at or above the threshold, so it can be used in CI or pre-processing pipelines.

## Run the tests

```bash
pytest
python examples/demo.py
```

## Design notes

- **Scores combine** with `1 - ∏(1 - wᵢ)`, so several weak signals add up.
- **Detection is a signal, not a guarantee.** Research on indirect prompt injection shows adaptive attacks can bypass detectors, so this tool is meant to be layered with architectural controls.
- Zero runtime dependencies; Python 3.9+.

## Limitations

- English-centric patterns; multilingual and heavily obfuscated attacks may slip through.
- Does not inspect images or other modalities.
- Heuristics can produce false positives on security-related documents.

## Contributing

Issues and pull requests are welcome. Please add a test for every new rule.

## License

MIT
