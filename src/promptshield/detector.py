"""Heuristic prompt-injection detector.

This is a *signal*, not a guarantee. Published research shows that
classifier- and rule-based detectors can be bypassed by adaptive attackers, so
use this as one layer among several (least privilege, human approval,
output validation).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .sanitizer import decode_base64_blobs, sanitize


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    weight: float
    description: str


def _r(name: str, regex: str, weight: float, description: str) -> Rule:
    return Rule(name, re.compile(regex, re.IGNORECASE), weight, description)


RULES: list[Rule] = [
    _r("override_instructions",
       r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|system)\b.{0,30}\b(instructions?|prompts?|rules?|guidelines?)\b",
       0.6, "Asks the model to discard earlier instructions."),
    _r("role_reassignment",
       r"\b(you are now|from now on you are|act as|pretend (to be|you are))\b",
       0.3, "Tries to reassign the model's role or persona."),
    _r("prompt_exfiltration",
       r"\b(reveal|show|print|repeat|output|leak)\b.{0,30}\b(system prompt|hidden prompt|initial instructions|your instructions)\b",
       0.6, "Attempts to extract the system prompt."),
    _r("safety_bypass",
       r"\b(developer mode|no restrictions|without (any )?(restrictions|filters)|bypass (the )?(safety|filters?|guardrails?))\b",
       0.4, "Mentions bypassing safety controls."),
    _r("tool_abuse",
       r"\b(send|forward|email|post|upload)\b.{0,40}\b(to|at)\b.{0,40}(https?://|@[\w.-]+\.\w+)",
       0.4, "Asks for data to be sent to an external destination."),
    _r("markdown_exfil",
       r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s]*=\s*\{?[^)\s]*\)",
       0.5, "Markdown image with query parameters, a known data-exfiltration channel."),
    _r("fake_delimiters",
       r"(</?(system|assistant|instructions?)>|\[/?INST\]|<\|im_(start|end)\|>)",
       0.5, "Fake chat-template or role delimiters."),
    _r("urgency_authority",
       r"\b(important|urgent|new)\b.{0,20}\b(instruction|message|notice)\b.{0,20}\b(from|by)\b.{0,20}\b(the )?(system|admin|developer|user)\b",
       0.3, "Impersonates a trusted authority."),
    _r("hidden_to_user",
       r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|mention|show)\b.{0,20}\b(the )?user\b",
       0.5, "Asks the model to conceal actions from the user."),
]


@dataclass
class Finding:
    rule: str
    weight: float
    description: str
    excerpt: str


@dataclass
class ScanResult:
    score: float
    findings: list[Finding] = field(default_factory=list)
    hidden_chars_removed: bool = False

    @property
    def is_suspicious(self) -> bool:
        return self.score >= 0.5

    def summary(self) -> str:
        if not self.findings:
            return "clean"
        names = ", ".join(f.rule for f in self.findings)
        return f"score={self.score:.2f} [{names}]"


def scan(text: str, *, threshold: float = 0.5) -> ScanResult:
    """Scan ``text`` and return a :class:`ScanResult`.

    Scores from individual rules are combined as ``1 - prod(1 - w)`` so that
    several weak signals can add up without any single one dominating.
    """
    # Keep HTML comments in the scanned text: attackers hide payloads there.
    cleaned = sanitize(text, drop_html_comments=False)
    hidden = len(cleaned) < len(text.strip()) and cleaned != text.strip()

    candidates = [cleaned] + decode_base64_blobs(cleaned)
    findings: list[Finding] = []
    seen: set[str] = set()
    for chunk in candidates:
        for rule in RULES:
            if rule.name in seen:
                continue
            m = rule.pattern.search(chunk)
            if m:
                seen.add(rule.name)
                findings.append(Finding(rule.name, rule.weight, rule.description,
                                        m.group(0)[:120]))

    remaining = 1.0
    for f in findings:
        remaining *= 1.0 - f.weight
    score = round(1.0 - remaining, 3)
    result = ScanResult(score=score, findings=findings, hidden_chars_removed=hidden)
    return result
