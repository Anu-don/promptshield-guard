"""promptshield-guard: lightweight, defensive tooling against prompt injection.

Modules
-------
detector   Heuristic scoring of text for injection-like content.
sanitizer  Normalisation and invisible-character stripping, plus spotlighting.
guard      Canary tokens, output validation and tool-call allow-listing.
"""

from .detector import Finding, ScanResult, scan
from .guard import CanaryToken, ToolPolicy, validate_output
from .sanitizer import sanitize, spotlight

__all__ = [
    "Finding",
    "ScanResult",
    "scan",
    "sanitize",
    "spotlight",
    "CanaryToken",
    "ToolPolicy",
    "validate_output",
]

__version__ = "0.1.0"
