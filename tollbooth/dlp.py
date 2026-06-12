"""DLP detection engine (R6): span-based scanning with overlap suppression.

Detections carry only a pattern id and character span — never the matched
value. Nothing in this module logs, stores, or interpolates scanned content;
callers redact/block by slicing with the spans (R7).

Regexes are adapted from claude-dlp-guard's rule packs. Its engine controls
false positives with document-level signals (min match counts, nearby context
keywords) that don't exist in a single tool call, so patterns here are tighter
and use per-match validators instead (Luhn for PANs, placeholder rejection for
key=value assignments).
"""

import re
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Detection:
    """One finding: which pattern fired and where. The value itself is never stored."""

    pattern_id: str
    start: int
    end: int


@dataclass(frozen=True)
class Pattern:
    """A detection pattern. Higher specificity suppresses overlapping lower (R6)."""

    id: str
    regex: re.Pattern[str]
    specificity: int
    validator: Callable[[str], bool] | None = None


def luhn_check(number: str) -> bool:
    """Luhn checksum over the digits in `number` (separators ignored)."""
    digits = [int(d) for d in number if d.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


_PLACEHOLDER = re.compile(
    r"^(?:\$\{.*\}|<.*>|\{\{.*\}\}|change_?me|todo|placeholder|dummy"
    r"|your_.*_here|x{4,}|\*{4,}|•{4,})$",
    re.IGNORECASE,
)


def _assignment_value_is_real(match: str) -> bool:
    """For key=value matches: reject masked/placeholder values (FP control)."""
    value = re.split(r"[=:]", match, maxsplit=1)[1].strip().strip("'\"")
    return not _PLACEHOLDER.match(value)


# PAN brand formats (Visa / Mastercard / Amex / Discover), Luhn-gated.
_PAN = (
    r"\b(?:"
    r"4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"
    r"|5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"
    r"|6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"
    r"|3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}"
    r")\b"
)

# The optional body group makes a full PEM block one detection, so redaction
# covers the key material, not just the header line.
_PEM_KIND = r"(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+)?"
_PRIVATE_KEY = (
    rf"-----BEGIN\s+{_PEM_KIND}PRIVATE\s+KEY-----"
    rf"(?:[\s\S]*?-----END\s+{_PEM_KIND}PRIVATE\s+KEY-----)?"
)

PATTERNS: list[Pattern] = [
    # Exact-format secrets — specificity 3.
    Pattern("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 3),
    Pattern(
        "github-token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
        3,
    ),
    Pattern("private-key-pem", re.compile(_PRIVATE_KEY), 3),
    # Structured formats with validation/required context — specificity 2.
    Pattern(
        "aws-secret-key",
        re.compile(r"(?i)(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
        2,
    ),
    Pattern("pan", re.compile(_PAN), 2, validator=luhn_check),
    Pattern(
        "connection-string",
        # Credentials (user:pass@) required: a plain DB URL is not sensitive.
        re.compile(
            r"(?i)\b(?:jdbc:)?(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp|mssql)"
            r"://[^\s/@:]+:[^\s@]+@\S+"
        ),
        2,
    ),
    Pattern("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), 2),
    Pattern(
        "us-phone",
        # Separators are mandatory: 10 bare digits are more often ids than phones.
        re.compile(r"(?<!\d)(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"),
        2,
    ),
    # Generic key=value assignments — specificity 1, suppressed by anything above.
    Pattern(
        "api-key-assignment",
        re.compile(r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9_-]{20,}"),
        1,
        validator=_assignment_value_is_real,
    ),
    Pattern(
        "password-assignment",
        re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}"),
        1,
        validator=_assignment_value_is_real,
    ),
]

PATTERN_IDS = frozenset(p.id for p in PATTERNS)


def scan(text: str, patterns: list[Pattern] | None = None) -> list[Detection]:
    """Scan `text`, returning non-overlapping detections ordered by position (R6).

    Overlap suppression: a more-specific match claims its span; overlapping
    less-specific matches are dropped (cross-cutting Pattern 1). Offsets index
    `text` exactly as given — no normalization — so spans stay valid for
    in-place redaction (R7).
    """
    if patterns is None:
        patterns = PATTERNS
    candidates: list[tuple[int, int, int, str]] = []
    for pattern in patterns:
        for match in pattern.regex.finditer(text):
            if pattern.validator is not None and not pattern.validator(match.group()):
                continue
            candidates.append((pattern.specificity, match.start(), match.end(), pattern.id))
    # Most specific first; ties broken by longer match, then position.
    candidates.sort(key=lambda c: (-c[0], -(c[2] - c[1]), c[1]))
    accepted: list[Detection] = []
    for _, start, end, pattern_id in candidates:
        if any(d.start < end and start < d.end for d in accepted):
            continue
        accepted.append(Detection(pattern_id, start, end))
    accepted.sort(key=lambda d: d.start)
    return accepted
