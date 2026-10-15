"""Security heuristics, masking, and JWT helpers.

Heuristic checks are an extra layer, not a guarantee against prompt injection.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from .config import settings

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignore_previous_instructions", re.compile(r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+instructions?\b", re.I)),
    ("reveal_system_prompt", re.compile(r"\b(?:reveal|show|print|disclose|repeat)\s+(?:the\s+)?(?:system prompt|hidden instructions|secrets)\b", re.I)),
    ("developer_override", re.compile(r"\bdeveloper (?:message|instruction).{0,60}\b(?:override|ignore|bypass)\b", re.I | re.S)),
    ("jailbreak", re.compile(r"\b(?:jailbreak|DAN mode|do anything now|bypass (?:all )?safety)\b", re.I)),
    ("credential_exfiltration", re.compile(r"\bexfiltrat(?:e|ion|ing)\b.{0,80}\b(?:token|secret|credential|api key|password)\b", re.I | re.S)),
    ("sensitive_credential_access", re.compile(r"\b(?:(?:attempt|try|trying)\s+to\s+)?(?:access|retrieve|obtain|read|show|reveal|list|export|extract|dump|steal|disclose|fetch|collect|view|find|get|give|provide|send|print)\b.{0,80}\b(?:(?:customer|client|user|account|login|employee)\s+)?(?:passwords?|credentials?|api\s+keys?|tokens?|private\s+keys?|secrets?)\b", re.I | re.S)),
    ("unrestricted_model", re.compile(r"\bact as (?:an? )?(?:unrestricted|unfiltered|uncensored) model\b", re.I)),
    ("tool_policy_bypass", re.compile(r"\b(?:ignore|bypass|disable)\b.{0,50}\b(?:security policy|tool restrictions|approval checks|guardrails)\b", re.I | re.S)),
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    # Match card candidates before phone numbers so the phone pattern cannot
    # partially redact a payment-card number before Luhn validation runs.
    ("credit_card", re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")),
    # Designed to catch common international and US-style phone number forms;
    # intentionally avoids replacing a plain short integer.
    ("phone", re.compile(r"(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\(?\d{2,4}\)?[ .-]?)\d{3,4}[ .-]?\d{4}(?!\w)")),
    ("api_key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("account_id", re.compile(r"\b(?:acct|account)(?:[-_ ]+id)?\s*[:#]?\s*(?=[A-Z0-9-]{6,}\b)(?=[A-Z0-9-]*\d)[A-Z0-9-]{6,}\b", re.I)),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I | re.S)),
)


# A quoted attack phrase in a clearly educational/analytical request is not, by
# itself, an instruction to the gateway. Only suppress a match when the matched
# text is fully inside a quotation AND the surrounding request is explicitly
# about explaining/classifying a phrase or studying security. Any active match
# outside the quoted passage remains a block.
_QUOTED_SPANS = re.compile(
    r'"[^"\n]{1,600}"|“[^”\n]{1,600}”|‘[^’\n]{1,600}’|`[^`\n]{1,600}`'
)
_BENIGN_ANALYSIS_CONTEXT = re.compile(
    r"(?:\b(?:explain|analy[sz]e|classify|describe|discuss|review|evaluate|study|document|quote)\b"
    r".{0,180}\b(?:phrase|sentence|example|wording|pattern|prompt[ -]?injection|instruction)\b)"
    r"|(?:\b(?:cybersecurity|security|academic|research|educational|training)\s+"
    r"(?:assignment|report|exercise|analysis|example|lesson)\b)",
    re.I | re.S,
)


def detect_prompt_injection(text: str) -> list[str]:
    """Return suspicious pattern identifiers, reducing quoted-phrase false positives.

    Heuristic scanning is intentionally conservative. Quoted attack strings are
    ignored only in an explicit educational/analysis context and only when every
    matched occurrence is inside quotes. This is not a replacement for a model-
    aware classifier or human review.
    """
    if not isinstance(text, str) or not text:
        return []

    educational_analysis = bool(_BENIGN_ANALYSIS_CONTEXT.search(text))
    quoted_spans = [match.span() for match in _QUOTED_SPANS.finditer(text)] if educational_analysis else []
    detected: list[str] = []
    for name, pattern in INJECTION_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span()
            if educational_analysis and any(q_start <= start and end <= q_end for q_start, q_end in quoted_spans):
                continue
            detected.append(name)
            break
    return detected


def flatten_keys(value: Any):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key)
            yield from flatten_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from flatten_keys(nested)


def walk_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from walk_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk_strings(nested)


def risk_score(text: str, tool_name: str, args: dict[str, Any]) -> int:
    """Return a deterministic 0-100 risk score separate from hard-block rules.

    Injection patterns are still enforced by detect_prompt_injection(). This score
    also reflects operation impact, broad scope, external distribution and sensitive
    data context so a legitimate-but-high-impact request can be routed to review.
    """
    lowered_tool = (tool_name or "").lower()
    lowered_text = text or ""
    matched_patterns = len(detect_prompt_injection(lowered_text))
    # A detected active injection is still blocked separately by the guardrail;
    # adding it to the score helps represent blocked attempts in the risk graph.
    score = min(60, matched_patterns * 35)

    sensitive_keys = {"password", "secret", "token", "api_key", "private_key", "credential"}
    if any(
        key.lower() in sensitive_keys
        or any(s in key.lower() for s in ("password", "secret", "token", "private_key", "credential"))
        for key in flatten_keys(args)
    ):
        score += 35

    if any(word in lowered_tool for word in ("delete", "transfer", "payment", "write", "send", "admin", "shell", "execute", "update", "create")):
        score += 25

    # Independent contextual signals let a request reach the >60 human-review
    # threshold without treating a harmless quoted injection example as malicious.
    if re.search(r"\b(?:production|prod|bulk|mass|all customers|all accounts|irreversible|permanent|wipe|purge|overwrite|delete)\b", lowered_text, re.I):
        score += 20
    if re.search(r"\b(?:external(?:ly)?|public(?:ly)?|publish|export|share|third[- ]party|distribute)\b", lowered_text, re.I):
        score += 20
    if re.search(r"\b(?:admin|administrator|root|privileged|elevated access)\b", lowered_text, re.I):
        score += 15
    if re.search(r"\b(?:sensitive data|customer records|personal data|financial records|credentials|api keys|passwords)\b", lowered_text, re.I):
        score += 15

    # Do not score an educational quoted example as a malicious instruction.
    # The hard-block detector remains responsible for active injection matches.
    if any(detect_prompt_injection(value) for value in walk_strings(args)):
        score += 25
    return max(0, min(100, score))


def _luhn_valid(value: str) -> bool:
    digits = [int(ch) for ch in value if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def mask_sensitive_data(value: Any) -> Any:
    """Recursively redact common secrets from strings in tool responses."""
    if isinstance(value, dict):
        return {str(key): mask_sensitive_data(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [mask_sensitive_data(nested) for nested in value]
    if isinstance(value, tuple):
        return [mask_sensitive_data(nested) for nested in value]
    if not isinstance(value, str):
        return value

    masked = value
    for name, pattern in SECRET_PATTERNS:
        if name == "credit_card":
            masked = pattern.sub(lambda match: f"[REDACTED_CREDIT_CARD]" if _luhn_valid(match.group(0)) else match.group(0), masked)
        else:
            masked = pattern.sub(f"[REDACTED_{name.upper()}]", masked)
    return masked


def issue_token(username: str, role: str, profile: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "profile": profile,
        "iss": settings.jwt_issuer,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_ttl_minutes),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"], issuer=settings.jwt_issuer)
