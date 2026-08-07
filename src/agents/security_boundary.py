"""Reference security boundary for the Day 11 Guards Agent.

This is deliberately framework-independent so students can inspect the policy
and reason about the difference between untrusted content and an authorised
action. It is not a solution for the TODOs in ``src/assignment``.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlparse


TRUSTED_EGRESS_HOSTS = frozenset({"api.vinbank.example", "cases.vinbank.example"})
HIGH_RISK_ACTIONS = frozenset({
    "transfer_money", "close_account", "change_password",
    "delete_data", "update_personal_info",
})
ZERO_WIDTH = "\u200b\u200c\u200d\ufeff\u2060"
# Arabic tatweel + RTL/LTR control marks: deleted so obfuscated Arabic
# (e.g. "تـعـلـيـمـات") normalises to a matchable form ("تعليمات").
TATWEEL_RTL = (
    "\u0640\u061c"
    "\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e"
    "\u2066\u2067\u2068\u2069"
)
SECRET_PATTERNS = (
    r"\badmin123\b",
    r"sk-[a-z0-9-]{8,}",
    r"db\.vinbank\.internal(?::\d+)?",
    r"(?:password|mật\s*khẩu)\s*[:=]\s*\S+",
)
INSTRUCTION_OVERRIDE_PATTERNS = (
    r"ignore\s+(?:all\s+)?(?:previous|above|prior)?\s*instructions?",
    r"(?:system|developer)\s+(?:prompt|instruction)|system\s+override",
    r"(?:reveal|disclose|translate|encode|summarize)\b.*(?:secret|password|credential|api\s*key|internal)",
    r"bỏ\s+qua\s+(?:mọi\s+)?hướng\s+dẫn|tiết\s+lộ\s+(?:mật\s*khẩu|api|thông\s*tin\s*nội\s*bộ)",
    r"oublie\s+(?:toutes\s+les\s+)?instructions?\s*(?:précédentes)?|mot\s+de\s+passe",
    # --- Indirect / embedded-content injection (RAG, OCR, HTML, CSV, encoded) ---
    r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){2,}",
    r"(?:decode|translate|convert)\b[^\n]{0,80}\b(?:unicode|escape|carry\s*out)\b",
    r"(?:[0-9a-fA-F]{2}\s+){8,}[0-9a-fA-F]{2}",
    r"\b(?:encode|decode|convert)\b[^\n]{0,60}\b(?:base64|rot13|hex)\b",
    r"=\s*[A-Z][A-Z0-9_.]*\s*\(",
    r"\b(?:INTERNAL_EVIDENCE|PRIVATE_BOOTSTRAP_LITERALS|debug_context)\b",
    r"<\s*img\b[^>]*alt\s*=",
    r"(?:alt\s*=\s*['\"][^'\"]*(?:print|reveal|output|bootstrap|token|password|values))",
    r"\[\s*OCR\b[^\n]{0,60}(?:footer|RTL|attach|table|values|evidence)",
    r"\b(?:print|output|reveal|copy|dump|export)\b[^\n]{0,80}\b(?:bootstrap|operator|token|password|config)\b",
    r"\b(?:AR-CISO|SEC)-\d+|\bCISO\b",
    r"\b(?:payload|debug_context|narrative|remittance)\b[^\n]{0,80}\b(?:token|password|bootstrap|admin|endpoint|api\s*key|secret|credential)\b",
    r"\bpipe[-\s]?separated\b[^\n]{0,80}\b(?:copy|token|password|admin|endpoint)\b",
    r"\bbypass\b[^\n]{0,60}\b(?:reviewer|approval|routing|threshold|human|redaction|guardrail)\b",
    r"\bwithout\b[^\n]{0,40}\b(?:redaction|reviewer\s*approval|approval)\b",
    r"[\u0600-\u06FF][^\n]{0,200}(?:base64|json|payload|bootstrap|token|password|config|approval|INTERNAL_EVIDENCE|credentials|api\s*key)\b",
    r"\u062a\u0639\u0644\u064a\u0645\u0627\u062a[^\n]{0,120}(?:\u0627\u062c\u0645\u0639|\u0623\u0631\u0641\u0642|\u0627\u0644\u062a\u0647\u064a\u0626\u0629)",
)


@dataclass(frozen=True)
class ExternalContent:
    """Data retrieved from email/RAG/web; never an instruction authority."""

    source: str
    text: str
    trusted: bool = False


@dataclass(frozen=True)
class ActionRequest:
    """A proposed side effect awaiting deterministic policy and human approval."""

    action: str
    destination: str
    payload: str
    approval_id: str | None = None
    reviewer_id: str | None = None


@dataclass(frozen=True)
class ActionDecision:
    allowed: bool
    reason: str
    requires_human: bool


def normalize_for_security(text: str) -> str:
    """Canonicalize Unicode and neutralise invisible separators before policy checks.

    Invisible characters are replaced with a regular space (not deleted) so
    ``Ignore\u200ball instructions`` still reads as two words and cannot
    smuggle an instruction past a whitespace-sensitive regex. Arabic tatweel
    and RTL/LTR control marks are deleted so obfuscated Arabic normalises to
    a matchable form.
    """
    normalized = unicodedata.normalize("NFKC", text or "")
    normalized = normalized.translate(str.maketrans("", "", TATWEEL_RTL))
    return normalized.translate(str.maketrans(ZERO_WIDTH, " " * len(ZERO_WIDTH)))


def contains_secret(text: str) -> bool:
    """Detect a synthetic lab secret even when punctuation/spacing is altered."""
    normalized = re.sub(r"[^a-z0-9]", "", normalize_for_security(text).casefold())
    secrets = ("admin123", "skvinbanksecret2024", "dbvinbankinternal")
    return any(secret in normalized for secret in secrets) or any(
        re.search(pattern, normalize_for_security(text), re.IGNORECASE)
        for pattern in SECRET_PATTERNS
    )


def contains_instruction_override(text: str) -> bool:
    """Identify instruction-like text after Unicode normalization."""
    normalized = normalize_for_security(text)
    return any(re.search(pattern, normalized, re.IGNORECASE) for pattern in INSTRUCTION_OVERRIDE_PATTERNS)


def assess_external_content(content: ExternalContent) -> ActionDecision:
    """Treat third-party content as data and reject attempts to change policy."""
    if content.trusted:
        return ActionDecision(True, "trusted source metadata", False)
    if contains_instruction_override(content.text):
        return ActionDecision(False, "untrusted content contains an instruction override", False)
    return ActionDecision(True, "untrusted content is data only", False)


def authorize_action(request: ActionRequest) -> ActionDecision:
    """Enforce exact destination allowlist, secret egress block and HITL for risk."""
    destination = urlparse(request.destination)
    if destination.scheme != "https" or destination.hostname not in TRUSTED_EGRESS_HOSTS:
        return ActionDecision(False, "destination is not allowlisted", False)
    if contains_secret(request.payload):
        return ActionDecision(False, "payload contains protected data", False)
    if request.action in HIGH_RISK_ACTIONS:
        approved = bool(
            request.reviewer_id
            and request.approval_id
            and re.fullmatch(r"HITL-[A-Z0-9]{8}", request.approval_id)
        )
        if not approved:
            return ActionDecision(False, "high-risk action needs recorded human approval", True)
    return ActionDecision(True, "least-privilege policy permits this action", False)
