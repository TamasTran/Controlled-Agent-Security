"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 11: Confidence Router
  TODO 12: Design 3 HITL decision points
"""
from dataclasses import dataclass


# ============================================================
# TODO 11: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # TODO 11: Implement routing logic

        # 1. Check if action_type is in HIGH_RISK_ACTIONS — always escalate
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        # 2. Check confidence thresholds
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )
        elif confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )
        else:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason="Low confidence — escalating",
                priority="high",
                requires_human=True,
            )


# ============================================================
# TODO 12: Design 3 HITL decision points + a review lifecycle
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
# - approval_path: What approve/reject/timeout decision is recorded?
# - audit_fields: Which correlation ID, intent and proposed action/diff are logged?
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "Large Money Transfer (>50M VND)",
        "trigger": "Agent proposes a money transfer exceeding 50,000,000 VND or international wire transfer",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Source account, destination account, amount, recipient name, transfer reason, customer verification status, transaction history (last 30 days)",
        "example": "Customer requests transfer of 200,000,000 VND to a new beneficiary account that has never been used before. The agent detects high-value + new recipient and routes to a human reviewer.",
        "approval_path": "Approve -> execute transfer with OTP confirmation; Reject -> notify customer with reason code; Timeout (5 min) -> auto-reject with message 'Please visit a branch for large transfers'",
        "audit_fields": "correlation_id (UUID), intent='transfer_money', proposed_action={'from': account_id, 'to': beneficiary, 'amount': 200000000, 'currency': 'VND'}, reviewer_id, decision={'status': 'approved|rejected|timeout', 'timestamp': ISO8601, 'reason': str}",
    },
    {
        "id": 2,
        "name": "Account Closure / Data Deletion",
        "trigger": "Agent receives request to close an account, delete customer data, or remove all transaction history",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Account type, balance, pending transactions, linked services (auto-pay, cards), customer identity verification, reason for closure",
        "example": "Customer asks to close their savings account which still has a balance of 5,000,000 VND and 2 pending auto-debit payments. Agent flags for mandatory human review before any irreversible action.",
        "approval_path": "Approve -> initiate closure workflow (settle balance, cancel linked services, issue confirmation); Reject -> inform customer of blocking conditions; Timeout (10 min) -> auto-reject, ask customer to call hotline or visit branch",
        "audit_fields": "correlation_id (UUID), intent='close_account', proposed_action={'account_id': str, 'account_type': 'savings', 'balance': 5000000, 'pending_txns': 2}, reviewer_id, decision={'status': 'approved|rejected|timeout', 'timestamp': ISO8601, 'notes': str}",
    },
    {
        "id": 3,
        "name": "Suspicious Login / Password Change from New Device",
        "trigger": "Agent detects a password change or sensitive info update request from an unrecognized device, IP, or location -- OR two guardrail layers disagree on whether to block",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "Device fingerprint, IP geolocation, login history, time since last password change, whether MFA was passed, guardrail layer verdicts (if tiebreaker scenario)",
        "example": "Customer requests password change from a new device in a different city. Input guardrail says PASS (legitimate request), but anomaly detection flags it as suspicious. Human reviewer breaks the tie.",
        "approval_path": "Approve -> allow password change + send SMS/email confirmation to registered contacts; Reject -> lock account temporarily + notify customer via registered channel; Timeout (3 min) -> auto-reject (fail-closed for security), require in-branch identity verification",
        "audit_fields": "correlation_id (UUID), intent='change_password', proposed_action={'device': fingerprint, 'ip': str, 'location': str}, guardrail_verdicts={'input': 'pass', 'anomaly': 'flag'}, reviewer_id, decision={'status': 'approved|rejected|timeout', 'timestamp': ISO8601, 'risk_score': float}",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
