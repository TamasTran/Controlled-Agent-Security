"""
Lab 11 — Configuration & API Key Setup
"""
import os


def setup_api_key():
    """Load Google API key from .env (if present) or prompt."""
    _load_dotenv_if_available()
    if "GOOGLE_API_KEY" not in os.environ:
        os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ")
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print("API key loaded.")


def _load_dotenv_if_available():
    """Load .env from the repo root so main.py works without exporting vars.

    python-dotenv is in requirements.txt; if it is missing we just skip the
    file and fall back to environment variables / interactive prompt.
    """
    try:
        from dotenv import load_dotenv
        from pathlib import Path

        # repo root = two parents above src/core/config.py
        root = Path(__file__).resolve().parents[2]
        load_dotenv(root / ".env")
    except ImportError:
        pass


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
    # Arabic banking keywords so legit Arabic questions are not blocked as off-topic
    "\u062d\u0633\u0627\u0628",          # حساب = account
    "\u062a\u0648\u0641\u064a\u0631",   # توفير = savings
    "\u0641\u0627\u0626\u062f\u0629",   # فائدة = interest
    "\u062a\u062d\u0648\u064a\u0644",   # تحويل = transfer
    "\u062d\u0648\u0627\u0644\u0629",   # حوالة = money order / wire
    "\u0628\u0637\u0627\u0642\u0629",   # بطاقة = card
    "\u0642\u0631\u0636",                # قرض = loan
    "\u0631\u0635\u064a\u062f",         # رصيد = balance
    "\u0633\u062d\u0628",                # سحب = withdrawal
    "\u0625\u064a\u062f\u0627\u0639",   # إيداع = deposit
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
