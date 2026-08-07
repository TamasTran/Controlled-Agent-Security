"""Demo server: static dashboard + REAL agent chat API.

Serves the VinBank dashboard exactly like ``python -m http.server`` (same
repo-root directory) and additionally exposes a real chat endpoint that runs
the *actual* protected agent with the *actual* guardrail plugins from ``src/``:

    GET  /            -> static files (demo/index.html, outputs/*.json)
    GET  /api/health  -> {"ok": true, "api_key": bool}
    POST /api/chat    -> {"message": "..."} -> agent reply + verdict

When the Gemini API key is missing or the API is down (quota 429), the server
does NOT crash: deterministic guardrails (rate limit, injection, topic,
output PII filter) still run through the real plugins, and the reply falls
back to a friendly offline message.

Usage:
    python scripts/demo_server.py [--port 8900] [--host 127.0.0.1]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except ImportError:
    pass

os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "0")

# ---------------------------------------------------------------------------
# Pipeline singleton (created lazily on first chat request)
# ---------------------------------------------------------------------------
_pipeline = None
_pipeline_lock = threading.Lock()

# The shared ADK runner is NOT thread-safe: ThreadingHTTPServer spawns a thread
# per request, each with its own event loop (asyncio.run), so concurrent chats
# could corrupt runner/session state. The demo is single-user, so a lock is the
# pragmatic fix — it serialises chat execution.
_chat_lock = threading.Lock()


def get_pipeline():
    """Build (agent, runner, rate_limiter) once, reusing across requests.

    IMPORTANT: the guardrail plugins are NOT attached to the runner. In ADK
    2.6.2 an ``on_user_message_callback`` return value only REWRITES the user
    message (the model is then asked to respond to the block text), so an
    attached limiter/input plugin would silently double-count requests and
    could produce nonsense replies ("Rate limit exceeded..." fed to the model).
    The server enforces every deterministic layer itself (see _run_chat); the
    agent is just the plain LLM.
    """
    global _pipeline
    with _pipeline_lock:
        if _pipeline is not None:
            return _pipeline

        from assignment.rate_limiter import RateLimitPlugin
        from agents.agent import create_protected_agent

        api_key = os.environ.get("GOOGLE_API_KEY", "").strip()
        rate_limiter = RateLimitPlugin(max_requests=30, window_seconds=60)

        agent, runner = create_protected_agent(plugins=[])
        _pipeline = {
            "agent": agent,
            "runner": runner,
            "rate_limiter": rate_limiter,
        }
        print(
            f"[demo_server] pipeline ready (api_key={'present' if api_key else 'MISSING'})"
        )
        return _pipeline


OFFLINE_MSG = (
    "⚠️ VinBank assistant đang ở chế độ offline: không có GOOGLE_API_KEY "
    "hoặc API Gemini đang quá tải (quota). Các guardrails offline (rate limit, "
    "chống injection, lọc chủ đề, lọc PII) vẫn hoạt động bình thường. "
    "Thêm API key vào .env rồi khởi động lại server để bật câu trả lời thật."
)


async def _run_chat(message: str) -> dict:
    """Run one message through the real pipeline; never raises.

    NOTE: in ADK 2.6.2 an ``on_user_message_callback`` returning a block
    Content only REWRITES the user message (the model is then asked to respond
    to the block text), so the input guardrail plugin does not actually stop
    the LLM call. The demo server therefore enforces the deterministic input
    guardrails (the very same functions the plugin calls) HERE, before any
    model call, and returns the block message directly — mirroring the
    classification the assignment suite performs in ``run_assignment_suite``.
    """
    pipeline = get_pipeline()
    agent, runner = pipeline["agent"], pipeline["runner"]

    from google.genai import types as _types

    # --- 1. Rate limiter (real plugin, direct call) ------------------------
    class _FakeCtx:
        user_id = "demo_user"

    rl = pipeline["rate_limiter"]
    rl_result = await rl.on_user_message_callback(
        invocation_context=_FakeCtx(),
        user_message=_types.Content(
            role="user", parts=[_types.Part.from_text(text=message)]
        ),
    )
    if rl_result is not None:
        text = "".join(p.text for p in rl_result.parts if getattr(p, "text", None))
        return {"ok": True, "blocked": True, "blocked_at": "rate_limit", "response": text}

    # --- 2. Input guardrails (real functions from src/guardrails) ----------
    from guardrails.input_guardrails import (
        detect_injection,
        topic_filter,
        matching_injection_patterns,
    )

    if detect_injection(message):
        return {
            "ok": True,
            "blocked": True,
            "blocked_at": "input_injection",
            "matched": matching_injection_patterns(message)[:4],
            "response": "I cannot process that request. I'm here to help with banking questions only.",
        }

    if topic_filter(message):
        return {
            "ok": True,
            "blocked": True,
            "blocked_at": "input_topic",
            "response": (
                "I'm a VinBank assistant and can only help with banking-related questions. "
                "How can I assist you with your account, transactions, or other banking needs?"
            ),
        }

    # --- 3. Real agent call (Gemini, guardrail plugins attached) ------------
    from core.utils import chat_with_agent

    try:
        response, _ = await chat_with_agent(agent, runner, message)
    except Exception as e:  # API down / no key / any transport error
        print(f"[demo_server] LLM error: {type(e).__name__}: {e}")
        return {
            "ok": True,
            "blocked": False,
            "blocked_at": None,
            "offline": True,
            "response": OFFLINE_MSG,
        }

    # --- 4. Output guardrail (real content_filter from src/guardrails) ------
    from guardrails.output_guardrails import content_filter

    cf = content_filter(response)
    if not cf["safe"]:
        return {
            "ok": True,
            "blocked": True,
            "blocked_at": "output_filter",
            "issues": cf["issues"][:4],
            "response": cf["redacted"],
        }

    return {
        "ok": True,
        "blocked": False,
        "blocked_at": None,
        "offline": False,
        "response": response,
    }


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class DemoHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    # -- CORS + helpers -----------------------------------------------------
    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            get_pipeline()  # ensure the pipeline is built before reporting
            self._send_json(
                {
                    "ok": True,
                    "api_key": bool(os.environ.get("GOOGLE_API_KEY", "").strip()),
                    "demo_input_judge": "off (deterministic guardrails enforce before LLM)",
                }
            )
            return
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/chat":
            self._send_json({"ok": False, "error": "not found"}, 404)
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            body = json.loads(raw.decode("utf-8"))
            message = str(body.get("message", "")).strip()
        except Exception as e:
            self._send_json({"ok": False, "error": f"bad request: {e}"}, 400)
            return

        if not message:
            self._send_json({"ok": False, "error": "empty message"}, 400)
            return

        try:
            with _chat_lock:  # serialise access to the shared ADK runner
                result = asyncio.run(_run_chat(message))
        except Exception as e:
            print(f"[demo_server] chat error: {type(e).__name__}: {e}")
            self._send_json({"ok": False, "error": str(e)}, 500)
            return
        self._send_json(result)

def main():
    parser = argparse.ArgumentParser(description="VinBank demo server (static + real chat API)")
    parser.add_argument("--port", type=int, default=8900)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    print(f"[demo_server] serving {ROOT} at http://{args.host}:{args.port}")
    print("[demo_server]  GET /             -> dashboard")
    print("[demo_server]  POST /api/chat    -> real agent + guardrails")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[demo_server] shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
