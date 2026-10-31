#!/usr/bin/env python3
"""WXZ Dump — Flask · one-time dump tickets · rate-limit · bundled lune."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory, abort
import urllib.request

ROOT = Path(__file__).resolve().parent
TOOLS = ROOT / "tools"
STATIC = ROOT / "static"
UPLOADS = ROOT / "uploads"
OUTPUTS = ROOT / "outputs"
for d in (UPLOADS, OUTPUTS):
    d.mkdir(parents=True, exist_ok=True)

LUNE_CANDIDATES = [
    os.environ.get("LUNE_BIN"),
    str(ROOT / "bin" / "lune"),
    str(ROOT / "lune"),
    "/usr/local/bin/lune",
    str(Path.home() / "bin" / "lune"),
    "/tmp/lune10/lune",
    shutil.which("lune"),
]
LUNE = next((p for p in LUNE_CANDIDATES if p and Path(p).is_file()), None)
DUMP_ENGINE = TOOLS / "string_dump.luau"

SECRET = os.environ.get("WXZ_SECRET") or secrets.token_hex(24)
MAX_BODY = 8 * 1024 * 1024
RATE_WINDOW = 60.0
RATE_MAX_DUMP = 10
RATE_MAX_GLOBAL = 48
RATE_MAX_REQ = 150
BAN_SECONDS = 300
TICKET_TTL = 45.0  # seconds — must dump quickly after mint

_lock = threading.Lock()
_hits: dict[str, deque] = defaultdict(deque)
_global_hits: deque = deque()
_bans: dict[str, float] = {}
# ticket_id -> {exp, ip, sig, used}
_tickets: dict[str, dict] = {}

app = Flask(__name__, static_folder=str(STATIC), static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY + 256 * 1024


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()[:64]
    return (request.remote_addr or "0.0.0.0")[:64]


def _prune(dq: deque, now: float, window: float) -> None:
    while dq and now - dq[0] > window:
        dq.popleft()


def _rate_ok(kind: str) -> tuple[bool, str]:
    ip = _client_ip()
    now = time.time()
    with _lock:
        if ip in _bans and _bans[ip] > now:
            return False, "banned"
        if ip in _bans and _bans[ip] <= now:
            del _bans[ip]

        dq = _hits[ip]
        _prune(dq, now, RATE_WINDOW)
        if len(dq) >= RATE_MAX_REQ:
            _bans[ip] = now + BAN_SECONDS
            return False, "rate limit"

        if kind == "dump":
            dump_n = sum(1 for t, k in dq if k == "dump")
            if dump_n >= RATE_MAX_DUMP:
                return False, "dump rate limit"
            _prune(_global_hits, now, RATE_WINDOW)
            if len(_global_hits) >= RATE_MAX_GLOBAL:
                return False, "busy"
            _global_hits.append(now)

        dq.append((now, kind))
    return True, "ok"


def _purge_tickets(now: float) -> None:
    dead = [k for k, v in _tickets.items() if v["exp"] < now or v.get("used")]
    for k in dead:
        del _tickets[k]


def _mint_ticket(ip: str) -> dict:
    """Create a one-time dump secret bound to IP + short TTL."""
    now = time.time()
    tid = secrets.token_urlsafe(24)
    # binding material
    nonce = secrets.token_hex(16)
    raw = f"{tid}|{ip}|{int(now)}|{nonce}"
    sig = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    with _lock:
        _purge_tickets(now)
        # limit open tickets per IP
        open_n = sum(1 for v in _tickets.values() if v["ip"] == ip and not v.get("used") and v["exp"] > now)
        if open_n >= 3:
            # invalidate oldest for this ip
            oldest = sorted(
                ((k, v) for k, v in _tickets.items() if v["ip"] == ip and not v.get("used")),
                key=lambda kv: kv[1]["exp"],
            )
            for k, _ in oldest[: max(0, open_n - 2)]:
                _tickets[k]["used"] = True
        _tickets[tid] = {
            "exp": now + TICKET_TTL,
            "ip": ip,
            "sig": sig,
            "nonce": nonce,
            "ts": int(now),
            "used": False,
        }
    return {"ticket": tid, "sig": sig, "ttl": int(TICKET_TTL)}


def _consume_ticket(tid: str, sig: str, ip: str) -> tuple[bool, str]:
    """Atomic one-time consume. Replay → fail."""
    now = time.time()
    with _lock:
        t = _tickets.get(tid)
        if not t:
            return False, "invalid ticket"
        if t.get("used"):
            return False, "ticket already used"
        if t["exp"] < now:
            t["used"] = True
            return False, "ticket expired"
        if t["ip"] != ip:
            return False, "ticket ip mismatch"
        if not hmac.compare_digest(t["sig"], sig or ""):
            return False, "bad signature"
        # consume NOW — before dump work
        t["used"] = True
        return True, "ok"


@app.after_request
def _headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers.pop("Server", None)
    return resp


@app.get("/")
def index():
    ok, _ = _rate_ok("page")
    if not ok:
        abort(429)
    return send_from_directory(ROOT, "index.html")


@app.get("/health")
def health():
    return jsonify({"ok": True, "status": "up"})


@app.post("/api/ticket")
def issue_ticket():
    """
    Called right before dump. Returns one-time secret.
    Console-logged curls cannot reuse it after a successful dump.
    """
    ok, reason = _rate_ok("ticket")
    if not ok:
        return jsonify({"error": reason}), 429
    ip = _client_ip()
    ticket = _mint_ticket(ip)
    return jsonify(ticket)


@app.post("/api/dump")
def dump():
    ok, reason = _rate_ok("dump")
    if not ok:
        return jsonify({"error": reason}), 429

    tid = (
        request.headers.get("X-WXZ-Ticket")
        or request.form.get("ticket")
        or ""
    ).strip()
    sig = (
        request.headers.get("X-WXZ-Sig")
        or request.form.get("sig")
        or ""
    ).strip()

    ok_t, why = _consume_ticket(tid, sig, _client_ip())
    if not ok_t:
        # look generic — frustrate scrapers
        return jsonify({"error": "unauthorized", "detail": why}), 401

    source = (request.form.get("source") or "").strip()
    url = (request.form.get("url") or "").strip()
    log_parts = []
    text = source

    f = request.files.get("file")
    if f and f.filename:
        raw = f.read()
        if len(raw) > MAX_BODY:
            return jsonify({"error": "too large"}), 400
        text = raw.decode("utf-8", errors="replace")
        log_parts.append(f"upload {f.filename} ({len(raw)}b)")

    if url:
        if not re.match(r"^https?://", url, re.I):
            return jsonify({"error": "bad url"}), 400
        try:
            text = fetch_url(url)
            log_parts.append(f"url {len(text)}b")
        except Exception as ex:
            return jsonify({"error": f"fetch: {ex}"}), 400

    if not (text or "").strip():
        return jsonify({"error": "empty"}), 400
    if len(text) > MAX_BODY:
        return jsonify({"error": "too large"}), 400

    result = run_dump(text)
    if log_parts:
        result["log"] = "\n".join(log_parts + [result.get("log") or ""]).strip()
    # never echo ticket material
    if result.get("error") and not result.get("output"):
        return jsonify(result), 500
    return jsonify(result)


def fetch_url(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "WXZ-Dump/1.4"}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    if len(data) > MAX_BODY:
        raise ValueError("remote too large")
    return data.decode("utf-8", errors="replace")


def run_dump(source: str, timeout: int = 150) -> dict:
    if not DUMP_ENGINE.is_file():
        return {"error": "engine missing", "output": ""}
    if not LUNE:
        return {"error": "lune binary not found", "output": ""}

    job = uuid.uuid4().hex[:12]
    in_path = UPLOADS / f"{job}_in.lua"
    out_path = OUTPUTS / f"{job}_out.txt"
    in_path.write_text(source, encoding="utf-8")

    env = os.environ.copy()
    env["PATH"] = f"{Path(LUNE).parent}:{env.get('PATH', '')}"
    cmd = [LUNE, "run", str(DUMP_ENGINE), str(in_path), str(out_path)]
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=str(TOOLS), env=env
        )
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "output": "", "log": ""}
    except Exception as ex:
        return {"error": str(ex), "output": "", "log": ""}

    elapsed = time.time() - t0
    stdout = (proc.stdout or "")[-6000:]
    stderr = (proc.stderr or "")[-1500:]
    log = (stdout + ("\n" + stderr if stderr else "")).strip()
    output = out_path.read_text(encoding="utf-8", errors="replace") if out_path.is_file() else ""
    if not output.strip() and stdout.strip():
        output = stdout

    lines = output.count("\n") + (1 if output and not output.endswith("\n") else 0)
    return {
        "output": output,
        "log": log,
        "engine": "string_dump",
        "elapsed": round(elapsed, 2),
        "lines": lines,
        "urls": len(re.findall(r"https?://[^\s\"']+", output)),
        "loads": len(re.findall(r"loadstring", output, re.I)),
        "code": proc.returncode,
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8765"))
    host = os.environ.get("HOST", "0.0.0.0")
    bundled = ROOT / "bin" / "lune"
    if bundled.is_file():
        try:
            os.chmod(bundled, 0o755)
        except OSError:
            pass
    print(f"WXZ Dump → http://{host}:{port}")
    print(f"  health  → /health")
    print(f"  ticket  → POST /api/ticket  (one-time)")
    print(f"  dump    → POST /api/dump    (needs ticket)")
    print(f"  lune    → {LUNE}")
    app.run(host=host, port=port, debug=False, threaded=True)
