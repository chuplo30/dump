#!/usr/bin/env python3
"""WXZ Dump — Flask server for string dump + thick fake env (UptimeRobot-friendly)."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
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
    "/tmp/lune10/lune",
    shutil.which("lune"),
]
LUNE = next((p for p in LUNE_CANDIDATES if p and Path(p).is_file()), None)
DUMP_ENGINE = TOOLS / "string_dump.luau"

app = Flask(__name__, static_folder=str(STATIC), static_url_path="/static")


@app.get("/")
def index():
    return send_from_directory(ROOT, "index.html")


@app.get("/health")
@app.get("/api/health")
def health():
    """Simple endpoint for UptimeRobot / monitors."""
    return jsonify(
        {
            "ok": True,
            "status": "up",
            "lune": bool(LUNE),
            "lune_path": LUNE,
            "engine": DUMP_ENGINE.is_file(),
        }
    )


def fetch_url(url: str, timeout: int = 25) -> str:
    if not re.match(r"^https?://", url, re.I):
        raise ValueError("URL must start with http:// or https://")
    req = urllib.request.Request(url, headers={"User-Agent": "WXZ-Dump/1.2"}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    if len(data) > 12 * 1024 * 1024:
        raise ValueError("Remote file too large (>12MB)")
    return data.decode("utf-8", errors="replace")


def run_dump(source: str, timeout: int = 150) -> dict:
    if not DUMP_ENGINE.is_file():
        return {"error": "string_dump.luau missing in tools/", "output": ""}
    if not LUNE:
        return {
            "error": "lune binary not found — install lune or set LUNE_BIN",
            "output": "",
        }

    job = uuid.uuid4().hex[:12]
    in_path = UPLOADS / f"{job}_in.lua"
    out_path = OUTPUTS / f"{job}_out.txt"
    in_path.write_text(source, encoding="utf-8")

    env = os.environ.copy()
    bin_dir = str(Path(LUNE).parent)
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"

    cmd = [LUNE, "run", str(DUMP_ENGINE), str(in_path), str(out_path)]
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(TOOLS),
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"timeout after {timeout}s", "output": "", "log": ""}
    except Exception as ex:
        return {"error": str(ex), "output": "", "log": ""}

    elapsed = time.time() - t0
    stdout = (proc.stdout or "")[-6000:]
    stderr = (proc.stderr or "")[-2000:]
    log = (stdout + ("\n" + stderr if stderr else "")).strip()

    output = ""
    if out_path.is_file():
        output = out_path.read_text(encoding="utf-8", errors="replace")
    if not output.strip() and stdout.strip():
        output = stdout

    lines = output.count("\n") + (1 if output and not output.endswith("\n") else 0)
    urls = len(re.findall(r"https?://[^\s\"']+", output))
    loads = len(re.findall(r"loadstring", output, re.I))

    if proc.returncode != 0 and not output.strip():
        return {
            "error": f"engine exit {proc.returncode}",
            "output": output or stderr or stdout,
            "log": log,
            "engine": "string_dump",
            "elapsed": round(elapsed, 2),
        }

    return {
        "output": output,
        "log": log,
        "engine": "string_dump",
        "elapsed": round(elapsed, 2),
        "lines": lines,
        "urls": urls,
        "loads": loads,
        "code": proc.returncode,
    }


@app.post("/api/dump")
def dump():
    mode = (request.form.get("mode") or "string_dump").strip()
    source = (request.form.get("source") or "").strip()
    url = (request.form.get("url") or "").strip()
    log_parts = []
    text = source

    f = request.files.get("file")
    if f and f.filename:
        raw = f.read()
        if len(raw) > 10 * 1024 * 1024:
            return jsonify({"error": "file too large"}), 400
        text = raw.decode("utf-8", errors="replace")
        log_parts.append(f"upload {f.filename} ({len(raw)} bytes)")

    if url:
        try:
            text = fetch_url(url)
            log_parts.append(f"fetched url ({len(text)} bytes)")
        except Exception as ex:
            return jsonify({"error": f"fetch failed: {ex}"}), 400

    if not (text or "").strip():
        return jsonify({"error": "empty source"}), 400
    if len(text) > 12 * 1024 * 1024:
        return jsonify({"error": "source too large"}), 400

    result = run_dump(text)
    if log_parts:
        result["log"] = "\n".join(log_parts + [result.get("log") or ""]).strip()

    if result.get("error") and not result.get("output"):
        return jsonify(result), 500
    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8765"))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"WXZ Dump → http://{host}:{port}")
    print(f"  health: http://{host}:{port}/health")
    print(f"  lune: {LUNE}")
    print(f"  engine: {DUMP_ENGINE.is_file()}")
    # threaded=True so health checks don't block dumps
    app.run(host=host, port=port, debug=False, threaded=True)
