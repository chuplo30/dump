#!/usr/bin/env python3
"""WXZ Dump — string dump + thick fake env (no lupro required)."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
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
    "/tmp/lune10/lune",
    shutil.which("lune"),
    str(ROOT / "bin" / "lune"),
    str(ROOT / "lune"),
]
LUNE = next((p for p in LUNE_CANDIDATES if p and Path(p).is_file()), None)

DUMP_ENGINE = TOOLS / "string_dump.luau"

app = FastAPI(title="WXZ Dump", version="1.1")
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/")
def index():
    return FileResponse(ROOT / "index.html")


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "lune": bool(LUNE),
        "lune_path": LUNE,
        "engine": DUMP_ENGINE.is_file(),
    }


def fetch_url(url: str, timeout: int = 25) -> str:
    if not re.match(r"^https?://", url, re.I):
        raise ValueError("URL must start with http:// or https://")
    req = urllib.request.Request(url, headers={"User-Agent": "WXZ-Dump/1.1"}, method="GET")
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
            "error": "lune binary not found — put lune on PATH or set LUNE_BIN",
            "output": "",
        }

    job = uuid.uuid4().hex[:12]
    in_path = UPLOADS / f"{job}_in.lua"
    out_path = OUTPUTS / f"{job}_out.txt"
    in_path.write_text(source, encoding="utf-8")

    env = os.environ.copy()
    env["PATH"] = f"/tmp/lune10:{env.get('PATH', '')}"

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
async def dump(
    mode: str = Form("string_dump"),
    source: str = Form(""),
    url: str = Form(""),
    file: UploadFile | None = File(None),
):
    text = (source or "").strip()
    log_parts = []

    if file and file.filename:
        raw = await file.read()
        if len(raw) > 10 * 1024 * 1024:
            return JSONResponse({"error": "file too large"}, status_code=400)
        text = raw.decode("utf-8", errors="replace")
        log_parts.append(f"upload {file.filename} ({len(raw)} bytes)")

    if url and url.strip():
        try:
            text = fetch_url(url.strip())
            log_parts.append(f"fetched url ({len(text)} bytes)")
        except Exception as ex:
            return JSONResponse({"error": f"fetch failed: {ex}"}, status_code=400)

    if not text.strip():
        return JSONResponse({"error": "empty source"}, status_code=400)
    if len(text) > 12 * 1024 * 1024:
        return JSONResponse({"error": "source too large"}, status_code=400)

    result = run_dump(text)
    if log_parts:
        result["log"] = "\n".join(log_parts + [result.get("log") or ""]).strip()

    if result.get("error") and not result.get("output"):
        return JSONResponse(result, status_code=500)
    return result


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8765"))
    print(f"WXZ Dump → http://127.0.0.1:{port}")
    print(f"  lune: {LUNE}")
    print(f"  engine: {DUMP_ENGINE.is_file()}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
