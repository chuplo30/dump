#!/usr/bin/env python3
"""WXZ Dump Discord bot — .dump / .d — Lune string dump on Render."""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import discord
from discord.ext import commands

ROOT = Path(__file__).resolve().parent
TOOLS = ROOT / "tools"
BIN = ROOT / "bin"
DUMP_ENGINE = TOOLS / "dump.luau"
WORK = ROOT / "work"
WORK.mkdir(parents=True, exist_ok=True)

TOKEN = os.environ.get("DISCORD_TOKEN")
MAX_SOURCE = 8 * 1024 * 1024
DUMP_TIMEOUT = int(os.environ.get("DUMP_TIMEOUT", "150"))
FETCH_TIMEOUT = int(os.environ.get("FETCH_TIMEOUT", "25"))
BANNER = "-- This file was generated with xz at discord.gg/tqmaYsxGKm v0.1 --\n"

LUNE_URL = os.environ.get(
    "LUNE_URL",
    "https://github.com/lune-org/lune/releases/download/v0.10.4/lune-0.10.4-linux-x86_64.zip",
)

# Browser-like headers — many raw hosts (pastebin, github raw, pastefy, …) reject bare clients
FETCH_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/plain,text/html,application/json,application/octet-stream,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Connection": "close",
}


def log(*a):
    print(*a, flush=True)


def ensure_lune() -> str:
    """Return path to lune binary; download if missing."""
    candidates = [
        os.environ.get("LUNE_BIN"),
        str(BIN / "lune"),
        str(ROOT / "lune"),
        shutil.which("lune"),
        "/tmp/lune_bot",
        "/tmp/lune10/lune",
    ]
    for c in candidates:
        if not c:
            continue
        p = Path(c)
        if not p.is_file():
            continue
        try:
            p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except OSError:
            pass
        # verify actually executable (noexec mounts fail here)
        try:
            r = subprocess.run([str(p), "--version"], capture_output=True, text=True, timeout=10)
            if r.returncode == 0 or "lune" in ((r.stdout or "") + (r.stderr or "")).lower():
                return str(p)
        except (OSError, subprocess.TimeoutExpired):
            continue

    log("[lune] not found — downloading…")
    BIN.mkdir(parents=True, exist_ok=True)
    zpath = BIN / "lune.zip"
    try:
        req = urllib.request.Request(LUNE_URL, headers=FETCH_HEADERS)
        with urllib.request.urlopen(req, timeout=120) as resp:
            zpath.write_bytes(resp.read())
        with zipfile.ZipFile(zpath, "r") as zf:
            names = zf.namelist()
            target = None
            for n in names:
                if Path(n).name == "lune" or Path(n).name.startswith("lune"):
                    target = n
                    break
            if not target:
                target = names[0]
            out = BIN / "lune"
            out.write_bytes(zf.read(target))
            out.chmod(0o755)
        zpath.unlink(missing_ok=True)
        log("[lune] installed →", out)
        return str(out)
    except Exception as ex:
        log("[lune] download failed:", ex)
        raise RuntimeError(
            "lune binary missing — put bin/lune in repo or set LUNE_BIN / LUNE_URL"
        ) from ex


def fetch_url(url: str) -> str:
    """GET raw script URL with browser-like headers."""
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        raise RuntimeError("url must start with http:// or https://")

    # normalize common paste hosts to raw when user pastes view URLs
    raw = url
    if "pastebin.com/" in url and "/raw/" not in url:
        raw = re.sub(
            r"https?://(?:www\.)?pastebin\.com/([A-Za-z0-9]+)",
            r"https://pastebin.com/raw/\1",
            url,
            count=1,
        )
    elif "paste.ee/p/" in url:
        raw = url.replace("/p/", "/r/")
    elif "ghostbin." in url and "/paste/" in url and "/raw" not in url:
        raw = url.rstrip("/") + "/raw"

    headers = dict(FETCH_HEADERS)
    # github / gist prefer raw
    if "github.com" in raw and "/blob/" in raw:
        raw = raw.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    if "gist.github.com" in raw and "/raw" not in raw:
        headers["Accept"] = "text/plain"

    req = urllib.request.Request(raw, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            data = resp.read()
    except urllib.error.HTTPError as ex:
        body = ""
        try:
            body = ex.read()[:200].decode("utf-8", errors="replace")
        except Exception:
            pass
        raise RuntimeError(f"fetch HTTP {ex.code}: {body or ex.reason}") from ex
    except urllib.error.URLError as ex:
        raise RuntimeError(f"fetch failed: {ex.reason}") from ex

    if len(data) > MAX_SOURCE:
        raise RuntimeError("remote file too large")
    text = data.decode("utf-8", errors="replace")
    if not text.strip():
        raise RuntimeError("remote returned empty body")
    return text


def run_dump(source: str) -> tuple[str, str]:
    """Run tools/dump.luau; returns (output_text, log_text)."""
    if not DUMP_ENGINE.is_file():
        raise RuntimeError("tools/dump.luau missing")

    lune = ensure_lune()
    job = f"{int(time.time() * 1000) % 10_000_000:07d}"
    in_path = WORK / f"{job}_in.lua"
    out_path = WORK / f"{job}_out.txt"
    in_path.write_text(source, encoding="utf-8", errors="replace")

    env = os.environ.copy()
    env["PATH"] = f"{Path(lune).parent}:{env.get('PATH', '')}"
    cmd = [lune, "run", str(DUMP_ENGINE), str(in_path), str(out_path)]
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=DUMP_TIMEOUT,
            cwd=str(TOOLS),
            env=env,
        )
    except subprocess.TimeoutExpired as ex:
        raise RuntimeError(f"dump timeout ({DUMP_TIMEOUT}s)") from ex
    finally:
        elapsed = time.time() - t0

    stdout = (proc.stdout or "")[-8000:]
    stderr = (proc.stderr or "")[-2000:]
    log_txt = (stdout + ("\n" + stderr if stderr else "")).strip()
    output = ""
    if out_path.is_file():
        output = out_path.read_text(encoding="utf-8", errors="replace")
    if not output.strip() and stdout.strip():
        output = stdout

    for p in (in_path, out_path):
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass

    if not output.strip():
        raise RuntimeError(
            "empty dump output"
            + (f"\n--- log ---\n{log_txt[-1500:]}" if log_txt else "")
        )

    if not output.lstrip().startswith(BANNER.strip()):
        output = BANNER + "\n" + output
    log(f"[dump] done in {elapsed:.2f}s  out={len(output)}b  code={proc.returncode}")
    return output, log_txt


CODEBLOCK_RE = re.compile(
    r"```(?:lua|luau|txt|text)?\s*\n(.*?)```",
    re.DOTALL | re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


async def extract_source(message: discord.Message) -> str:
    """Attachment → URL in message → code block → raw text after command."""
    for att in message.attachments:
        if att.size and att.size > MAX_SOURCE:
            raise RuntimeError(f"file too large ({att.size} > {MAX_SOURCE})")
        data = await att.read()
        if len(data) > MAX_SOURCE:
            raise RuntimeError("file too large")
        return data.decode("utf-8", errors="replace")

    content = message.content or ""

    # URL anywhere in message (prefer after command)
    urls = URL_RE.findall(content)
    if urls:
        # skip discord CDN attachment urls if any weirdness — still ok to fetch
        url = urls[0].rstrip(".,;>")
        log("[fetch]", url)
        return await asyncio.to_thread(fetch_url, url)

    m = CODEBLOCK_RE.search(content)
    if m:
        return m.group(1)

    lines = content.split("\n")
    if lines:
        first = re.sub(
            r"^[.\s]*(?:dump|d)\b", "", lines[0], count=1, flags=re.I
        ).strip()
        rest = "\n".join([first] + lines[1:]) if first else "\n".join(lines[1:])
    else:
        rest = content
    rest = rest.strip()
    if rest:
        return rest
    raise RuntimeError("attach a file, paste a raw URL, or send a code block")


def start_health_server():
    port = int(os.environ.get("PORT", "0") or "0")
    if port <= 0:
        return

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"ok":true,"service":"wxz-dump-bot"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            return

    def run():
        try:
            httpd = HTTPServer(("0.0.0.0", port), H)
            log(f"[health] :{port}")
            httpd.serve_forever()
        except Exception as ex:
            log("[health] failed:", ex)

    threading.Thread(target=run, daemon=True).start()


intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=".", help_command=None, intents=intents)


@bot.event
async def on_ready():
    log(f"[bot] logged in as {bot.user} id={bot.user.id}")
    try:
        await bot.change_presence(
            status=discord.Status.online,
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name=".dump | .d",
            ),
        )
        log("[bot] presence online")
    except Exception as ex:
        log("[bot] presence failed:", ex)
    try:
        ensure_lune()
        log("[bot] lune ok")
    except Exception as ex:
        log("[bot] lune warn:", ex)


async def do_dump(ctx: commands.Context):
    if ctx.author.bot:
        return
    status = await ctx.reply("dumping…", mention_author=False)
    try:
        source = await extract_source(ctx.message)
        if not source or not str(source).strip():
            await status.edit(content="empty source.")
            return
        if len(source) > MAX_SOURCE:
            await status.edit(content="source too large.")
            return

        output, _log = await asyncio.to_thread(run_dump, source)

        tmp = tempfile.NamedTemporaryFile(
            prefix="wxz_dump_",
            suffix=".txt",
            delete=False,
        )
        try:
            tmp.write(output.encode("utf-8", errors="replace"))
            tmp.close()
            file = discord.File(tmp.name, filename="message.txt")
            await ctx.reply(
                content="skidding lol 😂",
                file=file,
                mention_author=False,
            )
            try:
                await status.delete()
            except discord.HTTPException:
                await status.edit(content="done.")
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
    except Exception as ex:
        msg = str(ex)
        if len(msg) > 1800:
            msg = msg[:1800] + "…"
        await status.edit(content=f"dump failed:\n```\n{msg}\n```")


@bot.command(name="dump")
async def cmd_dump(ctx: commands.Context):
    await do_dump(ctx)


@bot.command(name="d")
async def cmd_d(ctx: commands.Context):
    await do_dump(ctx)


def main():
    if not TOKEN:
        log("ERROR: set DISCORD_TOKEN env var")
        sys.exit(1)
    if not DUMP_ENGINE.is_file():
        log("ERROR: missing", DUMP_ENGINE)
        sys.exit(1)

    start_health_server()
    log("[bot] starting…")
    bot.run(TOKEN, log_handler=None)


if __name__ == "__main__":
    main()
