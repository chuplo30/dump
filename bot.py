#!/usr/bin/env python3
"""WXZ Dump Discord bot — .dump / .d / .get — Lune dump on Render + Flask health."""
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
from pathlib import Path

import discord
from discord.ext import commands
from flask import Flask, jsonify

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


def sanitize_public_error(msg: str) -> str:
    """Never leak host paths, engine filenames, or C stack frames to Discord."""
    msg = str(msg or "")
    msg = re.sub(r"/[\w.\-:/\\]+", "", msg)
    msg = re.sub(r"[A-Za-z]:\\[\w.\\/]+", "", msg)
    msg = re.sub(r"\[string \"[^\"]*\"\]", "", msg)
    msg = re.sub(r"\[C\]:[^\n]*", "", msg)
    msg = re.sub(r"tools/[\w.\-]+", "", msg)
    msg = re.sub(r"dump\.luau|string_dump|RobloxFidelity", "", msg, flags=re.I)
    msg = re.sub(r"/opt/render[^\s]*", "", msg)
    msg = re.sub(r"\s+", " ", msg).strip(" :-\n")
    if not msg:
        return "dump failed"
    return msg[:300]


def ensure_lune() -> str:
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
        try:
            r = subprocess.run(
                [str(p), "--version"], capture_output=True, text=True, timeout=10
            )
            blob = ((r.stdout or "") + (r.stderr or "")).lower()
            if r.returncode == 0 or "lune" in blob:
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
            target = next(
                (n for n in names if Path(n).name == "lune" or Path(n).name.startswith("lune")),
                names[0],
            )
            out = BIN / "lune"
            out.write_bytes(zf.read(target))
            out.chmod(0o755)
        zpath.unlink(missing_ok=True)
        log("[lune] installed →", out)
        return str(out)
    except Exception as ex:
        raise RuntimeError("lune binary missing") from ex


def fetch_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        raise RuntimeError("url must start with http:// or https://")

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
    if "github.com" in raw and "/blob/" in raw:
        raw = raw.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

    req = urllib.request.Request(raw, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            data = resp.read()
    except urllib.error.HTTPError as ex:
        raise RuntimeError(f"fetch HTTP {ex.code}") from ex
    except urllib.error.URLError as ex:
        raise RuntimeError("fetch failed") from ex

    if len(data) > MAX_SOURCE:
        raise RuntimeError("remote file too large")
    text = data.decode("utf-8", errors="replace")
    if not text.strip():
        raise RuntimeError("remote returned empty body")
    return text


def run_dump(source: str) -> str:
    if not DUMP_ENGINE.is_file():
        raise RuntimeError("engine missing")

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
    elapsed = time.time() - t0

    stdout = (proc.stdout or "")
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

    # strip any accidental path leaks from engine stdout
    clean_lines = []
    for line in (output or "").splitlines():
        if re.search(r"/opt/render|tools/dump|/home/|/Users/", line):
            if line.strip().startswith("[NOTE]"):
                clean_lines.append("[NOTE] runtime stopped")
            continue
        if "[C]:" in line and "function" in line:
            continue
        clean_lines.append(line)
    output = "\n".join(clean_lines).strip()

    if not output.strip():
        raise RuntimeError("empty dump output")

    if not output.lstrip().startswith(BANNER.strip()):
        output = BANNER + "\n" + output
    log(f"[dump] {elapsed:.2f}s out={len(output)}b code={proc.returncode}")
    return output


CODEBLOCK_RE = re.compile(
    r"```(?:lua|luau|txt|text)?\s*\n(.*?)```",
    re.DOTALL | re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


async def extract_source(message: discord.Message) -> str:
    for att in message.attachments:
        if att.size and att.size > MAX_SOURCE:
            raise RuntimeError("file too large")
        data = await att.read()
        if len(data) > MAX_SOURCE:
            raise RuntimeError("file too large")
        return data.decode("utf-8", errors="replace")

    content = message.content or ""
    urls = URL_RE.findall(content)
    if urls:
        url = urls[0].rstrip(".,;>")
        log("[fetch]", url)
        return await asyncio.to_thread(fetch_url, url)

    m = CODEBLOCK_RE.search(content)
    if m:
        return m.group(1)

    lines = content.split("\n")
    if lines:
        first = re.sub(
            r"^[.\s]*(?:dump|d|get)\b", "", lines[0], count=1, flags=re.I
        ).strip()
        rest = "\n".join([first] + lines[1:]) if first else "\n".join(lines[1:])
    else:
        rest = content
    rest = rest.strip()
    if rest:
        return rest
    raise RuntimeError("attach a file/URL or send a code block")


# --- Flask keep-alive (UptimeRobot → GET /health) ---
flask_app = Flask(__name__)


@flask_app.get("/")
@flask_app.get("/health")
def health():
    return jsonify({"ok": True, "service": "wxz-dump-bot"})


def start_flask():
    port = int(os.environ.get("PORT", "10000") or "10000")
    log(f"[flask] health on 0.0.0.0:{port}")
    flask_app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


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
                name=".d",
            ),
        )
    except Exception as ex:
        log("[bot] presence:", ex)
    try:
        ensure_lune()
        log("[bot] lune ok")
    except Exception as ex:
        log("[bot] lune warn:", sanitize_public_error(ex))


@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    # only 3 commands — ignore everything else silently (no .help)
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.CommandInvokeError):
        err = sanitize_public_error(error.original)
    else:
        err = sanitize_public_error(error)
    try:
        await ctx.reply(f"dump failed: {err}", mention_author=False)
    except discord.HTTPException:
        pass


async def do_dump(ctx: commands.Context, *, silent: bool):
    """silent=True (.get) → file only, no caption / no status text left."""
    if ctx.author.bot:
        return

    status_msg = None
    if not silent:
        status_msg = await ctx.reply("dumping…", mention_author=False)

    try:
        source = await extract_source(ctx.message)
        if not source or not str(source).strip():
            raise RuntimeError("empty source")
        if len(source) > MAX_SOURCE:
            raise RuntimeError("source too large")

        output = await asyncio.to_thread(run_dump, source)

        tmp = tempfile.NamedTemporaryFile(
            prefix="wxz_", suffix=".txt", delete=False
        )
        try:
            tmp.write(output.encode("utf-8", errors="replace"))
            tmp.close()
            file = discord.File(tmp.name, filename="message.txt")
            if silent:
                await ctx.reply(file=file, mention_author=False)
            else:
                await ctx.reply(
                    content="skidding lol 😂",
                    file=file,
                    mention_author=False,
                )
            if status_msg:
                try:
                    await status_msg.delete()
                except discord.HTTPException:
                    pass
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
    except Exception as ex:
        err = sanitize_public_error(ex)
        if status_msg:
            await status_msg.edit(content=f"dump failed:\n```\n{err}\n```")
        else:
            # .get still needs a minimal error signal
            await ctx.reply(f"dump failed:\n```\n{err}\n```", mention_author=False)


@bot.command(name="dump")
async def cmd_dump(ctx: commands.Context):
    await do_dump(ctx, silent=False)


@bot.command(name="d")
async def cmd_d(ctx: commands.Context):
    await do_dump(ctx, silent=False)


@bot.command(name="get")
async def cmd_get(ctx: commands.Context):
    """Download / fetch URL (or attachment) → message.txt — NO dump."""
    if ctx.author.bot:
        return
    try:
        content = ctx.message.content or ""
        urls = URL_RE.findall(content)
        data = None
        name = "message.txt"

        if ctx.message.attachments:
            att = ctx.message.attachments[0]
            if att.size and att.size > MAX_SOURCE:
                raise RuntimeError("file too large")
            raw = await att.read()
            if len(raw) > MAX_SOURCE:
                raise RuntimeError("file too large")
            data = raw
            name = att.filename or "message.txt"
        elif urls:
            url = urls[0].rstrip(".,;>")
            log("[get]", url)
            text = await asyncio.to_thread(fetch_url, url)
            data = text.encode("utf-8", errors="replace")
        else:
            # raw text after .get
            lines = content.split("\n")
            first = re.sub(r"^[.\s]*get\b", "", lines[0], count=1, flags=re.I).strip() if lines else ""
            rest = "\n".join([first] + lines[1:]) if first else "\n".join(lines[1:] if lines else [])
            rest = rest.strip()
            if not rest:
                raise RuntimeError("usage: .get <url>  or attach a file")
            data = rest.encode("utf-8", errors="replace")

        tmp = tempfile.NamedTemporaryFile(prefix="wxz_get_", suffix=".txt", delete=False)
        try:
            tmp.write(data)
            tmp.close()
            await ctx.reply(file=discord.File(tmp.name, filename="message.txt"), mention_author=False)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
    except Exception as ex:
        await ctx.reply(f"get failed:\n```\n{sanitize_public_error(ex)}\n```", mention_author=False)


def main():
    if not TOKEN:
        log("ERROR: set DISCORD_TOKEN")
        sys.exit(1)
    if not DUMP_ENGINE.is_file():
        log("ERROR: engine missing")
        sys.exit(1)

    threading.Thread(target=start_flask, daemon=True).start()
    log("[bot] starting…")
    bot.run(TOKEN, log_handler=None)


if __name__ == "__main__":
    main()
