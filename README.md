# WXZ Dump

Modern glass UI + video background for **VM string dump** with a thick fake Roblox env.

No lupro required. Backend is **Flask** (easy health checks for UptimeRobot).

## Features

- Hooks: `loadstring` · `HttpGet` · `print`/`warn`
- Full `string.*` · `buffer` · `bit32` · `utf8` · base64/crypt
- Soft `Instance` / `game:GetService` / Signal
- Virtual clock + `task.wait`
- Static + runtime constant harvest
- Upload file or paste raw URL
- Health endpoint: `GET /health` (for UptimeRobot)

## Install Lune (Linux x86_64)

```bash
# pick a recent release from https://github.com/lune-org/lune/releases
LUNE_VER=0.10.4
curl -sL "https://github.com/lune-org/lune/releases/download/v${LUNE_VER}/lune-${LUNE_VER}-linux-x86_64.zip" -o /tmp/lune.zip
mkdir -p ~/bin
unzip -o /tmp/lune.zip -d /tmp/lune-extract
chmod +x /tmp/lune-extract/lune
mv /tmp/lune-extract/lune ~/bin/lune

# optional: system-wide
# sudo mv /tmp/lune-extract/lune /usr/local/bin/lune

export PATH="$HOME/bin:$PATH"
lune --version
```

Or point the server at a binary:

```bash
export LUNE_BIN=/path/to/lune
```

## Python deps

```bash
cd wxz-dump
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
export LUNE_BIN=~/bin/lune   # if not on PATH
export PORT=8765
python3 server.py
```

Open http://127.0.0.1:8765

### UptimeRobot

- Monitor type: **HTTP(s)**
- URL: `https://your-host/health` (or `/api/health`)
- Expected: JSON with `"ok": true` / `"status": "up"`

## CLI (no web)

```bash
cd tools
lune run string_dump.luau /path/to/obf.lua out.txt
```

## Layout

```
wxz-dump/
  index.html              # English glass UI
  server.py               # Flask app
  requirements.txt
  static/bg.mp4
  tools/
    string_dump.luau
    RobloxFidelity.luau
```
