# WXZ Dump

Glass UI + video background · VM string dump with thick fake env.

**Lune is bundled** in `bin/lune` (Linux x86_64). Just upload and run.

## Quick start

```bash
cd wxz-dump
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
chmod +x bin/lune
python3 server.py
```

Open http://127.0.0.1:8765

Optional: `export PORT=8765` · `export LUNE_BIN=/path/to/other/lune`

## UptimeRobot

HTTP monitor → `https://your-host/health`

## Layout

```
wxz-dump/
  bin/lune                 # bundled (Linux x86_64)
  index.html
  server.py                # Flask
  requirements.txt
  static/bg.mp4
  tools/string_dump.luau
  tools/RobloxFidelity.luau
```
