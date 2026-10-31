# WXZ Dump

Web UI glass + video nền · **string dump** với **thick fake env** (hook VM).

**Không cần lupro.** Chỉ cần [Lune](https://lune-org.github.io/docs).

## Tính năng dump

- Hook `loadstring` / `HttpGet` / `print` / `warn`
- Full `string.*` · `buffer` · `bit32` · `utf8` · base64/crypt
- Soft `Instance` / `game:GetService` / Signal
- Virtual clock + `task.wait` (chạy VM không kẹt)
- Static + runtime harvest constants

## Chạy web

```bash
cd wxz-dump
pip install fastapi uvicorn python-multipart

# Cần binary lune:
#   mac/linux: https://github.com/lune-org/lune/releases
export LUNE_BIN=/path/to/lune   # hoặc để lune trên PATH

PORT=8765 python3 server.py
```

Mở http://127.0.0.1:8765

## CLI (không web)

```bash
cd tools
lune run string_dump.luau ../path/to/obf.lua out.txt
```

## Cấu trúc

```
wxz-dump/
  index.html
  server.py
  static/bg.mp4
  tools/
    string_dump.luau      # engine chính
    RobloxFidelity.luau   # thick number/env helpers
```
