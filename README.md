# WXZ Dump

Glass UI · VM string dump · **one-time dump tickets** · lune bundled (Linux x86_64).

## Run

```bash
chmod +x bin/lune
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 server.py
```

- UI: http://127.0.0.1:8765  
- Health (UptimeRobot): `/health`  
- Optional: `export WXZ_SECRET=long-random`

## One-time ticket (anti replay)

1. Client clicks **Run** → `POST /api/ticket` → `{ ticket, sig, ttl }`
2. Client `POST /api/dump` with `X-WXZ-Ticket` + `X-WXZ-Sig`
3. Server **consumes** ticket immediately (IP-bound, ~45s TTL)
4. Same curl / F12 replay → **401 ticket already used**

Stops reused API logs from console hooks. Does **not** stop someone using the site live.

Also: per-IP rate limits, soft ban, body cap 8MB, security headers.
