# WXZ Dump Bot

Commands: `.dump` / `.d`

## Input
- Attachment (`.lua` / `.txt`)
- Raw URL (pastebin / github raw / pastefy / …) — browser headers
- Code block

## Output
- Reply file: **`message.txt`**
- Text: `skidding lol 😂`
- Banner: `-- This file was generated with xz at discord.gg/tqmaYsxGKm v0.1 --`
- Status: **Online** · Watching `.dump | .d`

## Render
```
DISCORD_TOKEN=<token>
Build: pip install -r requirements.txt
Start: python3 bot.py
```
Enable **Message Content Intent**.
