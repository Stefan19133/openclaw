#!/usr/bin/env python3
"""Merge MS Teams channel config into ~/.openclaw/openclaw.json (used on VPS).

Omit `appPassword` in JSON: set `MSTEAMS_APP_PASSWORD` in `~/.openclaw/.env` and load it
via the gateway unit `EnvironmentFile` (or export in the service env). Core resolves the
password from the environment when the config field is absent.
"""
from __future__ import annotations

import json
from pathlib import Path

OPENCLAW_JSON = Path.home() / ".openclaw" / "openclaw.json"
def main() -> None:
    cfg = json.loads(OPENCLAW_JSON.read_text(encoding="utf-8"))
    # Use bundled msteams from the global openclaw package (avoid duplicate plugin id).
    cfg.setdefault("channels", {})["msteams"] = {
        "enabled": True,
        "appId": "b71cce40-504d-4f53-b5f6-6839f4e59cee",
        "tenantId": "3e31b2a0-b635-42d4-8063-0a2312893cc1",
        "webhook": {"port": 3979, "path": "/openclaw/api/messages"},
        "dmPolicy": "pairing",
        "groupPolicy": "allowlist",
    }
    OPENCLAW_JSON.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("ok: msteams merged into", OPENCLAW_JSON)


if __name__ == "__main__":
    main()
