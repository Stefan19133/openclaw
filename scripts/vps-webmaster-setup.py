#!/usr/bin/env python3
"""Configure the "Rubis Webmaster IA" agent on the VPS for fast, single-shot Teams replies.

What this script does (idempotent):

1. Updates ``~/.openclaw/openclaw.json``:
   - Defines a dedicated ``webmaster`` agent with a focused workspace + agentDir
   - Routes inbound Teams traffic to that agent via ``bindings``
   - Tunes ``agents.defaults`` for low-latency Teams delivery:
       * model: anthropic/claude-haiku-4-5 (fast) with sonnet-4-6 fallback
       * thinkingDefault: "off"
       * blockStreamingDefault: "off"        (send one consolidated bubble, not chunks)
       * timeoutSeconds: 90                  (under the 120s ACPX idle timeout)
       * humanDelay.mode: "off"              (no artificial pauses)
   - Removes the per-channel ``blockStreamingCoalesce`` on msteams (the chunk
     pacing was producing multiple bubbles + the streamed-then-stopped UI in
     Teams) so msteams sends a single message at end-of-turn.

2. Creates ``~/.openclaw/agents/webmaster/`` with ``AGENTS.md`` (system-prompt-like
   profile) + an empty workspace dir. Existing AGENTS.md is left untouched if
   already customized; a ``.bak`` is written before any rewrite.

3. Adds the Infomaniak SFTP defaults to ``~/.openclaw/.env`` so the agent can
   read them via the gateway unit's ``EnvironmentFile``. Existing values in the
   .env are preserved (only missing keys are added). Critical keys checked:
   ``MSTEAMS_APP_PASSWORD``, ``ANTHROPIC_API_KEY``, ``RUBIS_SFTP_*``.

4. Verifies the Infomaniak SSH key permissions (chmod 600 if needed).

5. Restarts the user gateway: ``systemctl --user restart openclaw-gateway``.

Run on the VPS as the user that owns ``~/.openclaw``:

    python3 vps-webmaster-setup.py

Dry-run (no writes):

    python3 vps-webmaster-setup.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

HOME = Path.home()
OPENCLAW_DIR = HOME / ".openclaw"
OPENCLAW_JSON = OPENCLAW_DIR / "openclaw.json"
AGENT_ROOT = OPENCLAW_DIR / "agents" / "webmaster"
AGENT_DIR = AGENT_ROOT / "agent"
AGENT_WORKSPACE = AGENT_ROOT / "workspace"
AGENTS_MD = AGENT_WORKSPACE / "AGENTS.md"

WEBMASTER_SYSTEM_PROMPT = """# Rubis Webmaster IA

Tu es le webmaster du site WordPress https://foyerdejour-rubis.ch.
Theme : Divi (parent, NE PAS TOUCHER) + divi-enfant (child, ici les
customisations CSS/PHP custom).

Réponds en français, **concis**, ≤ 1000 caractères. Une bulle Teams.
Pas de raisonnement à voix haute. Avant toute modif, montre l'extrait
ou le diff et attends 'ok' / 'vas-y'. Refuse poliment toute demande
hors scope (DNS, refonte, autre site).

## Édition : deux voies

### 1) WordPress REST API + Application Password (méthode PRINCIPALE)

Pour éditer **posts, pages, médias, menus**, utilise l'API REST
WordPress avec Basic Auth via Application Password. C'est plus rapide
et sûr que SFTP, et ne risque pas de casser le thème.

Variables d'env (jamais en clair) :
- RUBIS_WP_BASE          = https://foyerdejour-rubis.ch/wp-json
- RUBIS_WP_USER          = admin WordPress
- RUBIS_WP_APP_PASSWORD  = mot de passe d'application

Pattern :

    curl -u "$RUBIS_WP_USER:$RUBIS_WP_APP_PASSWORD" \
         -H "Content-Type: application/json" \
         "$RUBIS_WP_BASE/wp/v2/pages?search=accueil&per_page=5"

Endpoints utiles :
- GET  /wp/v2/pages?search=...   ou /posts?search=...
- GET  /wp/v2/pages/<id>?context=edit   pour le contenu éditable
- POST /wp/v2/pages/<id>          (body {"content": "..."}) pour modifier
- GET  /wp/v2/media               pour les médias
- GET  /wp/v2/users/me            pour vérifier l'auth

### 2) SFTP (pour les fichiers thème / customisations CSS/PHP)

Quand l'édition demande un fichier hors REST API (style.css du child
theme, functions.php, template PHP), passe par SFTP :

- Host : afij.ftp.infomaniak.com / User : afij_Claude
- Key  : ~/.ssh/ssjn_infomaniak
- Root : rubis/2020 (relatif, depuis la home FTP chrootée)
- Child theme : rubis/2020/wp-content/themes/divi-enfant/

Workflow : sftp get → montre le diff → attends 'ok' → sftp put.

## Hors limite

- wp-config.php, wp-admin/, wp-includes/, Divi/ parent theme.
- DNS, certificats, emails serveur, autres bots.
- Édition directe de la base de données.
- Suppression sans demande explicite.
"""


def log(msg: str) -> None:
    print(f"[vps-webmaster-setup] {msg}")


def load_config() -> dict[str, Any]:
    if not OPENCLAW_JSON.exists():
        log(f"creating new {OPENCLAW_JSON}")
        return {}
    return json.loads(OPENCLAW_JSON.read_text(encoding="utf-8"))


def write_config(cfg: dict[str, Any], dry_run: bool) -> None:
    payload = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
    if dry_run:
        log(f"[dry-run] would write {OPENCLAW_JSON} ({len(payload)} bytes)")
        return
    if OPENCLAW_JSON.exists():
        backup = OPENCLAW_JSON.with_suffix(".json.bak")
        shutil.copy2(OPENCLAW_JSON, backup)
        log(f"backup written to {backup}")
    OPENCLAW_JSON.write_text(payload, encoding="utf-8")
    log(f"wrote {OPENCLAW_JSON}")


def ensure_agents_md(dry_run: bool) -> None:
    for d in (AGENT_DIR, AGENT_WORKSPACE):
        if dry_run:
            log(f"[dry-run] would mkdir -p {d}")
        else:
            d.mkdir(parents=True, exist_ok=True)

    if AGENTS_MD.exists():
        existing = AGENTS_MD.read_text(encoding="utf-8")
        if existing.strip() == WEBMASTER_SYSTEM_PROMPT.strip():
            log(f"AGENTS.md already up-to-date at {AGENTS_MD}")
            return
        backup = AGENTS_MD.with_suffix(".md.bak")
        if dry_run:
            log(f"[dry-run] would back up existing {AGENTS_MD} -> {backup}")
        else:
            shutil.copy2(AGENTS_MD, backup)
            log(f"backed up existing AGENTS.md -> {backup}")

    if dry_run:
        log(f"[dry-run] would write {AGENTS_MD} ({len(WEBMASTER_SYSTEM_PROMPT)} chars)")
        return
    AGENTS_MD.write_text(WEBMASTER_SYSTEM_PROMPT, encoding="utf-8")
    log(f"wrote {AGENTS_MD}")


PLUGINS_DISABLED_FOR_WEBMASTER: tuple[str, ...] = (
    # The webmaster bot only needs acpx (agent runtime), msteams (channel),
    # bonjour (mandatory advertising), and optionally telegram. The bundled
    # plugins below are loaded by default but unused here, and each adds
    # cold-start cost to the gateway boot AND the per-message dispatch.
    "browser",
    "device-pair",
    "memory-core",
    "phone-control",
    "talk-voice",
)


def merge_plugin_entries(cfg: dict[str, Any]) -> None:
    plugins = cfg.setdefault("plugins", {})
    entries = plugins.setdefault("entries", {})
    for name in PLUGINS_DISABLED_FOR_WEBMASTER:
        entry = entries.setdefault(name, {})
        entry["enabled"] = False


def merge_agents(cfg: dict[str, Any]) -> None:
    agents = cfg.setdefault("agents", {})

    defaults = agents.setdefault("defaults", {})
    # Use Haiku 4.5 alone — Sonnet 4.6 fallback was actually slower than Haiku
    # under timeout, so failover made the user-visible failure mode worse.
    defaults["model"] = {"primary": "anthropic/claude-haiku-4-5"}
    defaults["thinkingDefault"] = "off"
    defaults["verboseDefault"] = "off"
    defaults["blockStreamingDefault"] = "off"
    # 180s instead of 90s — pi-agent's multi-tool reasoning can chain several
    # Haiku calls + REST round-trips, and the cap was triggering even on
    # legitimate single-question turns.
    defaults["timeoutSeconds"] = 180
    defaults["humanDelay"] = {"mode": "off"}
    # Skip openclaw's bootstrap (which would inline SOUL.md / USER.md / etc.
    # into every prompt). The lean AGENTS.md alone is enough.
    defaults["skipBootstrap"] = True
    # Drop legacy keys we want to make sure aren't carried over from older runs.
    defaults.pop("blockStreamingCoalesce", None)
    defaults.pop("contextTokens", None)
    defaults.pop("compaction", None)

    agent_list = agents.setdefault("list", [])
    webmaster_entry = {
        "id": "webmaster",
        "default": True,
        "name": "Rubis Webmaster IA",
        "workspace": str(AGENT_WORKSPACE),
        "agentDir": str(AGENT_DIR),
        "identity": {"name": "Rubis Webmaster IA"},
        # Lean tool surface for the webmaster: read/write/edit on the local
        # mirror (workspace/site), exec for curl (WP REST API) and sftp/lftp.
        # Drops web_search, web_fetch, browser, process, etc. — those add
        # ~10 KB to the system prompt for no benefit here.
        "tools": {"allow": ["read", "write", "edit", "exec"]},
    }

    # Replace any existing webmaster entry, preserve the rest.
    new_list = [e for e in agent_list if not (isinstance(e, dict) and e.get("id") == "webmaster")]
    # Mark webmaster as default; clear "default" from siblings to avoid two defaults.
    for e in new_list:
        if isinstance(e, dict) and e.get("default") is True:
            e["default"] = False
    new_list.insert(0, webmaster_entry)
    agents["list"] = new_list


def merge_bindings(cfg: dict[str, Any]) -> None:
    bindings = cfg.setdefault("bindings", [])
    target = {"agentId": "webmaster", "match": {"channel": "msteams"}}
    # De-dup any existing msteams binding, then prepend ours.
    bindings = [
        b
        for b in bindings
        if not (isinstance(b, dict) and b.get("match", {}).get("channel") == "msteams"
                and not b.get("match", {}).get("peer"))
    ]
    bindings.insert(0, target)
    cfg["bindings"] = bindings


def merge_msteams(cfg: dict[str, Any]) -> None:
    channels = cfg.setdefault("channels", {})
    msteams = channels.setdefault("msteams", {})
    # Preserve appId / tenantId / dmPolicy / allowFrom if already present.
    msteams.setdefault("enabled", True)
    msteams.setdefault("appId", "b71cce40-504d-4f53-b5f6-6839f4e59cee")
    msteams.setdefault("tenantId", "3e31b2a0-b635-42d4-8063-0a2312893cc1")
    webhook = msteams.setdefault("webhook", {})
    webhook.setdefault("port", 3979)
    webhook.setdefault("path", "/openclaw/api/messages")
    msteams.setdefault("dmPolicy", "pairing")
    msteams.setdefault("groupPolicy", "allowlist")

    # Critical for the "Cette réponse a été arrêtée" symptom: drop the chunked
    # streaming pacing on Teams. With blockStreamingDefault=off the agent
    # generates the full reply, then we send it as a single Bot Framework
    # activity. No more half-streamed bubbles, no more stop-button UI.
    msteams.pop("blockStreamingCoalesce", None)
    msteams.pop("streaming", None)
    msteams.pop("chunkMode", None)


RUBIS_ENV_DEFAULTS: dict[str, str] = {
    # WordPress REST API (preferred edit path) — user must fill the password
    # by generating an Application Password in WP-Admin → Users → Profile.
    "RUBIS_WP_BASE": "https://foyerdejour-rubis.ch/wp-json",
    "RUBIS_WP_USER": "__SET_ME_WP_USERNAME__",
    "RUBIS_WP_APP_PASSWORD": "__SET_ME_IN_WP_ADMIN__",
    # SFTP (fallback for theme files etc.)
    "RUBIS_SFTP_HOST": "afij.ftp.infomaniak.com",
    "RUBIS_SFTP_USER": "afij_Claude",
    "RUBIS_SFTP_KEY": str(HOME / ".ssh" / "ssjn_infomaniak"),
    # Relative path from the FTP user's chroot home. Absolute on the server
    # is /home/clients/<account>/rubis/2020/. Verified via direct SFTP listing
    # against afij.ftp.infomaniak.com — the live foyerdejour-rubis.ch docroot
    # has wp-content modified hourly while /web/ and /sites/* are stale.
    "RUBIS_SFTP_REMOTE_ROOT": "rubis/2020",
    "RUBIS_LOCAL_MIRROR": str(AGENT_WORKSPACE / "site"),
}


def parse_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip().strip('"').strip("'")
    return out


def render_env_file(existing: dict[str, str]) -> str:
    """Merge defaults + existing, preserving any user overrides; emit sorted lines."""
    merged: dict[str, str] = {}
    merged.update(existing)
    for key, val in RUBIS_ENV_DEFAULTS.items():
        merged.setdefault(key, val)
    lines: list[str] = []
    for key in sorted(merged):
        lines.append(f"{key}={merged[key]}")
    return "\n".join(lines) + "\n"


def ensure_env_file(dry_run: bool) -> None:
    env_path = OPENCLAW_DIR / ".env"
    existing = parse_env_file(env_path)
    new_text = render_env_file(existing)

    missing_critical = [
        key
        for key in ("MSTEAMS_APP_PASSWORD", "ANTHROPIC_API_KEY")
        if key not in existing and key not in os.environ
    ]
    for key in missing_critical:
        log(f"warning: {key} not present in {env_path} nor environment")

    if env_path.exists() and env_path.read_text(encoding="utf-8") == new_text:
        log(f"{env_path} already has all RUBIS_* vars")
        return
    if dry_run:
        log(f"[dry-run] would update {env_path} (RUBIS_SFTP_* defaults)")
        return
    if env_path.exists():
        backup = env_path.with_suffix(".env.bak")
        shutil.copy2(env_path, backup)
        log(f"backup written to {backup}")
    OPENCLAW_DIR.mkdir(parents=True, exist_ok=True)
    env_path.write_text(new_text, encoding="utf-8")
    try:
        env_path.chmod(0o600)
    except OSError:
        pass
    log(f"wrote {env_path} with RUBIS_SFTP_* defaults")


def check_ssh_key(dry_run: bool) -> None:
    key_path = Path(RUBIS_ENV_DEFAULTS["RUBIS_SFTP_KEY"]).expanduser()
    if key_path.exists():
        try:
            mode = key_path.stat().st_mode & 0o777
            if mode not in (0o600, 0o400):
                if dry_run:
                    log(f"[dry-run] would chmod 600 {key_path} (currently {oct(mode)})")
                else:
                    key_path.chmod(0o600)
                    log(f"chmod 600 {key_path}")
        except OSError as exc:
            log(f"warning: cannot stat {key_path}: {exc}")
        return
    log(
        f"warning: {key_path} does not exist. Drop the Infomaniak SSH key there "
        "(chmod 600), or set RUBIS_SFTP_KEY in ~/.openclaw/.env to the right path."
    )


def restart_gateway(dry_run: bool) -> None:
    cmd = ["systemctl", "--user", "restart", "openclaw-gateway"]
    if dry_run:
        log(f"[dry-run] would run: {' '.join(cmd)}")
        return
    log(f"running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        log("systemctl not available; restart the gateway manually")
    except subprocess.CalledProcessError as exc:
        log(f"systemctl failed (exit {exc.returncode}); restart the gateway manually")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="show changes without writing")
    parser.add_argument(
        "--no-restart",
        action="store_true",
        help="skip systemctl --user restart openclaw-gateway",
    )
    args = parser.parse_args()

    if "MSTEAMS_APP_PASSWORD" not in os.environ:
        env_file = OPENCLAW_DIR / ".env"
        if env_file.exists() and "MSTEAMS_APP_PASSWORD" in env_file.read_text(encoding="utf-8"):
            log(f"MSTEAMS_APP_PASSWORD found in {env_file} (loaded by the gateway unit)")
        else:
            log(f"warning: MSTEAMS_APP_PASSWORD not in env nor in {env_file}")

    cfg = load_config()
    merge_agents(cfg)
    merge_bindings(cfg)
    merge_msteams(cfg)
    merge_plugin_entries(cfg)
    write_config(cfg, dry_run=args.dry_run)
    ensure_agents_md(dry_run=args.dry_run)
    ensure_env_file(dry_run=args.dry_run)
    check_ssh_key(dry_run=args.dry_run)
    if not args.no_restart:
        restart_gateway(dry_run=args.dry_run)

    log("done. Send a Teams message to the bot to verify the new flow.")
    log("expected: < 5s before reply starts, single bubble, no 'arrêtée' message.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
