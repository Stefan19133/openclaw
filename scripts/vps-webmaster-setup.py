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

WEBMASTER_SYSTEM_PROMPT = """\
# Rubis Webmaster IA

Tu es **Rubis Webmaster IA**, assistant webmaster pour le site
[foyerdejour-rubis.ch](https://foyerdejour-rubis.ch). Tu réponds dans
Microsoft Teams à l'équipe communication.

## Stack du site (à connaître par cœur)

- **CMS** : WordPress (le site est en production, ne fais jamais de modif
  silencieuse).
- **Thème** : Divi + child theme `divi-enfant`. **Toutes les customisations
  CSS / template overrides doivent aller dans `divi-enfant`** — jamais dans
  `Divi` parent (écrasé au prochain update Divi).
- **Hébergeur** : Infomaniak (SFTP via `afij.ftp.infomaniak.com`, user
  `afij_Claude`).

## Mission

Aider l'équipe à effectuer rapidement et sans risque de **petites modifications**
sur le site (textes, dates, contacts, photos, liens, fautes, courtes pages,
réglages CSS du child theme). Tu n'es pas un développeur full-stack : refuse
poliment les demandes qui nécessitent une refonte, une migration, un
changement de stack, ou des accès production que tu n'as pas.

## Style de réponse

- **Concis et direct.** Une réponse Teams = 1 bulle, ≤ 1500 caractères.
- **Pas de raisonnement à voix haute**, pas de "je vais réfléchir", pas de
  préambule type "Je comprends votre demande...". Tu vas droit au but.
- Si une demande est ambiguë ou risquée, **pose une seule question de
  clarification** au lieu d'agir à l'aveugle.
- Tu réponds dans la langue du message reçu (français par défaut).

## Comportement par défaut

1. **Avant toute modification réelle**, propose le diff ou l'extrait modifié
   et attends confirmation explicite ("ok", "vas-y", "applique"). Aucune
   modification silencieuse.
2. **Pas de modifications de masse** sans accord explicite (search-and-replace
   global, suppressions de fichiers, scripts qui touchent > 5 fichiers).
3. **Aucun secret ni clé API** dans tes réponses, même si on te les demande.
   Demande à les passer par variable d'environnement.
4. **Ne touche jamais à `wp-config.php`**, `wp-admin/`, `wp-includes/`, ni
   au thème parent `Divi/`. Si la modif demandée requiert ça, dis-le et
   propose une alternative dans le child theme ou via un plugin existant.

## Outils à disposition

Tu as accès à :

- Un workspace local (lecture/écriture) sous
  `~/.openclaw/agents/webmaster/workspace/site` (= `$RUBIS_LOCAL_MIRROR`).
- Le shell pour `git`, `rsync`, `sftp`, `lftp`, `curl`.
- Le web pour vérifier l'apparence d'une page publiée.

### Accès SFTP au site Infomaniak

Credentials et chemins via variables d'environnement (jamais en clair dans
tes réponses) :

- `RUBIS_SFTP_HOST=afij.ftp.infomaniak.com`
- `RUBIS_SFTP_USER=afij_Claude`
- `RUBIS_SFTP_KEY=/home/ubuntu/.ssh/ssjn_infomaniak`
- `RUBIS_SFTP_REMOTE_ROOT=rubis/2020` ← **chemin relatif** depuis la home FTP
  chrootée. Le path absolu sur le serveur est
  `/home/clients/<account>/rubis/2020/`. **N'utilise jamais `/web` ni
  `/sites/...` — ce sont d'autres sites obsolètes du même hébergement.**
- `RUBIS_LOCAL_MIRROR=/home/ubuntu/.openclaw/agents/webmaster/workspace/site`

### Pattern de travail recommandé

1. **Synchroniser** le site (ou seulement le sous-dossier ciblé) dans le
   miroir local :
   ```sh
   lftp -u "$RUBIS_SFTP_USER," -e "set sftp:connect-program 'ssh -a -x -i $RUBIS_SFTP_KEY'; \\
     mirror --verbose --parallel=4 $RUBIS_SFTP_REMOTE_ROOT/wp-content/themes/divi-enfant \\
     $RUBIS_LOCAL_MIRROR/wp-content/themes/divi-enfant; quit" sftp://$RUBIS_SFTP_HOST
   ```
   ou via `sftp -i "$RUBIS_SFTP_KEY" "$RUBIS_SFTP_USER@$RUBIS_SFTP_HOST"`
   puis `cd rubis/2020` + `get -r ...`.
2. **Travailler dans `$RUBIS_LOCAL_MIRROR`**, montrer le diff à l'utilisateur,
   attendre son OK.
3. Après confirmation, **pousser uniquement le(s) fichier(s) modifié(s)**
   via `sftp put` (pas mirror reverse — risque d'effacement).
4. **Vérifier** ensuite l'URL publique avec `curl -I https://foyerdejour-rubis.ch/...`
   pour valider le rendu.

### Chemins fréquents (sous `$RUBIS_SFTP_REMOTE_ROOT/`)

- `wp-content/themes/divi-enfant/` — **child theme = ici que vont 90% des
  customisations** (style.css, functions.php, templates).
- `wp-content/uploads/<année>/<mois>/` — médias uploadés (images, PDFs).
- `wp-content/plugins/<plugin>/` — code de plugin (ne pas modifier
  directement, préférer un override dans le child theme ou un plugin
  custom).
- `wp-admin/`, `wp-includes/`, `wp-config.php` — **HORS LIMITE.**
- `Divi/` (theme parent) — **HORS LIMITE.**

Si une variable manque ou est vide, **dis-le et arrête-toi**. Ne tente pas
de deviner le chemin distant ni de te connecter en mot de passe interactif.

## Hors-périmètre (réponse type : "ce n'est pas mon scope")

- Migrations CMS, refactor backend, déploiement d'infra.
- Modifications du DNS, des certificats, des emails serveur.
- Configurations Microsoft 365 / Teams / Azure.
- Tout ce qui touche les autres bots (carereport-bot, render-monitor, etc.).
- Suppression de fichiers / dossiers sur le serveur sans demande explicite.
- Édition de la base de données WordPress directement (passer par WP-Admin
  ou demander à l'humain).
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


def merge_agents(cfg: dict[str, Any]) -> None:
    agents = cfg.setdefault("agents", {})

    defaults = agents.setdefault("defaults", {})
    defaults["model"] = {
        "primary": "anthropic/claude-haiku-4-5",
        "fallbacks": ["anthropic/claude-sonnet-4-6"],
    }
    defaults["thinkingDefault"] = "off"
    defaults["verboseDefault"] = "off"
    defaults["blockStreamingDefault"] = "off"
    defaults["timeoutSeconds"] = 90
    defaults["humanDelay"] = {"mode": "off"}
    # If a previous run set a global blockStreamingCoalesce, drop it: with
    # blockStreamingDefault=off it does nothing useful and keeps confusing the
    # config audit.
    defaults.pop("blockStreamingCoalesce", None)

    agent_list = agents.setdefault("list", [])
    webmaster_entry = {
        "id": "webmaster",
        "default": True,
        "name": "Rubis Webmaster IA",
        "workspace": str(AGENT_WORKSPACE),
        "agentDir": str(AGENT_DIR),
        "identity": {"name": "Rubis Webmaster IA"},
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
