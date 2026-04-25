import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { OpenClawPluginApi, OpenClawPluginService } from "openclaw/plugin-sdk/core";

// ─── Config ──────────────────────────────────────────────────────────────────

type VpsTarget = {
  /** Friendly name shown in alerts. Defaults to the host. */
  name?: string;
  host: string;
  user: string;
  keyPath: string;
};

type VpsMonitorConfig = {
  enabled: boolean;
  targets: VpsTarget[];
  pollIntervalMinutes: number;
  dedupeTtlMinutes: number;
  telegramChatId: string;
  diskThresholdPct: number;
};

function env(name: string): string | null {
  const v = process.env[name]?.trim() ?? "";
  return v || null;
}

function envNum(name: string, fallback: number): number {
  const v = env(name);
  if (!v) return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function safeJsonParse<T>(raw: string | null): T | null {
  if (!raw) return null;
  try { return JSON.parse(raw) as T; } catch { return null; }
}

/**
 * Resolve VPS targets in priority order:
 * 1. `vps.targets` array in plugin config
 * 2. `VPS_SSH_TARGETS_JSON` env var (JSON array)
 * 3. Single-host fallback via `VPS_SSH_HOST` / `VPS_SSH_USER` / `VPS_SSH_KEY_PATH`
 *    (also accepts `VPS_SSH_HOST` as comma-separated list)
 */
function resolveVpsTargets(rootCfg: Record<string, unknown>): VpsTarget[] {
  const vpsCfg = (rootCfg.vps ?? {}) as Record<string, unknown>;

  // 1. Plugin config array
  if (Array.isArray(vpsCfg.targets)) {
    const out: VpsTarget[] = [];
    for (const item of vpsCfg.targets as Array<Record<string, unknown>>) {
      const host = typeof item?.host === "string" ? item.host.trim() : "";
      const keyPath = typeof item?.keyPath === "string" ? item.keyPath.trim() : "";
      if (!host || !keyPath) continue;
      out.push({
        host,
        keyPath,
        user: typeof item.user === "string" ? item.user.trim() || "ubuntu" : "ubuntu",
        name: typeof item.name === "string" ? item.name.trim() || undefined : undefined,
      });
    }
    if (out.length > 0) return out;
  }

  // 2. JSON env var
  const fromEnv = safeJsonParse<Array<Record<string, unknown>>>(env("VPS_SSH_TARGETS_JSON"));
  if (Array.isArray(fromEnv)) {
    const out: VpsTarget[] = [];
    for (const item of fromEnv) {
      const host = typeof item?.host === "string" ? item.host.trim() : "";
      const keyPath = typeof item?.keyPath === "string" ? item.keyPath.trim() : "";
      if (!host || !keyPath) continue;
      out.push({
        host,
        keyPath,
        user: typeof item.user === "string" ? item.user.trim() || "ubuntu" : "ubuntu",
        name: typeof item.name === "string" ? item.name.trim() || undefined : undefined,
      });
    }
    if (out.length > 0) return out;
  }

  // 3. Single-host (or comma-separated hosts) fallback
  const hostRaw = String(vpsCfg.host ?? env("VPS_SSH_HOST") ?? "");
  const user = String(vpsCfg.user ?? env("VPS_SSH_USER") ?? "ubuntu");
  const keyPath = String(vpsCfg.keyPath ?? env("VPS_SSH_KEY_PATH") ?? "");
  if (!hostRaw || !keyPath) return [];

  return hostRaw
    .split(",")
    .map((h) => h.trim())
    .filter(Boolean)
    .map((host) => ({ host, user, keyPath }));
}

export function loadVpsMonitorConfig(api: OpenClawPluginApi): VpsMonitorConfig {
  const root = (api.pluginConfig ?? {}) as Record<string, unknown>;
  const c = ((root.vps ?? {}) as Record<string, unknown>);

  const targets = resolveVpsTargets(root);

  const pollIntervalMinutes =
    (typeof c.pollIntervalMinutes === "number" ? c.pollIntervalMinutes : 0) ||
    envNum("VPS_SSH_POLL_INTERVAL_MINUTES", 5);
  const dedupeTtlMinutes =
    (typeof c.dedupeTtlMinutes === "number" ? c.dedupeTtlMinutes : 0) ||
    envNum("VPS_SSH_DEDUPE_TTL_MINUTES", 60);
  const diskThresholdPct =
    (typeof c.diskThresholdPct === "number" ? c.diskThresholdPct : 0) ||
    envNum("VPS_DISK_THRESHOLD_PCT", 85);

  const telegramChatId =
    String(c.telegramChatId ?? "") ||
    env("TELEGRAM_CHAT_ID") ||
    env("VPS_TELEGRAM_CHAT_ID") ||
    "";

  const enabled =
    c.enabled !== false &&
    targets.length > 0 &&
    (c.enabled === true || env("VPS_MONITOR_ENABLED") !== "false");

  return { enabled, targets, pollIntervalMinutes, dedupeTtlMinutes, telegramChatId, diskThresholdPct };
}

// ─── SSH ─────────────────────────────────────────────────────────────────────

function sshExec(params: {
  host: string;
  user: string;
  keyPath: string;
  command: string;
  timeoutMs?: number;
}): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const args = [
      "-i", params.keyPath,
      "-o", "StrictHostKeyChecking=no",
      "-o", "ConnectTimeout=10",
      "-o", "BatchMode=yes",
      `${params.user}@${params.host}`,
      params.command,
    ];
    execFile("ssh", args, { timeout: params.timeoutMs ?? 30_000 }, (err, stdout, stderr) => {
      if (err && !stdout.trim()) {
        reject(new Error(`${err.message}\n${stderr}`));
      } else {
        resolve({ stdout: stdout ?? "", stderr: stderr ?? "" });
      }
    });
  });
}

// ─── State ───────────────────────────────────────────────────────────────────

type VpsMonitorState = {
  version: 1;
  updatedAtMs: number;
  /** fingerprint → timestamp when first alerted */
  alertedFingerprints: Record<string, number>;
};

function emptyVpsState(): VpsMonitorState {
  return { version: 1, updatedAtMs: Date.now(), alertedFingerprints: {} };
}

async function loadVpsState(stateDir: string): Promise<VpsMonitorState> {
  try {
    const raw = await readFile(join(stateDir, "vps-state.json"), "utf8");
    const parsed = JSON.parse(raw) as VpsMonitorState;
    return parsed.version === 1 ? parsed : emptyVpsState();
  } catch {
    return emptyVpsState();
  }
}

async function saveVpsState(stateDir: string, state: VpsMonitorState): Promise<void> {
  await mkdir(stateDir, { recursive: true });
  await writeFile(join(stateDir, "vps-state.json"), JSON.stringify(state, null, 2), "utf8");
}

function pruneVpsState(state: VpsMonitorState, nowMs: number, ttlMinutes: number): VpsMonitorState {
  const maxAgeMs = ttlMinutes * 60_000;
  const kept: Record<string, number> = {};
  for (const [fp, alertedAt] of Object.entries(state.alertedFingerprints)) {
    if (nowMs - alertedAt <= maxAgeMs) kept[fp] = alertedAt;
  }
  return { ...state, alertedFingerprints: kept, updatedAtMs: nowMs };
}

function fp(data: string): string {
  return createHash("sha256").update(data).digest("hex").slice(0, 16);
}

// ─── Telegram ────────────────────────────────────────────────────────────────

async function sendTelegramAlert(params: {
  api: OpenClawPluginApi;
  chatId: string;
  text: string;
}): Promise<void> {
  const send = params.api.runtime?.channel?.telegram?.sendMessageTelegram;
  if (!send) {
    params.api.logger.warn?.("vps-monitor: telegram runtime unavailable");
    return;
  }
  await send(params.chatId, params.text.slice(0, 4096), { silent: false, textMode: "markdown" });
}

// ─── Probes ──────────────────────────────────────────────────────────────────

type VpsAlert = { fingerprint: string; text: string };

function targetLabel(t: VpsTarget): string {
  return t.name ? `${t.name} (${t.host})` : t.host;
}

/**
 * Patterns we deliberately ignore in journal output. These are recurring
 * benign log lines (port scanners hitting sshd, expected probes from
 * monitoring systems, etc.) that would otherwise spam Telegram.
 *
 * Match anywhere in the line, case-insensitive.
 */
const JOURNAL_NOISE_PATTERNS: RegExp[] = [
  // SSH connection-attempt noise from port scanners hitting :22 — extremely
  // common on any internet-facing VPS, never indicates a real problem.
  /sshd\[.*kex_protocol_error/i,
  /sshd\[.*kex_exchange_identification/i,
  /sshd\[.*Connection reset by peer/i,
  /sshd\[.*Connection closed by .* preauth/i,
  /sshd\[.*Bad protocol version identification/i,
  /sshd\[.*banner exchange/i,
  /sshd\[.*invalid user/i,
];

function isNoiseLine(line: string): boolean {
  return JOURNAL_NOISE_PATTERNS.some((re) => re.test(line));
}

/** Fetch recent error-priority journal entries. Falls back to syslog grep. */
async function probeJournalErrors(
  target: VpsTarget,
  sinceMinutes: number,
): Promise<VpsAlert[]> {
  const cmd = [
    `journalctl -p err -n 20 --since "${sinceMinutes} minutes ago" --no-pager -o short 2>/dev/null`,
    `|| grep -iE "(error|critical|fatal|panic)" /var/log/syslog 2>/dev/null | tail -n 20`,
    `|| true`,
  ].join(" ");
  const { stdout } = await sshExec({ ...target, command: cmd });
  const lines = stdout
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 15 && !l.startsWith("--") && !/^Hint:/.test(l))
    .filter((l) => !isNoiseLine(l));

  const label = targetLabel(target);
  return lines.map((line) => {
    const escaped = line.replace(/[_*`[\]]/g, "\\$&");
    return {
      fingerprint: fp(`${target.host}:journal:${line}`),
      text: [
        `🔴 *VPS error* \`${label}\``,
        ``,
        `\`\`\``,
        escaped.slice(0, 900),
        `\`\`\``,
      ].join("\n"),
    };
  });
}

/**
 * Systemd units we tolerate in `failed` state. cloud-init's final stage
 * is a known false positive on most cloud images (it runs once at first
 * boot and reports failed afterwards on some providers).
 */
const FAILED_UNIT_NOISE: string[] = [
  "cloud-final.service",
  "cloud-init.service",
];

/** List systemd units currently in failed state. */
async function probeFailedUnits(target: VpsTarget): Promise<VpsAlert[]> {
  const cmd = `systemctl list-units --state=failed --no-legend --plain 2>/dev/null || true`;
  const { stdout } = await sshExec({ ...target, command: cmd });
  const units = stdout
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.includes("failed") || l.includes(".service"))
    .filter((l) => !FAILED_UNIT_NOISE.some((noise) => l.startsWith(noise)));

  if (units.length === 0) return [];

  const label = targetLabel(target);
  const body = units.join("\n").slice(0, 800).replace(/[_*`[\]]/g, "\\$&");
  return [{
    fingerprint: fp(`${target.host}:units:${units.join(",")}`),
    text: [
      `⚠️ *Failed systemd units* on \`${label}\``,
      ``,
      `\`\`\``,
      body,
      `\`\`\``,
    ].join("\n"),
  }];
}

/** Alert when any filesystem exceeds the configured threshold. */
async function probeDiskUsage(target: VpsTarget, threshold: number): Promise<VpsAlert[]> {
  const cmd = `df --output=pcent,target 2>/dev/null | tail -n +2 || true`;
  const { stdout } = await sshExec({ ...target, command: cmd });
  const label = targetLabel(target);
  const alerts: VpsAlert[] = [];
  for (const line of stdout.split("\n")) {
    const m = line.match(/^\s*(\d+)%\s+(.+)/);
    if (!m) continue;
    const pct = parseInt(m[1], 10);
    const mount = m[2].trim();
    if (pct < threshold) continue;
    // Bucket to nearest 5 % so we don't re-alert every tick while slowly filling.
    alerts.push({
      fingerprint: fp(`${target.host}:disk:${mount}:${Math.floor(pct / 5) * 5}`),
      text: `💾 *Disk ${pct}%* on \`${label}\` (mount: \`${mount}\`)`,
    });
  }
  return alerts;
}

// ─── Service ─────────────────────────────────────────────────────────────────

export function createVpsMonitorService(api: OpenClawPluginApi): OpenClawPluginService {
  let interval: ReturnType<typeof setInterval> | null = null;
  let state: VpsMonitorState | null = null;
  let cfg: VpsMonitorConfig | null = null;

  return {
    id: "vps-monitor",
    async start(ctx) {
      cfg = loadVpsMonitorConfig(api);
      if (!cfg.enabled) {
        api.logger.info?.("vps-monitor: disabled. Set VPS_SSH_KEY_PATH (and VPS_SSH_HOST) to enable.");
        return;
      }
      if (!cfg.telegramChatId) {
        api.logger.warn?.("vps-monitor: TELEGRAM_CHAT_ID missing — alerts will not be sent.");
      }

      state = await loadVpsState(ctx.stateDir);
      const pollMs = Math.max(60_000, Math.round(cfg.pollIntervalMinutes * 60_000));

      const tickOneTarget = async (target: VpsTarget, nowMs: number): Promise<VpsAlert[]> => {
        const [journal, units, disk] = await Promise.allSettled([
          probeJournalErrors(target, cfg!.pollIntervalMinutes + 1),
          probeFailedUnits(target),
          probeDiskUsage(target, cfg!.diskThresholdPct),
        ]);
        const alerts: VpsAlert[] = [];
        const label = targetLabel(target);
        if (journal.status === "fulfilled") alerts.push(...journal.value);
        else api.logger.warn?.(`vps-monitor[${label}]: journal probe: ${String((journal.reason as Error)?.message ?? journal.reason)}`);
        if (units.status === "fulfilled") alerts.push(...units.value);
        else api.logger.warn?.(`vps-monitor[${label}]: units probe: ${String((units.reason as Error)?.message ?? units.reason)}`);
        if (disk.status === "fulfilled") alerts.push(...disk.value);
        else api.logger.warn?.(`vps-monitor[${label}]: disk probe: ${String((disk.reason as Error)?.message ?? disk.reason)}`);
        return alerts;
      };

      const tick = async () => {
        if (!cfg || !state) return;
        const nowMs = Date.now();
        state = pruneVpsState(state, nowMs, cfg.dedupeTtlMinutes);

        // Fan out across all configured targets in parallel.
        const perTarget = await Promise.all(
          cfg.targets.map((t) => tickOneTarget(t, nowMs).catch((err) => {
            api.logger.error?.(`vps-monitor[${targetLabel(t)}]: tick error: ${String((err as Error)?.message ?? err)}`);
            return [] as VpsAlert[];
          })),
        );
        const allAlerts = perTarget.flat();

        for (const alert of allAlerts) {
          if (state.alertedFingerprints[alert.fingerprint]) continue;
          if (cfg.telegramChatId) {
            await sendTelegramAlert({ api, chatId: cfg.telegramChatId, text: alert.text });
          }
          state = {
            ...state,
            alertedFingerprints: { ...state.alertedFingerprints, [alert.fingerprint]: nowMs },
            updatedAtMs: nowMs,
          };
        }

        await saveVpsState(ctx.stateDir, state);
      };

      await tick().catch((err) => {
        api.logger.error?.(`vps-monitor: initial tick failed: ${String((err as Error)?.message ?? err)}`);
      });

      interval = setInterval(() => {
        tick().catch((err) => {
          api.logger.error?.(`vps-monitor: tick failed: ${String((err as Error)?.message ?? err)}`);
        });
      }, pollMs);
      interval.unref?.();

      const summary = cfg.targets.map((t) => targetLabel(t)).join(", ");
      api.logger.info?.(
        `vps-monitor: started (targets=[${summary}], pollIntervalMinutes=${cfg.pollIntervalMinutes}).`,
      );
    },

    async stop(ctx) {
      if (interval) {
        clearInterval(interval);
        interval = null;
      }
      if (state) {
        await saveVpsState(ctx.stateDir, state).catch(() => undefined);
      }
      state = null;
      cfg = null;
    },
  };
}
