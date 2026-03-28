import type { DetectedRenderIncident, RenderMonitorServiceTarget } from "./types.js";

const TELEGRAM_MAX_LENGTH = 4096;

function escapeTelegramMarkdown(raw: string): string {
  // Telegram legacy Markdown requires escaping these characters to prevent
  // formatting corruption: _ * ` [ ]
  return raw
    .replaceAll("\\", "\\\\")
    .replaceAll("_", "\\_")
    .replaceAll("*", "\\*")
    .replaceAll("`", "\\`")
    .replaceAll("[", "\\[");
}

export function truncateForTelegram(text: string, maxLen = TELEGRAM_MAX_LENGTH): string {
  if (text.length <= maxLen) return text;
  const suffix = "\n\n… (truncated)";
  return text.slice(0, maxLen - suffix.length) + suffix;
}

export function buildIncidentAlertText(params: {
  incident: DetectedRenderIncident;
  incidentId: string;
  service: RenderMonitorServiceTarget;
  dedupeHint?: boolean;
}): string {
  const { incident, service } = params;
  const env = service.environment ? ` (${service.environment})` : "";
  const name = service.name ? ` · ${service.name}` : "";
  const detailsRaw = incident.details && Object.keys(incident.details).length
    ? JSON.stringify(incident.details)
    : null;
  const detailsJson = detailsRaw
    ? `\n\nDetails: ${escapeTelegramMarkdown(detailsRaw)}`
    : "";
  return [
    `🚨 Render incident: *${escapeTelegramMarkdown(incident.incidentType)}*`,
    `Service: *${escapeTelegramMarkdown(service.serviceId)}*${escapeTelegramMarkdown(name)}${escapeTelegramMarkdown(env)}`,
    `Incident ID: \`${escapeTelegramMarkdown(params.incidentId)}\``,
    `When: ${new Date(incident.createdAtMs).toISOString()}`,
    ``,
    escapeTelegramMarkdown(incident.summary),
    detailsJson,
  ]
    .join("\n")
    .trim();
}

export function resolveRenderDashboardLinks(serviceId: string): { service: string; logs: string } {
  const base = "https://dashboard.render.com";
  return {
    service: `${base}/services/${serviceId}`,
    logs: `${base}/services/${serviceId}/logs`,
  };
}

