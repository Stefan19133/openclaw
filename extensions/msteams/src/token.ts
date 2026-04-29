import type { MSTeamsConfig } from "../runtime-api.js";
import {
  hasConfiguredSecretInput,
  normalizeResolvedSecretInputString,
  normalizeSecretInputString,
} from "./secret-input.js";

export type MSTeamsCredentials = {
  appId: string;
  appPassword: string;
  tenantId: string;
};

export function hasConfiguredMSTeamsCredentials(cfg?: MSTeamsConfig): boolean {
  return Boolean(
    normalizeSecretInputString(cfg?.appId) &&
    hasConfiguredSecretInput(cfg?.appPassword) &&
    normalizeSecretInputString(cfg?.tenantId),
  );
}

export function resolveMSTeamsCredentials(cfg?: MSTeamsConfig): MSTeamsCredentials | undefined {
  const appId =
    normalizeSecretInputString(cfg?.appId) ||
    normalizeSecretInputString(process.env.MSTEAMS_APP_ID);
  // Plaintext and env must win before SecretRef: sync path cannot resolve refs, and
  // normalizeResolvedSecretInputString throws for unresolved Ref objects.
  const appPasswordPlain = normalizeSecretInputString(cfg?.appPassword);
  const appPasswordEnv = normalizeSecretInputString(process.env.MSTEAMS_APP_PASSWORD);
  let appPassword = appPasswordPlain || appPasswordEnv;
  if (!appPassword) {
    appPassword = normalizeResolvedSecretInputString({
      value: cfg?.appPassword,
      path: "channels.msteams.appPassword",
    });
  }
  const tenantId =
    normalizeSecretInputString(cfg?.tenantId) ||
    normalizeSecretInputString(process.env.MSTEAMS_TENANT_ID);

  if (!appId || !appPassword || !tenantId) {
    return undefined;
  }

  return { appId, appPassword, tenantId };
}
