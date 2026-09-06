const COOKIE_NAME = "wowauth_config_secret";

export function getConfigSecret(): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${COOKIE_NAME}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

const SESSION_TTL_SECONDS = 24 * 60 * 60;

export function setConfigSecret(secret: string): void {
  // Set on / so it's attached to every request the SPA makes; expires after
  // 24h so the admin has to re-enter the secret periodically.
  document.cookie = `${COOKIE_NAME}=${encodeURIComponent(secret)}; path=/; max-age=${SESSION_TTL_SECONDS}; SameSite=Strict`;
}

export function clearConfigSecret(): void {
  document.cookie = `${COOKIE_NAME}=; path=/; max-age=0`;
}

export function isLoggedIn(): boolean {
  return getConfigSecret() !== null;
}
