const COOKIE_NAME = "wowauth_config_secret";

export function getConfigSecret(): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${COOKIE_NAME}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

export function setConfigSecret(secret: string): void {
  // Set on / so it's attached to every request the SPA makes; a year is
  // long enough that admins aren't re-pasting the secret every visit.
  document.cookie = `${COOKIE_NAME}=${encodeURIComponent(secret)}; path=/; max-age=31536000; SameSite=Strict`;
}

export function clearConfigSecret(): void {
  document.cookie = `${COOKIE_NAME}=; path=/; max-age=0`;
}

export function isLoggedIn(): boolean {
  return getConfigSecret() !== null;
}
