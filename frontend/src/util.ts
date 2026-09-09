import { ApiError } from "./api";
import { clearConfigSecret } from "./auth";

export function escapeHtml(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

/** Surfaces API errors in an inline `.error` element; sends the user back
 * to login if the config secret was rejected. */
export function reportError(err: unknown, target: HTMLElement): void {
  const message = err instanceof Error ? err.message : String(err);
  if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
    clearConfigSecret();
    location.hash = "#/login";
    return;
  }
  target.textContent = message;
}
