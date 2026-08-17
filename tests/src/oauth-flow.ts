// tests/src/oauth-flow.ts
//
// Drives the actual browser-redirect dance a real end user goes through,
// using manual-redirect fetches instead of a browser -- the TypeScript
// equivalent of "open the printed URL in a browser" from
// docs/examples/DEFAULT.md steps 4-5. Talks to a real, running wowauth
// instance (BASE_URL) and whatever MockProvider a test wired up as the app's
// auth_url/token_url.
import { createHash, randomBytes } from "node:crypto";
import { BASE_URL } from "./test-env.ts";

export const DUMMY_REDIRECT_URI = "https://example.com/oauth-callback";

function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function generatePkcePair(): { verifier: string; challenge: string } {
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

export function randomState(): string {
  return randomBytes(16).toString("hex");
}

/** Follows exactly one redirect hop, returning the Location header. Throws if the
 *  response isn't a redirect, so a wrong-turn in the flow fails loudly at the hop
 *  where it actually went wrong instead of surfacing as a confusing later assertion. */
export function nextHop(res: Response): string {
  if (res.status < 300 || res.status >= 400) {
    throw new Error(`expected a redirect (3xx), got ${res.status}: ${res.statusText}`);
  }
  const location = res.headers.get("location");
  if (!location) throw new Error("redirect response had no Location header");
  return location;
}

export interface AuthorizeParams {
  appId: string;
  redirectUri?: string;
  accountHint?: string;
  scope?: string;
  codeChallengeMethod?: string;
}

/** Hits GET /{app_id}/oauth/auth directly (the first hop only) -- for tests that care
 *  about wowauth's own response to a bad request, before any redirect chasing. */
export async function startAuthorize(params: AuthorizeParams) {
  const { verifier, challenge } = generatePkcePair();
  const state = randomState();
  const redirectUri = params.redirectUri ?? DUMMY_REDIRECT_URI;

  const url = new URL(`${BASE_URL}/${params.appId}/oauth/auth`);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", params.codeChallengeMethod ?? "S256");
  if (params.accountHint) url.searchParams.set("account_hint", params.accountHint);
  if (params.scope) url.searchParams.set("scope", params.scope);

  const res = await fetch(url, { redirect: "manual" });
  return { res, verifier, state, redirectUri };
}

export interface CompletedAuthorization {
  verifier: string;
  state: string;
  redirectUri: string;
  /** The query params wowauth's callback finally redirected the caller back with --
   *  either {code, state} on success or {error, error_description, state} on failure. */
  finalUrl: URL;
}

/** Drives the full flow: /oauth/auth -> mock provider auto-approves -> /oauth/callback
 *  -> lands on the caller's own redirect_uri. Assumes the mock provider is reachable and
 *  registered as the app's auth_url/token_url, and doesn't itself assert anything --
 *  callers inspect `finalUrl` for either a `code` or an `error`. */
export async function completeAuthorization(params: AuthorizeParams): Promise<CompletedAuthorization> {
  const { res: authorizeRes, verifier, state, redirectUri } = await startAuthorize(params);
  const providerUrl = nextHop(authorizeRes);
  const providerRes = await fetch(providerUrl, { redirect: "manual" });
  const callbackUrl = nextHop(providerRes);
  const callbackRes = await fetch(callbackUrl, { redirect: "manual" });
  const finalLocation = nextHop(callbackRes);
  return { verifier, state, redirectUri, finalUrl: new URL(finalLocation) };
}

export interface OAuthErrorBody {
  error: string;
  error_description?: string;
}

/** Typed read of an RFC 6749 error body (`{error, error_description?}`), e.g. from a
 *  400 response at /oauth/token. */
export async function oauthErrorBody(res: Response): Promise<OAuthErrorBody> {
  return (await res.json()) as OAuthErrorBody;
}

export async function exchangeCode(params: {
  appId: string;
  code: string;
  redirectUri: string;
  verifier: string;
}): Promise<Response> {
  return fetch(`${BASE_URL}/${params.appId}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: params.code,
      redirect_uri: params.redirectUri,
      code_verifier: params.verifier,
    }),
  });
}

/** End-to-end helper for tests that just need a connected user and don't care about the
 *  individual hops -- runs completeAuthorization() + exchangeCode() and returns both the
 *  token response body and the resolved user_id/label needed for admin-API calls. */
export async function connectUser(params: AuthorizeParams) {
  const { verifier, redirectUri, finalUrl } = await completeAuthorization(params);
  const error = finalUrl.searchParams.get("error");
  if (error) {
    throw new Error(`authorization failed: ${error} (${finalUrl.searchParams.get("error_description")})`);
  }
  const code = finalUrl.searchParams.get("code");
  if (!code) throw new Error("callback redirect had neither code nor error");

  const tokenRes = await exchangeCode({ appId: params.appId, code, redirectUri, verifier });
  if (tokenRes.status !== 200) {
    throw new Error(`token exchange failed: ${tokenRes.status} ${await tokenRes.text()}`);
  }
  const tokenBody = (await tokenRes.json()) as { access_token: string; scope?: string };
  return { tokenBody };
}
