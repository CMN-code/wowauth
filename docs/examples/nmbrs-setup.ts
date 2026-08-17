#!/usr/bin/env bun
/**
 * Interactive Nmbrs connection setup for wowauth.
 *
 * Walks a person through connecting a Nmbrs account to wowauth end-to-end --
 * generating an encryption key, registering the connection, handing off to
 * Nmbrs's own signup form, logging in once through a browser, and finally
 * proving the connection works with two real HTTP calls. It explains what
 * it's doing and what it's sending at each step, blurring secrets in the
 * narration (but not in the final copy-pasteable commands, which need the
 * real values to actually run).
 *
 * This is the scripted, narrated equivalent of docs/examples/NMBRS.md --
 * read that file for the full "why" behind each step; this file explains
 * enough inline to hand to someone non-technical and have them run it
 * standalone.
 *
 * Run it with:
 *
 *   bun run docs/examples/nmbrs-setup.ts
 *
 * (or `npx tsx docs/examples/nmbrs-setup.ts` if you don't have bun --
 * nothing here is bun-specific, just built-in Node/Bun APIs. No npm
 * install needed either way.)
 */

import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";

// ---------------------------------------------------------------------------
// Nmbrs-specific constants (see docs/examples/NMBRS.md for where these come
// from). Everything else in this script is generic wowauth setup that would
// look the same for any other provider.
// ---------------------------------------------------------------------------

const NMBRS_AUTH_URL = "https://identityservice.nmbrs.com/connect/authorize";
const NMBRS_TOKEN_URL = "https://identityservice.nmbrs.com/connect/token";

// The full read-only scope set Nmbrs documents for partner apps, plus the
// mandatory offline_access -- without it Nmbrs never issues a refresh
// token, and wowauth would have nothing to renew with once the access
// token expires. Deliberately no "openid" here: despite looking like
// standard OIDC, Nmbrs doesn't grant it to partner-app clients and
// requesting it is a common cause of "Invalid scope" errors. If Nmbrs
// rejects one of the scopes below for your specific partner client, trim
// it from this list and re-run the script.
const NMBRS_SCOPES = [
  "offline_access",
  "employee.employment.read",
  "employee.info.read",
  "employee.payment.read",
  "company.info.read",
  "company.payrollsettings.read",
].join(" ");

// A light, read-only call used at the very end to prove the connection
// actually works against real Nmbrs data.
const NMBRS_SMOKE_TEST_URL = "https://api.nmbrsapp.com/api/companies";

// ---------------------------------------------------------------------------
// Small helpers: prompting, masking secrets, and narrating requests.
// Nothing provider-specific below this line.
// ---------------------------------------------------------------------------

const rl = createInterface({ input: process.stdin, output: process.stdout });

async function ask(question: string, defaultValue?: string): Promise<string> {
  const suffix = defaultValue ? ` [${defaultValue}]` : "";
  const answer = (await rl.question(`${question}${suffix}: `)).trim();
  return answer || defaultValue || "";
}

async function askRequired(question: string): Promise<string> {
  for (;;) {
    const answer = (await rl.question(`${question}: `)).trim();
    if (answer) return answer;
    console.log("  (this one's required -- try again)");
  }
}

function step(n: number, title: string): void {
  console.log(`\n${"─".repeat(70)}\nSTEP ${n}: ${title}\n${"─".repeat(70)}`);
}

function explain(text: string): void {
  console.log(text.trim() + "\n");
}

function fail(message: string): never {
  console.error(`\n✗ ${message}`);
  rl.close();
  process.exit(1);
}

/** Blurs the middle of a secret so it's recognizable in logs but not readable. */
function mask(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  const stars = "*".repeat(Math.min(value.length - 8, 24));
  return `${value.slice(0, 4)}${stars}${value.slice(-4)}`;
}

function narrate(
  method: string,
  url: string,
  headers: Record<string, string>,
  maskHeaders: string[],
  bodyDisplay?: string,
): void {
  console.log(`\n  → ${method} ${url}`);
  for (const [key, value] of Object.entries(headers)) {
    console.log(`    ${key}: ${maskHeaders.includes(key) ? mask(value) : value}`);
  }
  if (bodyDisplay) {
    console.log(
      bodyDisplay
        .split("\n")
        .map((line) => `    ${line}`)
        .join("\n"),
    );
  }
}

/** Makes an HTTP call, printing exactly what's sent (with secrets blurred) and
 *  what comes back, so nothing this script does to your data is hidden. */
async function call<T = unknown>(
  method: string,
  url: string,
  opts: {
    headers?: Record<string, string>;
    json?: Record<string, unknown>;
    form?: URLSearchParams;
    maskBodyKeys?: string[];
    maskHeaders?: string[];
    onError?: string;
  } = {},
): Promise<T> {
  const headers = { ...(opts.headers ?? {}) };
  const maskKeys = opts.maskBodyKeys ?? [];
  let requestBody: string | URLSearchParams | undefined;
  let bodyDisplay: string | undefined;

  if (opts.json) {
    headers["Content-Type"] = "application/json";
    requestBody = JSON.stringify(opts.json);
    const masked: Record<string, unknown> = { ...opts.json };
    for (const key of maskKeys) {
      if (typeof masked[key] === "string") masked[key] = mask(masked[key] as string);
    }
    bodyDisplay = JSON.stringify(masked, null, 2);
  } else if (opts.form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    requestBody = opts.form;
    bodyDisplay = [...opts.form.entries()]
      .map(([key, value]) => `${key}=${maskKeys.includes(key) ? mask(value) : value}`)
      .join("\n");
  }

  narrate(method, url, headers, opts.maskHeaders ?? [], bodyDisplay);

  const res = await fetch(url, { method, headers, body: requestBody });
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : undefined;
  } catch {
    parsed = text;
  }

  console.log(`  ← ${res.status} ${res.statusText}`);

  if (!res.ok) {
    console.error(`\n✗ Request failed.${opts.onError ? ` ${opts.onError}` : ""}`);
    console.error(typeof parsed === "string" ? parsed : JSON.stringify(parsed, null, 2));
    rl.close();
    process.exit(1);
  }

  return parsed as T;
}

function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// Parsing the browser's final landing URL after login. There's no local
// listener catching the redirect automatically -- wowauth's own public
// `/health` endpoint (always up, no setup needed) is used as the
// redirect_uri instead, and the person running this pastes the resulting
// URL back in.
// ---------------------------------------------------------------------------

interface CallbackResult {
  code?: string;
  state?: string;
  error?: string;
  errorDescription?: string;
}

function parseCallbackUrl(raw: string): CallbackResult {
  const url = new URL(raw);
  return {
    code: url.searchParams.get("code") ?? undefined,
    state: url.searchParams.get("state") ?? undefined,
    error: url.searchParams.get("error") ?? undefined,
    errorDescription: url.searchParams.get("error_description") ?? undefined,
  };
}

// ---------------------------------------------------------------------------
// The walkthrough itself.
// ---------------------------------------------------------------------------

async function main() {
  console.log(`
Connect a Nmbrs account to wowauth
===================================

This walks through the whole thing: generating an encryption key,
registering the connection with wowauth, handing off to Nmbrs's own
signup form, logging in once through your browser, and finally proving
the connection works. It explains what it's doing and what it's sending
at each step -- nothing here is hidden from you.
`);

  step(1, "Where is wowauth?");
  explain(`
Three things are needed to talk to your wowauth instance's admin API --
see wowauth's .env for these values if you're the one who deployed it.
`);
  const adminUrl = (
    await ask("wowauth admin URL (where this script runs commands from)", "http://localhost:3000")
  ).replace(/\/+$/, "");
  const publicUrl = (
    await ask(
      "wowauth PUBLIC URL (what Nmbrs and your browser redirect to -- must be internet-reachable HTTPS in production)",
      adminUrl,
    )
  ).replace(/\/+$/, "");
  const configSecret = await askRequired("wowauth CONFIG_SECRET (the admin bearer secret from wowauth's .env)");
  const adminHeaders = { Authorization: `Bearer ${configSecret}` };

  step(2, "Generate an encryption key for your tokens");
  explain(`
Every token wowauth ever hands back for this connection gets encrypted to
a key you control, so only someone holding the matching private key can
read it -- not even wowauth's own database can.
`);
  const keyPath = await ask("Where should the private key be saved?", "./wowauth_nmbrs_private_key.pem");
  const { publicKey, privateKey } = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  // The DER SubjectPublicKeyInfo encoding for X25519 is a fixed 12-byte
  // header followed by the raw 32-byte key -- wowauth wants just the raw
  // key, base64-encoded.
  const publicKeyB64 = publicKey.subarray(publicKey.length - 32).toString("base64");
  writeFileSync(keyPath, privateKey, { mode: 0o600 });
  console.log(`  ✓ Private key saved to ${keyPath} (readable only by you) -- wowauth never sees it.`);
  console.log(`  ✓ Public key (this one's fine to share): ${publicKeyB64}`);

  step(3, "Where the browser lands after logging in");
  explain(`
In a minute you'll open a Nmbrs login page in your browser. Afterwards it
needs somewhere to land -- that's wowauth's own public health endpoint, so
no local server or open port is required. You'll copy the resulting URL
back out of the address bar once you get there.
`);
  const redirectUri = `${publicUrl}/health`;
  console.log(`  ✓ Using ${redirectUri} as the redirect target`);

  step(4, "Register the connection with wowauth");
  explain(`
This tells wowauth about Nmbrs: where to send people to log in, where to
exchange a login for a token, and what data to ask permission for. The
client_id/client_secret below are placeholders -- Nmbrs hasn't issued the
real ones yet, that happens in step 6.
`);
  const connectionName = await ask("A short name for this connection", "nmbrs");
  const app = await call<{ id: string }>("POST", `${adminUrl}/apps`, {
    headers: adminHeaders,
    json: {
      name: connectionName,
      client_id: "pending-nmbrs-client-id",
      client_secret: "pending-nmbrs-secret",
      auth_url: NMBRS_AUTH_URL,
      token_url: NMBRS_TOKEN_URL,
      redirect_url: "placeholder-set-in-the-next-step",
      allowed_redirect_uris: [redirectUri],
      scopes: NMBRS_SCOPES,
      public_key: publicKeyB64,
    },
    maskBodyKeys: ["client_secret", "public_key"],
    maskHeaders: ["Authorization"],
  });
  const appId = app.id;
  console.log(`  ✓ Registered. wowauth's internal id for this connection: ${appId}`);

  step(5, "Point wowauth's own callback at itself");
  explain(`
Nmbrs needs one fixed URL to redirect to once someone logs in -- wowauth's
own callback, which only exists now that this connection has an id.
`);
  const wowauthCallback = `${publicUrl}/${appId}/oauth/callback`;
  await call("PATCH", `${adminUrl}/apps/${appId}`, {
    headers: adminHeaders,
    json: { redirect_url: wowauthCallback },
    maskHeaders: ["Authorization"],
  });
  console.log(`  ✓ wowauth will register itself with Nmbrs using: ${wowauthCallback}`);

  step(6, "Register the app in Nmbrs's own portal");
  explain(`
Go to Nmbrs's partner/developer portal and register a new app with:

    App name:          ${connectionName} (or anything descriptive)
    Application type:  Web
    Redirect URLs:      ${wowauthCallback}
    (description / icon URL / privacy policy: anything, Nmbrs just wants
     them filled in)

Nmbrs caps you at 5 redirect URLs total, so if you'll run more than one
wowauth deployment (e.g. staging and production), register all of their
callback URLs up front rather than editing this later.

Submit the form. Nmbrs will then show you a Client ID (shaped like
PartnerApp_<name>_<suffix>) and a Client Secret -- keep that page open.
`);
  await rl.question("Press Enter once you have your Nmbrs Client ID and Client Secret ready...");
  const nmbrsClientId = await askRequired("Paste the Client ID Nmbrs gave you");
  const nmbrsClientSecret = await askRequired("Paste the Client Secret Nmbrs gave you");

  explain(`
Patching wowauth with the real credentials. client_secret is write-only --
no wowauth endpoint ever returns it back once sent, by design.
`);
  await call("PATCH", `${adminUrl}/apps/${appId}`, {
    headers: adminHeaders,
    json: { client_id: nmbrsClientId, client_secret: nmbrsClientSecret },
    maskBodyKeys: ["client_secret"],
    maskHeaders: ["Authorization"],
  });
  console.log("  ✓ wowauth now has your real Nmbrs credentials.");

  step(7, "Log in to Nmbrs once, in your browser");
  const state = randomBytes(16).toString("hex");
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  const accountHint = await ask(
    "A memorable label for this Nmbrs account (e.g. the company name), or leave blank",
  );

  const authorizeParams = new URLSearchParams({
    redirect_uri: redirectUri,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  if (accountHint) authorizeParams.set("account_hint", accountHint);
  const authorizeUrl = `${publicUrl}/${appId}/oauth/auth?${authorizeParams}`;

  explain(`
Open this URL in a browser -- it'll take you to Nmbrs to log in and
approve access, then bounce you back to wowauth's health endpoint with
"?code=...&state=..." (or "?error=...") added to the URL:

  ${authorizeUrl}
`);
  console.log(
    '  (If your browser lands on a Nmbrs error page reading "Invalid scope" instead of a\n' +
      "   login screen, Nmbrs is rejecting one of NMBRS_SCOPES from the top of this file for\n" +
      "   your specific partner client -- trim it down and re-run.)",
  );

  const landedOn = await askRequired("Once you're redirected, paste the full URL from your browser's address bar");
  let result: CallbackResult;
  try {
    result = parseCallbackUrl(landedOn);
  } catch {
    fail("That didn't look like a valid URL.");
  }
  if (result.error) fail(`Nmbrs (via wowauth) reported an error: ${result.error} ${result.errorDescription ?? ""}`);
  if (result.state !== state) fail("The state returned didn't match what we sent -- aborting.");
  if (!result.code) fail("No authorization code was received.");
  console.log("  ✓ Login approved, code received.");

  step(8, "Exchange the login for a token");
  explain(`
Standard OAuth token exchange. code_verifier proves this exchange is
coming from the same script that started the login (PKCE) -- shown
blurred here since it's effectively a secret, even though it's already
spent by the time you read this.
`);
  const tokenResponse = await call<{ access_token: string; expires_in?: number }>(
    "POST",
    `${publicUrl}/${appId}/oauth/token`,
    {
      form: new URLSearchParams({
        grant_type: "authorization_code",
        code: result.code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }),
      maskBodyKeys: ["code_verifier"],
    },
  );
  console.log(`  ✓ Got a working access token: ${mask(tokenResponse.access_token)}`);
  explain(`
(There's no refresh_token in that response, on purpose -- wowauth keeps
that to itself and handles renewing your access from here on. That's the
whole point of using wowauth instead of talking to Nmbrs directly.)
`);

  step(9, "Find the connected user");
  const users = await call<{ user_id: string; label?: string }[]>("GET", `${adminUrl}/apps/${appId}/users`, {
    headers: adminHeaders,
    maskHeaders: ["Authorization"],
  });
  const userId = users[0]?.user_id;
  if (!userId) fail("No connected user found -- something went wrong above.");
  console.log(`  ✓ user_id: ${userId}${users[0]?.label ? ` (labeled "${users[0].label}")` : ""}`);

  step(10, "Save these");
  console.log(`
  APP_ID       = ${appId}
  USER_ID      = ${userId}
  PRIVATE_KEY  = ${keyPath}

  Any script pulling a fresh Nmbrs token from now on needs these three
  plus your CONFIG_SECRET -- and nothing else. No more browser logins.
`);

  step(11, "Prove it works");
  explain(`
Two real calls: the first is exactly what a recurring script calls to get
a token going forward (wowauth refreshes it automatically once it's
expired); the second uses a token against Nmbrs itself.
`);
  const tokenInfo = await call<{ token: string; expires_at?: string }>(
    "GET",
    `${adminUrl}/apps/${appId}/users/${userId}/token`,
    { headers: adminHeaders, maskHeaders: ["Authorization"] },
  );
  console.log(`
  wowauth returned: ${mask(tokenInfo.token)}

  That's expected to look like gibberish -- it's encrypted to the public
  key from step 2, so only ${keyPath} can decrypt it. Decrypting it is a
  job for the actual integration script that uses this connection day to
  day, not this setup script (see docs/examples/DEFAULT.md step 7 for how,
  in Python, or use an HPKE library in whatever language that script is
  in).

  To prove the Nmbrs connection itself works right now, here's the plain
  access token this script already has in memory from step 8:
`);

  const smokeTest = await fetch(NMBRS_SMOKE_TEST_URL, {
    headers: { Authorization: `Bearer ${tokenResponse.access_token}` },
  });
  console.log(`  → GET ${NMBRS_SMOKE_TEST_URL}`);
  console.log(`  ← ${smokeTest.status} ${smokeTest.statusText}`);
  if (smokeTest.ok) {
    console.log("  ✓ Nmbrs answered -- the connection works.");
  } else {
    console.log("  Nmbrs didn't return 2xx -- double check the scopes granted to your partner client.");
  }

  console.log(`
${"─".repeat(70)}
All done. Two commands to check this connection any time -- unlike
everywhere else in this script, these are shown in full since you need
the real values to actually run them:

1) Get a fresh (encrypted) token from wowauth -- what a recurring script
   would call:

curl -s "${adminUrl}/apps/${appId}/users/${userId}/token" \\
  -H "Authorization: Bearer ${configSecret}" | jq .

2) Use today's access token directly against Nmbrs, to confirm the
   connection works right now (this token won't stay valid forever --
   it's only for this quick check):

curl -s "${NMBRS_SMOKE_TEST_URL}" \\
  -H "Authorization: Bearer ${tokenResponse.access_token}"
${"─".repeat(70)}
`);

  rl.close();
}

main().catch((err) => {
  console.error("\nSomething unexpected went wrong:");
  console.error(err);
  rl.close();
  process.exit(1);
});
