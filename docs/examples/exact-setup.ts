#!/usr/bin/env bun
/**
 * Interactive Exact Online connection setup for wowauth.
 *
 * Walks a person through connecting an Exact Online account to wowauth
 * end-to-end -- generating an encryption key, registering the connection,
 * handing off to Exact's own app registration, logging in once through a
 * browser, and finally proving the connection works with a real HTTP call.
 * It explains what it's doing and what it's sending at each step, blurring
 * secrets in the narration (but not in the final copy-pasteable commands,
 * which need the real values to actually run).
 *
 * This is the Exact Online counterpart to docs/examples/nmbrs-setup.ts --
 * read that file's header for the general shape; only the Exact-specific
 * differences are called out here:
 *
 *   - Exact runs one identical OAuth API per country, on a different
 *     domain per country (start.exactonline.nl, .de, .co.uk, ...) -- step 1
 *     below asks which one your Exact account lives on.
 *   - Exact doesn't have OAuth scopes at all. Access is all-or-nothing,
 *     governed by whatever permissions the logging-in user already has
 *     inside Exact -- so unlike Nmbrs there's no scope picker here.
 *   - Exact's token endpoint wants client_id/client_secret as an HTTP
 *     Basic header, not in the POST body -- that's wowauth's default
 *     (`token_auth_method: "basic"`), so nothing extra needs to be
 *     configured for it.
 *   - Exact access tokens last 10 minutes and its refresh tokens rotate on
 *     every use (each refresh both consumes and replaces the one you had).
 *     wowauth already stores the new one every time it refreshes -- this
 *     is mentioned in step 9's narration but needs no special handling
 *     here.
 *   - There's no per-account "company" concept to pick during login --
 *     Exact accounts can see multiple administrations ("divisions"), and
 *     which ones is entirely a function of what the logged-in user can
 *     see in Exact. The smoke test at the end calls Exact's `current/Me`
 *     endpoint, which reports the division your token defaults to.
 *
 * You'll need an Exact Online account with rights to register an app in
 * Exact's App Center at https://apps.exactonline.com (step 7 below will
 * ask you to register the app there).
 *
 * Run it with:
 *
 *   bun run docs/examples/exact-setup.ts
 *
 * (or `npx tsx docs/examples/exact-setup.ts` if you don't have bun --
 * nothing here is bun-specific, just built-in Node/Bun APIs. No npm
 * install needed either way.)
 */

import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";

// ---------------------------------------------------------------------------
// Exact-specific constants. Everything else in this script is generic
// wowauth setup that would look the same for any other provider.
// ---------------------------------------------------------------------------

// Exact runs the identical API under a different top-level domain per
// country -- there's no single global endpoint. Pick whichever matches
// where the Exact account was created; using the wrong one just means the
// login page rejects the account as unknown, not a security problem.
const EXACT_COUNTRIES: { label: string; domain: string }[] = [
  { label: "Netherlands", domain: "start.exactonline.nl" },
  { label: "Belgium", domain: "start.exactonline.be" },
  { label: "Germany", domain: "start.exactonline.de" },
  { label: "United Kingdom", domain: "start.exactonline.co.uk" },
  { label: "France", domain: "start.exactonline.fr" },
  { label: "Spain", domain: "start.exactonline.es" },
  { label: "United States / rest of world", domain: "start.exactonline.com" },
];

// A light, read-only call used at the end to prove the connection actually
// works against real Exact data -- also the standard way to discover which
// "division" (administration) a token defaults to, since Exact accounts can
// see more than one.
const EXACT_ME_PATH = "/api/v1/current/Me";

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

/**
 * Interactive single-select picker for the Exact country/domain: ↑/↓ to
 * move, enter to confirm.
 *
 * `rl` already put stdin into keypress-emitting mode (readline does this for
 * any TTY input at construction time) and attached its own keypress listener
 * for line editing. That listener would otherwise fight this one -- readline
 * would try to interpret arrow keys as history navigation -- so it's
 * detached for the duration of the picker and reattached once done, leaving
 * later rl.question() calls unaffected.
 */
async function selectCountry(countries: { label: string; domain: string }[]): Promise<{
  label: string;
  domain: string;
}> {
  if (!process.stdin.isTTY) {
    console.log(`  (non-interactive terminal -- defaulting to ${countries[0]!.domain})`);
    return countries[0]!;
  }

  let cursor = 0;

  const draw = () => {
    for (const [i, country] of countries.entries()) {
      const pointer = i === cursor ? "›" : " ";
      process.stdout.write(`\x1b[2K\r  ${pointer} ${country.label} (${country.domain})\n`);
    }
  };

  console.log("  ↑/↓ move    enter confirm\n");
  draw();

  const readlineKeypressListeners = process.stdin.listeners("keypress");
  for (const listener of readlineKeypressListeners) process.stdin.removeListener("keypress", listener as never);
  const wasRaw = process.stdin.isRaw ?? false;
  process.stdin.setRawMode(true);

  await new Promise<void>((resolve) => {
    const onKeypress = (_str: string, key: { name?: string; ctrl?: boolean } | undefined) => {
      if (!key) return;
      if (key.ctrl && key.name === "c") {
        process.stdout.write("\n");
        process.exit(130);
      }
      if (key.name === "up") cursor = (cursor - 1 + countries.length) % countries.length;
      else if (key.name === "down") cursor = (cursor + 1) % countries.length;
      else if (key.name === "return") {
        process.stdin.off("keypress", onKeypress);
        resolve();
        return;
      } else {
        return;
      }
      process.stdout.write(`\x1b[${countries.length}A`);
      draw();
    };
    process.stdin.on("keypress", onKeypress);
  });

  process.stdin.setRawMode(wasRaw);
  for (const listener of readlineKeypressListeners) process.stdin.on("keypress", listener as never);
  console.log("");

  return countries[cursor]!;
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

/** Makes an HTTP call. By default prints exactly what's sent (with secrets
 *  blurred) and what comes back, so nothing this script does to your data is
 *  hidden. Pass `quiet: true` for internal bookkeeping calls where that
 *  detail isn't useful to the person running the script -- errors still
 *  print either way. */
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
    quiet?: boolean;
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

  if (!opts.quiet) narrate(method, url, headers, opts.maskHeaders ?? [], bodyDisplay);

  const res = await fetch(url, { method, headers, body: requestBody });
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : undefined;
  } catch {
    parsed = text;
  }

  if (!opts.quiet) console.log(`  ← ${res.status} ${res.statusText}`);

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
Connect an Exact Online account to wowauth
===========================================

Just answer each question below. Press Enter to accept anything shown
in [brackets].
`);

  step(1, "Where is wowauth?");
  explain(`
Find these three values in wowauth's .env file.
`);
  const adminUrl = (
    await ask("wowauth admin URL", "https://wowauth.fuse.creativemedianetwork.com")
  ).replace(/\/+$/, "");
  const publicUrl = (await ask("wowauth public URL", adminUrl)).replace(/\/+$/, "");
  const configSecret = await askRequired("wowauth CONFIG_SECRET");
  const adminHeaders = { Authorization: `Bearer ${configSecret}` };

  step(2, "Which Exact Online country is this account on?");
  explain(`
Exact runs the same API on a different domain per country -- pick
whichever matches where the Exact account was created.
`);
  const country = await selectCountry(EXACT_COUNTRIES);
  const exactAuthUrl = `https://${country.domain}/api/oauth2/auth`;
  const exactTokenUrl = `https://${country.domain}/api/oauth2/token`;
  const exactApiBase = `https://${country.domain}`;
  console.log(`  ✓ Using ${country.domain}`);

  step(3, "Generate an encryption key for your tokens");
  const { publicKey, privateKey } = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
  // The DER SubjectPublicKeyInfo/PrivateKeyInfo encodings for X25519 are
  // both a fixed header followed by the raw 32-byte key -- wowauth wants
  // just the raw key, base64-encoded, and so does exact-secrets.json below.
  const publicKeyB64 = publicKey.subarray(publicKey.length - 32).toString("base64");
  const privateKeyB64 = privateKey.subarray(privateKey.length - 32).toString("base64");
  console.log("  ✓ Key pair generated");

  step(4, "Where the browser lands after logging in");
  const redirectUri = `${publicUrl}/health`;
  console.log(`  ✓ Using ${redirectUri}`);

  step(5, "Register the connection with wowauth");
  explain(`
Exact Online doesn't have OAuth scopes -- access is all-or-nothing,
governed by whatever the logging-in user is already allowed to see and do
inside Exact. So unlike Nmbrs, there's no scope picker here.
`);
  const reuseName = await ask(
    "Reuse an existing wowauth connection by name (e.g. one a previous, incomplete run of\n" +
      "  this script already registered), or leave blank to register a new one",
    "",
  );

  let appId: string;
  let connectionName: string;
  // Whether step 7 below still needs to register a (new) app in Exact's App
  // Center -- true for a brand-new connection, and for a reused one that
  // never got past step 7 last time (still holding the placeholder
  // credentials set below).
  let needsExactRegistration = true;

  if (reuseName) {
    const lookup = await fetch(`${adminUrl}/apps/by-name/${encodeURIComponent(reuseName)}`, {
      headers: adminHeaders,
    });
    if (lookup.status === 404) {
      fail(`No existing wowauth connection named "${reuseName}" was found -- check the name and try again.`);
    }
    if (!lookup.ok) {
      fail(`Looking up "${reuseName}" failed: ${lookup.status} ${await lookup.text()}`);
    }
    const existing = (await lookup.json()) as { id: string; name: string; client_id: string };
    appId = existing.id;
    connectionName = existing.name;
    needsExactRegistration = existing.client_id === "pending-exact-client-id";
    console.log(`  ✓ Reusing "${connectionName}" (id: ${appId})`);

    const status = await call<{ user_count: number }>("GET", `${adminUrl}/apps/${appId}/status`, {
      headers: adminHeaders,
      maskHeaders: ["Authorization"],
      quiet: true,
    });
    if (status.user_count > 0) {
      const confirm = await ask(
        `"${connectionName}" already has ${status.user_count} connected user(s). The new encryption key\n` +
          "  from step 3 will replace the old one, which disconnects all of them. Type \"yes\" to continue",
        "",
      );
      if (confirm.toLowerCase() !== "yes") fail("Aborted -- no changes made.");
    }

    await call("PATCH", `${adminUrl}/apps/${appId}`, {
      headers: adminHeaders,
      json: { public_key: publicKeyB64, allowed_redirect_uris: [redirectUri] },
      maskBodyKeys: ["public_key"],
      maskHeaders: ["Authorization"],
      quiet: true,
    });
    console.log("  ✓ Encryption key on file updated to match step 3");
  } else {
    connectionName = await ask("A short name for this connection", "exact-online");
    const app = await call<{ id: string }>("POST", `${adminUrl}/apps`, {
      headers: adminHeaders,
      json: {
        name: connectionName,
        client_id: "pending-exact-client-id",
        client_secret: "pending-exact-secret",
        auth_url: exactAuthUrl,
        token_url: exactTokenUrl,
        redirect_url: "placeholder-set-in-the-next-step",
        allowed_redirect_uris: [redirectUri],
        // No scopes field sent -- Exact doesn't use OAuth scopes, and
        // wowauth defaults an omitted `scopes` to "". token_auth_method is
        // also omitted: wowauth's default ("basic") is exactly what
        // Exact's token endpoint expects (client_id/secret as an HTTP
        // Basic header, not in the POST body).
        public_key: publicKeyB64,
      },
      maskBodyKeys: ["client_secret", "public_key"],
      maskHeaders: ["Authorization"],
      quiet: true,
    });
    appId = app.id;
    console.log(`  ✓ Registered (id: ${appId})`);
  }

  step(6, "Point wowauth's own callback at itself");
  const wowauthCallback = `${publicUrl}/${appId}/oauth/callback`;
  await call("PATCH", `${adminUrl}/apps/${appId}`, {
    headers: adminHeaders,
    json: { redirect_url: wowauthCallback },
    maskHeaders: ["Authorization"],
    quiet: true,
  });
  console.log(`  ✓ Done`);

  step(7, "Register the app in Exact's App Center");
  explain(`
Go to https://apps.exactonline.com and sign in, then create a new app
(My Apps → New App):

    App name:      ${connectionName}
    Redirect URI:  ${wowauthCallback}

    (fill in anything for the remaining descriptive fields -- they don't
    affect how the connection works)

Submit the form, then copy the Client ID and Client Secret it gives you.
`);
  await rl.question("Press Enter once you have your Exact Client ID and Client Secret ready...");
  const exactClientId = await askRequired("Paste the Client ID Exact gave you");
  const exactClientSecret = await askRequired("Paste the Client Secret Exact gave you");

  await call("PATCH", `${adminUrl}/apps/${appId}`, {
    headers: adminHeaders,
    json: { client_id: exactClientId, client_secret: exactClientSecret },
    maskBodyKeys: ["client_secret"],
    maskHeaders: ["Authorization"],
    quiet: true,
  });
  console.log("  ✓ wowauth now has your real Exact credentials.");

  step(8, "Log in to Exact once, in your browser");
  explain(`
Exact access tokens only last 10 minutes, but that's not something you'll
ever notice: wowauth automatically exchanges the refresh token for a new
access token behind the scenes whenever you ask it for one, with no
browser involved. Exact rotates the refresh token on every use (each
refresh both consumes and replaces it) -- wowauth already stores the new
one every time, so as long as it keeps refreshing at least once within
Exact's refresh-token validity window, this login is the only one you'll
ever have to do.
`);
  const state = randomBytes(16).toString("hex");
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  const accountHint = await ask(
    "A memorable label for this Exact account (e.g. the company name), or leave blank",
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
Open this link, log in to Exact, and approve access:

  ${authorizeUrl}

You'll land on a mostly-blank page. Copy the full URL from your browser's
address bar and paste it below.
`);

  const landedOn = await askRequired("Once you're redirected, paste the full URL from your browser's address bar");
  let result: CallbackResult;
  try {
    result = parseCallbackUrl(landedOn);
  } catch {
    fail("That didn't look like a valid URL.");
  }
  if (result.error) {
    if (result.error === "server_error") {
      // wowauth's callback handler discards the real reason the code
      // exchange failed before it ever reaches this redirect (see
      // src/oauth_handlers.rs: the Err(_) branch around exchange_code) --
      // there's no error_description to show, and it isn't logged
      // server-side either. So this is a checklist against everything this
      // script sent, not a message from Exact itself.
      console.error(`
✗ wowauth reported a generic "server_error". This means the *browser* leg
  (Exact login + consent) worked, but wowauth's own server-to-server call to
  Exact's token endpoint failed right after -- wowauth doesn't surface why,
  so check these in order:

  1. Client ID / Client Secret pasted in step 7 -- a typo or stray
     whitespace here is the most common cause. wowauth's PATCH response for
     client_id in that step confirms half of it; client_secret is
     write-only, so a mistake there only shows up here. Re-copy both
     directly from https://apps.exactonline.com (My Apps -> ${connectionName}).

  2. Redirect URI registered on the Exact side -- Exact requires an exact,
     byte-for-byte match against what wowauth sends. Confirm the app at
     https://apps.exactonline.com has *exactly*:

       ${wowauthCallback}

     (no trailing slash mismatch, no http vs https, no typo).

  3. Country/domain picked in step 2 -- this run used:

       ${country.label} (${country.domain})

     If the Exact account or the app registration is actually on a
     different country's Exact environment, the token endpoint
     (${exactTokenUrl}) will reject the exchange outright.

  4. Timing -- Exact's authorization codes are single-use and expire in
     roughly 3 minutes. If there was a long pause between approving access
     and pasting the URL back in, the code may have simply expired.

  The authorization code from this attempt is already spent (wowauth
  deleted it either way) -- fix whichever of the above looks wrong, then
  re-run this script and answer "${connectionName}" at the "reuse an
  existing wowauth connection" prompt in step 5 to skip re-registering and
  jump straight back to step 8.
`);
      rl.close();
      process.exit(1);
    }
    fail(
      `Exact reported an error during login: ${result.error}${
        result.errorDescription ? ` -- ${result.errorDescription}` : " (no further description given)"
      }`,
    );
  }
  if (result.state !== state) {
    fail(
      "The state returned didn't match what we sent -- aborting.\n" +
        `  expected: ${state}\n` +
        `  got:      ${result.state ?? "(none)"}\n` +
        "  (this usually means the URL was pasted from a stale browser tab -- re-run step 8 and use the freshest link.)",
    );
  }
  if (!result.code) fail(`No authorization code was received. Full callback URL was:\n  ${landedOn}`);
  console.log("  ✓ Login approved, code received.");

  step(9, "Exchange the login for a token");
  explain(`
Exact's authorization codes are single-use and short-lived (about 3
minutes) -- if the exchange below fails with an expired/invalid code,
re-run step 8 and paste the URL back in promptly.
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
      quiet: true,
    },
  );
  console.log(`  ✓ Got a working access token: ${mask(tokenResponse.access_token)}`);

  step(10, "Find the connected user");
  const users = await call<{ user_id: string; label?: string }[]>("GET", `${adminUrl}/apps/${appId}/users`, {
    headers: adminHeaders,
    maskHeaders: ["Authorization"],
    quiet: true,
  });
  const userId = users[0]?.user_id;
  if (!userId) fail("No connected user found -- something went wrong above.");
  console.log(`  ✓ user_id: ${userId}${users[0]?.label ? ` (labeled "${users[0].label}")` : ""}`);

  step(11, "Save these");
  const secretsPath = "./exact-secrets.json";
  const secrets = {
    specific: { api_base: exactApiBase },
    wowauth: {
      name: connectionName,
      app_id: appId,
      user_id: userId,
      admin_url: adminUrl,
      config_secret: configSecret,
      private_key: { format: "x25519-raw-base64", value: privateKeyB64 },
    },
  };
  writeFileSync(secretsPath, JSON.stringify(secrets, null, 2), { mode: 0o600 });
  console.log(`
  ✓ Saved to ${secretsPath} (readable only by you -- treat it like a database
    credential, never commit it; see docs/examples/fuse-secrets.schema.json
    for its shape). That's all you'll need going forward -- no more browser
    logins.
`);

  step(12, "Prove it works");
  const tokenInfo = await call<{ token: string; expires_at?: string }>(
    "GET",
    `${adminUrl}/apps/${appId}/users/${userId}/token`,
    { headers: adminHeaders, maskHeaders: ["Authorization"] },
  );
  console.log(`
  wowauth returned: ${mask(tokenInfo.token)}

  That's expected to look like gibberish -- it's encrypted, and only the
  private key in ${secretsPath} can decrypt it (see docs/examples/DEFAULT.md
  step 7 for how).

  Here's today's plain access token, to prove the Exact connection itself
  works right now -- calling Exact's "current user" endpoint, which also
  reports which division (administration) this account defaults to:
`);

  const meUrl = `${exactApiBase}${EXACT_ME_PATH}`;
  const smokeTest = await fetch(meUrl, {
    headers: {
      Authorization: `Bearer ${tokenResponse.access_token}`,
      Accept: "application/json",
    },
  });
  console.log(`  → GET ${meUrl}`);
  console.log(`  ← ${smokeTest.status} ${smokeTest.statusText}`);
  if (smokeTest.ok) {
    const me = (await smokeTest.json()) as { d?: { results?: { CurrentDivision?: number }[] } };
    const division = me.d?.results?.[0]?.CurrentDivision;
    console.log(
      `  ✓ Exact answered -- the connection works.${division ? ` Default division: ${division}` : ""}`,
    );
  } else {
    console.log("  Exact didn't return 2xx -- double check the app registration in step 7.");
  }

  console.log(`
${"─".repeat(70)}
All done. Two commands to check this connection any time:

1) Get a fresh token from wowauth:

curl -s "${adminUrl}/apps/${appId}/users/${userId}/token" \\
  -H "Authorization: Bearer ${configSecret}" | jq .

2) Confirm the connection works right now (this token won't stay vali pd
   forever):

curl -s "${meUrl}" \\
  -H "Authorization: Bearer ${tokenResponse.access_token}" \\
  -H "Accept: application/json"
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
