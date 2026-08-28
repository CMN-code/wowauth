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
 * You'll need a Nmbrs partner account to add a custom integration -- do that
 * at https://partner-portal.nmbrsapp.com/integrations before running this
 * script (step 8 below will ask you to register the app there).
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

// offline_access is mandatory -- without it Nmbrs never issues a refresh
// token, and wowauth would have nothing to renew with once the access
// token expires. Always requested; not part of the interactive picker below.
const NMBRS_MANDATORY_SCOPES = ["offline_access"];

// The full read-only-and-otherwise scope set Nmbrs documents for partner
// apps. Deliberately no "openid" here: despite looking like standard OIDC,
// Nmbrs doesn't grant it to partner-app clients and requesting it is a
// common cause of "Invalid scope" errors. Presented as a checklist at the
// start of the walkthrough -- if Nmbrs rejects one of these for your
// specific partner client, deselect it there and re-run the script.
const NMBRS_OPTIONAL_SCOPES = [
  "employee.employment",
  "employee.employment.read",
  "employee.info",
  "employee.info.read",
  "employee.payment",
  "employee.payment.read",
  "employee.leave",
  "employee.leave.read",
  "employee.orgstructure",
  "employee.orgstructure.read",
  "employee.bankaccount.read",
  "employee.bankaccount",
  "employee.document.read",
  "employee.document",
  "employee.payrollsettings",
  "employee.payrollsettings.read",
  "company.info",
  "company.info.read",
  "company.payrollsettings.read",
  "company.leave.read",
  "user.info.read",
];

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

/**
 * Interactive checkbox picker for scopes: ↑/↓ to move, space to toggle,
 * enter to confirm. Every optional scope starts checked -- Nmbrs partner
 * clients are commonly scoped down rather than up, so "everything, then
 * trim" is the safer default.
 *
 * `rl` already put stdin into keypress-emitting mode (readline does this for
 * any TTY input at construction time) and attached its own keypress listener
 * for line editing. That listener would otherwise fight this one -- readline
 * would try to interpret arrow keys as history navigation and space as text
 * input -- so it's detached for the duration of the picker and reattached
 * once done, leaving later rl.question() calls unaffected.
 */
async function selectScopes(mandatory: string[], optional: string[]): Promise<string[]> {
  if (!process.stdin.isTTY) {
    console.log("  (non-interactive terminal -- requesting every documented scope)");
    return [...mandatory, ...optional];
  }

  const selected = new Set(optional);
  let cursor = 0;

  const draw = () => {
    for (const [i, scope] of optional.entries()) {
      const marker = selected.has(scope) ? "[x]" : "[ ]";
      const pointer = i === cursor ? "›" : " ";
      process.stdout.write(`\x1b[2K\r  ${pointer} ${marker} ${scope}\n`);
    }
  };

  console.log(`  (${mandatory.join(", ")} is always requested -- wowauth needs it to refresh tokens)\n`);
  console.log("  ↑/↓ move    space toggle    enter confirm\n");
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
      if (key.name === "up") cursor = (cursor - 1 + optional.length) % optional.length;
      else if (key.name === "down") cursor = (cursor + 1) % optional.length;
      else if (key.name === "space") {
        const scope = optional[cursor]!;
        if (selected.has(scope)) selected.delete(scope);
        else selected.add(scope);
      } else if (key.name === "return") {
        process.stdin.off("keypress", onKeypress);
        resolve();
        return;
      } else {
        return;
      }
      process.stdout.write(`\x1b[${optional.length}A`);
      draw();
    };
    process.stdin.on("keypress", onKeypress);
  });

  process.stdin.setRawMode(wasRaw);
  for (const listener of readlineKeypressListeners) process.stdin.on("keypress", listener as never);
  console.log("");

  return [...mandatory, ...optional.filter((s) => selected.has(s))];
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
Connect a Nmbrs account to wowauth
===================================

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

  step(2, "Your Nmbrs subscription key");
  explain(`
    Go to https://developer.payroll.nmbrs.com/profile and copy a primary subscription key here.
`);
  const subscriptionKey = await askRequired("Nmbrs subscription key");

  step(3, "Generate an encryption key for your tokens");
  const { publicKey, privateKey } = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
  // The DER SubjectPublicKeyInfo/PrivateKeyInfo encodings for X25519 are
  // both a fixed header followed by the raw 32-byte key -- wowauth wants
  // just the raw key, base64-encoded, and so does nmbrs-secrets.json below.
  const publicKeyB64 = publicKey.subarray(publicKey.length - 32).toString("base64");
  const privateKeyB64 = privateKey.subarray(privateKey.length - 32).toString("base64");
  console.log("  ✓ Key pair generated");

  step(4, "Where the browser lands after logging in");
  const redirectUri = `${publicUrl}/health`;
  console.log(`  ✓ Using ${redirectUri}`);

  step(5, "Choose which Nmbrs scopes to request");
  explain(`
Turn off anything you don't want to allow.
`);
  const scopes = (await selectScopes(NMBRS_MANDATORY_SCOPES, NMBRS_OPTIONAL_SCOPES)).join(" ");
  console.log(`  ✓ Requesting: ${scopes}`);

  step(6, "Register the connection with wowauth");
  const reuseName = await ask(
    "Reuse an existing wowauth connection by name (e.g. one a previous, incomplete run of\n" +
      "  this script already registered), or leave blank to register a new one",
    "",
  );

  let appId: string;
  let connectionName: string;
  // Whether step 8 below still needs to register a (new) app in Nmbrs's
  // portal -- true for a brand-new connection, and for a reused one that
  // never got past step 8 last time (still holding the placeholder
  // credentials set below).
  let needsNmbrsRegistration = true;

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
    needsNmbrsRegistration = existing.client_id === "pending-nmbrs-client-id";
    console.log(`  ✓ Reusing "${connectionName}" (id: ${appId})`);
    console.log("  (ignoring the scopes picked in step 5 -- reusing whatever's already registered)");

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
    connectionName = await ask("A short name for this connection", "nmbrs");
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
        scopes,
        public_key: publicKeyB64,
      },
      maskBodyKeys: ["client_secret", "public_key"],
      maskHeaders: ["Authorization"],
      quiet: true,
    });
    appId = app.id;
    console.log(`  ✓ Registered (id: ${appId})`);
  }

  step(7, "Point wowauth's own callback at itself");
  const wowauthCallback = `${publicUrl}/${appId}/oauth/callback`;
  await call("PATCH", `${adminUrl}/apps/${appId}`, {
    headers: adminHeaders,
    json: { redirect_url: wowauthCallback },
    maskHeaders: ["Authorization"],
    quiet: true,
  });
  console.log(`  ✓ Done`);

  step(8, "Register the app in Nmbrs's own portal");
  explain(`
Go to https://partner-portal.nmbrsapp.com/integrations and create a new app:

    App name:          ${connectionName}
    Application type:  Web
    Redirect URL:      ${wowauthCallback}
    CMN-icon URL:      https://cdn.prod.website-files.com/664d8603947eced5ca9765b0/664dd23030ceb92425696ff4_CMN-logo-footer.svg

    (fill in anything for description / privacy policy)

Submit the form, then copy the Client ID and Client Secret it gives you.
`);
  await rl.question("Press Enter once you have your Nmbrs Client ID and Client Secret ready...");
  const nmbrsClientId = await askRequired("Paste the Client ID Nmbrs gave you");
  const nmbrsClientSecret = await askRequired("Paste the Client Secret Nmbrs gave you");
  await rl.question(
    "Go back to the Nmbrs dialog and click Save (the app isn't live on Nmbrs's side until you do -- " +
      "logging in before this point fails with a generic error page). Press Enter once you've saved it...",
  );

  await call("PATCH", `${adminUrl}/apps/${appId}`, {
    headers: adminHeaders,
    json: { client_id: nmbrsClientId, client_secret: nmbrsClientSecret },
    maskBodyKeys: ["client_secret"],
    maskHeaders: ["Authorization"],
    quiet: true,
  });
  console.log("  ✓ wowauth now has your real Nmbrs credentials.");

  step(9, "Log in to Nmbrs once, in your browser");
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
Open this link, log in to Nmbrs, and approve access:

  ${authorizeUrl}

You'll land on a mostly-blank page. Copy the full URL from your browser's
address bar and paste it below.
`);
  console.log(
    "  (If you see an error page instead of a login page, go back to step 5,\n" +
      "   turn off the scope it's complaining about, and run this again.)",
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

  step(10, "Exchange the login for a token");
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

  step(11, "Find the connected user");
  const users = await call<{ user_id: string; label?: string }[]>("GET", `${adminUrl}/apps/${appId}/users`, {
    headers: adminHeaders,
    maskHeaders: ["Authorization"],
    quiet: true,
  });
  const userId = users[0]?.user_id;
  if (!userId) fail("No connected user found -- something went wrong above.");
  console.log(`  ✓ user_id: ${userId}${users[0]?.label ? ` (labeled "${users[0].label}")` : ""}`);

  step(12, "Save these");
  const secretsPath = "./nmbrs-secrets.json";
  const secrets = {
    specific: { subscription_key: subscriptionKey, },
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

  step(13, "Prove it works");
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

  Here's today's plain access token, to prove the Nmbrs connection itself
  works right now:
`);

  const smokeTest = await fetch(NMBRS_SMOKE_TEST_URL, {
    headers: {
      Authorization: `Bearer ${tokenResponse.access_token}`,
      "X-Subscription-Key": subscriptionKey,
    },
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
All done. Two commands to check this connection any time:

1) Get a fresh token from wowauth:

curl -s "${adminUrl}/apps/${appId}/users/${userId}/token" \\
  -H "Authorization: Bearer ${configSecret}" | jq .

2) Confirm the connection works right now (this token won't stay valid
   forever):

curl -s "${NMBRS_SMOKE_TEST_URL}" \\
  -H "Authorization: Bearer ${tokenResponse.access_token}" \\
  -H "X-Subscription-Key: ${subscriptionKey}"
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
