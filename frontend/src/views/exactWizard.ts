import { api } from "../api";
import { getConfigSecret } from "../auth";
import { EXACT_APP_CENTER_URL, EXACT_COUNTRIES, EXACT_ME_PATH } from "../exact";
import { escapeHtml, reportError } from "../util";
import { generateX25519KeyPair, pkceChallenge, randomPkceVerifier, randomState } from "../webcrypto";

type Step = 1 | 2 | 3 | 4;

const DEFAULT_PUBLIC_URL = "https://wowauth.fuse.creativemedianetwork.com";

interface Model {
  step: Step;
  publicUrl: string;
  countryDomain: string;
  connectionName: string;
  publicKeyB64: string;
  privateKeyB64: string;
  redirectUri: string;
  appId: string;
  accountHint: string;
  oauthState: string;
  pkceVerifier: string;
  accessToken: string;
  userId: string;
  userLabel?: string;
}

function freshModel(): Model {
  return {
    step: 1,
    publicUrl: DEFAULT_PUBLIC_URL,
    countryDomain: EXACT_COUNTRIES[0]!.domain,
    connectionName: "exact-online",
    publicKeyB64: "",
    privateKeyB64: "",
    redirectUri: "",
    appId: "",
    accountHint: "",
    oauthState: "",
    pkceVerifier: "",
    accessToken: "",
    userId: "",
  };
}

let model: Model = freshModel();

export async function renderExactWizard(container: HTMLElement): Promise<void> {
  model = freshModel();
  render(container);
}

async function finishAfterLogin(code: string): Promise<void> {
  const res = await fetch(`/${model.appId}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: model.redirectUri,
      code_verifier: model.pkceVerifier,
    }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Token exchange failed: ${text}`);
  const token = JSON.parse(text) as { access_token: string };
  model.accessToken = token.access_token;

  const users = await api.listUsers(model.appId);
  const user = users[0];
  if (!user) throw new Error("No connected user found -- something went wrong during login.");
  model.userId = user.user_id;
  model.userLabel = user.label ?? undefined;
}

function render(container: HTMLElement): void {
  switch (model.step) {
    case 1:
      return renderStep1(container);
    case 2:
      return renderStep2(container);
    case 3:
      void renderStep3(container);
      return;
    case 4:
      return renderStep4(container);
  }
}

function wireBack(container: HTMLElement, prevStep: Step): void {
  container.querySelector("#back")?.addEventListener("click", () => {
    model.step = prevStep;
    render(container);
  });
}

function renderStep1(container: HTMLElement): void {
  container.innerHTML = `
    <div class="card">
      <h2>Connect Exact Online</h2>
      <form id="step-form">
        <label>wowauth's public URL
          <span class="hint">Where Exact (and you, later) can reach this wowauth instance. Must be a real https address — Exact won't accept localhost.</span>
          <input type="url" name="publicUrl" value="${escapeHtml(model.publicUrl)}" required />
        </label>
        <label>Exact Online country
          <span class="hint">Exact runs the same API on a different domain per country — pick whichever matches where the Exact account was created.</span>
          <select name="country">
            ${EXACT_COUNTRIES.map(
              (c) =>
                `<option value="${escapeHtml(c.domain)}" ${c.domain === model.countryDomain ? "selected" : ""}>${escapeHtml(c.label)} (${escapeHtml(c.domain)})</option>`,
            ).join("")}
          </select>
        </label>
        <label>Connection name
          <span class="hint">A short name for this app registration in wowauth.</span>
          <input type="text" name="connectionName" value="${escapeHtml(model.connectionName)}" required />
        </label>
        <div class="row"><button type="submit">Continue</button></div>
        <p class="error" id="step-error"></p>
      </form>
    </div>
  `;
  const form = container.querySelector<HTMLFormElement>("#step-form")!;
  const errorEl = container.querySelector<HTMLElement>("#step-error")!;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorEl.textContent = "";
    const data = new FormData(form);
    model.publicUrl = String(data.get("publicUrl") ?? "").trim().replace(/\/+$/, "") || DEFAULT_PUBLIC_URL;
    model.countryDomain = String(data.get("country") ?? "").trim() || EXACT_COUNTRIES[0]!.domain;
    model.connectionName = String(data.get("connectionName") ?? "").trim() || "exact-online";
    const submitBtn = form.querySelector<HTMLButtonElement>('button[type="submit"]')!;
    submitBtn.disabled = true;
    try {
      if (!model.publicKeyB64) {
        try {
          const kp = await generateX25519KeyPair();
          model.publicKeyB64 = kp.publicKeyB64;
          model.privateKeyB64 = kp.privateKeyB64;
        } catch (err) {
          throw new Error(
            `Couldn't generate an encryption key in this browser: ${err instanceof Error ? err.message : String(err)}. Try a recent version of Chrome, Firefox, or Safari.`,
          );
        }
      }
      if (!model.appId) {
        model.redirectUri = `${model.publicUrl}/health`;
        const app = await api.createApp({
          name: model.connectionName,
          client_id: "pending-exact-client-id",
          client_secret: "pending-exact-secret",
          auth_url: `https://${model.countryDomain}/api/oauth2/auth`,
          token_url: `https://${model.countryDomain}/api/oauth2/token`,
          redirect_url: "placeholder-set-in-the-next-step",
          allowed_redirect_uris: [model.redirectUri],
          // Exact has no OAuth scopes -- access is all-or-nothing, governed
          // by whatever the logging-in user can already see and do inside
          // Exact. token_auth_method "basic" is wowauth's default and
          // exactly what Exact's token endpoint expects.
          scopes: "",
          token_auth_method: "basic",
          extra_auth_params: {},
          extra_headers: {},
          public_key: model.publicKeyB64,
        });
        model.appId = app.id;
        await api.updateApp(app.id, { redirect_url: `${model.publicUrl}/${app.id}/oauth/callback` });
      }
      model.step = 2;
      render(container);
    } catch (err) {
      reportError(err, errorEl);
    } finally {
      submitBtn.disabled = false;
    }
  });
}

function renderStep2(container: HTMLElement): void {
  const wowauthCallback = `${model.publicUrl}/${model.appId}/oauth/callback`;
  container.innerHTML = `
    <div class="card">
      <p class="hint">Register the app in Exact's App Center</p>
      <p>Open <a href="${EXACT_APP_CENTER_URL}" target="_blank" rel="noopener">start.exactonline.nl</a> and sign in. Navigate to "Import/Export" -> "App-registraties" and create a new integration with redirect url:</p>
      <table>
        <tbody>
          <tr><th>App name</th><td><code>${escapeHtml(model.connectionName)}</code></td></tr>
          <tr><th>Redirect URI</th><td><code>${escapeHtml(wowauthCallback)}</code></td></tr>
        </tbody>
      </table>
      <p class="hint">Fill in anything for the remaining descriptive fields — they don't affect how the connection works. Submit the form, then copy the Client ID and Client Secret it gives you below.</p>
      <form id="step-form">
        <label>Exact Client ID
          <input type="text" name="clientId" required />
        </label>
        <label>Exact Client Secret
          <input type="password" name="clientSecret" autocomplete="off" required />
        </label>
        <div class="row">
          <button type="button" class="secondary" id="back">Back</button>
          <button type="submit">Save & continue</button>
        </div>
        <p class="error" id="step-error"></p>
      </form>
    </div>
  `;
  wireBack(container, 1);
  const form = container.querySelector<HTMLFormElement>("#step-form")!;
  const errorEl = container.querySelector<HTMLElement>("#step-error")!;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorEl.textContent = "";
    const data = new FormData(form);
    const submitBtn = form.querySelector<HTMLButtonElement>('button[type="submit"]')!;
    submitBtn.disabled = true;
    try {
      await api.updateApp(model.appId, {
        client_id: String(data.get("clientId") ?? "").trim(),
        client_secret: String(data.get("clientSecret") ?? "").trim(),
      });
      model.step = 3;
      render(container);
    } catch (err) {
      reportError(err, errorEl);
    } finally {
      submitBtn.disabled = false;
    }
  });
}

async function renderStep3(container: HTMLElement): Promise<void> {
  // A fresh nonce/verifier every time this step is (re-)entered -- never
  // reused across visits, and still in memory (no tab navigation happens)
  // by the time the user pastes the redirect URL back.
  model.oauthState = randomState();
  model.pkceVerifier = randomPkceVerifier();
  const challenge = await pkceChallenge(model.pkceVerifier);

  const buildAuthorizeUrl = (): string => {
    const authorizeParams = new URLSearchParams({
      redirect_uri: model.redirectUri,
      state: model.oauthState,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    if (model.accountHint) authorizeParams.set("account_hint", model.accountHint);
    return `${model.publicUrl}/${model.appId}/oauth/auth?${authorizeParams}`;
  };

  container.innerHTML = `
    <div class="card">
      <p class="hint">Log in to Exact</p>
      <p>Open the link below in a new tab, log in to Exact, and approve access. You'll land on wowauth's health-check page — copy the full URL from your browser's address bar and paste it below.</p>
      <label>A memorable label for this Exact account (e.g. the company name)
        <span class="hint">Optional</span>
        <input type="text" id="account-hint" value="${escapeHtml(model.accountHint)}" />
      </label>
      <p class="hint">Exact's authorization codes are single-use and expire in roughly 3 minutes — paste the redirected URL back promptly.</p>
      <p><a id="go" href="${escapeHtml(buildAuthorizeUrl())}" target="_blank" rel="noopener"><code>${escapeHtml(buildAuthorizeUrl())}</code></a></p>
      <div class="row">
        <button class="secondary" id="back">Back</button>
      </div>
      <form id="step-form">
        <label>Redirect URL
          <span class="hint">The full URL you landed on (with ?code=... in it) after approving access at Exact.</span>
          <input type="text" name="redirectedUrl" required />
        </label>
        <div class="row"><button type="submit">Continue</button></div>
        <p class="error" id="step-error"></p>
      </form>
    </div>
  `;
  wireBack(container, 2);
  container.querySelector<HTMLInputElement>("#account-hint")!.addEventListener("input", (e) => {
    model.accountHint = (e.target as HTMLInputElement).value;
    const url = buildAuthorizeUrl();
    const link = container.querySelector<HTMLAnchorElement>("#go")!;
    link.href = url;
    link.innerHTML = `<code>${escapeHtml(url)}</code>`;
  });

  const form = container.querySelector<HTMLFormElement>("#step-form")!;
  const errorEl = container.querySelector<HTMLElement>("#step-error")!;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorEl.textContent = "";
    const data = new FormData(form);
    const submitBtn = form.querySelector<HTMLButtonElement>('button[type="submit"]')!;
    submitBtn.disabled = true;
    try {
      let parsed: URL;
      try {
        parsed = new URL(String(data.get("redirectedUrl") ?? "").trim());
      } catch {
        throw new Error("That doesn't look like a valid URL.");
      }
      const oauthError = parsed.searchParams.get("error");
      if (oauthError) {
        throw new Error(
          `Exact reported an error during login: ${oauthError} ${parsed.searchParams.get("error_description") ?? ""}`,
        );
      }
      if (parsed.searchParams.get("state") !== model.oauthState) {
        throw new Error("The state in that URL didn't match what we sent -- aborting for safety.");
      }
      const code = parsed.searchParams.get("code");
      if (!code) throw new Error("No authorization code was found in that URL.");
      await finishAfterLogin(code);
      model.step = 4;
      render(container);
    } catch (err) {
      reportError(err, errorEl);
    } finally {
      submitBtn.disabled = false;
    }
  });
}

function renderStep4(container: HTMLElement): void {
  const configSecret = getConfigSecret() ?? "";
  const secrets = {
    specific: {},
    wowauth: {
      name: model.connectionName,
      app_id: model.appId,
      user_id: model.userId,
      admin_url: model.publicUrl,
      config_secret: configSecret,
      private_key: { format: "x25519-raw-base64", value: model.privateKeyB64 },
    },
  };
  const secretsJson = JSON.stringify(secrets, null, 2);
  // The private key has now been handed to the user (in the JSON above, for
  // them to save) -- wowauth itself never sees it, and there's no reason to
  // keep holding it in memory beyond this point.
  model.privateKeyB64 = "";

  const meUrl = `https://${model.countryDomain}${EXACT_ME_PATH}`;
  const tokenCurl = `curl -s "${model.publicUrl}/apps/${model.appId}/users/${model.userId}/token" \\\n  -H "Authorization: Bearer ${configSecret}" | jq .`;
  const smokeCurl = `curl -s "${meUrl}" \\\n  -H "Authorization: Bearer ${model.accessToken}" \\\n  -H "Accept: application/json"`;

  container.innerHTML = `
    <div class="card">
      <h2>✓ Connected</h2>
      <p>${escapeHtml(model.connectionName)} is connected${model.userLabel ? ` (labeled "${escapeHtml(model.userLabel)}")` : ""}. Save the JSON below now — the private key is never shown again.</p>
      <textarea readonly rows="14" id="secrets-json">${escapeHtml(secretsJson)}</textarea>
      <div class="row">
        <button id="copy-json" class="secondary">Copy JSON</button>
        <button id="download-json" class="secondary">Download exact-secrets.json</button>
      </div>
    </div>

    <div class="card">
      <h3>Check this connection any time</h3>
      <p class="hint">Get a fresh token from wowauth:</p>
      <textarea readonly rows="2">${escapeHtml(tokenCurl)}</textarea>
      <p class="hint">Confirm the connection works against Exact right now (this specific access token won't stay valid forever) — this also reports which division (administration) the token defaults to:</p>
      <textarea readonly rows="3">${escapeHtml(smokeCurl)}</textarea>
    </div>

    <div class="row">
      <a href="#/"><button class="secondary">Done</button></a>
    </div>
  `;

  container.querySelector("#copy-json")!.addEventListener("click", () => {
    void navigator.clipboard.writeText(secretsJson);
  });
  container.querySelector("#download-json")!.addEventListener("click", () => {
    const blob = new Blob([secretsJson], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "exact-secrets.json";
    a.click();
    URL.revokeObjectURL(url);
  });
}
