import { beforeAll, describe, expect, it } from "vitest";
import { createAppBody } from "../src/app-fixtures.ts";
import { client } from "../src/client.ts";
import { generateTestKeypair } from "../src/keys.ts";
import { MockProvider } from "../src/mock-provider.ts";
import {
  completeAuthorization,
  DUMMY_REDIRECT_URI,
  exchangeCode,
  oauthErrorBody,
  startAuthorize,
} from "../src/oauth-flow.ts";
import { BASE_URL } from "../src/test-env.ts";

// The "negative space" companion to lifecycle.test.ts: every test here expects a request
// to fail, and asserts it fails the *right* way -- see src/oauth_handlers.rs and
// src/pkce.rs for where each of these checks originates.

describe("OAuth flow error handling (negative space)", () => {
  let provider: MockProvider;
  let appId: string;

  beforeAll(async () => {
    provider = new MockProvider();
    await provider.start();

    const { publicKeyB64 } = await generateTestKeypair();
    const created = await client.POST("/apps", {
      body: createAppBody({
        name: "lifecycle-errors-app",
        client_id: "test-client-id",
        client_secret: "test-client-secret",
        auth_url: provider.authUrl,
        token_url: provider.tokenUrl,
        redirect_url: "placeholder-set-below",
        allowed_redirect_uris: [DUMMY_REDIRECT_URI],
        scopes: "read write",
        public_key: publicKeyB64,
      }),
    });
    expect(created.error, JSON.stringify(created.error)).toBeUndefined();
    appId = created.data!.id;

    const patched = await client.PATCH("/apps/{app_id}", {
      params: { path: { app_id: appId } },
      body: { redirect_url: `${BASE_URL}/${appId}/oauth/callback` },
    });
    expect(patched.error, JSON.stringify(patched.error)).toBeUndefined();

    return async () => {
      await provider.stop();
    };
  });

  it("404s /oauth/auth for an app that doesn't exist", async () => {
    const { res } = await startAuthorize({ appId: "00000000-0000-0000-0000-000000000000" });
    expect(res.status).toBe(404);
  });

  it("404s the discovery document for an app that doesn't exist", async () => {
    const res = await fetch(`${BASE_URL}/00000000-0000-0000-0000-000000000000/.well-known/openid-configuration`);
    expect(res.status).toBe(404);
  });

  it("400s /oauth/auth when code_challenge_method isn't S256", async () => {
    const { res } = await startAuthorize({ appId, codeChallengeMethod: "plain" });
    expect(res.status).toBe(400);
  });

  it("400s /oauth/auth when redirect_uri isn't allow-listed", async () => {
    const { res } = await startAuthorize({ appId, redirectUri: "https://evil.example.com/callback" });
    expect(res.status).toBe(400);
  });

  it("rejects a code exchange with the wrong PKCE verifier", async () => {
    const { finalUrl, redirectUri } = await completeAuthorization({ appId });
    const code = finalUrl.searchParams.get("code")!;
    expect(code).toBeTruthy();

    const res = await exchangeCode({ appId, code, redirectUri, verifier: "not-the-right-verifier" });
    expect(res.status).toBe(400);
    const body = await oauthErrorBody(res);
    expect(body.error).toBe("invalid_grant");
  });

  it("rejects a code exchange whose redirect_uri doesn't match the one used to authorize", async () => {
    const { verifier, finalUrl } = await completeAuthorization({ appId });
    const code = finalUrl.searchParams.get("code")!;

    const res = await exchangeCode({ appId, code, redirectUri: "https://example.com/different", verifier });
    expect(res.status).toBe(400);
  });

  it("rejects reusing an already-redeemed code", async () => {
    const { verifier, redirectUri, finalUrl } = await completeAuthorization({ appId });
    const code = finalUrl.searchParams.get("code")!;

    const first = await exchangeCode({ appId, code, redirectUri, verifier });
    expect(first.status).toBe(200);

    const second = await exchangeCode({ appId, code, redirectUri, verifier });
    expect(second.status).toBe(400);
    const body = await oauthErrorBody(second);
    expect(body.error).toBe("invalid_grant");
  });

  it("rejects an unknown code outright", async () => {
    const res = await exchangeCode({
      appId,
      code: "totally-made-up-code",
      redirectUri: DUMMY_REDIRECT_URI,
      verifier: "whatever",
    });
    expect(res.status).toBe(400);
  });

  it("400s an unsupported grant_type at /oauth/token", async () => {
    const res = await fetch(`${BASE_URL}/${appId}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials" }),
    });
    expect(res.status).toBe(400);
    const body = await oauthErrorBody(res);
    expect(body.error).toBe("unsupported_grant_type");
  });

  it("surfaces an upstream denial (e.g. invalid_scope) as an error redirect, not a crash", async () => {
    provider.behavior.denyAuthorizeWith = "invalid_scope";
    try {
      const { finalUrl } = await completeAuthorization({ appId });
      expect(finalUrl.searchParams.get("error")).toBe("invalid_scope");
    } finally {
      provider.behavior.denyAuthorizeWith = undefined;
    }
  });
});
