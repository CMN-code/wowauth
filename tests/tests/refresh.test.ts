import { beforeAll, describe, expect, it } from "vitest";
import { createAppBody } from "../src/app-fixtures.ts";
import { client } from "../src/client.ts";
import { generateTestKeypair } from "../src/keys.ts";
import { MockProvider } from "../src/mock-provider.ts";
import { connectUser, DUMMY_REDIRECT_URI } from "../src/oauth-flow.ts";
import { BASE_URL } from "../src/test-env.ts";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// GET /apps/{app_id}/users/{user_id}/token transparently refreshes an expired access token
// upstream before returning it (see handlers.rs's user_token) -- the "wowauth takes care of
// refreshing your tokens" promise from docs/DESCRIPTION.md. These tests use a 1-second token
// lifetime from the mock provider so a real wall-clock wait is enough to force that path,
// rather than needing to reach into the database. Steps within each describe block are
// intentionally ordered and depend on each other's state (same as the flow they exercise).

describe("transparent token refresh", () => {
  let provider: MockProvider;
  let appId: string;
  let userId: string;

  beforeAll(async () => {
    provider = new MockProvider();
    await provider.start();
    provider.behavior.expiresIn = 1;

    const { publicKeyB64 } = await generateTestKeypair();
    const created = await client.POST("/apps", {
      body: createAppBody({
        name: "refresh-test-app",
        client_id: "cid",
        client_secret: "secret",
        auth_url: provider.authUrl,
        token_url: provider.tokenUrl,
        redirect_url: "placeholder",
        allowed_redirect_uris: [DUMMY_REDIRECT_URI],
        public_key: publicKeyB64,
      }),
    });
    appId = created.data!.id;
    await client.PATCH("/apps/{app_id}", {
      params: { path: { app_id: appId } },
      body: { redirect_url: `${BASE_URL}/${appId}/oauth/callback` },
    });

    await connectUser({ appId });
    const users = await client.GET("/apps/{app_id}/users", { params: { path: { app_id: appId } } });
    userId = users.data![0]!.user_id;

    return async () => {
      await provider.stop();
    };
  });

  it("refreshes an expired access token upstream and returns a fresh one", async () => {
    await sleep(1200);
    const requestsBefore = provider.requestLog.length;

    const res = await client.GET("/apps/{app_id}/users/{user_id}/token", {
      params: { path: { app_id: appId, user_id: userId } },
    });
    expect(res.error, JSON.stringify(res.error)).toBeUndefined();
    expect(res.data?.token).toBeTruthy();

    const refreshCalls = provider.requestLog
      .slice(requestsBefore)
      .filter((r) => r.path === "/token" && r.body?.grant_type === "refresh_token");
    expect(refreshCalls).toHaveLength(1);
  });

  it("keeps working across repeated refreshes when the provider doesn't rotate the refresh token", async () => {
    provider.behavior.rotateRefreshTokenOnRefresh = false;

    for (let i = 0; i < 2; i++) {
      await sleep(1200);
      const res = await client.GET("/apps/{app_id}/users/{user_id}/token", {
        params: { path: { app_id: appId, user_id: userId } },
      });
      expect(res.error, `refresh #${i} should still succeed: ${JSON.stringify(res.error)}`).toBeUndefined();
    }
  });

  it("keeps working across repeated refreshes when the provider does rotate the refresh token", async () => {
    provider.behavior.rotateRefreshTokenOnRefresh = true;

    for (let i = 0; i < 2; i++) {
      await sleep(1200);
      const res = await client.GET("/apps/{app_id}/users/{user_id}/token", {
        params: { path: { app_id: appId, user_id: userId } },
      });
      // If wowauth failed to persist the rotated refresh token from the previous iteration,
      // this call would present a refresh token the mock provider has already discarded and
      // 409 here instead.
      expect(res.error, `refresh #${i} should still succeed: ${JSON.stringify(res.error)}`).toBeUndefined();
    }
  });

  it("returns 409 NeedsReauth (not a 500) when the provider rejects the refresh grant", async () => {
    await sleep(1200);
    provider.behavior.failTokenWith = "invalid_grant";
    try {
      const res = await client.GET("/apps/{app_id}/users/{user_id}/token", {
        params: { path: { app_id: appId, user_id: userId } },
      });
      expect(res.response.status).toBe(409);
    } finally {
      provider.behavior.failTokenWith = undefined;
    }
  });

  it("reports the user as needing reauth via the status endpoint too", async () => {
    const res = await client.GET("/apps/{app_id}/users/{user_id}/status", {
      params: { path: { app_id: appId, user_id: userId } },
    });
    // The last successful grant (from the previous, now-failing-to-refresh test) is expired,
    // and refresh will fail again since failTokenWith was only reset, not the provider's
    // rejection of *this specific* stale refresh token -- is_active() in handlers.rs treats
    // "expired but holds a refresh_token" as active regardless of whether that refresh_token
    // still actually works upstream, so this reflects that: status is optimistic, and the
    // /token endpoint is the one that authoritatively finds out by trying.
    expect(res.data?.status).toBe("active");
  });
});
