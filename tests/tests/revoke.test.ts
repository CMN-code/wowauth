import { beforeAll, describe, expect, it } from "vitest";
import { createAppBody } from "../src/app-fixtures.ts";
import { client } from "../src/client.ts";
import { generateTestKeypair } from "../src/keys.ts";
import { MockProvider } from "../src/mock-provider.ts";
import { connectUser, DUMMY_REDIRECT_URI } from "../src/oauth-flow.ts";
import { BASE_URL } from "../src/test-env.ts";

// POST /{app_id}/oauth/revoke -- RFC 7009. Unauthenticated by design (whoever holds the
// token can revoke it, not just an admin), and always 200 whether or not the token was
// recognized, so it can't be used as an oracle to probe for valid tokens (see
// oauth_handlers.rs's RevokeResponse doc comment).

describe("token revocation (RFC 7009)", () => {
  let provider: MockProvider;
  let appId: string;

  beforeAll(async () => {
    provider = new MockProvider();
    await provider.start();

    const { publicKeyB64 } = await generateTestKeypair();
    const created = await client.POST("/apps", {
      body: createAppBody({
        name: "revoke-test-app",
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

    return async () => {
      await provider.stop();
    };
  });

  async function revoke(token: string) {
    return fetch(`${BASE_URL}/${appId}/oauth/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token }),
    });
  }

  it("200s an unrecognized token without deleting anything (no oracle)", async () => {
    await connectUser({ appId, accountHint: "bystander@example.com" });
    const usersBefore = await client.GET("/apps/{app_id}/users", { params: { path: { app_id: appId } } });
    const countBefore = usersBefore.data!.length;

    const res = await revoke("this-token-was-never-issued");
    expect(res.status).toBe(200);

    const usersAfter = await client.GET("/apps/{app_id}/users", { params: { path: { app_id: appId } } });
    expect(usersAfter.data).toHaveLength(countBefore);
  });

  it("revoking a real access token deletes that user and leaves others alone", async () => {
    const bystanders = await client.GET("/apps/{app_id}/users", { params: { path: { app_id: appId } } });
    const countBefore = bystanders.data!.length;

    const { tokenBody } = await connectUser({ appId, accountHint: "to-be-revoked@example.com" });

    const res = await revoke(tokenBody.access_token);
    expect(res.status).toBe(200);

    const users = await client.GET("/apps/{app_id}/users", { params: { path: { app_id: appId } } });
    expect(users.data).toHaveLength(countBefore);
    expect(users.data!.some((u) => u.label === "to-be-revoked@example.com")).toBe(false);
    expect(users.data!.some((u) => u.label === "bystander@example.com")).toBe(true);
  });
});
