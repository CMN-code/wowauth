import { describe, expect, it } from "vitest";
import { createAppBody } from "../src/app-fixtures.ts";
import { client } from "../src/client.ts";
import { decryptToken, generateTestKeypair } from "../src/keys.ts";
import { MockProvider } from "../src/mock-provider.ts";
import { connectUser, DUMMY_REDIRECT_URI } from "../src/oauth-flow.ts";
import { BASE_URL } from "../src/test-env.ts";

// The full lifecycle described in docs/DESCRIPTION.md and walked through with curl in
// docs/examples/DEFAULT.md, driven end-to-end here against a real wowauth instance and a
// mock upstream provider standing in for "the third-party service" (Airtable, Nmbrs, ...).

describe("full OAuth lifecycle against a mock upstream provider", () => {
  it("registers an app, connects a user, and issues a working token end to end", async () => {
    const provider = new MockProvider();
    await provider.start();
    try {
      const { keyPair, publicKeyB64 } = await generateTestKeypair();

      // 1. Register the app against the mock provider.
      const created = await client.POST("/apps", {
        body: createAppBody({
          name: "lifecycle-test-app",
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
      const appId = created.data!.id;

      // 2. Point wowauth's own callback (the fixed redirect_url it registers with the
      // upstream provider) at itself -- only known once appId exists.
      const patched = await client.PATCH("/apps/{app_id}", {
        params: { path: { app_id: appId } },
        body: { redirect_url: `${BASE_URL}/${appId}/oauth/callback` },
      });
      expect(patched.error, JSON.stringify(patched.error)).toBeUndefined();

      // 3. Drive the browser-redirect dance (auth -> mock provider auto-approves ->
      // callback -> code exchange), the one interactive step in the real flow.
      const { tokenBody } = await connectUser({ appId, accountHint: "jane@example.com" });
      expect(tokenBody.access_token).toBeTruthy();
      // /oauth/token never returns a refresh_token -- wowauth keeps that to itself.
      expect((tokenBody as Record<string, unknown>).refresh_token).toBeUndefined();

      // 4. The authorization produced exactly one user, labeled from account_hint.
      const users = await client.GET("/apps/{app_id}/users", { params: { path: { app_id: appId } } });
      expect(users.error, JSON.stringify(users.error)).toBeUndefined();
      expect(users.data).toHaveLength(1);
      const user = users.data![0]!;
      expect(user.label).toBe("jane@example.com");

      // 5. Pull a fresh token through the management API and decrypt it with the
      // private key half of the keypair registered in step 1 -- this is the "no state
      // required in your script" path from docs/DESCRIPTION.md.
      const userToken = await client.GET("/apps/{app_id}/users/{user_id}/token", {
        params: { path: { app_id: appId, user_id: user.user_id } },
      });
      expect(userToken.error, JSON.stringify(userToken.error)).toBeUndefined();
      const plaintext = await decryptToken(
        userToken.data!.token,
        keyPair.privateKey,
        appId,
        user.user_id,
      );
      expect(plaintext).toBe(tokenBody.access_token);

      // 6. Status reflects an active, unexpired grant.
      const status = await client.GET("/apps/{app_id}/users/{user_id}/status", {
        params: { path: { app_id: appId, user_id: user.user_id } },
      });
      expect(status.data?.status).toBe("active");

      // 7. App-level status counts line up.
      const appStatus = await client.GET("/apps/{app_id}/status", { params: { path: { app_id: appId } } });
      expect(appStatus.data).toMatchObject({ user_count: 1, active_user_count: 1, needs_reauth_count: 0 });

      // 8. Revoking the user removes them entirely.
      const deleted = await client.DELETE("/apps/{app_id}/users/{user_id}", {
        params: { path: { app_id: appId, user_id: user.user_id } },
      });
      expect(deleted.response.status).toBe(200);

      const afterDelete = await client.GET("/apps/{app_id}/users/{user_id}/status", {
        params: { path: { app_id: appId, user_id: user.user_id } },
      });
      expect(afterDelete.response.status).toBe(404);
    } finally {
      await provider.stop();
    }
  });
});
