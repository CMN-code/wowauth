import { describe, expect, it } from "vitest";
import { createAppBody } from "../src/app-fixtures.ts";
import { client } from "../src/client.ts";
import { generateTestKeypair } from "../src/keys.ts";
import { MockProvider } from "../src/mock-provider.ts";
import { connectUser, DUMMY_REDIRECT_URI } from "../src/oauth-flow.ts";
import { BASE_URL, CONFIG_SECRET } from "../src/test-env.ts";

const DUMMY_ID = "00000000-0000-0000-0000-000000000000";

// Every management endpoint requires the flat CONFIG_SECRET bearer (see src/auth.rs's
// AdminAuth). Bodies are `{}` rather than omitted/valid: AdminAuth is declared before the
// Json<...> body parameter in every handler in src/handlers.rs, so a bad/incomplete body
// must still 401 before it ever gets validated -- these tests lean on that ordering.
const ADMIN_ENDPOINTS: { method: string; path: string; body?: unknown }[] = [
  { method: "POST", path: "/apps", body: {} },
  { method: "PATCH", path: `/apps/${DUMMY_ID}`, body: {} },
  { method: "GET", path: `/apps/${DUMMY_ID}/status` },
  { method: "GET", path: `/apps/${DUMMY_ID}/users` },
  { method: "DELETE", path: `/apps/${DUMMY_ID}/users/${DUMMY_ID}` },
  { method: "GET", path: `/apps/${DUMMY_ID}/users/${DUMMY_ID}/status` },
  { method: "GET", path: `/apps/${DUMMY_ID}/users/${DUMMY_ID}/token` },
];

describe("admin API authentication", () => {
  it.each(ADMIN_ENDPOINTS)("401s $method $path with no Authorization header", async ({ method, path, body }) => {
    const res = await fetch(`${BASE_URL}${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    expect(res.status).toBe(401);
  });

  it.each(ADMIN_ENDPOINTS)("401s $method $path with a wrong bearer token", async ({ method, path, body }) => {
    const res = await fetch(`${BASE_URL}${path}`, {
      method,
      headers: { Authorization: "Bearer not-the-right-secret", "Content-Type": "application/json" },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    expect(res.status).toBe(401);
  });

  it("accepts the configured CONFIG_SECRET (gets past auth to a 404 for a made-up id)", async () => {
    const res = await fetch(`${BASE_URL}/apps/${DUMMY_ID}/status`, {
      headers: { Authorization: `Bearer ${CONFIG_SECRET}` },
    });
    expect(res.status).toBe(404);
  });
});

describe("admin API app management", () => {
  it("never echoes client_secret back in an AppView, on create or read", async () => {
    const { publicKeyB64 } = await generateTestKeypair();
    const created = await client.POST("/apps", {
      body: createAppBody({
        name: "admin-api-secret-test",
        client_id: "cid",
        client_secret: "super-secret-value",
        auth_url: "https://example.com/authorize",
        token_url: "https://example.com/token",
        redirect_url: "https://example.com/callback",
        allowed_redirect_uris: [],
        public_key: publicKeyB64,
      }),
    });
    expect(created.error, JSON.stringify(created.error)).toBeUndefined();
    expect(JSON.stringify(created.data)).not.toContain("super-secret-value");
    expect(created.data).not.toHaveProperty("client_secret");
  });

  it("rejects a malformed public_key on create, without creating the app", async () => {
    const res = await client.POST("/apps", {
      body: createAppBody({
        name: "bad-key-app",
        client_id: "cid",
        client_secret: "secret",
        auth_url: "https://example.com/authorize",
        token_url: "https://example.com/token",
        redirect_url: "https://example.com/callback",
        allowed_redirect_uris: [],
        public_key: "not-a-valid-key",
      }),
    });
    expect(res.response.status).toBe(400);
  });

  it("rejects a malformed public_key on update, leaving the app untouched", async () => {
    const { publicKeyB64 } = await generateTestKeypair();
    const created = await client.POST("/apps", {
      body: createAppBody({
        name: "bad-key-update-app",
        client_id: "cid",
        client_secret: "secret",
        auth_url: "https://example.com/authorize",
        token_url: "https://example.com/token",
        redirect_url: "https://example.com/callback",
        allowed_redirect_uris: [],
        public_key: publicKeyB64,
      }),
    });
    const appId = created.data!.id;

    const rejected = await client.PATCH("/apps/{app_id}", {
      params: { path: { app_id: appId } },
      body: { public_key: "not-a-valid-key" },
    });
    expect(rejected.response.status).toBe(400);

    const unchanged = await client.GET("/apps/{app_id}/status", { params: { path: { app_id: appId } } });
    expect(unchanged.data?.name).toBe("bad-key-update-app");
  });

  it("rotating public_key wipes every connected user under that app", async () => {
    const provider = new MockProvider();
    await provider.start();
    try {
      const { publicKeyB64 } = await generateTestKeypair();
      const created = await client.POST("/apps", {
        body: createAppBody({
          name: "key-rotation-app",
          client_id: "cid",
          client_secret: "secret",
          auth_url: provider.authUrl,
          token_url: provider.tokenUrl,
          redirect_url: "placeholder",
          allowed_redirect_uris: [DUMMY_REDIRECT_URI],
          public_key: publicKeyB64,
        }),
      });
      const appId = created.data!.id;
      await client.PATCH("/apps/{app_id}", {
        params: { path: { app_id: appId } },
        body: { redirect_url: `${BASE_URL}/${appId}/oauth/callback` },
      });

      await connectUser({ appId });
      const before = await client.GET("/apps/{app_id}/users", { params: { path: { app_id: appId } } });
      expect(before.data).toHaveLength(1);

      const { publicKeyB64: rotatedKey } = await generateTestKeypair();
      const rotated = await client.PATCH("/apps/{app_id}", {
        params: { path: { app_id: appId } },
        body: { public_key: rotatedKey },
      });
      expect(rotated.error, JSON.stringify(rotated.error)).toBeUndefined();

      const after = await client.GET("/apps/{app_id}/users", { params: { path: { app_id: appId } } });
      expect(after.data).toHaveLength(0);
    } finally {
      await provider.stop();
    }
  });
});
