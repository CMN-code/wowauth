// tests/src/test-env.ts
//
// Fixed, well-known configuration for the ephemeral wowauth instance this
// suite spawns for itself (see server-lifecycle.ts). These aren't real
// secrets: the spawned instance talks only to the in-process mock upstream
// provider (mock-provider.ts) over a throwaway SQLite file, both created
// fresh per run, so there's nothing here worth randomizing -- and keeping
// them fixed means vitest's globalSetup process and its test-worker
// processes agree on them without needing to pass state across that
// process boundary.
export const PORT = process.env.WOWAUTH_TEST_PORT ?? "3099";
export const BASE_URL = process.env.API_BASE_URL ?? `http://localhost:${PORT}`;

export const CONFIG_SECRET = "wowauth-integration-test-config-secret";

// 32 random bytes, base64-encoded once and hardcoded -- WOWAUTH_MASTER_KEY
// only needs to decode to exactly 32 bytes (see src/crypto.rs). Not used for
// anything beyond encrypting rows in the throwaway test database.
export const WOWAUTH_MASTER_KEY = "U/KQ82nhvFYrSKFBPuEu4tQaemtJ9t+c/vF+KL3kPbs=";

export const adminHeaders = {
  Authorization: `Bearer ${CONFIG_SECRET}`,
  "Content-Type": "application/json",
};
