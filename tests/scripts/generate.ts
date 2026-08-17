import { execSync } from "node:child_process";
import { BASE_URL } from "../src/test-env.ts";
import { ensureServer } from "../src/server-lifecycle.ts";

const SPEC_URL = process.env.API_SPEC_URL ?? `${BASE_URL}/docs/schema`;

const server = await ensureServer();
try {
  execSync(`bunx openapi-typescript ${SPEC_URL} -o ./schema/api.d.ts`, {
    stdio: "inherit",
  });
} finally {
  await server.stop();
}
