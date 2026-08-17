// tests/src/global-setup.ts
import { ensureServer } from "./server-lifecycle.ts";

export default async function setup() {
  const server = await ensureServer();
  return () => server.stop();
}
