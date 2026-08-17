// tests/src/server-lifecycle.ts
//
// Shared "make sure a healthy wowauth server is reachable" logic, used both by
// vitest's globalSetup (for running the test suite) and by scripts/generate.ts
// (for fetching the OpenAPI schema), since both need the same server up
// before they can do anything useful.
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { BASE_URL, CONFIG_SECRET, PORT, WOWAUTH_MASTER_KEY } from "./test-env.ts";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));

export type ManagedServer = { stop: () => Promise<void> };

/**
 * Ensures a healthy wowauth server is reachable at BASE_URL. If API_BASE_URL
 * is set, someone else owns that server's lifecycle -- we just wait for it.
 * Otherwise we build and spawn our own `cargo run` against a fresh, throwaway
 * SQLite file and hand back a stop() to tear it down.
 */
export async function ensureServer(): Promise<ManagedServer> {
  if (process.env.API_BASE_URL) {
    await waitForHealth(BASE_URL, 10, 1000);
    return { stop: async () => {} };
  }

  // Compile first: keeps the readiness timeout from having to cover a cold build.
  await run("cargo", ["build"]);

  const dbDir = mkdtempSync(join(tmpdir(), "wowauth-test-"));
  const databaseUrl = join(dbDir, "wowauth-test.db");

  const log: string[] = [];
  let exit: { code: number | null; signal: string | null } | undefined;

  const server = spawn("cargo", ["run"], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      LISTEN_PORT: PORT,
      DATABASE_URL: databaseUrl,
      WOWAUTH_MASTER_KEY,
      CONFIG_SECRET,
      PUBLIC_BASE_URL: BASE_URL,
      RUST_LOG: process.env.RUST_LOG ?? "info",
    },
    stdio: ["ignore", "pipe", "pipe"],
    detached: true, // own process group, so we can signal cargo *and* the server
  });

  server.stdout.on("data", (d) => log.push(String(d)));
  server.stderr.on("data", (d) => log.push(String(d)));
  server.on("exit", (code, signal) => (exit = { code, signal }));

  try {
    await waitForHealth(BASE_URL, 100, 100, () => exit);
  } catch (err) {
    await stop(server);
    throw new Error(`${(err as Error).message}\n\n--- server output ---\n${log.join("")}`);
  }

  return { stop: () => stop(server) };
}

async function waitForHealth(
  baseUrl: string,
  maxAttempts: number,
  delayMs: number,
  exited?: () => { code: number | null; signal: string | null } | undefined,
) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const dead = exited?.();
    if (dead) {
      throw new Error(`server exited during startup (code ${dead.code}, signal ${dead.signal})`);
    }
    try {
      const res = await fetch(`${baseUrl}/health`);
      if (res.ok) return;
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw new Error(`wowauth server at ${baseUrl} did not become healthy in time`);
}

async function stop(server: ChildProcess) {
  if (server.exitCode !== null || server.signalCode !== null || !server.pid) return;

  const exited = new Promise<void>((r) => server.once("exit", () => r()));
  process.kill(-server.pid, "SIGTERM"); // negative pid = whole process group

  const timer = setTimeout(() => {
    try {
      process.kill(-server.pid!, "SIGKILL");
    } catch {
      /* already gone */
    }
  }, 5000);

  await exited;
  clearTimeout(timer);
}

function run(cmd: string, args: string[]) {
  return new Promise<void>((resolve, reject) => {
    const p = spawn(cmd, args, { cwd: REPO_ROOT, stdio: "inherit" });
    p.on("error", reject);
    p.on("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(`${cmd} ${args.join(" ")} exited with ${code}`)),
    );
  });
}
