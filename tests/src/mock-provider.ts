// tests/src/mock-provider.ts
//
// A minimal stand-in for "the upstream OAuth provider" wowauth is a client
// of (Airtable, Nmbrs, ... in the real world). wowauth's own tests have
// nothing free and real to talk to the way FUSE's adapters do (a real
// sandboxed Airtable base), since the whole point of an app registered with
// wowauth is that *some* third party issues its tokens -- so this fakes
// that third party well enough to drive wowauth's real code paths
// end-to-end: /authorize auto-approves and redirects back like a user who
// just clicked "allow", and /token implements both the authorization_code
// and refresh_token grants.
//
// Deliberately not a full OAuth server: no real client authentication, no
// real scope enforcement. `behavior` lets a test steer it into the specific
// success/failure shapes wowauth needs to react to (short-lived tokens to
// force a refresh, a refresh grant that fails to force NeedsReauth, etc).
import http from "node:http";
import { randomUUID } from "node:crypto";

export interface ProviderBehavior {
  /** Access token lifetime in seconds handed out by both grants. Default 3600. */
  expiresIn?: number;
  /** Whether the authorization_code grant issues a refresh_token. Default true. */
  issueRefreshToken?: boolean;
  /** Whether a refresh_token grant issues a *new* refresh_token (rotation) or omits one
   *  (meaning "keep using the old one", per RFC 6749 -- see handlers.rs's is_active/refresh
   *  logic). Default false (no rotation). */
  rotateRefreshTokenOnRefresh?: boolean;
  /** If set, every /token request fails with this RFC 6749 error code. */
  failTokenWith?: string;
  /** If set, /authorize redirects straight back with this error instead of a code. */
  denyAuthorizeWith?: string;
}

export interface LoggedRequest {
  path: string;
  method: string;
  query?: Record<string, string>;
  body?: Record<string, string>;
  authorizationHeader?: string;
}

interface IssuedCode {
  redirectUri: string;
  scope: string;
}

export class MockProvider {
  behavior: ProviderBehavior = {};
  requestLog: LoggedRequest[] = [];

  #server: http.Server;
  #codes = new Map<string, IssuedCode>();
  #refreshTokens = new Map<string, string>(); // refreshToken -> scope
  url = "";

  constructor() {
    this.#server = http.createServer((req, res) => this.#handle(req, res));
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve) => this.#server.listen(0, "127.0.0.1", resolve));
    const address = this.#server.address();
    if (!address || typeof address === "string") {
      throw new Error("mock provider failed to bind a TCP port");
    }
    this.url = `http://127.0.0.1:${address.port}`;
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve, reject) =>
      this.#server.close((err) => (err ? reject(err) : resolve())),
    );
  }

  get authUrl(): string {
    return `${this.url}/authorize`;
  }

  get tokenUrl(): string {
    return `${this.url}/token`;
  }

  async #handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    try {
      const url = new URL(req.url ?? "/", this.url || "http://127.0.0.1");
      if (req.method === "GET" && url.pathname === "/authorize") {
        this.#authorize(url, res);
        return;
      }
      if (req.method === "POST" && url.pathname === "/token") {
        const body = await readFormBody(req);
        this.#token(body, req.headers.authorization, res);
        return;
      }
      res.writeHead(404).end("not found");
    } catch (err) {
      res.writeHead(500).end(String(err));
    }
  }

  #authorize(url: URL, res: http.ServerResponse): void {
    const query = Object.fromEntries(url.searchParams.entries());
    this.requestLog.push({ path: "/authorize", method: "GET", query });

    const redirectUri = query.redirect_uri;
    const state = query.state ?? "";
    if (!redirectUri) {
      res.writeHead(400).end("missing redirect_uri");
      return;
    }

    const callback = new URL(redirectUri);
    if (this.behavior.denyAuthorizeWith) {
      callback.searchParams.set("error", this.behavior.denyAuthorizeWith);
      callback.searchParams.set("state", state);
      res.writeHead(302, { Location: callback.toString() }).end();
      return;
    }

    const code = `mock-code-${randomUUID()}`;
    this.#codes.set(code, { redirectUri, scope: query.scope ?? "" });
    callback.searchParams.set("code", code);
    callback.searchParams.set("state", state);
    res.writeHead(302, { Location: callback.toString() }).end();
  }

  #token(
    body: Record<string, string>,
    authorizationHeader: string | undefined,
    res: http.ServerResponse,
  ): void {
    this.requestLog.push({ path: "/token", method: "POST", body, authorizationHeader });

    if (this.behavior.failTokenWith) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: this.behavior.failTokenWith }));
      return;
    }

    const expiresIn = this.behavior.expiresIn ?? 3600;
    const scope = body.grant_type === "authorization_code" ? this.#redeemCode(body, res) : undefined;
    if (body.grant_type === "authorization_code" && scope === undefined) return; // error already written

    let refreshToken: string | undefined;
    if (body.grant_type === "authorization_code") {
      if (this.behavior.issueRefreshToken ?? true) {
        refreshToken = `mock-refresh-${randomUUID()}`;
        this.#refreshTokens.set(refreshToken, scope ?? "");
      }
    } else if (body.grant_type === "refresh_token") {
      const presented = body.refresh_token;
      const knownScope = presented ? this.#refreshTokens.get(presented) : undefined;
      if (!presented || knownScope === undefined) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_grant" }));
        return;
      }
      if (this.behavior.rotateRefreshTokenOnRefresh) {
        this.#refreshTokens.delete(presented);
        refreshToken = `mock-refresh-${randomUUID()}`;
        this.#refreshTokens.set(refreshToken, knownScope);
      }
      // else: no refresh_token in the response at all, meaning "keep the old one".
    } else {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "unsupported_grant_type" }));
      return;
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        access_token: `mock-access-${randomUUID()}`,
        token_type: "Bearer",
        expires_in: expiresIn,
        ...(refreshToken ? { refresh_token: refreshToken } : {}),
      }),
    );
  }

  /** Validates+consumes an authorization code, writing an error response and returning
   *  undefined if it's missing/unknown/already used; otherwise returns its scope. */
  #redeemCode(body: Record<string, string>, res: http.ServerResponse): string | undefined {
    const code = body.code;
    const issued = code ? this.#codes.get(code) : undefined;
    if (!issued) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
      return undefined;
    }
    this.#codes.delete(code!); // single-use, same as a real provider
    return issued.scope;
  }
}

function readFormBody(req: http.IncomingMessage): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => resolve(Object.fromEntries(new URLSearchParams(raw).entries())));
    req.on("error", reject);
  });
}
