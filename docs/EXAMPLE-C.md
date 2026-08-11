# Walkthrough: registering an app and using it

This walks through the whole lifecycle with real `curl` commands: register
an app, connect a real user's account through the standard OAuth flow, then
pull a usable token for that user from a script — the scenario described in
`docs/DESCRIPTION.md`.

Find-and-replace these two placeholders throughout with your own values
before running anything:

- `yoyoyo` — the bearer secret from your `.env` (see `.env.example`)
- `http://localhost:3000` — where wowauth is reachable, e.g. `http://localhost:3000`

Everything else is captured into shell variables as you go, so the rest of
this doc can be pasted into a terminal top to bottom.

## 0. Start the server

```sh
flox activate
just run
```

## 1. Generate a key pair for token encryption

Tokens wowauth hands back are encrypted to an X25519 public key you supply;
only the matching private key can decrypt them. Generate a real pair with
`openssl` — `apps.public_key` needs the _raw_ 32-byte key, base64-encoded
(not PEM), which is what the `tail -c 32` below extracts:

```sh
openssl genpkey -algorithm X25519 -out wowauth_private_key.pem
openssl pkey -in wowauth_private_key.pem -pubout -outform DER \
  | tail -c 32 | base64 -w0 > wowauth_public_key.txt

PUBLIC_KEY=$(cat wowauth_public_key.txt)
echo "$PUBLIC_KEY"
```

Keep `wowauth_private_key.pem` — you'll need it in step 7 to actually read a
token. wowauth never sees it.

## 2. Register the app

This example connects to a fictional provider; swap `auth_url`/`token_url`/
`client_id`/`client_secret` for the real ones from your provider's developer
console (e.g. Airtable's OAuth app settings).

```sh
curl -s -X POST "http://localhost:3000/apps" \
  -H "Authorization: Bearer yoyoyo" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "airtable",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "auth_url": "https://provider.example.com/oauth/authorize",
    "token_url": "https://provider.example.com/oauth/token",
    "redirect_url": "placeholder-set-in-step-3",
    "allowed_redirect_uris": ["https://example.com/oauth-callback"],
    "scopes": "data.records:read data.records:write",
    "public_key": "'"$PUBLIC_KEY"'"
  }' | tee /tmp/app.json | jq .

APP_ID=$(jq -r .id /tmp/app.json)
echo "APP_ID=$APP_ID"
```

`allowed_redirect_uris` is the allow-list of pages the `/oauth/*` facade is
willing to send end users back to after they authorize — here, some page
you control that can display a URL's query string back to you. It doesn't
need to be a real running server; you're just reading the address bar in
step 5.

## 3. Point the provider at wowauth's callback

`redirect_url` is the _one_ URL wowauth itself registers with the upstream
provider — fixed, and only known once `APP_ID` exists, hence the
placeholder in step 2. Update it now:

```sh
curl -s -X PATCH "http://localhost:3000/apps/$APP_ID" \
  -H "Authorization: Bearer yoyoyo" \
  -H "Content-Type: application/json" \
  -d '{"redirect_url": "'"http://localhost:3000/$APP_ID/oauth/callback"'"}' | jq .
```

Now go into the provider's developer console and set its "redirect URI" /
"callback URL" to that same value: `http://localhost:3000/$APP_ID/oauth/callback`.

## 4. Start the authorization flow

This is the one interactive step — a real person has to approve access.
Generate a PKCE pair for this flow (the `/oauth/*` facade requires it — it
treats every caller as a public client, no secret):

```sh
VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=\n')
CALLER_STATE=$(openssl rand -hex 16)

echo "http://localhost:3000/$APP_ID/oauth/auth?redirect_uri=https://example.com/oauth-callback&state=$CALLER_STATE&code_challenge=$CHALLENGE&code_challenge_method=S256&account_hint=jane@example.com"
```

Open the printed URL in a browser. It redirects to the provider, where the
account owner logs in and approves the requested scopes; the provider then
redirects back through wowauth, which redirects a final time to your
`redirect_uri` — landing on `https://example.com/oauth-callback?code=...&state=...`.

Copy the `code` from that final address bar:

```sh
CODE="paste-the-code-from-the-browser-url-here"
```

(`state` should come back equal to `$CALLER_STATE` — that's wowauth proving
this redirect really is the one you started, not a forged callback.)

## 5. Exchange the code for a token

Standard OAuth token exchange — any OAuth client library can do this step
too, since this endpoint follows RFC 6749 exactly:

```sh
curl -s -X POST "http://localhost:3000/$APP_ID/oauth/token" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=https://example.com/oauth-callback" \
  --data-urlencode "code_verifier=$VERIFIER" | jq .
```

This returns a normal, plaintext `access_token` — useful if you're building
something that talks to the provider right then and there. There's no
`refresh_token` in the response on purpose: wowauth keeps that to itself
and handles renewal for you from here on, which is the point of steps 6–7.

## 6. Find the resulting user

```sh
curl -s "http://localhost:3000/apps/$APP_ID/users" -H "Authorization: Bearer yoyoyo" | jq .

USER_ID=$(curl -s "http://localhost:3000/apps/$APP_ID/users" -H "Authorization: Bearer yoyoyo" | jq -r '.[0].user_id')
echo "USER_ID=$USER_ID"
```

This is the id a script uses from now on — save it alongside `APP_ID`
wherever your script keeps config. Re-running the authorization flow for
the same `account_hint` later reuses this same `USER_ID` rather than
minting a new one.

## 7. Use it from a script — no state required

This is what a recurring, stateless script (e.g. a weekly cron job) does
every time it runs — no browser, no OAuth flow, just these two calls:

```sh
pip install pyhpke

curl -s "http://localhost:3000/apps/$APP_ID/users/$USER_ID/token" \
  -H "Authorization: Bearer yoyoyo" | jq .
```

```py
import base64
import subprocess

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

APP_ID = "..."
USER_ID = "..."
yoyoyo = "..."
http://localhost:3000 = "..."

token_info = subprocess.run(
    ["curl", "-s", f"{http://localhost:3000}/apps/{APP_ID}/users/{USER_ID}/token",
     "-H", f"Authorization: Bearer {yoyoyo}"],
    capture_output=True, text=True, check=True,
).stdout
import json
token_info = json.loads(token_info)

suite = CipherSuite.new(
    KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305
)
private_key = KEMKey.from_pem(open("wowauth_private_key.pem", "rb").read())

sealed = base64.b64decode(token_info["token"])
enc, ciphertext = sealed[:32], sealed[32:]

recipient = suite.create_recipient_context(enc, private_key, info=b"wowauth token v1")
access_token = recipient.open(ciphertext, aad=f"{APP_ID}:{USER_ID}".encode()).decode()

print(f"token expires at {token_info['expires_at']}")
# access_token is now a normal bearer token — use it with the provider's SDK
```

If the stored token was expired, wowauth transparently refreshes it with
the provider before returning it — this is the "wowauth takes care of
refreshing your tokens" promise from `docs/DESCRIPTION.md`, and it's why
the script above never has to think about expiry itself.

## Reference: other things you can do

Check whether a user's authorization is still active or needs reauth:

```sh
curl -s "http://localhost:3000/apps/$APP_ID/users/$USER_ID/status" -H "Authorization: Bearer yoyoyo" | jq .
```

Revoke a user's access (deletes their stored token):

```sh
curl -s -X DELETE "http://localhost:3000/apps/$APP_ID/users/$USER_ID" -H "Authorization: Bearer yoyoyo"
```

Revoke a token directly, RFC 7009-style (used by whoever holds the token,
not necessarily an admin — no `yoyoyo` needed):

```sh
curl -s -X POST "http://localhost:3000/$APP_ID/oauth/revoke" --data-urlencode "token=$ACCESS_TOKEN"
```

Rotate the app's public key — note this deletes every user under the app,
on purpose (see `docs/DESCRIPTION.md`):

```sh
curl -s -X PATCH "http://localhost:3000/apps/$APP_ID" \
  -H "Authorization: Bearer yoyoyo" \
  -H "Content-Type: application/json" \
  -d '{"public_key": "'"$NEW_PUBLIC_KEY"'"}' | jq .
```

The full, always-current API reference is served at `http://localhost:3000/docs/schema`
(OpenAPI JSON).
