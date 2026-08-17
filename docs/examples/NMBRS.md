# Registering wowauth with Nmbrs

Nmbrs-specific steps for connecting wowauth to Nmbrs's OAuth API. This
covers registration and connecting your first Nmbrs account; once that's
done, pulling tokens for scripts is entirely generic — see
`docs/EXAMPLE.md` step 7 onward, which isn't repeated here.

Find-and-replace three placeholders throughout:

- `yoyoyo` — the bearer secret from your `.env` (see
  `.env.example`), same as in `docs/EXAMPLE.md`.
- `http://localhost:3000` — where you run admin commands from, e.g.
  `http://localhost:3000`. Only you need to reach this.
- `https://wowauth.fuse.creativemedianetwork.com` — wowauth's public, internet-reachable address (your
  `http://localhost:3000`, port-forwarded). Nmbrs's servers and the Nmbrs user's
  browser both need to reach this — `localhost` will not work for
  anything under this name.

Everything else is captured into shell variables as you go.

## Before you start: what Nmbrs needs from you

Nmbrs's OAuth app registration form (in their partner/developer portal)
asks for:

| Nmbrs field              | What to put                                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| App name                 | Anything descriptive, e.g. `wowauth-nmbrs`                                                                          |
| Client ID                | Nmbrs assigns the real one after you submit — see step 4                                                            |
| App description          | Free text describing the integration                                                                                |
| Application type         | Web                                                                                                                 |
| Icon URL                 | A publicly reachable image URL — doesn't need to be related to wowauth at all                                       |
| Redirect URLs            | `https://wowauth.fuse.creativemedianetwork.com/$APP_ID/oauth/callback` — wowauth's own callback, computed in step 3 |
| Privacy policy / ToS URL | Your own hosted pages, or leave blank if optional                                                                   |

Two things worth knowing going in:

- Nmbrs caps you at 5 registered redirect URLs. If you'll eventually run
  separate deployments (e.g. staging and production wowauth instances,
  which will have different `$APP_ID`s and therefore different callback
  URLs), register all of them up front rather than editing later.
- Whatever `client_id` you type into the wowauth registration in step 2 is
  provisional — Nmbrs's portal generates its own client ID once you submit
  the form (it comes back shaped like `PartnerApp_<name>_<Nmbrs-assigned
suffix>`, not necessarily matching what you typed), and its own
  client_secret. Step 5 patches wowauth with whatever Nmbrs actually gives
  you.

Nmbrs's endpoints, needed in step 2 (confirmed against Nmbrs's own live
OIDC discovery document at
`https://identityservice.nmbrs.com/.well-known/openid-configuration`):

- `auth_url`: `https://identityservice.nmbrs.com/connect/authorize`
- `token_url`: `https://identityservice.nmbrs.com/connect/token`

Nmbrs's [scopes documentation](https://developer.nmbrs.com/docs/auth/scopes)
lists `offline_access` as the only _mandatory_ scope, plus a set of optional
data scopes for partner apps specifically:
`employee.employment[.read]`, `employee.info[.read]`,
`employee.payment[.read]`, `company.info[.read]`,
`company.payrollsettings.read`. **`openid` is not one of them** — despite
looking like standard OIDC and appearing in the discovery document's
server-wide `scopes_supported` list, it isn't documented as available to
partner-app clients, and per-client scope grants here are commonly a
restricted subset of everything the server supports. Requesting it is a
likely cause of `Invalid scope` errors — see step 2.

## 1. Generate a key pair for token encryption

Same as the general walkthrough — see `docs/EXAMPLE.md` step 1 for why:

```sh
openssl genpkey -algorithm X25519 -out wowauth_private_key.pem
openssl pkey -in wowauth_private_key.pem -pubout -outform DER \
  | tail -c 32 | base64 -w0 > wowauth_public_key.txt

PUBLIC_KEY=$(cat wowauth_public_key.txt)
echo "$PUBLIC_KEY"
```

## 2. Register the app in wowauth

Use Nmbrs's real endpoints. `client_id`/`client_secret` are placeholders
here — Nmbrs hasn't issued the real ones yet, and won't until you submit
their form in step 4, which itself needs `$APP_ID` from this response. So
this step comes first, with `redirect_url` also placeholder-ed since it
depends on the same `$APP_ID`.

`offline_access` in `scopes` is what makes Nmbrs issue a refresh token —
without it, wowauth has nothing to renew with once the access token
expires, and every connected user would need to redo the browser flow
periodically.

The example below pre-populates the full read-only scope set Nmbrs
documents as available to partner apps — no `openid` (see the note above),
and the `.read` variant of each rather than the write-capable one, since
testing doesn't need write access:

```
offline_access employee.employment.read employee.info.read employee.payment.read company.info.read company.payrollsettings.read
```

Nmbrs rejects the _entire_ authorization request with a 400 `Invalid
scope` error if any single scope in the list isn't one your specific
`PartnerApp` client is actually permitted to request — being on Nmbrs's
documented list doesn't guarantee it's granted to your client specifically.
If that happens, narrow down by removing scopes one at a time (via the
same `PATCH` below) and retrying step 6 until it succeeds, which tells you
exactly which one was the problem:

<!--```sh
curl -s -X PATCH "http://localhost:3000/apps/$APP_ID" \
  -H "Authorization: Bearer yoyoyo" \
  -H "Content-Type: application/json" \
  -d '{"scopes": "offline_access employee.employment.read employee.info.read employee.payment.read company.info.read company.payrollsettings.read"}' | jq .
```-->

```sh
curl -s -X POST "http://localhost:3000/apps" \
  -H "Authorization: Bearer yoyoyo" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "nmbrs",
    "client_id": "pending-nmbrs-client-id",
    "client_secret": "pending-nmbrs-secret",
    "auth_url": "https://identityservice.nmbrs.com/connect/authorize",
    "token_url": "https://identityservice.nmbrs.com/connect/token",
    "redirect_url": "placeholder-set-in-step-3",
    "allowed_redirect_uris": ["https://example.com/oauth-callback"],
    "scopes": "offline_access employee.employment.read employee.info.read employee.payment.read company.info.read company.payrollsettings.read",
    "public_key": "'"$PUBLIC_KEY"'"
  }' | tee /tmp/app.json | jq .

APP_ID=$(jq -r .id /tmp/app.json)
echo "APP_ID=$APP_ID"
```

## 3. Compute and set wowauth's callback

This has to be `https://wowauth.fuse.creativemedianetwork.com`, not `http://localhost:3000` — Nmbrs's servers redirect
here directly, from the outside:

```sh
REDIRECT_URL="https://wowauth.fuse.creativemedianetwork.com/$APP_ID/oauth/callback"

curl -s -X PATCH "http://localhost:3000/apps/$APP_ID" \
  -H "Authorization: Bearer yoyoyo" \
  -H "Content-Type: application/json" \
  -d '{"redirect_url": "'"$REDIRECT_URL"'"}' | jq .

echo "$REDIRECT_URL"
```

## 4. Submit Nmbrs's registration form

Go to Nmbrs's partner/developer portal and fill in the table from the top
of this doc, using the `$REDIRECT_URL` just printed for "Redirect URLs".
Submit it.

Nmbrs's portal then shows you the app's real client ID and client secret —
copy both, then click **Save** on the dialog before moving on. The app
isn't actually live on Nmbrs's side until you save it — trying to log in
(step 6) before saving fails with a generic Nmbrs error page ("The
resource you are looking for has been removed...") instead of a login
screen, which is easy to mistake for a wowauth-side problem.

## 5. Patch wowauth with the real credentials

```sh
NMBRS_CLIENT_ID="paste-the-client-id-nmbrs-gave-you"
NMBRS_CLIENT_SECRET="paste-the-secret-nmbrs-gave-you"

curl -s -X PATCH "http://localhost:3000/apps/$APP_ID" \
  -H "Authorization: Bearer yoyoyo" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "'"$NMBRS_CLIENT_ID"'",
    "client_secret": "'"$NMBRS_CLIENT_SECRET"'"
  }' | jq .
```

If the secret contains shell-special characters (`!`, `$`, `?`, and so on),
keep it inside the single-quoted `-d '...'` body exactly as above — don't
`export` it or drop it into a bare double-quoted string, both of which will
silently mangle it.

The `client_id` in the PATCH response above confirms that half stuck.
`client_secret` is write-only — no endpoint ever returns it back, by
design — so the only real confirmation that it's correct is a successful
code exchange in step 6; if it's wrong, Nmbrs's token endpoint rejects the
exchange there.

## 6. Connect your first Nmbrs account

This is the one interactive step — a real person logs into Nmbrs and
approves access. `account_hint` is optional; include it if you want a
stable, memorable label (e.g. the Nmbrs company name) so that
re-connecting the same account later reuses the same `USER_ID` instead of
creating a new one:

```sh
VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=\n')
CALLER_STATE=$(openssl rand -hex 16)

echo "https://wowauth.fuse.creativemedianetwork.com/$APP_ID/oauth/auth?redirect_uri=https://example.com/oauth-callback&state=$CALLER_STATE&code_challenge=$CHALLENGE&code_challenge_method=S256&account_hint=nmbrs-prod"
```

Open the printed URL in a browser — it must be `https://wowauth.fuse.creativemedianetwork.com` here, since
the Nmbrs login page needs to be able to redirect back to it. wowauth
redirects to Nmbrs, you log in with the Nmbrs account you want to connect
and approve the requested scopes, Nmbrs redirects back to wowauth's
`.../oauth/callback`, and wowauth does a final redirect to your
`redirect_uri` — landing on:

```
https://example.com/oauth-callback?code=...&state=...
```

Confirm `state` matches `$CALLER_STATE`, then:

```sh
CODE="paste-the-code-from-the-browser-url-here"

curl -s -X POST "https://wowauth.fuse.creativemedianetwork.com/$APP_ID/oauth/token" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=https://example.com/oauth-callback" \
  --data-urlencode "code_verifier=$VERIFIER" | jq .
```

If this returns an access token, the Nmbrs account is now connected.

If instead the browser landed on a Nmbrs error page reading `Invalid
scope` with an error ID (a GUID) before ever showing you a login or
consent screen, that's Nmbrs rejecting one of the scopes in `scopes` as
not permitted for this client — see the note on scopes back in step 2:
remove scopes one at a time (starting with whichever seems least likely to
be granted), patch it, and retry this step from the top (a new
`$CALLER_STATE`/`$CODE` each time) until it succeeds. `offline_access`
alone getting you to a real — if empty-looking — consent screen (rather
than another `Invalid scope` error) confirms the flow mechanics and
credentials are fine, and narrows the problem down to one of the data
scopes.

## 7. Find the resulting user

```sh
curl -s "http://localhost:3000/apps/$APP_ID/users" -H "Authorization: Bearer yoyoyo" | jq .

USER_ID=$(curl -s "http://localhost:3000/apps/$APP_ID/users" -H "Authorization: Bearer yoyoyo" | jq -r '.[0].user_id')
echo "USER_ID=$USER_ID"
```

Save `$APP_ID` and `$USER_ID` wherever your integration keeps config. From
here, pulling a fresh token for this Nmbrs connection — including
wowauth's automatic refresh once the access token expires — is exactly
`docs/EXAMPLE.md` step 7, unchanged: `GET
http://localhost:3000/apps/$APP_ID/users/$USER_ID/token`, decrypted with the private
key from step 1. Nothing about that step talks to Nmbrs directly, so
nothing about it is Nmbrs-specific.
