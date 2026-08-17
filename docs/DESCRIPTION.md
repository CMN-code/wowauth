# About wowauth

**wowauth** is a standalone, minimalist and generic OAuth "receiver". Its sole purpose is to be used as a publicly accessible backend to register OAuth apps with third-party services. That is, when needing to register an OAuth app with service XYZ to access service XYZ's API, wowauth can help out, without you needing to worry about (a) making your own service publicly accessible or (b) dealing with OAuth token rotation quirks.

## Why

Many third-party services use some form of OAuth to protect their API. Some variants require server-side token refreshing which can be a hassle, especially if you are building stateless apps (such as an API or scripts). Instead of reinventing the wheel, use wowauth.

## How

wowauth has two sides: the default OAuth API interface that third party service providers know and love, and some configuration API endpoints that you, the service/script developer can use. Like this:

- **oauth endpoints** (industry default, per RFC 6749 / OIDC discovery): standard authorization-server-shaped endpoints for a registered app. Any OAuth/OIDC-capable client calls these directly during the OAuth flow
  - `{APP_ID}/oauth/token`
  - `{APP_ID}/oauth/auth`
  - `{APP_ID}/oauth/revoke`
  - `{APP_ID}/.well-known/openid-configuration`
  - ...
- **usage endpoints** (proprietary management and token fetching)
  - POST `/apps`: allows registering a new app, requiring you to specify:
    - The app name
    - Proprietary oauth variables (headers to use, custom endpoints to use, custom scopes, etc.)
    - The redirect URI wowauth registers with the provider, and the redirect URI(s) the `/oauth/*` facade accepts back from calling clients (controlled allow-list)
    - Your public secret: a public key using which all returned tokens will be encrypted, so that only the developer who created the app can decrypt them with your private key
  - PUT/PATCH `/apps/{APP_ID}`: allows overwriting app properties. Note that changing the public secret will erase all users and tokens (intentionally, rotating the key invalidates every grant encrypted under the old one).
  - GET `/apps/{APP_ID}/status`: check the status of an app (is it correctly configured, are there problems)
  - GET `/apps/{APP_ID}/users`: check the list of users that registered using the oauth app. The list returns wowauth-specific user IDs, a human-readable label (name/email, captured from the provider during authorization when available), and their granted scopes
  - DELETE `/apps/{APP_ID}/users/{USER_ID}`: revokes a single user's authorization and deletes their stored token.
  - GET `/apps/{APP_ID}/users/{USER_ID}/status`: returns the status of a user auth (for example a user authorization can be active, or expired, requiring users to reauth. Reauthorizing reuses the same USER_ID rather than minting a new one)
  - GET `/apps/{APP_ID}/users/{USER_ID}/token`: (when user auth is still valid) returns a valid OAuth token that can be used to make requests on behalf of this user, together with an expiry date. The token is encrypted using the public key configured for the app.

All usage endpoints require the Authorization bearer header to be set with the value configured through the `CONFIG_SECRET` environment variable. This secret is flat across all apps rather than scoped per app so every app is trusted at the same level. All responses are fully typed out using poem's openAPI adapter and the openAPI spec is available at the /docs/schema endpoint.

Flow initiation via the `/oauth/*` endpoints is intentionally public and unauthenticated, the same as any real OAuth provider's `/authorize` endpoint.

Token encryption uses [HPKE](https://www.rfc-editor.org/rfc/rfc9180) (RFC 9180), the current IETF standard for encrypting data to a recipient's public key, with the DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305 ciphersuite. `public_key` is the caller's X25519 public key. HPKE has mature, interoperable implementations in Rust, Python, and TypeScript.

wowauth is stateful: it will take care of refreshing your tokens and contacting third-party APIs when necessary, so that you can always mint a usable token!

### Usage as a Developer

This is an example scenario of how to use wowauth as a developer. Imagine you are writing a stateless python script that is executed every monday morning and fetches some Airtable data through their OAuth API.
(Also see /docs/examples)

#### Pre-config

1. Register a new app with wowauth using the POST /apps endpoint.
2. Register a new app in the Airtable admin interface, and point it to the wowauth app you configured in step 1
3. Log in with the wowauth app using your own user account, and select the scopes/protections that you need. If successful, this app will now have a user with an associated token to it

#### On Script Run

In your python script, you can now use the Airtable SDK as you otherwise would. At the initialization of your script, you only need the wowauth `CONFIG_SECRET`, app id, user id and your private key. The init would then look something like this (in pseudocode)

```
wowauthClient = Wowauth(CONFIG_SECRET)
token_info = wowauthClient.app(APP_ID).user(USER_ID).token()
usable_token = decrypt(token_info.token, private_key)
print("token expires at {token_info.expires_at}")

# Then just use it with Airtable!
airtableClient = Airtable(usable_token)
bases = airtableClient.bases()
print("you got access to bases {bases}")
```

No state required in your script!
