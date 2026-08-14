// tests/src/app-fixtures.ts
//
// `POST /apps`'s request body has several fields with an `#[oai(default = ...)]` on the
// Rust side (scopes, token_auth_method, extra_auth_params, extra_headers) -- but
// openapi-typescript doesn't treat "has a default" as "is optional" (see
// INTEGRATION_TESTING.md), so the generated CreateAppRequest type marks them required.
// Centralizing the boilerplate here means test files only spell out what they actually
// care about.
export interface CreateAppFields {
  name: string;
  client_id: string;
  client_secret: string;
  auth_url: string;
  token_url: string;
  redirect_url: string;
  allowed_redirect_uris: string[];
  public_key: string;
  scopes?: string;
  token_auth_method?: string;
}

export function createAppBody(fields: CreateAppFields) {
  return {
    scopes: "",
    token_auth_method: "basic",
    extra_auth_params: {},
    extra_headers: {},
    ...fields,
  };
}
