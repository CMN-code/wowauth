// @generated automatically by Diesel CLI.

diesel::table! {
    apps (id) {
        id -> Text,
        name -> Text,
        client_id -> Text,
        client_secret -> Binary,
        auth_url -> Text,
        token_url -> Text,
        redirect_url -> Text,
        scopes -> Text,
        token_auth_method -> Text,
        extra_auth_params -> Text,
        extra_headers -> Text,
        public_key -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    oauth_flows (id) {
        id -> Text,
        app_id -> Text,
        state -> Text,
        pkce_verifier -> Binary,
        redirect_after -> Text,
        external_account_hint -> Nullable<Text>,
        created_at -> Timestamp,
        expires_at -> Timestamp,
    }
}

diesel::table! {
    tokens (id) {
        id -> Text,
        app_id -> Text,
        external_account -> Text,
        access_token -> Binary,
        refresh_token -> Nullable<Binary>,
        scopes -> Text,
        expires_at -> Nullable<Timestamp>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::joinable!(oauth_flows -> apps (app_id));
diesel::joinable!(tokens -> apps (app_id));

diesel::allow_tables_to_appear_in_same_query!(apps, oauth_flows, tokens,);
