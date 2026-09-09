use poem_openapi::OpenApiService;
use wowauth::{handlers, oauth_handlers};

fn main() {
    let api_service = OpenApiService::new(
        (handlers::Api, oauth_handlers::OauthApi),
        "wowauth",
        env!("CARGO_PKG_VERSION"),
    );
    println!("{}", api_service.spec());
}
