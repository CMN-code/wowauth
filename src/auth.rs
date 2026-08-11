use poem::Request;
use poem_openapi::SecurityScheme;
use poem_openapi::auth::Bearer;

use crate::AppState;

/// Gates every management endpoint. The secret is flat across all apps by
/// design: wowauth is only ever operated by admins within the same
/// company, so every app is trusted at the same level.
#[derive(SecurityScheme)]
#[oai(ty = "bearer", checker = "check_bearer")]
pub struct AdminAuth(());

async fn check_bearer(req: &Request, bearer: Bearer) -> Option<()> {
    let state = req.data::<AppState>()?;
    constant_time_eq(bearer.token.as_bytes(), state.config_secret.as_bytes()).then_some(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
