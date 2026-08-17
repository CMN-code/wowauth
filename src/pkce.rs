use base64::Engine;
use sha2::{Digest, Sha256};

/// Verifies a PKCE (RFC 7636) `code_verifier` against the `code_challenge`
/// stored at the start of the flow. wowauth requires S256 (never `plain`)
/// from callers of the `/oauth/*` facade, since it's the only real
/// protection a public client (no client secret) has against authorization
/// code interception.
pub fn verify_s256(code_verifier: &str, code_challenge: &str) -> bool {
    let digest = Sha256::digest(code_verifier.as_bytes());
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    constant_time_eq(computed.as_bytes(), code_challenge.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_a_real_challenge_pair() {
        // RFC 7636 appendix B example pair.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_s256(verifier, challenge));
        assert!(!verify_s256("wrong-verifier", challenge));
    }
}
