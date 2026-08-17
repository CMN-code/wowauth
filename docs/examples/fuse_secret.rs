//! Parses a `fuse-secrets.json` file (see
//! docs/examples/fuse-secrets.schema.json) into `WowAuthSecret`, then
//! converts it into `NmbrsToken` -- the private key decoded and validated
//! once, ready to decrypt tokens returned by
//! `GET /apps/{app_id}/users/{user_id}/token`.
//!
//! Mirrors src/token_seal.rs on the receiving end: same HPKE suite
//! (DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305), same
//! `info` string, same `aad` shape (`{app_id}:{user_id}`), same wire format
//! (base64(encapsulated_key(32 bytes) || ciphertext)).
//!
//! Cargo.toml dependencies:
//!   serde = { version = "1.0", features = ["derive"] }
//!   serde_json = "1.0"
//!   base64 = "0.22"
//!   hpke = { version = "0.14", default-features = false, features = ["alloc", "getrandom", "x25519", "chacha"] }
//!   anyhow = "1.0"

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR};
use serde::Deserialize;

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;

/// Domain separation string wowauth seals tokens under -- must match
/// src/token_seal.rs::INFO exactly, or decryption fails.
const INFO: &[u8] = b"wowauth token v1";
/// X25519 encapsulated keys (ephemeral public keys) are always 32 bytes.
const ENCAPPED_KEY_LEN: usize = 32;

/// Raw shape of `fuse-secrets.json`, deserialized as-is -- see
/// docs/examples/fuse-secrets.schema.json for field meanings.
#[derive(Debug, Deserialize)]
pub struct WowAuthSecret {
    pub wowauth: WowAuthConfig,
    pub connection: Connection,
}

#[derive(Debug, Deserialize)]
pub struct WowAuthConfig {
    pub admin_url: String,
    pub config_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct Connection {
    pub name: String,
    pub app_id: String,
    pub user_id: String,
    pub private_key: PrivateKeyField,
}

#[derive(Debug, Deserialize)]
pub struct PrivateKeyField {
    pub format: String,
    pub value: String,
}

/// One connection ready to use: the private key decoded into an actual
/// X25519 key once, rather than re-parsed on every token pull.
pub struct NmbrsToken {
    app_id: String,
    user_id: String,
    private_key: <Kem as KemTrait>::PrivateKey,
}

impl TryFrom<WowAuthSecret> for NmbrsToken {
    type Error = anyhow::Error;

    /// Validates `private_key.format` and decodes `private_key.value`, so a
    /// malformed secrets file fails at startup instead of on the first
    /// token pull.
    fn try_from(secret: WowAuthSecret) -> Result<Self> {
        let key_field = secret.connection.private_key;
        if key_field.format != "x25519-raw-base64" {
            bail!(
                "unsupported private_key.format {:?}, expected \"x25519-raw-base64\"",
                key_field.format
            );
        }

        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_field.value.trim())
            .context("connection.private_key.value is not valid base64")?;
        let private_key = <Kem as KemTrait>::PrivateKey::from_bytes(&key_bytes).map_err(|_| {
            anyhow!("connection.private_key.value is not a valid X25519 private key")
        })?;

        Ok(NmbrsToken {
            app_id: secret.connection.app_id,
            user_id: secret.connection.user_id,
            private_key,
        })
    }
}

impl NmbrsToken {
    /// Parses and validates a `fuse-secrets.json` file in one step.
    pub fn from_json(json: &str) -> Result<Self> {
        let secret: WowAuthSecret = serde_json::from_str(json)
            .context("fuse-secrets.json doesn't match the expected shape")?;
        secret.try_into()
    }

    /// Decrypts the `token` field returned by
    /// `GET {admin_url}/apps/{app_id}/users/{user_id}/token` back into the
    /// plaintext access token to send on to Nmbrs.
    pub fn decrypt(&self, sealed_b64: &str) -> Result<String> {
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(sealed_b64.trim())
            .context("sealed token is not valid base64")?;
        if sealed.len() < ENCAPPED_KEY_LEN {
            bail!("sealed token is shorter than the encapsulated key alone");
        }
        let (encapped_key_bytes, ciphertext) = sealed.split_at(ENCAPPED_KEY_LEN);
        let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(encapped_key_bytes)
            .map_err(|_| anyhow!("malformed encapsulated key"))?;

        // Must match the aad wowauth sealed under exactly: "{app_id}:{user_id}".
        let aad = format!("{}:{}", self.app_id, self.user_id);
        let plaintext = hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &self.private_key,
            &encapped_key,
            INFO,
            ciphertext,
            aad.as_bytes(),
        )
        .map_err(|err| anyhow!("HPKE decryption failed: {err}"))?;

        String::from_utf8(plaintext).context("decrypted access token is not valid UTF-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{OpModeS, Serializable};

    #[test]
    fn parses_and_decrypts_round_trip() {
        let (sk, pk) = Kem::gen_keypair();
        let private_key_b64 = base64::engine::general_purpose::STANDARD.encode(sk.to_bytes());
        let json = format!(
            r#"{{
                "wowauth": {{ "admin_url": "https://wowauth.example.com", "config_secret": "shh" }},
                "connection": {{
                    "name": "nmbrs",
                    "app_id": "app-1",
                    "user_id": "user-1",
                    "private_key": {{ "format": "x25519-raw-base64", "value": "{private_key_b64}" }}
                }}
            }}"#
        );

        let token = NmbrsToken::from_json(&json).unwrap();

        let aad = b"app-1:user-1";
        let (encapped_key, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
            &OpModeS::Base,
            &pk,
            INFO,
            b"real-access-token",
            aad,
        )
        .unwrap();
        let mut sealed = encapped_key.to_bytes().to_vec();
        sealed.extend_from_slice(&ciphertext);
        let sealed_b64 = base64::engine::general_purpose::STANDARD.encode(sealed);

        assert_eq!(token.decrypt(&sealed_b64).unwrap(), "real-access-token");
    }

    #[test]
    fn rejects_unknown_private_key_format() {
        let json = r#"{
            "wowauth": { "admin_url": "https://wowauth.example.com", "config_secret": "shh" },
            "connection": {
                "name": "nmbrs",
                "app_id": "app-1",
                "user_id": "user-1",
                "private_key": { "format": "pem", "value": "irrelevant" }
            }
        }"#;

        assert!(NmbrsToken::from_json(json).is_err());
    }
}
