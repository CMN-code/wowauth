use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, Generate, KeyInit},
};

const NONCE_LEN: usize = 12;

/// Encrypts and decrypts the secret columns (client secrets, PKCE
/// verifiers, access/refresh tokens) before they touch the database, so a
/// stolen `.db` file alone is never enough to recover a usable credential.
pub struct Cipher {
    cipher: ChaCha20Poly1305,
}

impl Cipher {
    /// Reads the 32-byte key from `WOWAUTH_MASTER_KEY` (base64-encoded).
    /// This key lives only in the process environment, never in the
    /// database, so it must be provisioned the same way secrets normally
    /// are (e.g. via the deployment platform's secret store).
    pub fn from_env() -> Result<Self> {
        let encoded = std::env::var("WOWAUTH_MASTER_KEY")
            .context("WOWAUTH_MASTER_KEY must be set to a base64-encoded 32-byte key")?;
        Self::from_base64(&encoded)
    }

    pub fn from_base64(encoded: &str) -> Result<Self> {
        use base64::Engine;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .context("WOWAUTH_MASTER_KEY is not valid base64")?;
        if key_bytes.len() != 32 {
            bail!(
                "WOWAUTH_MASTER_KEY must decode to 32 bytes, got {}",
                key_bytes.len()
            );
        }
        let key = Key::try_from(key_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("WOWAUTH_MASTER_KEY has the wrong length"))?;
        let cipher = ChaCha20Poly1305::new(&key);
        Ok(Self { cipher })
    }

    /// Encrypts `plaintext`, returning `nonce || ciphertext`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = Nonce::generate(); // MUST be unique per message
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .expect("chacha20poly1305 encryption is infallible for valid inputs");
        [nonce.as_slice(), ciphertext.as_slice()].concat()
    }

    /// Decrypts a `nonce || ciphertext` blob produced by [`Cipher::encrypt`].
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_LEN {
            bail!("ciphertext too short to contain a nonce");
        }
        let (nonce, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = Nonce::try_from(nonce)
            .map_err(|_| anyhow::anyhow!("stored nonce has the wrong length"))?;
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("decryption failed: wrong key or corrupted data"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cipher() -> Cipher {
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        Cipher::from_base64(&key).unwrap()
    }

    #[test]
    fn round_trips() {
        let cipher = test_cipher();
        let plaintext = b"super-secret-client-secret";
        let ciphertext = cipher.encrypt(plaintext);
        assert_ne!(ciphertext, plaintext);
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let cipher = test_cipher();
        let mut ciphertext = cipher.encrypt(b"payload");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xff;
        assert!(cipher.decrypt(&ciphertext).is_err());
    }
}
