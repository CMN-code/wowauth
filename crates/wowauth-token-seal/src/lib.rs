//! HPKE (RFC 9180) sealing and opening for wowauth's encrypted token
//! payloads. Shared between wowauth itself (which only ever seals, since it
//! never holds a private key) and client libraries like `wowauth-client`
//! (which only ever open), so the wire format and domain-separation
//! constant can't drift out of sync between the two sides.

use anyhow::{Context, Result};
use base64::Engine;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;

// Domain separation for the KDF context; not secret, but must match on both
// sides of seal/open.
const INFO: &[u8] = b"wowauth token v1";

// X25519 encapsulated keys (ephemeral public keys) are a fixed 32 bytes,
// set by the KEM -- not something that varies with the ciphertext.
const ENCAPPED_KEY_LEN: usize = 32;

fn public_key_from_base64(public_key_b64: &str) -> Result<<Kem as KemTrait>::PublicKey> {
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64.trim())
        .context("public_key is not valid base64")?;
    <Kem as KemTrait>::PublicKey::from_bytes(&key_bytes)
        .map_err(|_| anyhow::anyhow!("public_key is not a valid X25519 public key"))
}

fn private_key_from_base64(private_key_b64: &str) -> Result<<Kem as KemTrait>::PrivateKey> {
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(private_key_b64.trim())
        .context("private_key is not valid base64")?;
    <Kem as KemTrait>::PrivateKey::from_bytes(&key_bytes)
        .map_err(|_| anyhow::anyhow!("private_key is not a valid X25519 private key"))
}

/// Fails if `public_key_b64` isn't a well-formed X25519 public key, so
/// registration/update rejects bad keys immediately rather than failing
/// later when a token is issued.
pub fn validate_public_key(public_key_b64: &str) -> Result<()> {
    public_key_from_base64(public_key_b64)?;
    Ok(())
}

/// Encrypts `plaintext` to `public_key_b64` using HPKE (RFC 9180) with
/// DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305, so only the
/// holder of the matching private key can read it back out. `aad` binds
/// the ciphertext to the record it's for (app + user), so it can't be
/// replayed elsewhere even if intercepted.
///
/// Returns `base64(encapsulated_key || ciphertext)`.
pub fn seal(public_key_b64: &str, plaintext: &[u8], aad: &[u8]) -> Result<String> {
    let recipient_pk = public_key_from_base64(public_key_b64)?;

    let (encapped_key, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &recipient_pk,
        INFO,
        plaintext,
        aad,
    )
    .map_err(|err| anyhow::anyhow!("HPKE encryption failed: {err}"))?;

    let mut out = encapped_key.to_bytes().to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

/// Decrypts a payload produced by [`seal`], using the matching private key.
/// `aad` must be exactly what was passed to `seal` -- wowauth uses
/// `"{app_id}:{user_id}"`.
pub fn open(private_key_b64: &str, sealed_b64: &str, aad: &[u8]) -> Result<Vec<u8>> {
    let recipient_sk = private_key_from_base64(private_key_b64)?;
    let sealed_bytes = base64::engine::general_purpose::STANDARD
        .decode(sealed_b64.trim())
        .context("sealed token is not valid base64")?;
    if sealed_bytes.len() < ENCAPPED_KEY_LEN {
        anyhow::bail!("sealed token is too short to contain an encapsulated key");
    }
    let (encapped_key_bytes, ciphertext) = sealed_bytes.split_at(ENCAPPED_KEY_LEN);
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(encapped_key_bytes)
        .map_err(|_| anyhow::anyhow!("sealed token has a malformed encapsulated key"))?;

    hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &recipient_sk,
        &encapped_key,
        INFO,
        ciphertext,
        aad,
    )
    .map_err(|err| anyhow::anyhow!("HPKE decryption failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_to_a_fresh_keypair() {
        let (_sk, pk) = Kem::gen_keypair();
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(pk.to_bytes());

        let sealed = seal(&public_key_b64, b"access-token", b"app:user").unwrap();
        assert!(!sealed.is_empty());
    }

    /// Proves `open` is actually the inverse of `seal`, the way a real
    /// caller (e.g. `wowauth-client`, or a hand-rolled decryptor in another
    /// language) would use it.
    #[test]
    fn round_trips_through_open() {
        let (sk, pk) = Kem::gen_keypair();
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(pk.to_bytes());
        let private_key_b64 = base64::engine::general_purpose::STANDARD.encode(sk.to_bytes());
        let aad = b"app-id:user-id";

        let sealed = seal(&public_key_b64, b"real-access-token", aad).unwrap();
        let plaintext = open(&private_key_b64, &sealed, aad).unwrap();

        assert_eq!(plaintext, b"real-access-token");
    }

    #[test]
    fn open_rejects_a_mismatched_aad() {
        let (sk, pk) = Kem::gen_keypair();
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(pk.to_bytes());
        let private_key_b64 = base64::engine::general_purpose::STANDARD.encode(sk.to_bytes());

        let sealed = seal(&public_key_b64, b"real-access-token", b"app:user").unwrap();
        assert!(open(&private_key_b64, &sealed, b"different:aad").is_err());
    }

    #[test]
    fn open_rejects_the_wrong_private_key() {
        let (_sk, pk) = Kem::gen_keypair();
        let (other_sk, _other_pk) = Kem::gen_keypair();
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(pk.to_bytes());
        let other_private_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(other_sk.to_bytes());

        let sealed = seal(&public_key_b64, b"real-access-token", b"app:user").unwrap();
        assert!(open(&other_private_key_b64, &sealed, b"app:user").is_err());
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(validate_public_key("not base64!!").is_err());
        assert!(validate_public_key("dG9vc2hvcnQ=").is_err());
    }
}
