// tests/src/keys.ts
//
// Mirrors src/token_seal.rs on the client side: same HPKE suite
// (DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305), same `info`
// string, same `aad` shape (`{app_id}:{user_id}`), same wire format
// (base64(encapsulated_key(32 bytes) || ciphertext)). This is the TypeScript
// equivalent of the Python snippet in docs/examples/DEFAULT.md step 7.
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

const suite = new CipherSuite({
  kem: KemId.DhkemX25519HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Chacha20Poly1305,
});

const INFO = new TextEncoder().encode("wowauth token v1");

// X25519 encapsulated keys (ephemeral public keys) are 32 bytes -- see
// token_seal.rs's ENCAPPED_KEY_LEN in its own round-trip test.
const ENCAPPED_KEY_LEN = 32;

export interface TestKeypair {
  keyPair: CryptoKeyPair;
  /** base64-encoded raw public key -- what goes in the `public_key` field of
   *  POST /apps or PATCH /apps/{id}. */
  publicKeyB64: string;
}

export async function generateTestKeypair(): Promise<TestKeypair> {
  const keyPair = await suite.kem.generateKeyPair();
  const publicKeyBytes = await suite.kem.serializePublicKey(keyPair.publicKey);
  const publicKeyB64 = Buffer.from(publicKeyBytes).toString("base64");
  return { keyPair, publicKeyB64 };
}

/** Decrypts the `token` field returned by GET /apps/{app_id}/users/{user_id}/token. */
export async function decryptToken(
  sealedB64: string,
  privateKey: CryptoKey,
  appId: string,
  userId: string,
): Promise<string> {
  const sealed = Buffer.from(sealedB64, "base64");
  const enc = sealed.subarray(0, ENCAPPED_KEY_LEN);
  const ciphertext = sealed.subarray(ENCAPPED_KEY_LEN);
  const aad = new TextEncoder().encode(`${appId}:${userId}`);

  const recipient = await suite.createRecipientContext({
    recipientKey: privateKey,
    enc,
    info: INFO,
  });
  const plaintext = await recipient.open(ciphertext, aad);
  return new TextDecoder().decode(plaintext);
}
