// Browser-native crypto for the Nmbrs connection wizard -- no external
// crypto library needed. X25519 keygen and PKCE both go through the
// standard Web Crypto API (window.crypto.subtle), same as any modern
// browser implements for TLS/WebAuthn.

export interface X25519KeyPair {
  publicKeyB64: string;
  privateKeyB64: string;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Generates an X25519 key pair entirely client-side. The private key never
 * leaves the browser until the user chooses to save it at the end of the
 * wizard. `raw` export gives the public key's bare 32 bytes directly;
 * private keys can only export as PKCS8, so the fixed-size DER header is
 * stripped to get the raw 32 bytes wowauth expects (same trick
 * docs/examples/nmbrs-setup.ts uses on the Node side). */
export async function generateX25519KeyPair(): Promise<X25519KeyPair> {
  const keyPair = (await crypto.subtle.generateKey({ name: "X25519" }, true, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const rawPublic = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const pkcs8Private = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  const rawPrivate = pkcs8Private.slice(pkcs8Private.length - 32);
  return { publicKeyB64: toBase64(rawPublic), privateKeyB64: toBase64(rawPrivate) };
}

export function randomState(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomPkceVerifier(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return toBase64Url(new Uint8Array(digest));
}
