// App Attest verification, following Apple's "Validating apps that connect
// to your server". Two halves:
//
//   attestation  (POST /attest, once per key)  -> proves the key was made in
//                the Secure Enclave of a genuine copy of the app; we keep its
//                public key.
//   assertion    (every attested request)      -> proves this request was
//                signed by that key, with a monotonically increasing counter.
//
// Everything here is pure WebCrypto plus small parsers, so it runs in a
// Worker without Node's crypto module.

import { decode as cborDecode } from "cbor-x";
import * as x509 from "@peculiar/x509";
import * as asn1js from "asn1js";
import appleRootPem from "./apple-root";

x509.cryptoProvider.set(crypto);

/** OID of the certificate extension that carries the attestation nonce. */
const NONCE_EXTENSION_OID = "1.2.840.113635.100.8.2";

const AAGUID_PRODUCTION = "appattest\0\0\0\0\0\0\0";
const AAGUID_DEVELOPMENT = "appattestdevelop";

export type Environment = "production" | "development";

export interface AttestationResult {
  /** Which of the accepted App IDs the attestation is for. */
  appId: string;
  /** SPKI DER, base64. */
  publicKey: string;
  environment: Environment;
}

export class AppAttestError extends Error {}

// ── Byte helpers ─────────────────────────────────────────────────────────────

export async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    joined.set(p, offset);
    offset += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", joined));
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

export function fromBase64(s: string): Uint8Array {
  const normalised = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalised + "=".repeat((4 - (normalised.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

export function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function asBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new AppAttestError("expected a byte string");
}

/**
 * ECDSA signatures from Apple are DER SEQUENCE { r INTEGER, s INTEGER };
 * WebCrypto wants the raw 64-byte r || s form.
 */
export function derSignatureToRaw(der: Uint8Array, size = 32): Uint8Array {
  if (der[0] !== 0x30)
    throw new AppAttestError("signature is not a DER sequence");
  let offset = 2;
  if ((der[1] ?? 0) & 0x80) offset = 2 + ((der[1] ?? 0) & 0x7f);
  const readInt = (): Uint8Array => {
    if (der[offset] !== 0x02)
      throw new AppAttestError("signature integer missing");
    const len = der[offset + 1] ?? 0;
    const start = offset + 2;
    let value = der.slice(start, start + len);
    offset = start + len;
    while (value.length > size && value[0] === 0) value = value.slice(1);
    if (value.length > size)
      throw new AppAttestError("signature integer too long");
    const out = new Uint8Array(size);
    out.set(value, size - value.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  const raw = new Uint8Array(size * 2);
  raw.set(r, 0);
  raw.set(s, size);
  return raw;
}

// ── Authenticator data ──────────────────────────────────────────────────────

export interface AuthData {
  rpIdHash: Uint8Array;
  flags: number;
  counter: number;
  aaguid?: string;
  credentialId?: Uint8Array;
}

/** rpIdHash (32) || flags (1) || counter (4, big-endian) || [attested credential data]. */
export function parseAuthData(data: Uint8Array): AuthData {
  if (data.length < 37)
    throw new AppAttestError("authenticator data too short");
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const result: AuthData = {
    rpIdHash: data.slice(0, 32),
    flags: data[32] ?? 0,
    counter: view.getUint32(33, false),
  };
  // Attested credential data is present when the AT flag (bit 6) is set.
  if ((result.flags & 0x40) !== 0 && data.length >= 55) {
    result.aaguid = new TextDecoder().decode(data.slice(37, 53));
    const credIdLen = view.getUint16(53, false);
    result.credentialId = data.slice(55, 55 + credIdLen);
  }
  return result;
}

/** The App ID among `appIds` whose SHA-256 is `rpIdHash`, or undefined when none is. */
export async function matchAppId(
  rpIdHash: Uint8Array,
  appIds: readonly string[],
): Promise<string | undefined> {
  let match: string | undefined;
  for (const candidate of appIds) {
    if (bytesEqual(rpIdHash, await sha256(new TextEncoder().encode(candidate))))
      match = candidate;
  }
  return match;
}

// ── Attestation ─────────────────────────────────────────────────────────────

interface AttestationObject {
  fmt: string;
  attStmt: { x5c: unknown[]; receipt?: unknown };
  authData: unknown;
}

function nonceFromCertificate(cert: x509.X509Certificate): Uint8Array {
  const ext = cert.getExtension(NONCE_EXTENSION_OID);
  if (!ext)
    throw new AppAttestError(
      "attestation certificate lacks the nonce extension",
    );
  // SEQUENCE { [1] EXPLICIT OCTET STRING nonce }
  const outer = asn1js.fromBER(ext.value);
  if (outer.offset === -1)
    throw new AppAttestError("nonce extension is not valid ASN.1");
  const sequence = outer.result as asn1js.Sequence;
  const tagged = sequence.valueBlock.value[0] as asn1js.Constructed | undefined;
  const octet = tagged?.valueBlock.value[0] as asn1js.OctetString | undefined;
  if (!octet)
    throw new AppAttestError("nonce extension has an unexpected shape");
  return new Uint8Array(octet.valueBlock.valueHexView);
}

/** The uncompressed X9.62 point (0x04 || X || Y) is the tail of a P-256 SPKI. */
function uncompressedPointFromSpki(spki: Uint8Array): Uint8Array {
  if (spki.length < 65) throw new AppAttestError("public key too short");
  return spki.slice(spki.length - 65);
}

export async function verifyAttestation(input: {
  attestation: Uint8Array;
  keyId: string;
  clientDataHash: Uint8Array;
  /** Every App ID the app accepts; the attestation must be for one of them. */
  appIds: readonly string[];
  allowDevelopment: boolean;
  now?: Date;
}): Promise<AttestationResult> {
  const now = input.now ?? new Date();
  let obj: AttestationObject;
  try {
    obj = cborDecode(input.attestation) as AttestationObject;
  } catch {
    throw new AppAttestError("attestation is not valid CBOR");
  }
  if (obj?.fmt !== "apple-appattest")
    throw new AppAttestError("attestation format is not apple-appattest");
  const x5c = obj.attStmt?.x5c;
  if (!Array.isArray(x5c) || x5c.length < 2)
    throw new AppAttestError("attestation lacks a certificate chain");
  const authDataBytes = asBytes(obj.authData);

  // 1. Chain: credCert <- intermediate <- Apple App Attestation Root CA.
  const credCert = new x509.X509Certificate(asBytes(x5c[0]));
  const intermediate = new x509.X509Certificate(asBytes(x5c[1]));
  const root = new x509.X509Certificate(appleRootPem);
  const intermediateOk = await intermediate.verify({
    publicKey: await root.publicKey.export(),
    date: now,
  });
  const credOk = await credCert.verify({
    publicKey: await intermediate.publicKey.export(),
    date: now,
  });
  if (!intermediateOk || !credOk)
    throw new AppAttestError(
      "certificate chain does not lead to Apple's App Attest root",
    );
  if (credCert.notBefore > now || credCert.notAfter < now)
    throw new AppAttestError("attestation certificate is not currently valid");

  // 2. Nonce: SHA256(authData || clientDataHash) must match the cert's extension.
  const expectedNonce = await sha256(authDataBytes, input.clientDataHash);
  if (!bytesEqual(nonceFromCertificate(credCert), expectedNonce))
    throw new AppAttestError("attestation nonce mismatch");

  // 3. Key identifier: SHA256 of the uncompressed public key == keyId.
  const spki = new Uint8Array(credCert.publicKey.rawData);
  const keyIdBytes = fromBase64(input.keyId);
  if (!bytesEqual(await sha256(uncompressedPointFromSpki(spki)), keyIdBytes))
    throw new AppAttestError(
      "key identifier does not match the certificate's key",
    );

  // 4. Authenticator data: our app, fresh counter, matching aaguid and credential.
  const authData = parseAuthData(authDataBytes);
  const appId = await matchAppId(authData.rpIdHash, input.appIds);
  if (appId === undefined)
    throw new AppAttestError("attestation is for a different app");
  if (authData.counter !== 0)
    throw new AppAttestError("attestation counter is not zero");
  let environment: Environment;
  if (authData.aaguid === AAGUID_PRODUCTION) environment = "production";
  else if (authData.aaguid === AAGUID_DEVELOPMENT && input.allowDevelopment)
    environment = "development";
  else throw new AppAttestError("attestation environment is not accepted");
  if (!authData.credentialId || !bytesEqual(authData.credentialId, keyIdBytes))
    throw new AppAttestError("credential identifier does not match the key");

  return { appId, publicKey: toBase64(spki), environment };
}

// ── Assertion ───────────────────────────────────────────────────────────────

interface AssertionObject {
  signature: unknown;
  authenticatorData: unknown;
}

export interface AssertionResult {
  counter: number;
}

/**
 * Verifies a batch's assertion against a registered key. `clientDataHash`
 * is SHA256 of the exact request body bytes.
 */
export async function verifyAssertion(input: {
  assertion: Uint8Array;
  publicKey: string;
  clientDataHash: Uint8Array;
  appId: string;
  previousCounter: number;
}): Promise<AssertionResult> {
  const { signature, authenticatorData } = decodeAssertion(input.assertion);
  const authData = parseAuthData(authenticatorData);
  const rpIdHash = await sha256(new TextEncoder().encode(input.appId));
  if (!bytesEqual(authData.rpIdHash, rpIdHash))
    throw new AppAttestError("assertion is for a different app");
  if (authData.counter <= input.previousCounter)
    throw new AppAttestError("assertion counter did not increase");

  const nonce = await sha256(authenticatorData, input.clientDataHash);
  const key = await crypto.subtle.importKey(
    "spki",
    fromBase64(input.publicKey),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    derSignatureToRaw(signature),
    nonce,
  );
  if (!ok) throw new AppAttestError("assertion signature is invalid");
  return { counter: authData.counter };
}

function decodeAssertion(bytes: Uint8Array): {
  signature: Uint8Array;
  authenticatorData: Uint8Array;
} {
  let obj: AssertionObject;
  try {
    obj = cborDecode(bytes) as AssertionObject;
  } catch {
    throw new AppAttestError("assertion is not valid CBOR");
  }
  return {
    signature: asBytes(obj?.signature),
    authenticatorData: asBytes(obj?.authenticatorData),
  };
}
