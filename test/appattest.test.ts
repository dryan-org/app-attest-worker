import { describe, expect, it } from "vitest";
import { encode as cborEncode } from "cbor-x";
import {
  derSignatureToRaw,
  fromBase64,
  parseAuthData,
  sha256,
  toBase64,
  verifyAssertion,
  AppAttestError,
} from "../src/appattest";

const APP_ID = "636WEWBRAF.com.dryan.crumbdb";

async function authDataFor(
  appId: string,
  counter: number,
  withCredential?: Uint8Array,
): Promise<Uint8Array> {
  const rpIdHash = await sha256(new TextEncoder().encode(appId));
  const head = new Uint8Array(37);
  head.set(rpIdHash, 0);
  head[32] = withCredential ? 0x40 : 0x00;
  new DataView(head.buffer).setUint32(33, counter, false);
  if (!withCredential) return head;
  const aaguid = new TextEncoder().encode("appattest\0\0\0\0\0\0\0");
  const out = new Uint8Array(37 + 16 + 2 + withCredential.length);
  out.set(head, 0);
  out.set(aaguid, 37);
  new DataView(out.buffer).setUint16(53, withCredential.length, false);
  out.set(withCredential, 55);
  return out;
}

/** Signs the way a device does, so verifyAssertion can be exercised end to end. */
async function signAssertion(authData: Uint8Array, clientDataHash: Uint8Array) {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const nonce = await sha256(authData, clientDataHash);
  const raw = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      pair.privateKey,
      nonce,
    ),
  );
  const der = rawSignatureToDer(raw);
  const spki = new Uint8Array(
    (await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer,
  );
  return {
    publicKey: toBase64(spki),
    assertion: cborEncode({ signature: der, authenticatorData: authData }),
  };
}

function rawSignatureToDer(raw: Uint8Array): Uint8Array {
  const int = (bytes: Uint8Array): Uint8Array => {
    let v = bytes;
    while (v.length > 1 && v[0] === 0 && ((v[1] ?? 0) & 0x80) === 0)
      v = v.slice(1);
    if ((v[0] ?? 0) & 0x80) v = new Uint8Array([0, ...v]);
    return new Uint8Array([0x02, v.length, ...v]);
  };
  const r = int(raw.slice(0, 32));
  const s = int(raw.slice(32));
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s]);
}

describe("derSignatureToRaw", () => {
  it("round-trips a WebCrypto signature", async () => {
    const pair = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const data = new TextEncoder().encode("hello");
    const raw = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        data,
      ),
    );
    expect(derSignatureToRaw(rawSignatureToDer(raw))).toEqual(raw);
  });

  it("rejects something that is not a sequence", () => {
    expect(() => derSignatureToRaw(new Uint8Array([0x02, 0x01, 0x00]))).toThrow(
      AppAttestError,
    );
  });
});

describe("parseAuthData", () => {
  it("reads the rpIdHash, flags, counter and credential", async () => {
    const cred = new Uint8Array(32).fill(7);
    const data = await authDataFor(APP_ID, 5, cred);
    const parsed = parseAuthData(data);
    expect(parsed.counter).toBe(5);
    expect(parsed.aaguid).toBe("appattest\0\0\0\0\0\0\0");
    expect(parsed.credentialId).toEqual(cred);
  });

  it("rejects short data", () => {
    expect(() => parseAuthData(new Uint8Array(10))).toThrow(AppAttestError);
  });
});

describe("verifyAssertion", () => {
  it("accepts a valid assertion and returns the counter", async () => {
    const body = new TextEncoder().encode('{"install_id":"x","events":[]}');
    const clientDataHash = await sha256(body);
    const authData = await authDataFor(APP_ID, 3);
    const { publicKey, assertion } = await signAssertion(
      authData,
      clientDataHash,
    );
    const result = await verifyAssertion({
      assertion,
      publicKey,
      clientDataHash,
      appId: APP_ID,
      previousCounter: 2,
    });
    expect(result.counter).toBe(3);
  });

  it("rejects a replayed counter", async () => {
    const clientDataHash = await sha256(new Uint8Array([1]));
    const authData = await authDataFor(APP_ID, 3);
    const { publicKey, assertion } = await signAssertion(
      authData,
      clientDataHash,
    );
    await expect(
      verifyAssertion({
        assertion,
        publicKey,
        clientDataHash,
        appId: APP_ID,
        previousCounter: 3,
      }),
    ).rejects.toThrow(/counter/);
  });

  it("rejects a body that was not the one signed", async () => {
    const authData = await authDataFor(APP_ID, 1);
    const { publicKey, assertion } = await signAssertion(
      authData,
      await sha256(new Uint8Array([1])),
    );
    await expect(
      verifyAssertion({
        assertion,
        publicKey,
        clientDataHash: await sha256(new Uint8Array([2])),
        appId: APP_ID,
        previousCounter: 0,
      }),
    ).rejects.toThrow(/signature/);
  });

  it("rejects another app's assertion", async () => {
    const clientDataHash = await sha256(new Uint8Array([1]));
    const authData = await authDataFor("TEAM.com.example.other", 1);
    const { publicKey, assertion } = await signAssertion(
      authData,
      clientDataHash,
    );
    await expect(
      verifyAssertion({
        assertion,
        publicKey,
        clientDataHash,
        appId: APP_ID,
        previousCounter: 0,
      }),
    ).rejects.toThrow(/different app/);
  });
});

describe("malformed assertions", () => {
  it("rejects bytes that are not an assertion, with no key fallback", async () => {
    const clientDataHash = await sha256(new Uint8Array([1]));
    const { publicKey } = await signAssertion(
      await authDataFor(APP_ID, 1),
      clientDataHash,
    );
    await expect(
      verifyAssertion({
        assertion: new Uint8Array([1, 2, 3]),
        publicKey,
        clientDataHash,
        appId: APP_ID,
        previousCounter: 0,
      }),
    ).rejects.toThrow(AppAttestError);
    const empty = cborEncode({
      signature: new Uint8Array(70),
      authenticatorData: await authDataFor(APP_ID, 9),
    });
    await expect(
      verifyAssertion({
        assertion: empty,
        publicKey,
        clientDataHash,
        appId: APP_ID,
        previousCounter: 0,
      }),
    ).rejects.toThrow(AppAttestError);
  });
});

describe("base64 helpers", () => {
  it("handles url-safe input", () => {
    expect(fromBase64("-_8")).toEqual(new Uint8Array([0xfb, 0xff]));
    expect(toBase64(new Uint8Array([0xfb, 0xff]))).toBe("+/8=");
  });
});
