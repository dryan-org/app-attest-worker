import { DatabaseSync } from "node:sqlite";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  APPS_CACHE_TTL_MS,
  AppAttestError,
  UNKNOWN_KEY_ERROR,
  UnknownAppError,
  attestAppIdsFor,
  attestHeaders,
  checkAssertion,
  checkChallenge,
  consumeChallenge,
  handleAttest,
  handleChallenge,
  listApps,
  loadApps,
  resolveApp,
  type AttestConfig,
} from "../src/index";
import { FakeDevice, attestDatabase, testConfig } from "../src/testing";

const MARIE = "636WEWBRAF.com.dryan.marie";
const HELPER = "636WEWBRAF.com.dryan.marie.worker";
const CRUMB = "636WEWBRAF.com.dryan.crumbdb";

let db: DatabaseSync;
let config: AttestConfig;
let device: FakeDevice;

async function challenge(): Promise<string> {
  return (
    (await (await handleChallenge(config)).json()) as { challenge: string }
  ).challenge;
}

beforeEach(async () => {
  db = attestDatabase([
    ["crumbdb", "CrumbDB", CRUMB],
    ["marie", "Marie", MARIE],
  ]);
  db.prepare(
    "INSERT INTO app_attest_ids (app, attest_app_id) VALUES ('marie', ?)",
  ).run(HELPER);
  config = testConfig(db, { defaultApp: "crumbdb" });
  device = await FakeDevice.create("key-1");
  device.register(db, "marie");
});

describe("challenges", () => {
  it("issues 64 hex characters, usable once", async () => {
    const res = await handleChallenge(config);
    expect(res.status).toBe(200);
    const { challenge: nonce } = (await res.json()) as { challenge: string };
    expect(nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(await consumeChallenge(config.challenges, nonce)).toBe(true);
    expect(await consumeChallenge(config.challenges, nonce)).toBe(false);
  });

  it("refuses a nonce it never issued, a malformed one and none", async () => {
    expect(await consumeChallenge(config.challenges, "a".repeat(64))).toBe(
      false,
    );
    expect(await consumeChallenge(config.challenges, "nope")).toBe(false);
    expect(await consumeChallenge(config.challenges, null)).toBe(false);
  });

  it("stores the nonce with a 60 second lifetime", async () => {
    const put = vi.fn(async () => {});
    await handleChallenge({
      ...config,
      challenges: { put } as unknown as KVNamespace,
    });
    expect(put).toHaveBeenCalledWith(
      expect.stringMatching(/^[0-9a-f]{64}$/),
      "1",
      { expirationTtl: 60 },
    );
  });
});

describe("app registry", () => {
  it("lists the apps and every App ID each accepts, the primary one first", async () => {
    expect((await listApps(config)).map((a) => a.id)).toEqual([
      "crumbdb",
      "marie",
    ]);
    const marie = (await loadApps(config)).get("marie")!;
    expect(await attestAppIdsFor(config, marie)).toEqual([MARIE, HELPER]);
  });

  it("resolves from the body, the header, both when they agree, and the default", async () => {
    expect((await resolveApp(config, "marie", null)).id).toBe("marie");
    expect((await resolveApp(config, undefined, "marie")).id).toBe("marie");
    expect((await resolveApp(config, "marie", "marie")).id).toBe("marie");
    expect((await resolveApp(config, undefined, null)).id).toBe("crumbdb");
    expect((await resolveApp(config, "", null)).id).toBe("crumbdb");
  });

  it("refuses unknown apps, non-strings, disagreement, and a missing app with no default", async () => {
    for (const [body, header] of [
      ["nope", null],
      [7, null],
      ["__proto__", null],
      ["marie", "crumbdb"],
    ] as const) {
      await expect(resolveApp(config, body, header)).rejects.toThrow(
        UnknownAppError,
      );
    }
    await expect(
      resolveApp({ ...config, defaultApp: undefined }, undefined, null),
    ).rejects.toThrow(UnknownAppError);
  });

  it("caches the table for APPS_CACHE_TTL_MS", async () => {
    const t0 = Date.now();
    expect((await loadApps(config, t0)).has("late")).toBe(false);
    db.prepare(
      "INSERT INTO apps (id, name, attest_app_id) VALUES ('late', 'Late', '636WEWBRAF.com.dryan.late')",
    ).run();
    expect(
      (await loadApps(config, t0 + APPS_CACHE_TTL_MS - 1)).has("late"),
    ).toBe(false);
    expect((await loadApps(config, t0 + APPS_CACHE_TTL_MS)).has("late")).toBe(
      true,
    );
  });
});

describe("attestHeaders and checkChallenge", () => {
  const request = (headers: Record<string, string>): Request =>
    new Request("https://x.test/", { method: "POST", headers });

  it("needs the key id and the assertion", async () => {
    for (const h of [
      {},
      { "x-app-attest-keyid": "k" },
      { "x-app-attest-assertion": "a" },
    ] as Record<string, string>[]) {
      const res = attestHeaders(request(h));
      expect(res).toBeInstanceOf(Response);
      expect((res as Response).status).toBe(401);
      expect(await (res as Response).json()).toEqual({
        error: "Missing App Attest headers",
      });
    }
    expect(
      attestHeaders(
        request({
          "x-app-attest-keyid": "k",
          "x-app-attest-assertion": "a",
          "x-app-attest-challenge": "c",
        }),
      ),
    ).toEqual({ keyId: "k", assertion: "a", challenge: "c" });
  });

  it("takes the body challenge, falls back to the header, and refuses a mismatch", async () => {
    const n1 = await challenge();
    expect(
      await checkChallenge(config, n1, {
        keyId: "k",
        assertion: "a",
        challenge: null,
      }),
    ).toBeNull();
    const n2 = await challenge();
    expect(
      await checkChallenge(config, undefined, {
        keyId: "k",
        assertion: "a",
        challenge: n2,
      }),
    ).toBeNull();
    const n3 = await challenge();
    const mismatch = await checkChallenge(config, n3, {
      keyId: "k",
      assertion: "a",
      challenge: "b".repeat(64),
    });
    expect(mismatch?.status).toBe(401);
    expect(await mismatch?.json()).toEqual({ error: "Challenge mismatch" });
    const replay = await checkChallenge(config, n1, {
      keyId: "k",
      assertion: "a",
      challenge: null,
    });
    expect(await replay?.json()).toEqual({
      error: "Invalid or expired challenge",
    });
  });
});

describe("checkAssertion", () => {
  const headersFor = async (appId: string, body: string, d = device) => {
    const h = await d.sign(appId, body);
    return {
      keyId: h["x-app-attest-keyid"]!,
      assertion: h["x-app-attest-assertion"]!,
      challenge: null,
    };
  };
  const marie = () => resolveApp(config, "marie", null);

  it("accepts a signed body and advances the counter and last_seen_at", async () => {
    expect(
      await checkAssertion(
        config,
        await marie(),
        await headersFor(MARIE, "body"),
        new TextEncoder().encode("body"),
        true,
      ),
    ).toBeNull();
    expect(
      db
        .prepare(
          "SELECT counter, last_seen_at IS NOT NULL AS seen FROM attest_keys",
        )
        .get(),
    ).toEqual({ counter: 1, seen: 1 });
  });

  it("leaves last_seen_at alone when asked, but still advances the counter", async () => {
    await checkAssertion(
      config,
      await marie(),
      await headersFor(MARIE, "b"),
      new TextEncoder().encode("b"),
      false,
    );
    expect(
      db.prepare("SELECT counter, last_seen_at FROM attest_keys").get(),
    ).toEqual({ counter: 1, last_seen_at: null });
  });

  it("gives an unknown key the exact 401 that tells the client to register", async () => {
    const other = await FakeDevice.create("stranger");
    const res = await checkAssertion(
      config,
      await marie(),
      await headersFor(MARIE, "b", other),
      new TextEncoder().encode("b"),
      true,
    );
    expect(res?.status).toBe(401);
    expect(await res?.json()).toEqual({ error: UNKNOWN_KEY_ERROR });
  });

  it("refuses a body that was not signed, and a replayed counter", async () => {
    const h = await headersFor(MARIE, "signed");
    const wrong = await checkAssertion(
      config,
      await marie(),
      h,
      new TextEncoder().encode("tampered"),
      true,
    );
    expect(await wrong?.json()).toEqual({
      error: "assertion signature is invalid",
    });
    expect(
      await checkAssertion(
        config,
        await marie(),
        h,
        new TextEncoder().encode("signed"),
        true,
      ),
    ).toBeNull();
    const replay = await checkAssertion(
      config,
      await marie(),
      h,
      new TextEncoder().encode("signed"),
      true,
    );
    expect(await replay?.json()).toEqual({
      error: "assertion counter did not increase",
    });
  });

  it("checks a key against the App ID it attested as only", async () => {
    db.prepare("UPDATE attest_keys SET attest_app_id = ?").run(HELPER);
    const asPrimary = await checkAssertion(
      config,
      await marie(),
      await headersFor(MARIE, "b"),
      new TextEncoder().encode("b"),
      true,
    );
    expect(await asPrimary?.json()).toEqual({
      error: "assertion is for a different app",
    });
    expect(
      await checkAssertion(
        config,
        await marie(),
        await headersFor(HELPER, "b"),
        new TextEncoder().encode("b"),
        true,
      ),
    ).toBeNull();
  });

  it("refuses a key whose App ID the app no longer lists", async () => {
    db.prepare(
      "UPDATE attest_keys SET attest_app_id = '636WEWBRAF.com.dryan.gone'",
    ).run();
    const res = await checkAssertion(
      config,
      await marie(),
      await headersFor(MARIE, "b"),
      new TextEncoder().encode("b"),
      true,
    );
    expect(await res?.json()).toEqual({
      error: "assertion is for a different app",
    });
  });
});

describe("handleAttest", () => {
  const stub = vi.fn();
  const attest = async (
    body: unknown,
    headers: Record<string, string> = {},
    cfg: AttestConfig = config,
  ): Promise<Response> =>
    handleAttest(
      new Request("https://x.test/attest", {
        method: "POST",
        body: typeof body === "string" ? body : JSON.stringify(body),
        headers,
      }),
      { ...cfg, verifyAttestation: stub },
    );

  beforeEach(() => {
    stub.mockReset();
    stub.mockResolvedValue({
      appId: MARIE,
      publicKey: "PUB",
      environment: "production",
    });
  });

  it("registers the key under the app and returns the environment", async () => {
    const res = await attest({
      app: "marie",
      key_id: "new-key",
      attestation: "AAAA",
      challenge: await challenge(),
      install_id: "ignored",
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      status: "registered",
      environment: "production",
    });
    expect(
      db
        .prepare(
          "SELECT app, public_key, counter, attest_app_id FROM attest_keys WHERE key_id = 'new-key'",
        )
        .get(),
    ).toEqual({
      app: "marie",
      public_key: "PUB",
      counter: 0,
      attest_app_id: MARIE,
    });
    expect(stub.mock.calls[0]![0]).toMatchObject({
      keyId: "new-key",
      appIds: [MARIE, HELPER],
      allowDevelopment: true,
    });
  });

  it("answers bad input with the same statuses and bodies as ever", async () => {
    const cases: [unknown, number, string][] = [
      ["", 400, "Empty body"],
      ["{", 400, "Invalid JSON body"],
      [
        { app: "marie", key_id: "k", attestation: "", challenge: "c" },
        400,
        "Invalid request body",
      ],
      [[1], 400, "Invalid request body"],
      [
        { app: "nope", key_id: "k", attestation: "AAAA", challenge: "c" },
        400,
        "Unknown app",
      ],
      [
        { app: "marie", key_id: "k", attestation: "AAAA", challenge: "c" },
        401,
        "Invalid or expired challenge",
      ],
    ];
    for (const [body, status, error] of cases) {
      const res = await attest(body);
      expect([res.status, await res.json()]).toEqual([status, { error }]);
    }
    const big = await attest("x".repeat(256 * 1024 + 1));
    expect([big.status, await big.json()]).toEqual([
      413,
      { error: "Body too large" },
    ]);
  });

  it("spends the challenge: a second use is refused", async () => {
    const c = await challenge();
    expect(
      (
        await attest({
          app: "marie",
          key_id: "k",
          attestation: "AAAA",
          challenge: c,
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await attest({
          app: "marie",
          key_id: "k",
          attestation: "AAAA",
          challenge: c,
        })
      ).status,
    ).toBe(401);
  });

  it("turns a failed verification into a 401 with its reason, storing nothing", async () => {
    stub.mockRejectedValue(
      new AppAttestError("attestation is for a different app"),
    );
    const res = await attest({
      app: "marie",
      key_id: "bad",
      attestation: "AAAA",
      challenge: await challenge(),
    });
    expect([res.status, await res.json()]).toEqual([
      401,
      { error: "attestation is for a different app" },
    ]);
    expect(
      db
        .prepare("SELECT count(*) AS n FROM attest_keys WHERE key_id = 'bad'")
        .get(),
    ).toEqual({ n: 0 });
  });

  it("re-registering a key resets its counter", async () => {
    db.prepare(
      "UPDATE attest_keys SET counter = 9 WHERE key_id = 'key-1'",
    ).run();
    await attest({
      app: "marie",
      key_id: "key-1",
      attestation: "AAAA",
      challenge: await challenge(),
    });
    expect(
      db
        .prepare("SELECT counter FROM attest_keys WHERE key_id = 'key-1'")
        .get(),
    ).toEqual({ counter: 0 });
  });

  it("reads the app from X-App, and refuses a body that disagrees", async () => {
    expect(
      (
        await attest(
          { key_id: "k", attestation: "AAAA", challenge: await challenge() },
          { "x-app": "marie" },
        )
      ).status,
    ).toBe(200);
    const res = await attest(
      {
        app: "crumbdb",
        key_id: "k",
        attestation: "AAAA",
        challenge: await challenge(),
      },
      { "x-app": "marie" },
    );
    expect(await res.json()).toEqual({
      error: "App in body and X-App header disagree",
    });
  });

  it("rejects an attestation that is not a real one when no stub is installed", async () => {
    const res = await handleAttest(
      new Request("https://x.test/attest", {
        method: "POST",
        body: JSON.stringify({
          app: "marie",
          key_id: "k",
          attestation: btoa("not cbor at all"),
          challenge: await challenge(),
        }),
      }),
      config,
    );
    expect(res.status).toBe(401);
  });
});
