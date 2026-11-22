// Test helpers for Workers that use this package: a just-enough D1 over
// node:sqlite, a KV stand-in, the tables App Attest reads, and a fake device
// that signs the way the app does. Import it from tests only
// ("@dryan/app-attest-worker/testing"); it needs Node's node:sqlite.
//
// ATTEST_SCHEMA is a copy of the final shape of the dryan-analytics tables
// the package reads (migrations 0001 and 0002 there own the real schema).
// A column added there that the package starts reading must be added here.

import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { encode as cborEncode } from "cbor-x";
import { sha256, toBase64 } from "./appattest";
import { clearAppsCache } from "./apps";
import type { AttestConfig } from "./config";

export const ATTEST_SCHEMA = `
CREATE TABLE apps (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  attest_app_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE app_attest_ids (
  app TEXT NOT NULL REFERENCES apps (id),
  attest_app_id TEXT NOT NULL,
  PRIMARY KEY (app, attest_app_id)
);
CREATE TABLE attest_keys (
  app TEXT NOT NULL REFERENCES apps (id),
  key_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  environment TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  last_seen_at TEXT,
  attest_app_id TEXT,
  PRIMARY KEY (app, key_id)
);
`;

class Statement {
  private args: SQLInputValue[] = [];
  constructor(
    private db: DatabaseSync,
    readonly sql: string,
  ) {}
  bind(...args: unknown[]): Statement {
    const next = new Statement(this.db, this.sql);
    next.args = args as SQLInputValue[];
    return next;
  }
  async run() {
    const r = this.db.prepare(this.sql).run(...this.args);
    return { success: true, results: [], meta: { changes: Number(r.changes) } };
  }
  async all<T>() {
    return {
      results: this.db.prepare(this.sql).all(...this.args) as T[],
      success: true,
      meta: {},
    };
  }
  async first<T>(): Promise<T | null> {
    return (
      (this.db.prepare(this.sql).get(...this.args) as T | undefined) ?? null
    );
  }
}

/** An in-memory database with the App Attest tables and the given apps (id, name, App ID). */
export function attestDatabase(
  apps: readonly [id: string, name: string, attestAppId: string][],
): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  db.exec(ATTEST_SCHEMA);
  for (const [id, name, attestAppId] of apps) {
    db.prepare(
      "INSERT INTO apps (id, name, attest_app_id) VALUES (?, ?, ?)",
    ).run(id, name, attestAppId);
  }
  return db;
}

export function fakeD1(db: DatabaseSync): D1Database {
  return {
    prepare: (sql: string) => new Statement(db, sql),
  } as unknown as D1Database;
}

export function fakeKV(): KVNamespace {
  const store = new Map<string, string>();
  return {
    get: async (k: string) => store.get(k) ?? null,
    put: async (k: string, v: string) => void store.set(k, v),
  } as unknown as KVNamespace;
}

/** A config over `db` and a fresh KV. Clears the app registry cache, since each test brings its own database. */
export function testConfig(
  db: DatabaseSync,
  extra: Partial<AttestConfig> = {},
): AttestConfig {
  clearAppsCache();
  return {
    db: fakeD1(db),
    challenges: fakeKV(),
    allowDevelopment: true,
    ...extra,
  };
}

/** authenticatorData for an assertion: rpIdHash || flags || counter. */
export async function authData(
  appId: string,
  counter: number,
): Promise<Uint8Array> {
  const out = new Uint8Array(37);
  out.set(await sha256(new TextEncoder().encode(appId)), 0);
  new DataView(out.buffer).setUint32(33, counter, false);
  return out;
}

function rawToDer(raw: Uint8Array): Uint8Array {
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

/** A fake device: an ECDSA key it signs assertions with. `register` stores its public key as POST /attest would. */
export class FakeDevice {
  counter = 0;
  private constructor(
    readonly keyId: string,
    private privateKey: CryptoKey,
    readonly publicKey: string,
  ) {}

  static async create(keyId: string): Promise<FakeDevice> {
    const pair = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const spki = new Uint8Array(
      (await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer,
    );
    return new FakeDevice(keyId, pair.privateKey, toBase64(spki));
  }

  register(
    db: DatabaseSync,
    app: string,
    attestAppId: string | null = null,
  ): void {
    db.prepare(
      "INSERT INTO attest_keys (app, key_id, public_key, environment, counter, created_at, attest_app_id) VALUES (?, ?, ?, 'production', 0, 'now', ?)",
    ).run(app, this.keyId, this.publicKey, attestAppId);
  }

  /** The two App Attest headers for a request with exactly these body bytes, advancing the counter. */
  async sign(appId: string, body: string): Promise<Record<string, string>> {
    this.counter += 1;
    const data = await authData(appId, this.counter);
    const nonce = await sha256(
      data,
      await sha256(new TextEncoder().encode(body)),
    );
    const raw = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        this.privateKey,
        nonce,
      ),
    );
    return {
      "x-app-attest-keyid": this.keyId,
      "x-app-attest-assertion": toBase64(
        cborEncode({ signature: rawToDer(raw), authenticatorData: data }),
      ),
    };
  }
}
