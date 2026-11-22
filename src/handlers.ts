// The two endpoints every Worker that checks App Attest serves itself, so an
// app can fetch its challenge from, and register its key through, whichever
// host it is talking to. Keys land in the shared `attest_keys` table.

import type { AttestConfig } from "./config";
import { json } from "./http";
import {
  attestAppIdsFor,
  resolveApp,
  UnknownAppError,
  type AppConfig,
} from "./apps";
import { consumeChallenge, issueChallenge } from "./challenge";
import {
  AppAttestError,
  fromBase64,
  sha256,
  verifyAttestation,
} from "./appattest";

const MAX_ATTEST_BODY_BYTES = 256 * 1024;

interface AttestBody {
  app?: string;
  install_id?: string;
  key_id: string;
  attestation: string;
  challenge: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** POST /challenge: `200 {"challenge": "<64 hex characters>"}`, valid for 60 seconds, usable once. */
export function handleChallenge(config: AttestConfig): Promise<Response> {
  return issueChallenge(config.challenges);
}

/**
 * POST /attest: registers an App Attest key for an app. Body:
 * `{ app?, key_id, attestation, challenge }` (`install_id` is accepted and discarded).
 * `200 {"status":"registered","environment":"production"|"development"}`.
 */
export async function handleAttest(
  request: Request,
  config: AttestConfig,
): Promise<Response> {
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.length === 0) return json(400, { error: "Empty body" });
  if (bytes.length > MAX_ATTEST_BODY_BYTES)
    return json(413, { error: "Body too large" });
  let body: AttestBody;
  try {
    body = JSON.parse(new TextDecoder().decode(bytes)) as AttestBody;
  } catch {
    return json(400, { error: "Invalid JSON body" });
  }
  // install_id is accepted (clients send it) but never required or stored.
  if (
    !isRecord(body) ||
    [body.key_id, body.attestation, body.challenge].some(
      (v) => typeof v !== "string" || !v,
    )
  ) {
    return json(400, { error: "Invalid request body" });
  }
  let app: AppConfig;
  try {
    app = await resolveApp(config, body.app, request.headers.get("x-app"));
  } catch (err) {
    if (err instanceof UnknownAppError)
      return json(400, { error: err.message });
    throw err;
  }
  if (!(await consumeChallenge(config.challenges, body.challenge))) {
    return json(401, { error: "Invalid or expired challenge" });
  }

  try {
    const result = await (config.verifyAttestation ?? verifyAttestation)({
      attestation: fromBase64(body.attestation),
      keyId: body.key_id,
      clientDataHash: await sha256(new TextEncoder().encode(body.challenge)),
      appIds: await attestAppIdsFor(config, app),
      allowDevelopment: config.allowDevelopment,
    });
    await config.db
      .prepare(
        `INSERT INTO attest_keys (app, key_id, public_key, environment, counter, created_at, attest_app_id)
       VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)
       ON CONFLICT(app, key_id) DO UPDATE SET public_key = excluded.public_key,
         environment = excluded.environment, counter = 0, created_at = excluded.created_at,
         attest_app_id = excluded.attest_app_id`,
      )
      .bind(
        app.id,
        body.key_id,
        result.publicKey,
        result.environment,
        new Date().toISOString(),
        result.appId,
      )
      .run();
    return json(200, { status: "registered", environment: result.environment });
  } catch (err) {
    if (err instanceof AppAttestError) return json(401, { error: err.message });
    throw err;
  }
}
