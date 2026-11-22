// The request checks every attested endpoint shares: the challenge (body copy
// covered by the signature, header copy for older clients) and the App Attest
// assertion against a key registered through POST /attest. There is no
// unregistered-key fallback: a key the server has not seen is a 401, which
// tells the client to register again.

import type { AttestConfig } from "./config";
import { json } from "./http";
import { attestAppIdsFor, type AppConfig } from "./apps";
import { consumeChallenge } from "./challenge";
import {
  AppAttestError,
  fromBase64,
  sha256,
  verifyAssertion,
} from "./appattest";

/** The exact 401 an unknown key gets. Marie's client forgets its key and re-attests on a repeated 401. */
export const UNKNOWN_KEY_ERROR = "Unknown key; register it with POST /attest";

export interface AttestHeaders {
  keyId: string;
  assertion: string;
  challenge: string | null;
}

/** The App Attest headers, or a 401 when one is missing. */
export function attestHeaders(request: Request): AttestHeaders | Response {
  const keyId = request.headers.get("x-app-attest-keyid");
  const assertion = request.headers.get("x-app-attest-assertion");
  if (!keyId || !assertion)
    return json(401, { error: "Missing App Attest headers" });
  return {
    keyId,
    assertion,
    challenge: request.headers.get("x-app-attest-challenge"),
  };
}

/**
 * Consumes the request's challenge. A body challenge is covered by the
 * signature and must match the header when both are sent; a client that
 * only sends the header still works. Returns a 401 response, or null.
 */
export async function checkChallenge(
  config: AttestConfig,
  bodyChallenge: unknown,
  headers: AttestHeaders,
): Promise<Response | null> {
  const challenge =
    typeof bodyChallenge === "string" ? bodyChallenge : headers.challenge;
  if (
    typeof bodyChallenge === "string" &&
    headers.challenge &&
    bodyChallenge !== headers.challenge
  ) {
    return json(401, { error: "Challenge mismatch" });
  }
  if (!(await consumeChallenge(config.challenges, challenge)))
    return json(401, { error: "Invalid or expired challenge" });
  return null;
}

/**
 * Verifies the assertion over SHA-256(body) with the app's registered key
 * and advances the key's counter. `touchLastSeen` false leaves last_seen_at
 * alone (identifying batches, so the key's activity time cannot be matched
 * to their arrival). Returns a 401 response, or null.
 */
export async function checkAssertion(
  config: AttestConfig,
  app: AppConfig,
  headers: AttestHeaders,
  body: Uint8Array,
  touchLastSeen: boolean,
): Promise<Response | null> {
  const key = await config.db
    .prepare(
      "SELECT public_key, counter, attest_app_id FROM attest_keys WHERE app = ?1 AND key_id = ?2",
    )
    .bind(app.id, headers.keyId)
    .first<{
      public_key: string;
      counter: number;
      attest_app_id: string | null;
    }>();
  if (!key) return json(401, { error: UNKNOWN_KEY_ERROR });
  // A key is checked against the App ID it attested as only (NULL: the app's primary one).
  const appId = key.attest_app_id ?? app.attestAppId;
  try {
    if (!(await attestAppIdsFor(config, app)).includes(appId))
      throw new AppAttestError("assertion is for a different app");
    const result = await verifyAssertion({
      assertion: fromBase64(headers.assertion),
      publicKey: key.public_key,
      clientDataHash: await sha256(body),
      appId,
      previousCounter: key.counter,
    });
    await config.db
      .prepare(
        "UPDATE attest_keys SET counter = ?1, last_seen_at = CASE WHEN ?5 = 1 THEN ?2 ELSE last_seen_at END WHERE app = ?3 AND key_id = ?4",
      )
      .bind(
        result.counter,
        new Date().toISOString(),
        app.id,
        headers.keyId,
        touchLastSeen ? 1 : 0,
      )
      .run();
    return null;
  } catch (err) {
    if (err instanceof AppAttestError) return json(401, { error: err.message });
    throw err;
  }
}
