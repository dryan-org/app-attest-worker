import { json } from "./http";

const CHALLENGE_TTL_SECONDS = 60;

/** POST /challenge: a one-time nonce the next attestation or request must present. */
export async function issueChallenge(
  challenges: KVNamespace,
): Promise<Response> {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const nonce = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(
    "",
  );
  await challenges.put(nonce, "1", { expirationTtl: CHALLENGE_TTL_SECONDS });
  return json(200, { challenge: nonce });
}

/**
 * Consumes a challenge: true if it existed and hasn't been used. KV deletes
 * are eventually consistent across edges, so a nonce is also marked used
 * with a short-lived value in case a replay races the delete.
 */
export async function consumeChallenge(
  challenges: KVNamespace,
  nonce: string | null,
): Promise<boolean> {
  if (!nonce || !/^[0-9a-f]{64}$/.test(nonce)) return false;
  const value = await challenges.get(nonce);
  if (value !== "1") return false;
  await challenges.put(nonce, "used", { expirationTtl: CHALLENGE_TTL_SECONDS });
  return true;
}
