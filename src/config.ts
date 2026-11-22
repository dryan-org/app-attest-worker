/**
 * What the handlers need from the Worker that calls them. A Worker builds
 * one from its own bindings, so nothing here depends on that Worker's Env.
 */
export interface AttestConfig {
  /**
   * The D1 database that holds `apps`, `app_attest_ids` and `attest_keys`
   * (the dryan-analytics database; its migrations own the schema).
   */
  db: D1Database;
  /** The KV namespace for one-time challenge nonces. Nothing else may live in it. */
  challenges: KVNamespace;
  /** Accept keys attested in Apple's development environment (Xcode builds). */
  allowDevelopment: boolean;
  /** The app a request that names none belongs to. Absent: every request must name its app. */
  defaultApp?: string;
  /**
   * Replaces verifyAttestation in `handleAttest`. A real attestation needs
   * Apple's certificate chain, so tests stub it. Production code leaves it unset.
   */
  verifyAttestation?: typeof import("./appattest").verifyAttestation;
}
