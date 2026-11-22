// The apps App Attest is checked for. The registry is the `apps` table in D1
// (id, name, App Attest app id) plus `app_attest_ids` (further App IDs an app
// accepts), read through a small in-memory cache, so adding an app is a row,
// not a deploy.

import type { AttestConfig } from "./config";

/** An app id: lowercase letters, digits and "-", starting with a letter (the apps table enforces the same). */
export type AppId = string;

export interface AppConfig {
  id: AppId;
  name: string;
  /** Team ID + bundle ID: the app's primary App ID, whose hash App Attest signs. More are accepted, see attestAppIdsFor. */
  attestAppId: string;
}

interface AppRow {
  id: string;
  name: string;
  attest_app_id: string;
}

/** How long a loaded registry is trusted before the next request reloads it. */
export const APPS_CACHE_TTL_MS = 60_000;

interface Registry {
  loadedAt: number;
  apps: ReadonlyMap<AppId, AppConfig>;
  /** Every App ID each app accepts, its primary one (AppConfig.attestAppId) first. */
  attestAppIds: ReadonlyMap<AppId, readonly string[]>;
}

let cache: Registry | null = null;

/** Forgets the cached registry. Tests use it; a running isolate just waits out the TTL. */
export function clearAppsCache(): void {
  cache = null;
}

/**
 * Every registered app, from the cache when it is fresh. One isolate reads
 * the table at most once a minute; a new row is picked up within
 * APPS_CACHE_TTL_MS everywhere, with no deploy.
 */
export async function loadApps(
  config: AttestConfig,
  now = Date.now(),
): Promise<ReadonlyMap<AppId, AppConfig>> {
  return (await loadRegistry(config, now)).apps;
}

async function loadRegistry(
  config: AttestConfig,
  now: number,
): Promise<Registry> {
  if (cache && now - cache.loadedAt < APPS_CACHE_TTL_MS) return cache;
  const { results } = await config.db
    .prepare("SELECT id, name, attest_app_id FROM apps ORDER BY id")
    .all<AppRow>();
  const extra = await config.db
    .prepare(
      "SELECT app, attest_app_id FROM app_attest_ids ORDER BY app, attest_app_id",
    )
    .all<{ app: string; attest_app_id: string }>();
  const apps = new Map(
    results.map(
      (r) =>
        [
          r.id,
          { id: r.id, name: r.name, attestAppId: r.attest_app_id },
        ] as const,
    ),
  );
  const attestAppIds = new Map<AppId, string[]>(
    results.map((r) => [r.id, [r.attest_app_id]] as const),
  );
  for (const e of extra.results) {
    const ids = attestAppIds.get(e.app);
    if (ids && !ids.includes(e.attest_app_id)) ids.push(e.attest_app_id);
  }
  cache = { loadedAt: now, apps, attestAppIds };
  return cache;
}

/**
 * Every App ID the app accepts for attestation and assertion: its primary
 * one (apps.attest_app_id) first, then the ones in app_attest_ids. A key
 * attested as one of them is only ever checked against that one.
 */
export async function attestAppIdsFor(
  config: AttestConfig,
  app: AppConfig,
  now = Date.now(),
): Promise<readonly string[]> {
  return (
    (await loadRegistry(config, now)).attestAppIds.get(app.id) ?? [
      app.attestAppId,
    ]
  );
}

export async function listApps(config: AttestConfig): Promise<AppConfig[]> {
  return [...(await loadApps(config)).values()];
}

export class UnknownAppError extends Error {}

/**
 * Resolves the requesting app from the body's `app` field and/or the `X-App`
 * header; if both are sent they must agree. Neither means config.defaultApp.
 * Anything not in the registry throws.
 */
export async function resolveApp(
  config: AttestConfig,
  bodyApp: unknown,
  headerApp: string | null,
): Promise<AppConfig> {
  if (bodyApp !== undefined && bodyApp !== null && typeof bodyApp !== "string")
    throw new UnknownAppError("Unknown app");
  const named = [bodyApp, headerApp].filter(
    (v): v is string => typeof v === "string" && v !== "",
  );
  if (named.length === 2 && named[0] !== named[1])
    throw new UnknownAppError("App in body and X-App header disagree");
  const id = named[0] ?? config.defaultApp;
  if (!id) throw new UnknownAppError("Unknown app");
  const app = (await loadApps(config)).get(id);
  if (!app) throw new UnknownAppError("Unknown app");
  return app;
}
