/** A JSON response. The error bodies of every handler in this package are `{ "error": "..." }`. */
export function json(
  status: number,
  body: unknown,
  extra: HeadersInit = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...extra },
  });
}

/** A Worker var that is on: the string "true" or "1". */
export function flag(value: string | undefined): boolean {
  return value === "true" || value === "1";
}
