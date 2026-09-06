/**
 * The CLI's request layer — the same two rules as the `@dnsdoctor/mcp` client:
 *
 * 1. **Relay, never compose.** Every response is returned untouched; the
 *    record strings a command prints are the API's bytes.
 * 2. **A transport failure is never a verdict.** 429/402/5xx/network faults are
 *    `transient` errors and exit 2 — a script must never read them as "the
 *    domain failed".
 *
 * Deliberately a small copy of the MCP client's layer rather than an import:
 * the client's `package.json` version is a pinned carrier across every
 * published artifact, and a CLI release must not force that wave. The backend
 * test `tests/mcp_server/test_cli_routes.py` pins this package's `ROUTES` to
 * the real app so the two layers cannot drift onto different paths.
 */

import { readFileSync } from "node:fs";

export const DEFAULT_API_BASE = "https://dnsdoctor.dev";

export const TRANSIENT_SUFFIX = "retry; this is not a verdict about the domain";
export const RATE_LIMITED_MESSAGE = "rate limited — slow down and retry";
export const PAYMENT_REQUIRED_MESSAGE =
  "past the free per-caller allowance — the API offered a paid retry over x402 (USDC on Base); pay with an x402 client, or wait and retry";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number | null,
    public readonly transient: boolean,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Base URL for the DNS Doctor API; `DNSDOCTOR_API_BASE` overrides for local runs. */
export function apiBase(): string {
  const raw = process.env.DNSDOCTOR_API_BASE?.trim();
  const base = raw ? raw : DEFAULT_API_BASE;
  return base.replace(/\/+$/, "");
}

/** A bearer token raises the anonymous budget; never prompted for, never required. */
function authHeaders(): Record<string, string> {
  const token = process.env.DNSDOCTOR_API_TOKEN?.trim();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export function packageVersion(): string {
  try {
    const raw = readFileSync(new URL("../package.json", import.meta.url), "utf8");
    const version = (JSON.parse(raw) as { version?: unknown }).version;
    return typeof version === "string" ? version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/**
 * The UA every call carries — this CLI's only attribution. `api/agents.py::
 * agent_family` is an allowlist, and `dnsdoctor-cli` is its entry: without
 * this marker the CLI channel would be invisible in the agent-request metric.
 */
export function userAgent(): string {
  return `dnsdoctor-cli/${packageVersion()} (+https://dnsdoctor.dev)`;
}

function detailOf(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return null;
  const detail = (body as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (detail === undefined || detail === null) return null;
  return JSON.stringify(detail);
}

async function readBody(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export async function toApiError(response: Response): Promise<ApiError> {
  const detail = detailOf(await readBody(response));
  const status = response.status;
  if (status === 429) {
    return new ApiError(detail ? `${RATE_LIMITED_MESSAGE} (${detail})` : RATE_LIMITED_MESSAGE, status, true);
  }
  if (status === 402) return new ApiError(PAYMENT_REQUIRED_MESSAGE, status, true);
  if (status === 503) {
    return new ApiError(`DNS Doctor could not complete the lookup (transient) — ${TRANSIENT_SUFFIX}`, status, true);
  }
  if (status >= 500) {
    return new ApiError(`DNS Doctor returned a server error (HTTP ${status}) — ${TRANSIENT_SUFFIX}`, status, true);
  }
  // 4xx — the API's own `detail` is the answer (422 malformed input, opaque 404). Verbatim.
  return new ApiError(detail ?? `DNS Doctor request failed (HTTP ${status})`, status, false);
}

async function send(path: string, init: RequestInit): Promise<unknown> {
  const url = `${apiBase()}${path}`;
  let response: Response;
  try {
    response = await fetch(url, {
      ...init,
      headers: {
        Accept: "application/json",
        "User-Agent": userAgent(),
        ...authHeaders(),
        ...(init.headers ?? {}),
      },
    });
  } catch (error) {
    const cause = error instanceof Error ? error.message : String(error);
    throw new ApiError(`Could not reach the DNS Doctor API (${cause}) — ${TRANSIENT_SUFFIX}`, null, true);
  }
  if (!response.ok) throw await toApiError(response);
  const body = await readBody(response);
  if (body === null) {
    throw new ApiError(
      `DNS Doctor returned an unreadable response (HTTP ${response.status}) — ${TRANSIENT_SUFFIX}`,
      response.status,
      true,
    );
  }
  return body;
}

/** GET a JSON resource. `path` is API-root-relative and already encoded. */
export function getJson(path: string): Promise<unknown> {
  return send(path, { method: "GET" });
}

/** POST a JSON body and return the parsed response, untouched. */
export function postJson(path: string, body: unknown): Promise<unknown> {
  return send(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/**
 * POST one file as multipart (`dmarc-report-parse`). The API reads bytes only;
 * the filename is cosmetic. Node ≥ 20 ships FormData/Blob natively.
 */
export function postFile(path: string, field: string, bytes: Uint8Array, filename: string): Promise<unknown> {
  const form = new FormData();
  form.append(field, new Blob([bytes as BlobPart], { type: "application/octet-stream" }), filename);
  return send(path, { method: "POST", body: form });
}
