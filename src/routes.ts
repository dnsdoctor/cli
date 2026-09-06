/**
 * Command → REST endpoint. The CLI translates nothing: each command sends the
 * endpoint's own field names and prints what comes back.
 *
 * Every one of the 16 MCP tools has a command here, so the CLI and the MCP
 * clients cover the same API. Pinned by the backend's
 * `tests/mcp_server/test_cli_routes.py` against the real app (path exists,
 * field names are the request model's, and the path SET equals the MCP
 * client's) — a renamed route fails CI before it 404s a published CLI. Keep
 * the literal shape: that test parses it.
 */

export interface Route {
  kind: "json" | "report" | "query" | "upload";
  path?: string;
  field?: string;
}

const ROUTES: Record<string, Route> = {
  scan: { kind: "json", path: "/api/v1/scan" },
  report: { kind: "report" },
  "dmarc-upgrade": { kind: "json", path: "/api/v1/dmarc-upgrade" },
  "signup-url": { kind: "json", path: "/api/v1/signup-url" },
  "spf-count": { kind: "json", path: "/api/tools/spf-count" },
  "dmarc-validate": { kind: "json", path: "/api/tools/dmarc-validate" },
  "dmarc-generate": { kind: "json", path: "/api/tools/dmarc-generate" },
  dkim: { kind: "json", path: "/api/tools/dkim-check" },
  "report-parse": { kind: "upload", path: "/api/tools/dmarc-report-parse", field: "file" },
  record: { kind: "json", path: "/api/tools/check-record" },
  propagation: { kind: "json", path: "/api/tools/propagation-check" },
  "reverse-dns": { kind: "json", path: "/api/tools/reverse-dns-check" },
  "spf-audit": { kind: "json", path: "/api/tools/spf-audit" },
  parked: { kind: "json", path: "/api/tools/parked-domain-records" },
  alerts: { kind: "query", path: "/api/v1/alerts" },
  readiness: { kind: "query", path: "/api/v1/readiness" },
};

export function routeFor(command: string): Route {
  const route = ROUTES[command];
  if (!route) throw new Error(`no route for command '${command}'`);
  return route;
}

/** The persisted-report path; the one route whose path is built from an argument. */
export function reportPath(domain: string): string {
  return `/api/v1/report/${encodeURIComponent(domain)}`;
}

export const COMMANDS = Object.keys(ROUTES).filter((c) => c !== "report");
