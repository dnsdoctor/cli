/**
 * Command → REST endpoint. The CLI translates nothing: each command posts the
 * endpoint's own field names and prints what comes back.
 *
 * Pinned by the backend's `tests/mcp_server/test_cli_routes.py` against the
 * real app (path exists, field names are the request model's), the same way
 * the two MCP clients' tables are — a renamed route fails CI here before it
 * 404s a published CLI. Keep the literal shape: that test parses it.
 */

export interface Route {
  kind: "json" | "report";
  path?: string;
}

const ROUTES: Record<string, Route> = {
  scan: { kind: "json", path: "/api/v1/scan" },
  report: { kind: "report" },
  propagation: { kind: "json", path: "/api/tools/propagation-check" },
  "dmarc-upgrade": { kind: "json", path: "/api/v1/dmarc-upgrade" },
  "reverse-dns": { kind: "json", path: "/api/tools/reverse-dns-check" },
  "spf-audit": { kind: "json", path: "/api/tools/spf-audit" },
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

export const COMMANDS = Object.keys(ROUTES);
