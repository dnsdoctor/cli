/**
 * The CLI's three promises, each read off real behaviour rather than review:
 * commands post the endpoint's own field names; every printed record is the
 * API's bytes; a transient never becomes a verdict (exit 2, never 1).
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, PAYMENT_REQUIRED_MESSAGE, RATE_LIMITED_MESSAGE, toApiError } from "../src/api.js";
import { exitCodeFor, formatDmarcRecord, formatDmarcUpgrade, formatParked, formatPropagation, formatReport, render } from "../src/format.js";
import { main, parse, run, type Parsed } from "../src/index.js";
import { COMMANDS, reportPath, routeFor } from "../src/routes.js";

const FIX = "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; np=reject";

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("parse", () => {
  it("maps a command and target with defaults", () => {
    const parsed = parse(["propagation", "www.example.com", "--expect", "203.0.113.10"]);
    expect(parsed).toMatchObject({ command: "propagation", target: "www.example.com", type: "A", expect: "203.0.113.10", json: false });
  });
  it("shows help for an unknown command or a missing target", () => {
    expect(parse(["nope", "x"])).toBe("help");
    expect(parse(["scan"])).toBe("help");
    expect(parse(["report", "example.com"])).toBe("help"); // the persisted read is `scan` without --fresh
    expect(parse(["alerts"])).not.toBe("help"); // the one targetless command
  });
  it("has a command for every MCP tool's endpoint", () => {
    expect([...COMMANDS].sort()).toEqual([
      "alerts", "dkim", "dmarc-generate", "dmarc-upgrade", "dmarc-validate", "parked", "propagation",
      "readiness", "record", "report-parse", "reverse-dns", "scan", "signup-url", "spf-audit", "spf-count",
    ]);
  });
});

function args(command: string, target: string | undefined, extra: Partial<Parsed> = {}): Parsed {
  return {
    command, target, json: false, fresh: false, type: "A", expect: undefined, selector: undefined, kind: undefined,
    host: undefined, rua: undefined, subdomainPolicy: undefined, strict: false, confirmNoMail: false, domain: undefined,
    since: undefined, before: undefined, alertType: undefined, limit: undefined, ...extra,
  };
}

describe("run posts the endpoint's own field names", () => {
  it("scan is the persisted report by default and POST /scan with --fresh", async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      return jsonResponse({ report: { domain: "example.com", checks: [] } });
    });
    await run(args("scan", "example.com"));
    await run(args("scan", "example.com", { fresh: true }));
    expect(calls[0]?.url).toBe(`https://dnsdoctor.dev${reportPath("example.com")}`);
    expect(calls[0]?.init?.method).toBe("GET");
    expect(calls[1]?.url).toBe(`https://dnsdoctor.dev${routeFor("scan").path}`);
    expect(JSON.parse(String(calls[1]?.init?.body))).toEqual({ domain: "example.com" });
  });
  it("propagation sends name, record_type and expected_value only when given", async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal("fetch", async (_url: string, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)));
      return jsonResponse({ verdict: "consistent", vantages: [] });
    });
    await run(args("propagation", "www.example.com", { type: "TXT" }));
    await run(args("propagation", "www.example.com", { expect: "203.0.113.10" }));
    expect(bodies[0]).toEqual({ name: "www.example.com", record_type: "TXT" });
    expect(bodies[1]).toEqual({ name: "www.example.com", record_type: "A", expected_value: "203.0.113.10" });
  });
  it("every request carries the CLI user agent", async () => {
    let ua = "";
    vi.stubGlobal("fetch", async (_url: string, init?: RequestInit) => {
      ua = String((init?.headers as Record<string, string>)["User-Agent"]);
      return jsonResponse({ ip: "203.0.113.10", verdict: "confirmed", addresses: [] });
    });
    await run(args("reverse-dns", "203.0.113.10"));
    expect(ua).toMatch(/^dnsdoctor-cli\/\d+\.\d+\.\d+ \(\+https:\/\/dnsdoctor\.dev\)$/);
  });
  it("the other commands send exactly the endpoint's fields", async () => {
    const seen: { url: string; body: unknown }[] = [];
    vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
      seen.push({ url, body: typeof init?.body === "string" ? JSON.parse(init.body) : null });
      return jsonResponse({});
    });
    await run(args("dkim", "example.com", { selector: "google" }));
    await run(args("record", "example.com", { kind: "mx" }));
    await run(args("parked", "example.com", { confirmNoMail: true }));
    await run(args("parked", "example.com", { confirmNoMail: true, rua: "r@example.com" }));
    await run(args("dmarc-generate", "quarantine", { rua: "r@example.com", strict: true }));
    await run(args("spf-count", "v=spf1 include:_spf.google.com -all"));
    await run(args("spf-count", "example.com"));
    await run(args("alerts", undefined, { domain: "example.com", limit: "5" }));
    await run(args("readiness", "example.com"));
    expect(seen.map((s) => s.body)).toEqual([
      { domain: "example.com", selector: "google" },
      { domain: "example.com", kind: "mx" },
      { domain: "example.com", confirm_no_mail: true },
      { domain: "example.com", confirm_no_mail: true, rua_email: "r@example.com" },
      { policy: "quarantine", strict_alignment: true, rua_email: "r@example.com" },
      { record: "v=spf1 include:_spf.google.com -all" },
      { domain: "example.com" },
      null,
      null,
    ]);
    expect(seen[7]?.url).toBe("https://dnsdoctor.dev/api/v1/alerts?domain=example.com&limit=5");
    expect(seen[8]?.url).toBe("https://dnsdoctor.dev/api/v1/readiness?domain=example.com");
  });
  it("dkim and record refuse to guess a missing option", async () => {
    await expect(run(args("dkim", "example.com"))).rejects.toThrow("--selector");
    await expect(run(args("record", "example.com"))).rejects.toThrow("--kind");
    await expect(run(args("parked", "example.com"))).rejects.toThrow("--confirm-no-mail");
  });
});

describe("records are relayed verbatim", () => {
  it("prints a fix_record byte-for-byte, failing checks first", () => {
    const out = formatReport({
      report: {
        domain: "example.com",
        checks: [
          { check: "spf", status: "pass", title: "SPF record is valid" },
          { check: "dmarc", status: "fail", title: "No DMARC record found", fix_record: FIX },
        ],
      },
      next_steps: { report_url: "https://dnsdoctor.dev/scan/example.com" },
    });
    const lines = out.split("\n");
    expect(lines[1]).toContain("FAIL");
    expect(lines[1]).toContain("dmarc");
    expect(out).toContain(`        ${FIX}`);
    expect(out).toContain("report: https://dnsdoctor.dev/scan/example.com");
  });
  it("prints the upgrade record verbatim, or the rationale when there is none", () => {
    expect(formatDmarcUpgrade({ domain: "example.com", current_policy: "none", record: FIX, rationale: "r" })).toContain(`  ${FIX}`);
    const none = formatDmarcUpgrade({ domain: "example.com", current_policy: "none", record: null, rationale: "publish rua first" });
    expect(none).toContain("no record recommended");
    expect(none).toContain("publish rua first");
  });
  it("prints validate/generate records and the parked pack verbatim", () => {
    const v = formatDmarcRecord({ valid: true, policy: "none", tags: [], findings: [{ level: "warn", message: "w" }], upgrade_record: FIX, upgrade_note: "n" });
    expect(v).toContain(`  ${FIX}`);
    expect(v).toContain("WARN  w");
    const pack = formatParked({ domain: "example.com", records: [{ step: 1, host: "example.com", record_type: "MX", value: "0 ." }], rationale: null, apply_note: "a" });
    expect(pack).toContain("example.com  MX  0 .");
    expect(render("nope", { a: 1 })).toContain('"a": 1');
  });
  it("expands a location only when its resolvers disagree", () => {
    const out = formatPropagation({
      name: "x", record_type: "A", verdict: "partial", vantage_reached: 1, vantage_total: 1,
      vantages: [{ region: "sa-east-1", label: "South America", reached: true, cells: [
        { resolver: "1.1.1.1", status: "mismatch", answers: ["198.51.100.7"] },
        { resolver: "8.8.8.8", status: "match", answers: ["203.0.113.10"] },
      ] }],
    });
    expect(out).toContain("1.1.1.1=mismatch 198.51.100.7  8.8.8.8=match 203.0.113.10");
  });
  it("shows an unreached location with its reason and never as an answer", () => {
    const out = formatPropagation({
      name: "www.example.com", record_type: "A", verdict: "unknown", vantage_reached: 1, vantage_total: 2,
      vantages: [
        { region: "af-south-1", label: "Africa", reached: false, detail: "deadline exceeded", cells: [] },
        { region: "origin", label: "Europe (France)", reached: true, cells: [{ resolver: "origin", status: "answered", answers: ["203.0.113.10"] }] },
      ],
    });
    expect(out).toContain("Africa             unreached — deadline exceeded");
    expect(out).toContain("answered 203.0.113.10  (1 resolver agree)");
  });
});

describe("exit codes", () => {
  it("1 only on a failing verdict, 0 otherwise", () => {
    expect(exitCodeFor("scan", { report: { checks: [{ status: "fail" }] } })).toBe(1);
    expect(exitCodeFor("scan", { report: { checks: [{ status: "warn" }, { status: "temperror" }] } })).toBe(0);
    expect(exitCodeFor("propagation", { verdict: "not_propagated" })).toBe(1);
    expect(exitCodeFor("propagation", { verdict: "unknown" })).toBe(0);
    expect(exitCodeFor("reverse-dns", { verdict: "ptr_missing" })).toBe(1);
  });
  it("a transient (429, 402, 503, network) exits 2 and is never read as a verdict", async () => {
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    vi.stubGlobal("fetch", async () => jsonResponse({ detail: "slow down" }, 429));
    expect(await main(["scan", "example.com"])).toBe(2);
    vi.stubGlobal("fetch", async () => jsonResponse({ x402Version: 1, accepts: [] }, 402, { "PAYMENT-REQUIRED": "x" }));
    expect(await main(["scan", "example.com", "--fresh"])).toBe(2);
    expect(String(write.mock.calls.at(-1)?.[0])).toContain(PAYMENT_REQUIRED_MESSAGE);
    write.mockRestore();
  });
  it("maps statuses the way the MCP client does", async () => {
    const limited = await toApiError(jsonResponse({ detail: "budget" }, 429));
    expect(limited).toBeInstanceOf(ApiError);
    expect(limited.transient).toBe(true);
    expect(limited.message).toBe(`${RATE_LIMITED_MESSAGE} (budget)`);
    const invalid = await toApiError(jsonResponse({ detail: "invalid domain" }, 422));
    expect(invalid.transient).toBe(false);
    expect(invalid.message).toBe("invalid domain");
  });
});
