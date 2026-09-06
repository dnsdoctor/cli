/**
 * Human output. Everything printed here is read off the API response:
 * statuses, titles, record strings (verbatim, never reformatted), URLs.
 *
 * Ordering is the one editorial act — failing checks first, the way the report
 * page reads — and the exit code is a pure function of the API's own verdicts.
 */

const STATUS_ORDER: Record<string, number> = { fail: 0, warn: 1, temperror: 2, info: 3, pass: 4 };
const STATUS_WORD: Record<string, string> = {
  fail: "FAIL",
  warn: "WARN",
  temperror: "TEMP",
  info: "INFO",
  pass: "PASS",
};

interface Check {
  check?: unknown;
  status?: unknown;
  title?: unknown;
  fix_record?: unknown;
  raw?: unknown;
  details?: unknown;
}

function str(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function record(obj: unknown): Record<string, unknown> {
  return typeof obj === "object" && obj !== null ? (obj as Record<string, unknown>) : {};
}

function checksOf(report: Record<string, unknown>): Check[] {
  const checks = report.checks;
  return Array.isArray(checks) ? (checks as Check[]) : [];
}

/** `scan`/`report`: the `ScanReport` (+ `next_steps`) as a worst-first check list. */
export function formatReport(body: unknown): string {
  const top = record(body);
  const report = record(top.report ?? top);
  const lines: string[] = [];
  const domain = str(report.domain) ?? "?";
  if (report.not_registered === true) {
    lines.push(`${domain}: not registered — no DNS records exist, so no check ran.`);
    return lines.join("\n");
  }
  lines.push(`${domain}${str(report.scanned_at) ? `  (scanned ${str(report.scanned_at)})` : ""}`);
  const checks = [...checksOf(report)].sort(
    (a, b) => (STATUS_ORDER[str(a.status) ?? ""] ?? 9) - (STATUS_ORDER[str(b.status) ?? ""] ?? 9),
  );
  for (const check of checks) {
    const status = str(check.status) ?? "?";
    const word = STATUS_WORD[status] ?? status.toUpperCase();
    lines.push(`  ${word.padEnd(4)}  ${(str(check.check) ?? "").padEnd(8)} ${str(check.title) ?? ""}`);
    if (Array.isArray(check.details)) {
      for (const detail of check.details) if (typeof detail === "string") lines.push(`        · ${detail}`);
    }
    const fix = str(check.fix_record);
    if (fix) {
      lines.push(`        fix (paste verbatim, a human must approve the DNS change):`);
      lines.push(`        ${fix}`);
    }
  }
  const next = record(top.next_steps);
  const reportUrl = str(next.report_url);
  if (reportUrl) lines.push(`  report: ${reportUrl}`);
  return lines.join("\n");
}

/** `propagation`: verdict, coverage, one line per location. */
export function formatPropagation(body: unknown): string {
  const result = record(body);
  const lines: string[] = [];
  lines.push(
    `${str(result.name) ?? "?"} ${str(result.record_type) ?? ""}: ${str(result.verdict) ?? "?"} — ${result.vantage_reached ?? "?"} of ${result.vantage_total ?? "?"} locations answered`,
  );
  const vantages = Array.isArray(result.vantages) ? result.vantages : [];
  for (const row of vantages) {
    const v = record(row);
    const label = `${str(v.label) ?? str(v.region) ?? "?"}`.padEnd(18);
    if (v.reached !== true) {
      lines.push(`  ${label} unreached${str(v.detail) ? ` — ${str(v.detail)}` : ""}`);
      continue;
    }
    const cells = (Array.isArray(v.cells) ? v.cells : []).map((c) => {
      const cell = record(c);
      const answers = Array.isArray(cell.answers) ? cell.answers.join(",") : "";
      return { resolver: str(cell.resolver) ?? "?", status: str(cell.status) ?? "?", answers };
    });
    const agree =
      cells.length > 0 && cells.every((c) => c.status === cells[0]?.status && c.answers === cells[0]?.answers);
    if (agree) {
      // One line when every resolver at the location said the same thing —
      // the reader wants the answer, not three copies of it.
      const first = cells[0];
      lines.push(`  ${label} ${first?.status}${first?.answers ? ` ${first.answers}` : ""}  (${cells.length} resolver${cells.length === 1 ? "" : "s"} agree)`);
      continue;
    }
    const parts = cells.map((c) => `${c.resolver}=${c.status}${c.answers ? ` ${c.answers}` : ""}`);
    lines.push(`  ${label} ${parts.join("  ")}`);
  }
  return lines.join("\n");
}

/** `dmarc-upgrade`: the record verbatim when there is one, else the rationale. */
export function formatDmarcUpgrade(body: unknown): string {
  const result = record(body);
  const lines: string[] = [];
  const rec = str(result.record);
  lines.push(`${str(result.domain) ?? "?"}: current policy ${str(result.current_policy) ?? "none published"}`);
  if (rec) {
    lines.push(`  record (paste verbatim as TXT at _dmarc; a human must approve the DNS change):`);
    lines.push(`  ${rec}`);
  } else {
    lines.push(`  no record recommended`);
  }
  const rationale = str(result.rationale);
  if (rationale) lines.push(`  ${rationale}`);
  return lines.join("\n");
}

/** `reverse-dns`: verdict, PTR, the addresses the name resolves to. */
export function formatReverseDns(body: unknown): string {
  const result = record(body);
  const addresses = Array.isArray(result.addresses) ? result.addresses.join(", ") : "";
  return [
    `${str(result.ip) ?? "?"}: ${str(result.verdict) ?? "?"}`,
    `  reverse name: ${str(result.ptr) ?? "(none)"}`,
    `  resolves to:  ${addresses || "(nothing)"}`,
  ].join("\n");
}

/** `spf-audit`: the walk's findings, then the lookup total. */
export function formatSpfAudit(body: unknown): string {
  const result = record(body);
  const lines: string[] = [];
  lines.push(`${str(result.domain) ?? "?"}: ${result.total_lookups ?? "?"} lookups${result.truncated === true ? " (walk truncated)" : ""}`);
  const findings = Array.isArray(result.findings) ? result.findings : [];
  if (findings.length === 0) lines.push("  no findings");
  for (const f of findings) {
    const finding = record(f);
    lines.push(`  ${String(finding.severity ?? "").toUpperCase().padEnd(5)} ${str(finding.domain) ?? ""}: ${str(finding.message) ?? ""}`);
  }
  const rec = str(result.record);
  if (rec) lines.push(`  record: ${rec}`);
  return lines.join("\n");
}

/**
 * Exit code from the API's own verdicts: 0 = nothing failing, 1 = a failing
 * verdict. Transient errors never reach here (they exit 2 in `main`).
 */
export function exitCodeFor(command: string, body: unknown): 0 | 1 {
  const result = record(body);
  if (command === "scan" || command === "report") {
    const report = record(result.report ?? result);
    return checksOf(report).some((c) => str(c.status) === "fail") ? 1 : 0;
  }
  if (command === "propagation") {
    const verdict = str(result.verdict);
    return verdict === "not_propagated" || verdict === "inconsistent" ? 1 : 0;
  }
  if (command === "reverse-dns") return str(result.verdict) === "confirmed" ? 0 : 1;
  if (command === "spf-audit") {
    const findings = Array.isArray(result.findings) ? result.findings : [];
    return findings.some((f) => String(record(f).severity ?? "").toLowerCase() === "high") ? 1 : 0;
  }
  return 0;
}
