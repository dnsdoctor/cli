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

const RECORD_NOTE = "paste verbatim; a human must approve the DNS change";

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

function rec(obj: unknown): Record<string, unknown> {
  return typeof obj === "object" && obj !== null ? (obj as Record<string, unknown>) : {};
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function checksOf(report: Record<string, unknown>): Check[] {
  return list(report.checks) as Check[];
}

/** `scan`: the `ScanReport` (+ `next_steps`) as a worst-first check list. */
export function formatReport(body: unknown): string {
  const top = rec(body);
  const report = rec(top.report ?? top);
  const lines: string[] = [];
  const domain = str(report.domain) ?? "?";
  if (report.not_registered === true) {
    return `${domain}: not registered — no DNS records exist, so no check ran.`;
  }
  lines.push(`${domain}${str(report.scanned_at) ? `  (scanned ${str(report.scanned_at)})` : ""}`);
  const checks = [...checksOf(report)].sort(
    (a, b) => (STATUS_ORDER[str(a.status) ?? ""] ?? 9) - (STATUS_ORDER[str(b.status) ?? ""] ?? 9),
  );
  for (const check of checks) {
    const status = str(check.status) ?? "?";
    const word = STATUS_WORD[status] ?? status.toUpperCase();
    lines.push(`  ${word.padEnd(4)}  ${(str(check.check) ?? "").padEnd(8)} ${str(check.title) ?? ""}`);
    for (const detail of list(check.details)) if (typeof detail === "string") lines.push(`        · ${detail}`);
    const fix = str(check.fix_record);
    if (fix) {
      lines.push(`        fix (${RECORD_NOTE}):`);
      lines.push(`        ${fix}`);
    }
  }
  const reportUrl = str(rec(top.next_steps).report_url);
  if (reportUrl) lines.push(`  report: ${reportUrl}`);
  return lines.join("\n");
}

/** `propagation`: verdict, coverage, one line per location. */
export function formatPropagation(body: unknown): string {
  const result = rec(body);
  const lines: string[] = [];
  lines.push(
    `${str(result.name) ?? "?"} ${str(result.record_type) ?? ""}: ${str(result.verdict) ?? "?"} — ${result.vantage_reached ?? "?"} of ${result.vantage_total ?? "?"} locations answered`,
  );
  for (const row of list(result.vantages)) {
    const v = rec(row);
    const label = `${str(v.label) ?? str(v.region) ?? "?"}`.padEnd(18);
    if (v.reached !== true) {
      lines.push(`  ${label} unreached${str(v.detail) ? ` — ${str(v.detail)}` : ""}`);
      continue;
    }
    const cells = list(v.cells).map((c) => {
      const cell = rec(c);
      const answers = list(cell.answers).join(",");
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
    lines.push(`  ${label} ${cells.map((c) => `${c.resolver}=${c.status}${c.answers ? ` ${c.answers}` : ""}`).join("  ")}`);
  }
  return lines.join("\n");
}

/** `dmarc-upgrade`: the record verbatim when there is one, else the rationale. */
export function formatDmarcUpgrade(body: unknown): string {
  const result = rec(body);
  const lines = [`${str(result.domain) ?? "?"}: current policy ${str(result.current_policy) ?? "none published"}`];
  const record = str(result.record);
  if (record) {
    lines.push(`  record (TXT at _dmarc; ${RECORD_NOTE}):`, `  ${record}`);
  } else {
    lines.push("  no record recommended");
  }
  const rationale = str(result.rationale);
  if (rationale) lines.push(`  ${rationale}`);
  return lines.join("\n");
}

/** `reverse-dns`: verdict, PTR, the addresses the name resolves to. */
export function formatReverseDns(body: unknown): string {
  const result = rec(body);
  return [
    `${str(result.ip) ?? "?"}: ${str(result.verdict) ?? "?"}`,
    `  reverse name: ${str(result.ptr) ?? "(none)"}`,
    `  resolves to:  ${list(result.addresses).join(", ") || "(nothing)"}`,
  ].join("\n");
}

/** `spf-audit`: the walk's findings, then the lookup total. */
export function formatSpfAudit(body: unknown): string {
  const result = rec(body);
  const lines = [`${str(result.domain) ?? "?"}: ${result.total_lookups ?? "?"} lookups${result.truncated === true ? " (walk truncated)" : ""}`];
  const findings = list(result.findings);
  if (findings.length === 0) lines.push("  no findings");
  for (const f of findings) {
    const finding = rec(f);
    lines.push(`  ${String(finding.severity ?? "").toUpperCase().padEnd(5)} ${str(finding.domain) ?? ""}: ${str(finding.message) ?? ""}`);
  }
  const record = str(result.record);
  if (record) lines.push(`  record: ${record}`);
  return lines.join("\n");
}

/** `spf-count`: the count against the limit, the findings, the record. */
export function formatSpfCount(body: unknown): string {
  const result = rec(body);
  const lines = [`${result.lookup_count ?? "?"} of ${result.lookup_limit ?? 10} DNS lookups${result.recursive === true ? " (recursive)" : ""}`];
  for (const f of list(result.findings)) if (typeof f === "string") lines.push(`  · ${f}`);
  const record = str(result.record);
  if (record) lines.push(`  record: ${record}`);
  return lines.join("\n");
}

/** `dmarc-validate` / `dmarc-generate`: validity, findings, the record(s) verbatim. */
export function formatDmarcRecord(body: unknown): string {
  const result = rec(body);
  const lines = [result.valid === true ? "valid" : "not valid"];
  const policy = str(result.policy);
  if (policy) lines[0] += ` · p=${policy}`;
  for (const f of list(result.findings)) {
    const finding = rec(f);
    lines.push(`  ${String(finding.level ?? "").toUpperCase().padEnd(5)} ${str(finding.message) ?? ""}`);
  }
  const record = str(result.record);
  if (record) lines.push(`  record (${RECORD_NOTE}):`, `  ${record}`);
  const upgrade = str(result.upgrade_record);
  if (upgrade) lines.push(`  next step (${RECORD_NOTE}):`, `  ${upgrade}`);
  const note = str(result.upgrade_note);
  if (note) lines.push(`  ${note}`);
  return lines.join("\n");
}

/** `dkim`: the status line, the parsed key when present, the record verbatim. */
export function formatDkim(body: unknown): string {
  const result = rec(body);
  const lines = [`${str(result.selector) ?? "?"}._domainkey.${str(result.domain) ?? "?"}: ${str(result.status) ?? "?"} — ${str(result.title) ?? ""}`];
  const key = rec(result.key);
  if (Object.keys(key).length > 0) {
    lines.push(`  key: ${str(key.algorithm) ?? "?"} · ${key.bits ?? "?"} bit · ${key.revoked === true ? "revoked" : "active"}${key.testing === true ? " · testing" : ""}`);
  }
  const record = str(result.record);
  if (record) lines.push(`  record: ${record}`);
  return lines.join("\n");
}

/** `report-parse`: the report's totals and one line per source. */
export function formatReportParse(body: unknown): string {
  const result = rec(body);
  const lines = [
    `${str(result.org_name) ?? "?"} → ${str(result.domain) ?? "?"}  ${str(result.date_begin) ?? ""} – ${str(result.date_end) ?? ""}`,
    `  ${result.total_messages ?? "?"} messages · ${result.aligned_pct ?? "?"}% aligned · published ${str(result.published_policy) ?? "?"}`,
  ];
  for (const s of list(result.sources)) {
    const source = rec(s);
    lines.push(`  ${String(source.ip ?? "?").padEnd(40)} ${String(source.total ?? "?").padStart(6)}  aligned ${source.aligned_pct ?? "?"}%`);
  }
  return lines.join("\n");
}

/** `record`: the authoritative answer beside what the caches still hold. */
export function formatRecord(body: unknown): string {
  const result = rec(body);
  const auth = rec(result.authoritative);
  const lines = [
    `${str(result.name) ?? "?"} ${str(result.rdtype) ?? ""}: ${result.in_sync === true ? "in sync" : `caches still clearing (up to ${result.max_wait_seconds ?? "?"} s)`}`,
    `  authoritative: ${list(auth.values).join(", ") || "(none)"}  TTL ${auth.ttl ?? "?"}  ${auth.nameservers_queried ?? "?"} NS${auth.ns_in_agreement === false ? " — DISAGREE" : ""}`,
  ];
  for (const c of list(result.cached)) {
    const cache = rec(c);
    lines.push(`  ${String(cache.resolver ?? "?").padEnd(14)} ${list(cache.values).join(", ") || "(none)"}  ${cache.ttl_remaining ?? "?"} s left`);
  }
  return lines.join("\n");
}

/** `parked`: the pack verbatim, or the refusal and its rationale. */
export function formatParked(body: unknown): string {
  const result = rec(body);
  const lines = [`${str(result.domain) ?? "?"}`];
  const records = result.records;
  if (Array.isArray(records) && records.length > 0) {
    lines.push(`  hardening pack (${RECORD_NOTE}):`);
    for (const r of records) {
      const row = rec(r);
      lines.push(`  ${str(row.host) ?? ""}  ${str(row.record_type) ?? ""}  ${str(row.value) ?? str(row.record) ?? ""}`);
    }
  } else {
    lines.push("  no pack issued");
  }
  const rationale = str(result.rationale);
  if (rationale) lines.push(`  ${rationale}`);
  const note = str(result.apply_note);
  if (note) lines.push(`  ${note}`);
  return lines.join("\n");
}

/** `signup-url`: the two links verbatim and the message. */
export function formatSignupUrl(body: unknown): string {
  const result = rec(body);
  return [
    `signup: ${str(result.signup_url) ?? "?"}`,
    `report: ${str(result.report_url) ?? "?"}`,
    `${str(result.message) ?? ""}`,
  ].join("\n");
}

/** `alerts`: one line per alert, newest first as the API orders them. */
export function formatAlerts(body: unknown): string {
  const result = rec(body);
  const alerts = list(result.alerts);
  if (alerts.length === 0) return "no alerts";
  const lines = alerts.map((a) => {
    const alert = rec(a);
    return `${String(alert.created_at ?? "").slice(0, 19)}  ${String(alert.domain ?? "").padEnd(24)} ${String(alert.type ?? "").padEnd(20)} ${str(alert.summary) ?? ""}${str(alert.delivery_class) ? ` [${str(alert.delivery_class)}]` : ""}`;
  });
  const next = str(result.next_before);
  if (next) lines.push(`  more: --before ${next}`);
  return lines.join("\n");
}

/** `readiness`: ready or not, the blockers, the next record verbatim. */
export function formatReadiness(body: unknown): string {
  const result = rec(body);
  const progress = rec(result.progress);
  const lines = [
    `${result.ready === true ? "ready" : "not ready"} for ${str(result.next_step) ?? "the next step"} — ${result.total_messages ?? "?"} messages over ${result.window_days ?? "?"} days${progress.progress_pct !== undefined ? ` · ${progress.progress_pct}%` : ""}`,
  ];
  for (const b of list(result.blockers)) {
    const blocker = rec(b);
    lines.push(`  blocker: ${str(blocker.source) ?? ""} ${str(blocker.metric) ?? ""}${str(blocker.fix_hint) ? ` — ${str(blocker.fix_hint)}` : ""}`);
  }
  const next = str(result.next_record);
  if (next) lines.push(`  next record (${RECORD_NOTE}):`, `  ${next}`);
  return lines.join("\n");
}

/** `whois`: the registry's own answer, or why there is none. Observation only. */
function formatWhois(body: unknown): string {
  const result = rec(body);
  const status = str(result.status);
  if (status !== "registered") {
    const why = str(result.reason);
    const head = status === "not_registered" ? "not registered" : `unknown${why ? ` (${why})` : ""}`;
    return `${str(result.domain) ?? ""}: ${head}`;
  }
  const reg = rec(result.registration);
  const lines = [`${str(result.domain) ?? ""}: registered${str(reg.registrar) ? ` with ${str(reg.registrar)}` : ""}`];
  for (const [label, key] of [["registered", "registered_at"], ["updated", "updated_at"], ["expires", "expires_at"]] as const) {
    const value = str(reg[key]);
    if (value) lines.push(`  ${label}: ${value.slice(0, 10)}`);
  }
  const ns = list(reg.nameservers).map((n) => String(n));
  if (ns.length) lines.push(`  nameservers: ${ns.join(", ")}`);
  const status_codes = list(reg.status).map((c) => String(c));
  if (status_codes.length) lines.push(`  status: ${status_codes.join(", ")}`);
  if (reg.dnssec === true) lines.push("  dnssec: signed");
  else if (reg.dnssec === false) lines.push("  dnssec: unsigned");
  lines.push(`  abuse contact: ${str(reg.abuse_email) ?? (reg.redacted === true ? "redacted by the registry" : "not published")}`);
  return lines.join("\n");
}

/** `bimi`: the status, what was found, eligibility per mailbox, the record verbatim. */
export function formatBimi(body: unknown): string {
  const result = rec(body);
  const lines = [`${str(result.domain) ?? "?"} BIMI: ${str(result.status) ?? "?"}`];
  const next = str(result.next_step);
  if (next) lines.push(`  next: ${next}`);
  const published = str(result.published_record);
  if (published) lines.push(`  published at ${str(result.record_location) ?? "?"}: ${published}`);
  for (const f of list(result.findings)) {
    const finding = rec(f);
    lines.push(`  ${String(finding.state ?? "").toUpperCase().padEnd(8)} ${str(finding.part) ?? ""}: ${str(finding.message) ?? ""}`);
  }
  const mailboxes = list(result.mailboxes);
  if (mailboxes.length) lines.push("  mailboxes (eligibility only; each mailbox decides whether a logo shows):");
  for (const m of mailboxes) {
    const row = rec(m);
    lines.push(`    ${String(row.mailbox ?? "?").padEnd(14)} ${str(row.label) ?? ""}: ${str(row.observed) ?? ""}`);
  }
  const generated = rec(result.generated);
  const record = str(generated.record);
  if (record) lines.push(`  record (TXT at ${str(generated.host) ?? "?"}; ${RECORD_NOTE}):`, `  ${record}`);
  const rationale = str(generated.rationale);
  if (rationale) lines.push(`  ${rationale}`);
  return lines.join("\n");
}

/** `email-test-start`: the address to send to and the command that reads the result. */
export function formatEmailTestStart(body: unknown): string {
  const result = rec(body);
  const limit = rec(result.limit);
  const id = str(result.test_id) ?? "?";
  return [
    `send one email to: ${str(result.address) ?? "?"}`,
    `  test id: ${id}`,
    `  expires: ${str(result.expires_at) ?? "?"} (takes one message)`,
    `  daily limit: ${limit.used_today ?? "?"} of ${limit.per_day ?? "?"} used (${str(limit.applied) ?? "?"})`,
    `Send it yourself, from the mail app or service you want to test, then run: dns-doctor email-test ${id}`,
  ].join("\n");
}

/** `email-test`: the status; once received, the score, its deductions and the DMARC fix verbatim. */
export function formatEmailTest(body: unknown): string {
  const top = rec(body);
  const status = str(top.status) ?? "?";
  const lines = [`${str(top.test_id) ?? "?"}: ${status}`];
  if (status === "pending") {
    lines.push(
      str(top.received_at)
        ? "  the message arrived and is being checked; run this command again in a few seconds"
        : `  no message has arrived yet; send one email to ${str(top.address) ?? "?"}, then run this command again`,
    );
  } else if (status === "expired" || status === "error") {
    if (status === "error") lines.push(`  error: ${str(top.error) ?? "?"}`);
    lines.push("  start a new test with: dns-doctor email-test-start");
  }
  const result = rec(top.result);
  if (status === "received") {
    if (str(result.from_domain)) lines.push(`  from: ${str(result.from_domain)}`);
    const score = rec(result.score);
    if (score.value === undefined) {
      lines.push("  score: none (this test predates scoring)");
    } else {
      const authOnly = str(result.coverage) === "auth_only" ? " (sender authentication only; the content was not checked)" : "";
      lines.push(`  score: ${score.value} of ${score.out_of ?? 10}${authOnly}`);
    }
    for (const d of list(score.deductions)) {
      const row = rec(d);
      const applied = row.applied ?? row.points;
      if (applied === 0) continue; // its category cap was already reached, so it cost nothing
      lines.push(`    -${applied ?? "?"}  ${str(row.reason) ?? str(row.code) ?? ""}`);
    }
    for (const n of list(score.not_scored)) {
      const row = rec(n);
      lines.push(`    not scored: ${str(row.check) ?? ""}: ${str(row.reason) ?? ""}`);
    }
    const dkim = list(result.dkim).map((s) => `${str(rec(s).domain) ?? "?"}=${str(rec(s).result) ?? "?"}`);
    lines.push(`  spf ${str(rec(result.spf).result) ?? "?"} · dkim ${dkim.join(", ") || "none"} · dmarc ${str(rec(result.dmarc).result) ?? "?"}`);
    const providers = rec(rec(result.estimates).providers);
    if (Object.keys(providers).length) lines.push("  estimates (not a promise of delivery):");
    for (const [name, value] of Object.entries(providers)) {
      const row = rec(value);
      const pct = (v: unknown) => (typeof v === "number" ? `${v}%` : "not estimated");
      const reason = str(row.unrated_reason) ? ` (${str(row.unrated_reason)!.replace(/_/g, " ")})` : "";
      lines.push(`    ${name.padEnd(10)} accepted ${pct(row.accepted_pct)} · inbox ${pct(row.inbox_pct)}${reason}`);
    }
    const fix = rec(rec(result.dmarc).fix);
    const record = str(fix.record);
    if (record) lines.push(`  dmarc fix (TXT at ${str(fix.host) ?? "?"}; ${RECORD_NOTE}):`, `  ${record}`);
    const withheld = str(rec(result.dmarc).fix_withheld);
    if (!record && withheld) lines.push(`  ${withheld}`);
    for (const a of list(top.advice)) if (typeof a === "string") lines.push(`  · ${a}`);
  }
  const reportUrl = str(top.report_url);
  if (reportUrl) lines.push(`  report: ${reportUrl}`);
  return lines.join("\n");
}

/** `email-tests`: one line per earlier test, newest first as the API orders them. */
export function formatEmailTests(body: unknown): string {
  const tests = list(rec(body).tests);
  if (tests.length === 0) return "no email tests";
  const note = tests.some((t) => str(rec(t).coverage) === "auth_only") ? "\n* score covers sender authentication only" : "";
  return tests
    .map((t) => {
      const test = rec(t);
      const score = rec(test.score);
      const scored = score.value !== undefined ? `${score.value}/${score.out_of ?? 10}${str(test.coverage) === "auth_only" ? "*" : ""}` : "-";
      return `${String(test.created_at ?? "").slice(0, 19)}  ${String(test.status ?? "").padEnd(8)} ${String(test.from_domain ?? "-").padEnd(24)} ${scored.padEnd(6)} dmarc ${str(test.dmarc_result) ?? "-"}  ${str(test.test_id) ?? ""}${str(test.report_url) ? `  ${str(test.report_url)}` : ""}`;
    })
    .join("\n") + note;
}

/** `domains`: each domain on the account with its state and the next step as given. */
export function formatDomains(body: unknown): string {
  const result = rec(body);
  const domains = list(result.domains);
  if (domains.length === 0) return `no domains on this account${str(result.next_step) ? `\n  ${str(result.next_step)}` : ""}`;
  return domains
    .map((d) => {
      const row = rec(d);
      return `${String(row.domain ?? "?").padEnd(28)} ${String(row.state ?? "?").padEnd(20)} ${str(row.next_step) ?? ""}`;
    })
    .join("\n");
}

const RENDERERS: Record<string, (body: unknown) => string> = {
  scan: formatReport,
  propagation: formatPropagation,
  "dmarc-upgrade": formatDmarcUpgrade,
  "reverse-dns": formatReverseDns,
  whois: formatWhois,
  "spf-audit": formatSpfAudit,
  "spf-count": formatSpfCount,
  "dmarc-validate": formatDmarcRecord,
  "dmarc-generate": formatDmarcRecord,
  dkim: formatDkim,
  "report-parse": formatReportParse,
  record: formatRecord,
  parked: formatParked,
  "signup-url": formatSignupUrl,
  alerts: formatAlerts,
  readiness: formatReadiness,
  bimi: formatBimi,
  "email-test-start": formatEmailTestStart,
  "email-test": formatEmailTest,
  "email-tests": formatEmailTests,
  domains: formatDomains,
};

export function render(command: string, body: unknown): string {
  const renderer = RENDERERS[command];
  return renderer ? renderer(body) : JSON.stringify(body, null, 2);
}

/**
 * Exit code from the API's own verdicts: 0 = nothing failing, 1 = a failing
 * verdict. Transient errors never reach here (they exit 2 in `main`).
 */
export function exitCodeFor(command: string, body: unknown): 0 | 1 {
  const result = rec(body);
  switch (command) {
    case "scan":
      return checksOf(rec(result.report ?? result)).some((c) => str(c.status) === "fail") ? 1 : 0;
    case "propagation": {
      const verdict = str(result.verdict);
      return verdict === "not_propagated" || verdict === "inconsistent" ? 1 : 0;
    }
    case "reverse-dns":
      return str(result.verdict) === "confirmed" ? 0 : 1;
    case "spf-audit":
      return list(result.findings).some((f) => String(rec(f).severity ?? "").toLowerCase() === "high") ? 1 : 0;
    case "spf-count":
      return result.over_limit === true || result.record_valid === false || result.has_pass_all === true ? 1 : 0;
    case "dmarc-validate":
      return result.valid === false ? 1 : 0;
    case "record":
      return rec(result.authoritative).ns_in_agreement === false ? 1 : 0;
    case "bimi":
      return str(result.status) === "broken" ? 1 : 0;
    case "email-test": {
      const status = str(result.status);
      if (status === "expired" || status === "error") return 1; // no result to trust
      return str(rec(rec(result.result).dmarc).result) === "fail" ? 1 : 0;
    }
    default:
      return 0;
  }
}
