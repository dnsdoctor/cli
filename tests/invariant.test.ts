/**
 * Structural guards — the CLI's half of the project-wide invariant that an
 * authoritative record string is only ever relayed, never composed, and that
 * traffic goes to one origin.
 */

import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";

const SRC_DIR = new URL("../src/", import.meta.url);

function sourceFiles(): { name: string; text: string }[] {
  return readdirSync(SRC_DIR)
    .filter((name) => name.endsWith(".ts"))
    .map((name) => ({ name, text: readFileSync(new URL(name, SRC_DIR), "utf8") }));
}

const RECORD_PATTERNS: RegExp[] = [/v=spf1/i, /v=DMARC1/i, /\bp=(none|quarantine|reject)\b/i, /\brua=/i];

describe("no record composition in src/", () => {
  const files = sourceFiles();
  it("finds source files to check", () => {
    expect(files.length).toBeGreaterThan(0);
  });
  for (const pattern of RECORD_PATTERNS) {
    it(`contains no ${pattern.source} literal`, () => {
      expect(files.filter((f) => pattern.test(f.text)).map((f) => f.name)).toEqual([]);
    });
  }
});

describe("one home for the origin", () => {
  it("mentions the hosted origin only in api.ts", () => {
    const offenders = sourceFiles()
      .filter((f) => f.name !== "api.ts" && f.text.includes("https://dnsdoctor.dev"))
      .map((f) => f.name);
    expect(offenders).toEqual([]);
  });
});

describe("the package publishes a runnable bin", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
    files: string[];
    bin: Record<string, string>;
    scripts: Record<string, string>;
    dependencies?: Record<string, string>;
  };
  it("ships dist and builds on pack", () => {
    expect(pkg.files).toContain("dist");
    expect(pkg.bin["dns-doctor"]).toBe("dist/index.js");
    expect(pkg.scripts.prepack).toContain("build");
  });
  it("has no runtime dependencies", () => {
    expect(pkg.dependencies ?? {}).toEqual({});
  });
});
