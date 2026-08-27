import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateAgentBOMCommand } from "./agentbom-validate.js";

describe("agentbom validate command", () => {
  let originalConsoleLog: typeof console.log;
  let originalConsoleError: typeof console.error;
  let consoleOutput: string[] = [];
  let errorOutput: string[] = [];
  let tempDir: string;

  beforeEach(() => {
    originalConsoleLog = console.log;
    originalConsoleError = console.error;
    consoleOutput = [];
    errorOutput = [];

    console.log = (...args: unknown[]) => {
      consoleOutput.push(args.map(String).join(" "));
    };
    console.error = (...args: unknown[]) => {
      errorOutput.push(args.map(String).join(" "));
    };

    tempDir = mkdtempSync(join(tmpdir(), "agentbom-validate-"));
  });

  afterEach(() => {
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
    rmSync(tempDir, { recursive: true, force: true });
  });

  function writeTempFile(name: string, content: string): string {
    const path = join(tempDir, name);
    writeFileSync(path, content, "utf-8");
    return path;
  }

  it("accepts a valid AgentBOM document", () => {
    const path = writeTempFile(
      "valid.json",
      JSON.stringify({
        agentbom_version: "0.1",
        identity: {
          agent_id: "validate-agent-001",
          agent_name: "Validate Agent",
          agent_version: "1.0.0",
          generated_at: "2026-08-01T00:00:00Z",
        },
        attestation: {
          generator: "test",
          generator_version: "0.0.1",
        },
      }),
    );

    const exitCode = validateAgentBOMCommand(path);

    expect(exitCode).toBe(0);
    expect(errorOutput).toHaveLength(0);
    expect(consoleOutput[0]).toContain("Valid AgentBOM v0.1");
  });

  it("rejects an invalid AgentBOM document with error details", () => {
    const path = writeTempFile(
      "invalid.json",
      JSON.stringify({ agentbom_version: "0.1" }),
    );

    const exitCode = validateAgentBOMCommand(path);

    expect(exitCode).toBe(1);
    expect(errorOutput[0]).toContain("Validation failed");
    expect(errorOutput.join("\n")).toContain("  - ");
  });

  it("rejects a file that is not valid JSON", () => {
    const path = writeTempFile("broken.json", "{not json");

    const exitCode = validateAgentBOMCommand(path);

    expect(exitCode).toBe(1);
    expect(errorOutput.join("\n")).toContain("is not valid JSON");
  });

  it("rejects a missing file", () => {
    const exitCode = validateAgentBOMCommand(
      join(tempDir, "does-not-exist.json"),
    );

    expect(exitCode).toBe(1);
    expect(errorOutput.join("\n")).toContain("cannot read file");
  });
});
