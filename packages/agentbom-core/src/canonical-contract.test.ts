import { describe, expect, it } from "bun:test";
import { getSchema } from "@wasmagent/protocol";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

/**
 * AB-4 — canonical fixture gate.
 *
 * Schemas are consumed from the exact published @wasmagent/protocol package
 * (never hand-copied). These tests pin the canonical contract surface:
 * a canonical AgentBOM document validates, a semantic-negative does not,
 * and the repo carries no local schema copies that could drift.
 */

function makeValidator(schemaName: string) {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  const schema = getSchema(schemaName);
  if (!schema)
    throw new Error(
      `canonical schema not found in @wasmagent/protocol: ${schemaName}`,
    );
  return ajv.compile(schema as Record<string, unknown>);
}

const CANONICAL_AGENTBOM = {
  agentbom_version: "0.1",
  identity: {
    agent_id: "canonical-fixture-001",
    agent_name: "Canonical Fixture Agent",
    agent_version: "1.0.0",
    generated_at: "2026-09-14T00:00:00Z",
  },
  attestation: {
    generator: "agentbom-core",
    generator_version: "0.0.0",
  },
};

describe("canonical contract fixtures (AB-4)", () => {
  it("validates a canonical AgentBOM document against the packaged schema", () => {
    const validate = makeValidator("agentbom");
    expect(validate(CANONICAL_AGENTBOM)).toBe(true);
  });

  it("rejects a semantic-negative (required identity removed)", () => {
    const validate = makeValidator("agentbom");
    const mutated = JSON.parse(JSON.stringify(CANONICAL_AGENTBOM)) as Record<
      string,
      unknown
    >;
    delete mutated.identity;
    expect(validate(mutated)).toBe(false);
  });

  it("rejects an unknown agentbom_version", () => {
    const validate = makeValidator("agentbom");
    const mutated = { ...CANONICAL_AGENTBOM, agentbom_version: "9.9" };
    expect(validate(mutated)).toBe(false);
  });

  it("canonical MCP Posture schema is available from the package", () => {
    const schema = getSchema("mcp-posture") as
      | { required?: string[] }
      | undefined;
    expect(schema).toBeDefined();
    expect(Array.isArray(schema?.required)).toBe(true);
  });

  it("validates a canonical MCP Posture document against the packaged schema", () => {
    const validate = makeValidator("mcp-posture");
    const doc = {
      posture_version: "0.1",
      identity: {
        snapshot_id: "snap-001",
        agent_id: "canonical-fixture-001",
        captured_at: "2026-09-14T00:00:00Z",
      },
      servers: [],
      attestation: { generator: "agentbom-core" },
    };
    expect(validate(doc)).toBe(true);
  });

  it("validates a canonical AEP v0.5 record against the packaged schema (AB-3)", () => {
    const validate = makeValidator("aep-record");
    const record = {
      schema_version: "aep/v0.5",
      run_id: "ab-canonical-aep-001",
      created_at_ms: 1750000000000,
      attribution_backing: "operator_asserted",
      run_attribution_backing_floor: "operator_asserted",
      run_attribution_backing_observed: ["operator_asserted"],
      authorization_evidence_count: 1,
    };
    expect(validate(record)).toBe(true);
  });

  it("rejects an AEP record carrying an unknown schema_version", () => {
    const validate = makeValidator("aep-record");
    const record = {
      schema_version: "aep/v9.9",
      run_id: "ab-canonical-aep-002",
      created_at_ms: 1750000000000,
    };
    expect(validate(record)).toBe(false);
  });

  it("validates a canonical Trust Passport document against the packaged schema (AB-3)", () => {
    const validate = makeValidator("trust-passport");
    const passport = {
      passport_version: "0.1",
      identity: {
        passport_id: "pp-001",
        agent_id: "canonical-fixture-001",
        issuer: "trustavo",
      },
      validity: {
        issued_at: "2026-09-14T00:00:00Z",
        expires_at: "2027-09-14T00:00:00Z",
      },
      revocation: { revoked: false },
      attestation: { issuer: "trustavo", signing_method: "ed25519" },
    };
    expect(validate(passport)).toBe(true);
  });

  it("repo carries no hand-copied canonical schema files (drift guard)", async () => {
    const { readdirSync, statSync } = await import("node:fs");
    const { join } = await import("node:path");
    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir)) {
        if (
          entry === "node_modules" ||
          entry === "dist" ||
          entry.startsWith(".")
        )
          continue;
        const p = join(dir, entry);
        if (statSync(p).isDirectory()) walk(p);
        else if (entry.endsWith(".schema.json")) offenders.push(p);
      }
    };
    walk(join(import.meta.dir, "../../.."));
    expect(offenders).toEqual([]);
  });
});
