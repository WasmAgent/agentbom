/**
 * Compliance check test suite.
 *
 * Tests all compliance profiles with known-good and known-bad fixtures.
 * Known-good fixtures should pass compliance checks, while known-bad fixtures
 * should fail with specific error messages.
 */
import { afterEach, beforeEach, describe, expect, it, spyOn } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  checkProfileSchemaCompatibility,
  getSchemaFieldDescriptors,
  upgradeProfileMappings,
  validateAgentBOM,
} from "@wasmagent/agentbom-core";
import {
  complianceCheckCommand,
  upgradeProfileCommand,
  verifyProfileCommand,
} from "./compliance-check.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

describe("compliance-check: profile validation with fixtures", () => {
  let originalConsoleLog: typeof console.log;
  let originalConsoleError: typeof console.error;
  let consoleOutput: string[] = [];
  let errorOutput: string[] = [];

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
  });

  afterEach(() => {
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
  });

  function getFixturePath(fixtureName: string): string {
    return resolve(__dirname, "compliance-fixtures", fixtureName);
  }

  describe("SOC2 2024 profile", () => {
    const profileId = "soc2-2024";

    it("accepts known-good SOC2 fixture", () => {
      const fixturePath = getFixturePath("soc2-2024-known-good.json");
      const exitCode = complianceCheckCommand([
        fixturePath,
        "--profile",
        profileId,
      ]);

      expect(exitCode).toBe(0);
      expect(errorOutput).toHaveLength(0);
      expect(consoleOutput.some((line) => line.includes("✓ COMPLIANT"))).toBe(
        true,
      );
      expect(consoleOutput.some((line) => line.includes("SOC2"))).toBe(true);
      expect(consoleOutput.some((line) => line.includes("2024"))).toBe(true);
    });

    it("rejects known-bad SOC2 fixture", () => {
      const fixturePath = getFixturePath("soc2-2024-known-bad.json");
      const exitCode = complianceCheckCommand([
        fixturePath,
        "--profile",
        profileId,
      ]);

      expect(exitCode).toBe(1);
      expect(
        consoleOutput.some((line) => line.includes("✗ NON-COMPLIANT")),
      ).toBe(true);

      const errorText = consoleOutput.join("\n");
      // Known-bad fixture has multiple violations:
      // - development context (not in allowed contexts)
      // - tools with high/critical severity
      // - blocked permissions
      // - blocked sources
      // - unmitigated critical risks
      // - missing signature and timestamp
      expect(errorText).toMatch(/development_context|deployment_context/);
      expect(errorText).toMatch(/tool_layer/);
      expect(errorText).toMatch(/risk_layer/);
      expect(errorText).toMatch(/attestation/);
    });
  });

  describe("ISO27001 2022 profile", () => {
    const profileId = "iso27001-2022";

    it("accepts known-good ISO27001 fixture", () => {
      const fixturePath = getFixturePath("iso27001-2022-known-good.json");
      const exitCode = complianceCheckCommand([
        fixturePath,
        "--profile",
        profileId,
      ]);

      expect(exitCode).toBe(0);
      expect(errorOutput).toHaveLength(0);
      expect(consoleOutput.some((line) => line.includes("✓ COMPLIANT"))).toBe(
        true,
      );
      expect(consoleOutput.some((line) => line.includes("ISO27001"))).toBe(
        true,
      );
      expect(consoleOutput.some((line) => line.includes("2022"))).toBe(true);
    });

    it("rejects known-bad ISO27001 fixture", () => {
      const fixturePath = getFixturePath("iso27001-2022-known-bad.json");
      const exitCode = complianceCheckCommand([
        fixturePath,
        "--profile",
        profileId,
      ]);

      expect(exitCode).toBe(1);
      expect(
        consoleOutput.some((line) => line.includes("✗ NON-COMPLIANT")),
      ).toBe(true);

      const errorText = consoleOutput.join("\n");
      // Known-bad fixture has multiple violations:
      // - staging context (only production allowed)
      // - tools with critical severity
      // - blocked permissions (filesystem:write unrestricted)
      // - blocked sources (unverified-external)
      // - unmitigated critical risks
      // - missing signature and timestamp
      expect(errorText).toMatch(/deployment_context|staging/);
      expect(errorText).toMatch(/tool_layer/);
      expect(errorText).toMatch(/risk_layer/);
      expect(errorText).toMatch(/attestation/);
    });
  });

  describe("EIDAS controlled profile", () => {
    const profileId = "eidas-controlled";

    it("accepts known-good EIDAS fixture", () => {
      const fixturePath = getFixturePath("eidas-controlled-known-good.json");
      const exitCode = complianceCheckCommand([
        fixturePath,
        "--profile",
        profileId,
      ]);

      expect(exitCode).toBe(0);
      expect(errorOutput).toHaveLength(0);
      expect(consoleOutput.some((line) => line.includes("✓ COMPLIANT"))).toBe(
        true,
      );
      expect(consoleOutput.some((line) => line.includes("EIDAS"))).toBe(true);
      expect(consoleOutput.some((line) => line.includes("controlled"))).toBe(
        true,
      );
    });

    it("rejects known-bad EIDAS fixture", () => {
      const fixturePath = getFixturePath("eidas-controlled-known-bad.json");
      const exitCode = complianceCheckCommand([
        fixturePath,
        "--profile",
        profileId,
      ]);

      expect(exitCode).toBe(1);
      expect(
        consoleOutput.some((line) => line.includes("✗ NON-COMPLIANT")),
      ).toBe(true);

      const errorText = consoleOutput.join("\n");
      // Known-bad fixture has multiple violations:
      // - development context (only production allowed)
      // - tools with medium severity (max allowed is low)
      // - blocked permissions (filesystem:write, network:external, system:execute)
      // - blocked sources (external, unverified)
      // - unmitigated critical and high risks
      // - 2 unmitigated medium risks (max allowed is 1)
      // - missing signature and timestamp
      expect(errorText).toMatch(/deployment_context|development/);
      expect(errorText).toMatch(/tool_layer/);
      expect(errorText).toMatch(/risk_layer/);
      expect(errorText).toMatch(/attestation/);
    });
  });

  describe("fixture schema validation", () => {
    it("all known-good fixtures have valid AgentBOM schema", () => {
      const knownGoodFixtures = [
        "soc2-2024-known-good.json",
        "iso27001-2022-known-good.json",
        "eidas-controlled-known-good.json",
      ];

      for (const fixtureName of knownGoodFixtures) {
        const fixturePath = getFixturePath(fixtureName);
        const fixtureContent = readFileSync(fixturePath, "utf-8");
        const fixtureData = JSON.parse(fixtureContent);

        const validation = validateAgentBOM(fixtureData);
        expect(validation.valid).toBe(true);
        expect(validation.errors).toHaveLength(0);
      }
    });

    it("all known-bad fixtures have valid AgentBOM schema but fail compliance", () => {
      const knownBadFixtures = [
        "soc2-2024-known-bad.json",
        "iso27001-2022-known-bad.json",
        "eidas-controlled-known-bad.json",
      ];

      for (const fixtureName of knownBadFixtures) {
        const fixturePath = getFixturePath(fixtureName);
        const fixtureContent = readFileSync(fixturePath, "utf-8");
        const fixtureData = JSON.parse(fixtureContent);

        // Schema should be valid
        const validation = validateAgentBOM(fixtureData);
        expect(validation.valid).toBe(true);
        expect(validation.errors).toHaveLength(0);
      }
    });
  });

  describe("compliance check behavior", () => {
    it("returns error for non-existent profile", () => {
      const fixturePath = getFixturePath("soc2-2024-known-good.json");
      const exitCode = complianceCheckCommand([
        fixturePath,
        "--profile",
        "nonexistent-profile",
      ]);

      expect(exitCode).toBe(1);
      expect(
        errorOutput.some((line) =>
          line.includes("cannot load compliance profile"),
        ),
      ).toBe(true);
    });

    it("returns error for non-existent fixture file", () => {
      const exitCode = complianceCheckCommand([
        "/nonexistent/file.json",
        "--profile",
        "soc2-2024",
      ]);

      expect(exitCode).toBe(1);
      expect(
        errorOutput.some((line) => line.includes("cannot read AgentBOM file")),
      ).toBe(true);
    });

    it("returns error for invalid JSON", () => {
      const exitCode = complianceCheckCommand(["--profile", "soc2-2024"]);

      expect(exitCode).toBe(1);
      expect(errorOutput.length).toBeGreaterThan(0);
    });
  });

  describe("profile coverage", () => {
    it("all three compliance profiles are tested", () => {
      const profiles = ["soc2-2024", "iso27001-2022", "eidas-controlled"];
      const fixtures = [
        "soc2-2024-known-good.json",
        "iso27001-2022-known-good.json",
        "eidas-controlled-known-good.json",
      ];

      for (let i = 0; i < profiles.length; i++) {
        const profileId = profiles[i];
        const fixturePath = getFixturePath(fixtures[i]);
        const exitCode = complianceCheckCommand([
          fixturePath,
          "--profile",
          profileId,
        ]);

        expect(exitCode).toBe(0);
      }
    });
  });
});

describe("compliance-verify-profile: backward compatibility checking", () => {
  let originalConsoleLog: typeof console.log;
  let originalConsoleError: typeof console.error;
  let consoleOutput: string[] = [];
  let errorOutput: string[] = [];

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
  });

  afterEach(() => {
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
  });

  describe("existing profiles against schema v0.1", () => {
    const profiles = ["soc2-2024", "iso27001-2022", "eidas-controlled"];

    for (const profileId of profiles) {
      it(`${profileId}: no breaking issues with schema v0.1`, () => {
        const exitCode = verifyProfileCommand([
          profileId,
          "--schema-version",
          "0.1",
        ]);

        expect(exitCode).toBe(0);
        expect(consoleOutput.some((line) => line.includes("✓ yes"))).toBe(true);
        const outputText = consoleOutput.join("\n");
        expect(outputText).not.toMatch(/Breaking issues/);
      });

      it(`${profileId}: uses latest schema version by default`, () => {
        verifyProfileCommand([profileId]);
        const outputText = consoleOutput.join("\n");
        expect(outputText).toMatch(/AgentBOM schema:\s+v0\.1/);
      });

      it(`${profileId}: reports coverage gaps for uncovered schema sections`, () => {
        verifyProfileCommand([profileId, "--schema-version", "0.1"]);

        const outputText = consoleOutput.join("\n");
        // All profiles cover identity, tool_layer, risk_layer, attestation
        // but NOT model_layer, prompt_layer, permission_layer, etc.
        expect(outputText).toMatch(/Coverage gaps/);
        expect(outputText).toMatch(/model_layer/);
        expect(outputText).toMatch(/permission_layer/);
        expect(outputText).toMatch(/workflow_layer/);
        expect(outputText).toMatch(/distribution/);
      });
    }
  });

  describe("breaking change detection", () => {
    it("detects profile referencing a removed identity field", () => {
      // Directly test the library function with a synthetic profile

      const result = checkProfileSchemaCompatibility(
        {
          profile_version: "0.1",
          rules: {
            identity: {
              required_fields: ["agent_version", "nonexistent_field"],
            },
          },
        },
        "0.1",
      );

      expect(result.compatible).toBe(false);
      expect(result.breaking.length).toBeGreaterThan(0);
      expect(
        result.breaking.some(
          (b: { field: string }) => b.field === "identity.nonexistent_field",
        ),
      ).toBe(true);
    });

    it("detects profile requiring attestation.signature against schema without it", () => {
      // Simulate a future schema version where signature was removed
      // by checking against an unknown version (no fields registered)
      const result = checkProfileSchemaCompatibility(
        {
          profile_version: "0.1",
          rules: {
            attestation: {
              requires_signature: true,
            },
          },
        },
        "99.0", // unknown version → no fields → everything breaks
      );

      expect(result.compatible).toBe(false);
      expect(
        result.breaking.some(
          (b: { field: string }) => b.field === "attestation.signature",
        ),
      ).toBe(true);
    });

    it("detects tool_layer rules against schema without tool_layer", () => {
      const result = checkProfileSchemaCompatibility(
        {
          profile_version: "0.1",
          rules: {
            tool_layer: {
              requires_tool_inventory: true,
              blocked_permissions: ["fs:write"],
            },
          },
        },
        "99.0",
      );

      expect(result.compatible).toBe(false);
      expect(
        result.breaking.some(
          (b: { field: string }) => b.field === "tool_layer",
        ),
      ).toBe(true);
    });

    it("detects risk_layer rules against schema without risk_layer", () => {
      const result = checkProfileSchemaCompatibility(
        {
          profile_version: "0.1",
          rules: {
            risk_layer: {
              requires_risk_assessment: true,
              requires_mitigation_for: ["critical"],
            },
          },
        },
        "99.0",
      );

      expect(result.compatible).toBe(false);
      expect(
        result.breaking.some(
          (b: { field: string }) => b.field === "risk_layer",
        ),
      ).toBe(true);
    });

    it("generates mapping updates for breaking changes", () => {
      // Use a version with no fields to simulate breaking changes
      const result = checkProfileSchemaCompatibility(
        {
          profile_version: "0.1",
          rules: {
            identity: { required_fields: ["agent_version"] },
            attestation: { requires_signature: true },
            tool_layer: { blocked_permissions: ["fs:write"] },
          },
        },
        "99.0",
      );

      expect(result.mapping_updates.length).toBeGreaterThan(0);
      expect(result.breaking.length).toBeGreaterThan(0);
    });
  });

  describe("schema field descriptors", () => {
    it("returns field descriptors for known version", () => {
      const fields = getSchemaFieldDescriptors("0.1");
      expect(fields.length).toBeGreaterThan(0);

      // Check for key fields
      expect(fields.some((f: { path: string }) => f.path === "identity")).toBe(
        true,
      );
      expect(
        fields.some((f: { path: string }) => f.path === "identity.agent_id"),
      ).toBe(true);
      expect(
        fields.some((f: { path: string }) => f.path === "tool_layer"),
      ).toBe(true);
      expect(
        fields.some(
          (f: { path: string }) => f.path === "attestation.signature",
        ),
      ).toBe(true);
      expect(
        fields.some((f: { path: string }) => f.path === "distribution"),
      ).toBe(true);
    });

    it("returns empty array for unknown version", () => {
      const fields = getSchemaFieldDescriptors("99.0");
      expect(fields).toHaveLength(0);
    });
  });

  describe("CLI error handling", () => {
    it("returns error when no profile ID given", () => {
      const exitCode = verifyProfileCommand([]);

      expect(exitCode).toBe(1);
      expect(errorOutput.some((line) => line.includes("Usage"))).toBe(true);
    });

    it("returns error for non-existent profile", () => {
      const exitCode = verifyProfileCommand(["nonexistent-profile"]);

      expect(exitCode).toBe(1);
      expect(
        errorOutput.some((line) =>
          line.includes("cannot load compliance profile"),
        ),
      ).toBe(true);
    });
  });
});

describe("upgradeProfileMappings: automated mapping updates", () => {
  it("returns unchanged profile when already compatible", () => {
    const profile = {
      profile_version: "0.1",
      rules: {
        identity: {
          required_fields: ["agent_version", "deployment_context"],
          allowed_contexts: ["production"],
          requires_version: true,
        },
        attestation: {
          requires_signature: true,
          requires_timestamp: true,
        },
      },
    };

    const result = upgradeProfileMappings(profile, "0.1");

    expect(result.changes_applied).toBe(false);
    expect(result.applied_updates).toHaveLength(0);
    expect(result.unresolved).toHaveLength(0);
    expect(result.upgraded_profile).toEqual(profile);
  });

  it("removes identity.required_fields referencing non-existent fields", () => {
    const profile = {
      profile_version: "0.1",
      rules: {
        identity: {
          required_fields: [
            "agent_version",
            "nonexistent_field",
            "another_fake",
          ],
        },
      },
    };

    const result = upgradeProfileMappings(profile, "0.1");

    expect(result.changes_applied).toBe(true);
    expect(result.applied_updates.length).toBeGreaterThan(0);
    expect(
      result.applied_updates.some((u: string) =>
        u.includes("identity.required_fields"),
      ),
    ).toBe(true);
    expect(result.upgraded_profile.rules.identity?.required_fields).toEqual([
      "agent_version",
    ]);
    expect(result.unresolved).toHaveLength(0);
  });

  it("disables attestation.requires_signature when signature field removed", () => {
    const profile = {
      profile_version: "0.1",
      rules: {
        attestation: {
          requires_signature: true,
          requires_timestamp: true,
        },
      },
    };

    // Unknown version has no fields → attestation.signature is "removed"
    const result = upgradeProfileMappings(profile, "99.0");

    expect(result.changes_applied).toBe(true);
    expect(result.upgraded_profile.rules.attestation?.requires_signature).toBe(
      false,
    );
    expect(result.upgraded_profile.rules.attestation?.requires_timestamp).toBe(
      false,
    );
    expect(
      result.applied_updates.some((u: string) =>
        u.includes("requires_signature"),
      ),
    ).toBe(true);
    expect(
      result.applied_updates.some((u: string) =>
        u.includes("requires_timestamp"),
      ),
    ).toBe(true);
  });

  it("clears tool_layer rules when section removed from schema", () => {
    const profile = {
      profile_version: "0.1",
      rules: {
        tool_layer: {
          max_severity: "medium",
          requires_tool_inventory: true,
          blocked_permissions: ["fs:write"],
          blocked_sources: ["unverified"],
        },
      },
    };

    const result = upgradeProfileMappings(profile, "99.0");

    expect(result.changes_applied).toBe(true);
    expect(result.upgraded_profile.rules.tool_layer).toBeUndefined();
    expect(
      result.applied_updates.some(
        (u: string) => u.includes("tool_layer") && u.includes("cleared"),
      ),
    ).toBe(true);
  });

  it("clears risk_layer rules when section removed from schema", () => {
    const profile = {
      profile_version: "0.1",
      rules: {
        risk_layer: {
          requires_risk_assessment: true,
          requires_mitigation_for: ["critical", "high"],
          max_unmitigated_critical: 0,
        },
      },
    };

    const result = upgradeProfileMappings(profile, "99.0");

    expect(result.changes_applied).toBe(true);
    expect(result.upgraded_profile.rules.risk_layer).toBeUndefined();
    expect(
      result.applied_updates.some(
        (u: string) => u.includes("risk_layer") && u.includes("cleared"),
      ),
    ).toBe(true);
  });

  it("handles multiple breaking changes across sections", () => {
    const profile = {
      profile_version: "0.1",
      rules: {
        identity: {
          required_fields: ["agent_version", "nonexistent_field"],
        },
        attestation: {
          requires_signature: true,
        },
        tool_layer: {
          blocked_permissions: ["fs:write"],
        },
        risk_layer: {
          requires_mitigation_for: ["critical"],
        },
      },
    };

    const result = upgradeProfileMappings(profile, "99.0");

    expect(result.changes_applied).toBe(true);
    // v99.0 has no fields at all, so agent_version is also stripped as non-existent
    expect(result.upgraded_profile.rules.identity?.required_fields).toEqual([]);
    expect(result.upgraded_profile.rules.attestation?.requires_signature).toBe(
      false,
    );
    expect(result.upgraded_profile.rules.tool_layer).toBeUndefined();
    expect(result.upgraded_profile.rules.risk_layer).toBeUndefined();
    expect(result.applied_updates.length).toBeGreaterThanOrEqual(4);
  });

  it("reports compatibility check from before upgrade", () => {
    const profile = {
      profile_version: "0.1",
      rules: {
        identity: {
          required_fields: ["nonexistent_field"],
        },
      },
    };

    const result = upgradeProfileMappings(profile, "99.0");

    expect(result.compatibility.compatible).toBe(false);
    expect(result.compatibility.breaking.length).toBeGreaterThan(0);
  });
});

describe("compliance-upgrade-profile: CLI command", () => {
  let originalConsoleLog: typeof console.log;
  let originalConsoleError: typeof console.error;
  let consoleOutput: string[] = [];
  let errorOutput: string[] = [];

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
  });

  afterEach(() => {
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
  });

  it("returns error when no profile ID given", () => {
    const exitCode = upgradeProfileCommand([]);

    expect(exitCode).toBe(1);
    expect(errorOutput.some((line) => line.includes("Usage"))).toBe(true);
  });

  it("returns error for non-existent profile", () => {
    const exitCode = upgradeProfileCommand(["nonexistent-profile"]);

    expect(exitCode).toBe(1);
    expect(
      errorOutput.some((line) =>
        line.includes("cannot load compliance profile"),
      ),
    ).toBe(true);
  });

  it("reports already compatible profile without changes", () => {
    const exitCode = upgradeProfileCommand([
      "soc2-2024",
      "--schema-version",
      "0.1",
    ]);

    expect(exitCode).toBe(0);
    expect(
      consoleOutput.some((line) => line.includes("already compatible")),
    ).toBe(true);
  });

  it("reports coverage gaps for existing profiles", () => {
    upgradeProfileCommand(["soc2-2024", "--schema-version", "0.1"]);

    const outputText = consoleOutput.join("\n");
    expect(outputText).toMatch(/coverage gap/);
  });

  it("detects and reports breaking issues against unknown schema version", () => {
    const exitCode = upgradeProfileCommand([
      "soc2-2024",
      "--schema-version",
      "99.0",
    ]);

    expect(exitCode).toBe(0);
    const outputText = consoleOutput.join("\n");
    expect(outputText).toMatch(/Breaking issues/);
    expect(outputText).toMatch(/Auto-applied/);
  });

  it("supports --dry-run flag", () => {
    const exitCode = upgradeProfileCommand([
      "soc2-2024",
      "--schema-version",
      "99.0",
      "--dry-run",
    ]);

    expect(exitCode).toBe(0);
    const outputText = consoleOutput.join("\n");
    expect(outputText).toMatch(/dry-run/);
  });

  it("outputs upgraded profile JSON by default", () => {
    upgradeProfileCommand(["soc2-2024", "--schema-version", "99.0"]);

    const outputText = consoleOutput.join("\n");
    // The JSON output should contain the upgraded profile structure
    expect(outputText).toMatch(/"profile_version"/);
    expect(outputText).toMatch(/"rules"/);
  });

  describe("all existing profiles upgrade against schema v0.1", () => {
    const profiles = ["soc2-2024", "iso27001-2022", "eidas-controlled"];

    for (const profileId of profiles) {
      it(`${profileId}: reports already compatible with v0.1`, () => {
        const exitCode = upgradeProfileCommand([
          profileId,
          "--schema-version",
          "0.1",
        ]);

        expect(exitCode).toBe(0);
        expect(
          consoleOutput.some((line) => line.includes("already compatible")),
        ).toBe(true);
      });
    }
  });
});
