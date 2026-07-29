import { describe, expect, it } from "bun:test";
import type { ComplianceProfile } from "./compliance.js";
import { checkCompliance, computeWeightedScore } from "./compliance.js";

const MINIMAL_PROFILE: ComplianceProfile = {
  profile_version: "1.0",
  profile_id: "test-profile",
  framework: { name: "Test Framework", version: "1.0" },
  rules: {},
};

const SOC2_LIKE_PROFILE: ComplianceProfile = {
  profile_version: "1.0",
  profile_id: "soc2-test",
  framework: { name: "SOC 2", version: "2024" },
  rules: {
    identity: {
      weight: 2,
      required_fields: ["agent_id", "agent_name", "generated_at"],
      allowed_contexts: ["production", "staging"],
      requires_version: true,
    },
    tool_layer: {
      weight: 1,
      requires_tool_inventory: true,
      blocked_permissions: ["admin:all"],
    },
    attestation: {
      weight: 1,
      requires_signature: false,
      requires_timestamp: false,
    },
  },
};

const VALID_BOM = {
  agentbom_version: "0.1",
  identity: {
    agent_id: "test-agent-001",
    agent_name: "Test Agent",
    deployment_context: "production",
    agent_version: "1.0.0",
    generated_at: "2026-01-01T00:00:00Z",
  },
  tool_layer: [
    {
      tool_id: "search",
      tool_name: "Web Search",
      source: "builtin",
      permissions: ["network:outbound"],
    },
  ],
  attestation: { generator: "test" },
};

describe("checkCompliance — minimal profile", () => {
  it("passes an empty profile (no rules)", () => {
    const result = checkCompliance(VALID_BOM, MINIMAL_PROFILE);
    expect(result.compliant).toBe(true);
    expect(result.score).toBe(1);
    expect(result.errors).toHaveLength(0);
    expect(result.profile_id).toBe("test-profile");
    expect(result.framework_name).toBe("Test Framework");
  });

  it("defaults threshold to 1.0", () => {
    const result = checkCompliance(VALID_BOM, MINIMAL_PROFILE);
    expect(result.threshold).toBe(1.0);
  });

  it("respects custom minScore", () => {
    // Should pass with low threshold even if score is 0
    const bomMissingAttestationSection = { agentbom_version: "0.1" };
    const profile: ComplianceProfile = {
      ...MINIMAL_PROFILE,
      rules: {
        attestation: { requires_signature: true, requires_timestamp: true },
      },
    };
    const result = checkCompliance(
      bomMissingAttestationSection as Record<string, unknown>,
      profile,
      0.0,
    );
    expect(result.compliant).toBe(true);
  });
});

describe("checkCompliance — SOC2-like profile", () => {
  it("passes a fully compliant BOM", () => {
    const result = checkCompliance(VALID_BOM, SOC2_LIKE_PROFILE);
    expect(result.compliant).toBe(true);
    expect(result.score).toBe(1);
    expect(result.errors).toHaveLength(0);
    expect(result.passed_checks.length).toBeGreaterThan(0);
  });

  it("fails when identity.deployment_context is not allowed", () => {
    const bom = {
      ...VALID_BOM,
      identity: { ...VALID_BOM.identity, deployment_context: "development" },
    };
    const result = checkCompliance(bom, SOC2_LIKE_PROFILE);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("deployment_context"))).toBe(
      true,
    );
  });

  it("fails when required identity field is missing", () => {
    const bom = {
      ...VALID_BOM,
      identity: {
        agent_id: "test",
        deployment_context: "production",
        agent_version: "1.0",
      },
    };
    const result = checkCompliance(
      bom as Record<string, unknown>,
      SOC2_LIKE_PROFILE,
    );
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("agent_name"))).toBe(true);
  });

  it("fails when agent_version is missing but required", () => {
    const { agent_version: _, ...identityWithoutVersion } = VALID_BOM.identity;
    const bom = { ...VALID_BOM, identity: identityWithoutVersion };
    const result = checkCompliance(
      bom as Record<string, unknown>,
      SOC2_LIKE_PROFILE,
    );
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("agent_version"))).toBe(true);
  });

  it("fails when tool_layer is missing but required by inventory rule", () => {
    const { tool_layer: _, ...bomWithoutTools } = VALID_BOM;
    const result = checkCompliance(bomWithoutTools, SOC2_LIKE_PROFILE);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("tool inventory"))).toBe(true);
  });

  it("fails when tool has a blocked permission", () => {
    const bom = {
      ...VALID_BOM,
      tool_layer: [
        {
          tool_id: "admin-tool",
          tool_name: "Admin Tool",
          source: "builtin",
          permissions: ["admin:all", "network:outbound"],
        },
      ],
    };
    const result = checkCompliance(bom, SOC2_LIKE_PROFILE);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("blocked permission"))).toBe(
      true,
    );
  });

  it("populates framework metadata in result", () => {
    const result = checkCompliance(VALID_BOM, SOC2_LIKE_PROFILE);
    expect(result.framework_name).toBe("SOC 2");
    expect(result.framework_version).toBe("2024");
    expect(result.profile_id).toBe("soc2-test");
  });
});

describe("checkCompliance — risk_layer rules", () => {
  const riskProfile: ComplianceProfile = {
    profile_version: "1.0",
    profile_id: "risk-test",
    framework: { name: "Risk Test", version: "1.0" },
    rules: {
      risk_layer: {
        requires_risk_assessment: true,
        max_unmitigated_critical: 0,
        max_unmitigated_high: 2,
      },
    },
  };

  it("fails when risk assessment is required but missing", () => {
    const result = checkCompliance(VALID_BOM, riskProfile);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("risk assessment"))).toBe(true);
  });

  it("fails when unmitigated critical risks exceed limit", () => {
    const bom = {
      ...VALID_BOM,
      risk_layer: [
        { risk_id: "R1", severity: "critical", status: "open" },
        { risk_id: "R2", severity: "high", status: "open" },
      ],
    };
    const result = checkCompliance(bom, riskProfile);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("unmitigated critical"))).toBe(
      true,
    );
  });

  it("passes when critical risks are mitigated", () => {
    const bom = {
      ...VALID_BOM,
      risk_layer: [
        { risk_id: "R1", severity: "critical", status: "mitigated" },
        { risk_id: "R2", severity: "high", status: "open" },
      ],
    };
    const result = checkCompliance(bom, riskProfile);
    expect(result.compliant).toBe(true);
  });
});

describe("checkCompliance — attestation rules", () => {
  const attProfile: ComplianceProfile = {
    profile_version: "1.0",
    profile_id: "attestation-test",
    framework: { name: "Attestation Test", version: "1.0" },
    rules: {
      attestation: { requires_signature: true, requires_timestamp: true },
    },
  };

  it("fails when signature is required but missing", () => {
    const result = checkCompliance(VALID_BOM, attProfile);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("signature"))).toBe(true);
    expect(result.errors.some((e) => e.includes("timestamp"))).toBe(true);
  });

  it("passes when signature and timestamp are present", () => {
    const bom = {
      ...VALID_BOM,
      attestation: {
        generator: "test",
        signature: "abc123",
        timestamp: "2026-01-01T00:00:00Z",
      },
    };
    const result = checkCompliance(bom, attProfile);
    expect(result.compliant).toBe(true);
    expect(result.passed_checks.some((c) => c.includes("signature"))).toBe(
      true,
    );
    expect(result.passed_checks.some((c) => c.includes("timestamp"))).toBe(
      true,
    );
  });

  it("fails when attestation section is missing entirely", () => {
    const { attestation: _, ...bomWithoutAttestation } = VALID_BOM;
    const result = checkCompliance(
      bomWithoutAttestation as Record<string, unknown>,
      attProfile,
    );
    expect(result.compliant).toBe(false);
    expect(
      result.errors.some((e) => e.includes("attestation section is missing")),
    ).toBe(true);
  });
});

describe("computeWeightedScore", () => {
  it("returns 1.0 when all sections pass", () => {
    // Must provide 4 results matching the 4 rule sections: identity, tool_layer, risk_layer, attestation
    const results = [
      { errors: [], warnings: [], passed: ["identity ok"] },
      { errors: [], warnings: [], passed: ["tool ok"] },
      { errors: [], warnings: [], passed: ["risk ok"] },
      { errors: [], warnings: [], passed: ["att ok"] },
    ];
    const profile = MINIMAL_PROFILE;
    expect(computeWeightedScore(results, profile)).toBe(1);
  });

  it("returns 0.0 when all sections fail", () => {
    const results = [
      { errors: ["err"], warnings: [], passed: [] },
      { errors: ["err"], warnings: [], passed: [] },
      { errors: ["err"], warnings: [], passed: [] },
      { errors: ["err"], warnings: [], passed: [] },
    ];
    expect(computeWeightedScore(results, MINIMAL_PROFILE)).toBe(0);
  });

  it("respects section weights", () => {
    const weightedProfile: ComplianceProfile = {
      ...MINIMAL_PROFILE,
      rules: {
        identity: { weight: 3 }, // 3 weight, passes
        tool_layer: { weight: 1 }, // 1 weight, fails
      },
    };
    const results = [
      { errors: [], warnings: [], passed: ["identity ok"] }, // identity passes
      { errors: ["tool error"], warnings: [], passed: [] }, // tool_layer fails
      { errors: [], warnings: [], passed: [] }, // risk_layer no rules
      { errors: [], warnings: [], passed: [] }, // attestation no rules
    ];
    const score = computeWeightedScore(results, weightedProfile);
    // identity(3)+risk_layer(1)+attestation(1) pass, tool_layer(1) fails
    // risk_layer and attestation have no rules defined, so they default to weight=1 and pass
    // total = 3+1+1+1=6, passed = 3+1+1=5 → 5/6 ≈ 0.833
    expect(score).toBeCloseTo(5 / 6);
  });
});
