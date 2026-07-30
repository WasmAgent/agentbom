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

// ─── Additional framework profiles ──────────────────────────────────────────

const ISO27001_PROFILE: ComplianceProfile = {
  profile_version: "1.0",
  profile_id: "iso27001-2022",
  framework: { name: "ISO 27001", version: "2022" },
  rules: {
    identity: {
      weight: 2,
      required_fields: ["agent_id", "agent_name", "generated_at"],
      requires_version: true,
    },
    tool_layer: {
      weight: 2,
      requires_tool_inventory: true,
      max_severity: "high",
      blocked_permissions: ["admin:all", "network:*"],
    },
    risk_layer: {
      weight: 3,
      requires_risk_assessment: true,
      max_unmitigated_critical: 0,
      max_unmitigated_high: 1,
      requires_mitigation_for: ["critical", "high"],
    },
    attestation: {
      weight: 1,
      requires_signature: true,
      requires_timestamp: true,
    },
  },
};

const EU_AI_ACT_PROFILE: ComplianceProfile = {
  profile_version: "1.0",
  profile_id: "eu-ai-act-annex-iv",
  framework: { name: "EU AI Act", version: "Annex IV" },
  rules: {
    identity: {
      weight: 3,
      required_fields: ["agent_id", "agent_name", "generated_at"],
      requires_version: true,
      allowed_contexts: ["production"],
    },
    tool_layer: {
      weight: 2,
      requires_tool_inventory: true,
      blocked_sources: ["untrusted"],
    },
    risk_layer: {
      weight: 4,
      requires_risk_assessment: true,
      max_unmitigated_critical: 0,
      max_unmitigated_high: 0,
      requires_mitigation_for: ["critical", "high", "medium"],
    },
    attestation: {
      weight: 2,
      requires_signature: true,
      requires_timestamp: true,
    },
  },
};

const ISO27001_COMPLIANT_BOM = {
  agentbom_version: "0.1",
  identity: {
    agent_id: "iso-agent-001",
    agent_name: "ISO27001 Compliant Agent",
    agent_version: "1.0.0",
    deployment_context: "production",
    generated_at: "2026-01-01T00:00:00Z",
  },
  tool_layer: [
    {
      tool_id: "data-query",
      tool_name: "Database Query",
      source: "builtin",
      permissions: ["db:read"],
      risk_signals: [],
    },
  ],
  risk_layer: [
    {
      risk_id: "R-ISO-1",
      severity: "medium",
      category: "data_access",
      description: "Read access to sensitive data",
      status: "mitigated",
    },
  ],
  attestation: {
    generator: "iso-tool",
    signature: "sha256:abc123",
    timestamp: "2026-01-01T00:00:00Z",
  },
};

const EU_ACT_COMPLIANT_BOM = {
  agentbom_version: "0.1",
  identity: {
    agent_id: "eu-agent-001",
    agent_name: "EU AI Act Compliant Agent",
    agent_version: "2.0.0",
    deployment_context: "production",
    generated_at: "2026-01-01T00:00:00Z",
  },
  tool_layer: [
    {
      tool_id: "analysis-tool",
      tool_name: "Data Analysis",
      source: "builtin",
      permissions: ["analytics:read"],
      risk_signals: [],
    },
  ],
  risk_layer: [
    {
      risk_id: "R-EU-1",
      severity: "medium",
      category: "bias",
      description: "Potential bias in analysis",
      status: "mitigated",
    },
    {
      risk_id: "R-EU-2",
      severity: "low",
      category: "transparency",
      description: "Output interpretation complexity",
      status: "accepted",
    },
  ],
  attestation: {
    generator: "eu-compliance-tool",
    signature: "sha256:def456",
    timestamp: "2026-01-01T00:00:00Z",
  },
};

describe("checkCompliance — ISO 27001:2022 profile", () => {
  it("passes a fully compliant ISO 27001 BOM", () => {
    const result = checkCompliance(ISO27001_COMPLIANT_BOM, ISO27001_PROFILE);
    expect(result.compliant).toBe(true);
    expect(result.score).toBe(1);
    expect(result.errors).toHaveLength(0);
    expect(result.framework_name).toBe("ISO 27001");
    expect(result.framework_version).toBe("2022");
    expect(result.profile_id).toBe("iso27001-2022");
  });

  it("fails when agent_version is missing (ISO 27001 requires versioning)", () => {
    const { agent_version: _, ...identityWithoutVersion } =
      ISO27001_COMPLIANT_BOM.identity;
    const bom = { ...ISO27001_COMPLIANT_BOM, identity: identityWithoutVersion };
    const result = checkCompliance(
      bom as Record<string, unknown>,
      ISO27001_PROFILE,
    );
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("agent_version"))).toBe(true);
  });

  it("fails when tool_layer is missing (ISO 27001 requires inventory)", () => {
    const { tool_layer: _, ...bomWithoutTools } = ISO27001_COMPLIANT_BOM;
    const result = checkCompliance(bomWithoutTools, ISO27001_PROFILE);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("tool inventory"))).toBe(true);
  });

  it("fails when tool has blocked permission admin:all", () => {
    const bom = {
      ...ISO27001_COMPLIANT_BOM,
      tool_layer: [
        {
          tool_id: "admin-tool",
          tool_name: "Admin",
          source: "builtin",
          permissions: ["admin:all"],
          risk_signals: [],
        },
      ],
    };
    const result = checkCompliance(bom, ISO27001_PROFILE);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("blocked permission"))).toBe(
      true,
    );
  });

  it("fails when unmitigated critical risk exceeds limit (0 allowed)", () => {
    const bom = {
      ...ISO27001_COMPLIANT_BOM,
      risk_layer: [
        {
          risk_id: "R-ISO-CRIT",
          severity: "critical",
          category: "breach",
          description: "Data breach",
          status: "open",
        },
      ],
    };
    const result = checkCompliance(bom, ISO27001_PROFILE);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("unmitigated critical"))).toBe(
      true,
    );
  });

  it("fails when signature is missing (ISO 27001 requires attestation)", () => {
    const bom = {
      ...ISO27001_COMPLIANT_BOM,
      attestation: {
        generator: "iso-tool",
        timestamp: "2026-01-01T00:00:00Z",
      },
    };
    const result = checkCompliance(bom, ISO27001_PROFILE);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("signature"))).toBe(true);
  });

  it("returns per-control details with ISO 27001 profile", () => {
    const result = checkCompliance(ISO27001_COMPLIANT_BOM, ISO27001_PROFILE);
    expect(result.controls).toHaveLength(4);
    const identityCtrl = result.controls.find(
      (c) => c.control_id === "identity",
    );
    expect(identityCtrl).toBeDefined();
    expect(identityCtrl?.passed).toBe(true);
    const toolCtrl = result.controls.find((c) => c.control_id === "tool_layer");
    expect(toolCtrl).toBeDefined();
    expect(toolCtrl?.passed).toBe(true);
  });
});

describe("checkCompliance — EU AI Act Annex IV profile", () => {
  it("passes a fully compliant EU AI Act BOM", () => {
    const result = checkCompliance(EU_ACT_COMPLIANT_BOM, EU_AI_ACT_PROFILE);
    expect(result.compliant).toBe(true);
    expect(result.score).toBe(1);
    expect(result.errors).toHaveLength(0);
    expect(result.framework_name).toBe("EU AI Act");
    expect(result.framework_version).toBe("Annex IV");
    expect(result.profile_id).toBe("eu-ai-act-annex-iv");
  });

  it("fails when deployment_context is not production (EU AI Act: production only)", () => {
    const bom = {
      ...EU_ACT_COMPLIANT_BOM,
      identity: {
        ...EU_ACT_COMPLIANT_BOM.identity,
        deployment_context: "staging",
      },
    };
    const result = checkCompliance(bom, EU_AI_ACT_PROFILE);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("deployment_context"))).toBe(
      true,
    );
  });

  it("fails when risk assessment is missing (EU AI Act requires it)", () => {
    const { risk_layer: _, ...bomWithoutRisk } = EU_ACT_COMPLIANT_BOM;
    const result = checkCompliance(bomWithoutRisk, EU_AI_ACT_PROFILE);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("risk assessment"))).toBe(true);
  });

  it("fails when any high-risk finding is unmitigated (EU AI Act: 0 allowed)", () => {
    const bom = {
      ...EU_ACT_COMPLIANT_BOM,
      risk_layer: [
        {
          risk_id: "R-EU-HIGH",
          severity: "high",
          category: "bias",
          description: "Unaddressed high bias risk",
          status: "open",
        },
      ],
    };
    const result = checkCompliance(bom, EU_AI_ACT_PROFILE);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("unmitigated high"))).toBe(
      true,
    );
  });

  it("fails when tool uses blocked source untrusted", () => {
    const bom = {
      ...EU_ACT_COMPLIANT_BOM,
      tool_layer: [
        {
          tool_id: "suspicious-tool",
          tool_name: "External Plugin",
          source: "plugin",
          permissions: [],
          risk_signals: [],
        },
        {
          tool_id: "bad-source-tool",
          tool_name: "Untrusted Tool",
          source: "plugin" as const,
          permissions: [],
          risk_signals: [],
        },
      ],
    };
    // Override the source to "untrusted" at runtime (bypassing TS enum)
    (bom.tool_layer[1] as Record<string, unknown>).source = "untrusted";
    const result = checkCompliance(
      bom as Record<string, unknown>,
      EU_AI_ACT_PROFILE,
    );
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("blocked source"))).toBe(true);
  });

  it("fails when attestation signature is missing (EU AI Act requires it)", () => {
    const bom = {
      ...EU_ACT_COMPLIANT_BOM,
      attestation: {
        generator: "eu-compliance-tool",
        timestamp: "2026-01-01T00:00:00Z",
      },
    };
    const result = checkCompliance(bom, EU_AI_ACT_PROFILE);
    expect(result.compliant).toBe(false);
    expect(result.errors.some((e) => e.includes("signature"))).toBe(true);
  });

  it("returns per-control details and each has correct control_id", () => {
    const result = checkCompliance(EU_ACT_COMPLIANT_BOM, EU_AI_ACT_PROFILE);
    const controlIds = result.controls.map((c) => c.control_id);
    expect(controlIds).toContain("identity");
    expect(controlIds).toContain("tool_layer");
    expect(controlIds).toContain("risk_layer");
    expect(controlIds).toContain("attestation");
    for (const ctrl of result.controls) {
      expect(ctrl.passed).toBe(true);
      expect(ctrl.errors).toHaveLength(0);
    }
  });

  it("per-control details show failure info when a control fails", () => {
    const bom = {
      ...EU_ACT_COMPLIANT_BOM,
      attestation: { generator: "eu-tool" }, // missing signature + timestamp
    };
    const result = checkCompliance(bom, EU_AI_ACT_PROFILE);
    const attCtrl = result.controls.find((c) => c.control_id === "attestation");
    expect(attCtrl).toBeDefined();
    expect(attCtrl?.passed).toBe(false);
    expect(attCtrl?.errors.length).toBeGreaterThan(0);
  });
});

describe("checkCompliance — controls field (structured per-control results)", () => {
  it("returns 4 controls for any profile", () => {
    const result = checkCompliance(VALID_BOM, MINIMAL_PROFILE);
    expect(result.controls).toHaveLength(4);
  });

  it("each control has the required fields", () => {
    const result = checkCompliance(VALID_BOM, MINIMAL_PROFILE);
    for (const ctrl of result.controls) {
      expect(typeof ctrl.control_id).toBe("string");
      expect(typeof ctrl.description).toBe("string");
      expect(typeof ctrl.passed).toBe("boolean");
      expect(Array.isArray(ctrl.errors)).toBe(true);
      expect(Array.isArray(ctrl.warnings)).toBe(true);
      expect(Array.isArray(ctrl.passed_checks)).toBe(true);
    }
  });

  it("control.passed is false when that section has errors", () => {
    const profile: ComplianceProfile = {
      ...MINIMAL_PROFILE,
      rules: {
        attestation: { requires_signature: true },
      },
    };
    const result = checkCompliance(VALID_BOM, profile);
    const attCtrl = result.controls.find((c) => c.control_id === "attestation");
    expect(attCtrl?.passed).toBe(false);
    expect(attCtrl?.errors.length).toBeGreaterThan(0);
  });

  it("control.passed is true when that section has no errors", () => {
    const result = checkCompliance(VALID_BOM, SOC2_LIKE_PROFILE);
    const identityCtrl = result.controls.find(
      (c) => c.control_id === "identity",
    );
    expect(identityCtrl?.passed).toBe(true);
    expect(identityCtrl?.errors).toHaveLength(0);
  });
});
