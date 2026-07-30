import { describe, expect, it } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  classifyDriftEvents,
  createDriftAlert,
  diffAgentBOM,
  formatAgentBOMDiff,
  formatDriftAlert,
  validateAgentBOM,
} from "./index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "../../..");

const VALID_AGENTBOM = {
  agentbom_version: "0.1",
  identity: {
    agent_id: "test-agent-001",
    agent_name: "Test Agent",
    deployment_context: "development",
    generated_at: "2026-06-28T00:00:00Z",
  },
  attestation: { generator: "test" },
};

describe("repository boundary: incubation repo must not publish releases", () => {
  it("keeps the publish workflow free of npm and binary release automation", () => {
    const workflow = resolve(REPO_ROOT, ".github/workflows/publish.yml");
    if (!existsSync(workflow)) return;

    const src = readFileSync(workflow, "utf-8");
    expect(src).not.toContain("JS-DevTools/npm-publish");
    expect(src).not.toContain("NPM_TOKEN");
    expect(src).not.toContain("gh release create");
    expect(src).not.toContain("build:binary");
    expect(src).not.toContain("id-token: write");
  });
});

describe("validateAgentBOM", () => {
  it("accepts valid AgentBOM", () => {
    const result = validateAgentBOM(VALID_AGENTBOM);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.errorDetails).toHaveLength(0);
  });

  it("rejects missing identity with a structured field-path error", () => {
    const result = validateAgentBOM({
      agentbom_version: "0.1",
      attestation: { generator: "test" },
    });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    const identityErr = result.errorDetails.find((e) => e.field === "identity");
    expect(identityErr).toBeDefined();
    expect(identityErr?.keyword).toBe("required");
  });

  it("rejects unknown version with the field path pointing at agentbom_version", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agentbom_version: "99.0",
    });
    expect(result.valid).toBe(false);
    const versionErr = result.errorDetails.find(
      (e) => e.field === "agentbom_version",
    );
    expect(versionErr).toBeDefined();
    expect(versionErr?.keyword).toBe("enum");
  });

  it("reports nested field paths for missing identity sub-fields", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      identity: { agent_name: "Test Agent" },
    });
    expect(result.valid).toBe(false);
    const fields = result.errorDetails.map((e) => e.field);
    expect(fields).toContain("identity.agent_id");
    expect(fields).toContain("identity.generated_at");
    expect(result.errorDetails.every((e) => e.keyword === "required")).toBe(
      true,
    );
  });

  it("rejects non-object root with a root field path", () => {
    const result = validateAgentBOM("not-a-bom");
    expect(result.valid).toBe(false);
    expect(result.errorDetails.length).toBeGreaterThan(0);
    expect(result.errorDetails[0].field).toBe("(root)");
  });

  // Test for #291 — ajv-formats must be registered so that uri format validation
  // works without emitting "unknown format "uri" ignored" warnings.
  it("validates distribution.registry_uri as a URI format (ajv-formats registered)", () => {
    // Valid URI — should pass
    const validResult = validateAgentBOM({
      ...VALID_AGENTBOM,
      distribution: { registry_uri: "https://registry.example.com/agents" },
    });
    expect(validResult.valid).toBe(true);
    expect(validResult.errors).toHaveLength(0);

    // Invalid URI — should fail with a format error (not silently ignored)
    const invalidResult = validateAgentBOM({
      ...VALID_AGENTBOM,
      distribution: { registry_uri: "not-a-valid-uri!!!" },
    });
    // With ajv-formats registered, AJV enforces the uri format constraint.
    // Without it, the invalid uri would silently pass — that was the bug (#291).
    expect(invalidResult.valid).toBe(false);
    const formatErr = invalidResult.errorDetails.find(
      (e) => e.keyword === "format" && e.field.includes("registry_uri"),
    );
    expect(formatErr).toBeDefined();
  });
});

const BASE_BOM = {
  agentbom_version: "0.1",
  identity: {
    agent_id: "test-agent-001",
    agent_name: "Test Agent",
    deployment_context: "development",
    generated_at: "2026-06-28T00:00:00Z",
  },
  tool_layer: [
    {
      tool_id: "fs-read",
      tool_name: "read_file",
      source: "builtin",
      permissions: ["fs:read"],
      risk_signals: [],
    },
    {
      tool_id: "bash-exec",
      tool_name: "bash",
      source: "builtin",
      permissions: ["process:exec"],
      risk_signals: ["command_execution"],
    },
  ],
  permission_layer: {
    granted_scopes: ["fs:read", "process:exec"],
    data_access: ["local_workspace"],
    credential_references: [],
  },
  risk_layer: [
    {
      risk_id: "risk-001",
      severity: "medium",
      category: "command_execution",
      description: "bash allows arbitrary execution",
      status: "accepted",
    },
  ],
  attestation: { generator: "test" },
};

describe("diffAgentBOM", () => {
  it("returns empty diff for identical AgentBOMs", () => {
    const diff = diffAgentBOM(BASE_BOM, { ...BASE_BOM });
    expect(diff.isEmpty()).toBe(true);
  });

  it("detects added tools", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        ...BASE_BOM.tool_layer,
        {
          tool_id: "fs-write",
          tool_name: "write_file",
          source: "builtin",
          permissions: ["fs:write"],
          risk_signals: [],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    expect(diff.isEmpty()).toBe(false);
    expect(diff.tools.added).toHaveLength(1);
    expect(diff.tools.added[0].tool_id).toBe("fs-write");
  });

  it("detects removed tools", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [BASE_BOM.tool_layer[0]],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    expect(diff.isEmpty()).toBe(false);
    expect(diff.tools.removed).toHaveLength(1);
    expect(diff.tools.removed[0].tool_id).toBe("bash-exec");
  });

  it("detects tool permission additions", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        {
          tool_id: "fs-read",
          tool_name: "read_file",
          source: "builtin",
          permissions: ["fs:read", "fs:write"],
          risk_signals: [],
        },
        {
          tool_id: "bash-exec",
          tool_name: "bash",
          source: "builtin",
          permissions: ["process:exec"],
          risk_signals: ["command_execution"],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    expect(diff.isEmpty()).toBe(false);
    expect(diff.tools.modified).toHaveLength(1);
    expect(diff.tools.modified[0].tool_id).toBe("fs-read");
    expect(diff.tools.modified[0].field).toBe("permissions");
    expect(diff.tools.modified[0].new).toBe("fs:write");
  });

  it("detects tool permission removals", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        {
          tool_id: "fs-read",
          tool_name: "read_file",
          source: "builtin",
          permissions: [],
          risk_signals: [],
        },
        {
          tool_id: "bash-exec",
          tool_name: "bash",
          source: "builtin",
          permissions: ["process:exec"],
          risk_signals: ["command_execution"],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    expect(diff.isEmpty()).toBe(false);
    expect(diff.tools.modified).toHaveLength(1);
    expect(diff.tools.modified[0].tool_id).toBe("fs-read");
    expect(diff.tools.modified[0].old).toBe("fs:read");
  });

  it("detects permission scope additions", () => {
    const newBom = {
      ...BASE_BOM,
      permission_layer: {
        granted_scopes: ["fs:read", "process:exec", "network:outbound"],
        data_access: ["local_workspace"],
        credential_references: [],
      },
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    expect(diff.isEmpty()).toBe(false);
    expect(diff.permissions.added).toHaveLength(1);
    expect(diff.permissions.added[0]).toBe("network:outbound");
  });

  it("detects permission scope removals", () => {
    const newBom = {
      ...BASE_BOM,
      permission_layer: {
        granted_scopes: ["fs:read"],
        data_access: ["local_workspace"],
        credential_references: [],
      },
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    expect(diff.isEmpty()).toBe(false);
    expect(diff.permissions.removed).toHaveLength(1);
    expect(diff.permissions.removed[0]).toBe("process:exec");
  });

  it("detects new risk entries", () => {
    const newBom = {
      ...BASE_BOM,
      risk_layer: [
        ...BASE_BOM.risk_layer,
        {
          risk_id: "risk-002",
          severity: "high",
          category: "exfiltration",
          description: "data exfiltration risk",
          status: "open",
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    expect(diff.isEmpty()).toBe(false);
    expect(diff.risks.added).toHaveLength(1);
    expect(diff.risks.added[0].risk_id).toBe("risk-002");
  });

  it("detects removed risk entries", () => {
    const newBom = {
      ...BASE_BOM,
      risk_layer: [],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    expect(diff.isEmpty()).toBe(false);
    expect(diff.risks.removed).toHaveLength(1);
    expect(diff.risks.removed[0].risk_id).toBe("risk-001");
  });

  it("detects risk severity changes", () => {
    const newBom = {
      ...BASE_BOM,
      risk_layer: [
        {
          risk_id: "risk-001",
          severity: "critical",
          category: "command_execution",
          description: "bash allows arbitrary execution",
          status: "accepted",
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    expect(diff.isEmpty()).toBe(false);
    expect(diff.risks.modified).toHaveLength(1);
    expect(diff.risks.modified[0].field).toBe("severity");
    expect(diff.risks.modified[0].old).toBe("medium");
    expect(diff.risks.modified[0].new).toBe("critical");
  });

  it("handles missing layers gracefully", () => {
    const minimal = {
      agentbom_version: "0.1",
      identity: BASE_BOM.identity,
      attestation: { generator: "test" },
    };
    const diff = diffAgentBOM(minimal, minimal);
    expect(diff.isEmpty()).toBe(true);
  });
});

describe("formatAgentBOMDiff", () => {
  it("shows clean message for empty diff", () => {
    const diff = diffAgentBOM(BASE_BOM, { ...BASE_BOM });
    const output = formatAgentBOMDiff(diff);
    expect(output).toContain("No differences found");
  });

  it("includes added tools in output", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        ...BASE_BOM.tool_layer,
        {
          tool_id: "net-fetch",
          tool_name: "fetch_url",
          source: "builtin",
          permissions: ["network:outbound"],
          risk_signals: [],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const output = formatAgentBOMDiff(diff);
    expect(output).toContain("Tools added (1)");
    expect(output).toContain("+ fetch_url (net-fetch) [builtin]");
  });

  it("includes removed tools in output", () => {
    const newBom = { ...BASE_BOM, tool_layer: [BASE_BOM.tool_layer[0]] };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const output = formatAgentBOMDiff(diff);
    expect(output).toContain("Tools removed (1)");
    expect(output).toContain("- bash (bash-exec) [builtin]");
  });

  it("includes permission changes in output", () => {
    const newBom = {
      ...BASE_BOM,
      permission_layer: {
        granted_scopes: ["fs:read", "process:exec", "network:outbound"],
        data_access: ["local_workspace"],
        credential_references: [],
      },
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const output = formatAgentBOMDiff(diff);
    expect(output).toContain("Permission scopes added (1)");
    expect(output).toContain("+ network:outbound");
  });

  it("includes new risk entries in output", () => {
    const newBom = {
      ...BASE_BOM,
      risk_layer: [
        ...BASE_BOM.risk_layer,
        {
          risk_id: "risk-002",
          severity: "high",
          category: "exfiltration",
          description: "data exfiltration",
          status: "open",
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const output = formatAgentBOMDiff(diff);
    expect(output).toContain("Risk entries added (1)");
    expect(output).toContain("[high]");
    expect(output).toContain("risk-002");
    expect(output).toContain("data exfiltration");
  });

  it("includes tool permission changes in output", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        {
          tool_id: "fs-read",
          tool_name: "read_file",
          source: "builtin",
          permissions: ["fs:read", "fs:write"],
          risk_signals: [],
        },
        {
          tool_id: "bash-exec",
          tool_name: "bash",
          source: "builtin",
          permissions: ["process:exec"],
          risk_signals: ["command_execution"],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const output = formatAgentBOMDiff(diff);
    expect(output).toContain("Tools changed (1)");
    expect(output).toContain("permission added: fs:write");
  });
});

// --- Continuous Trust Monitoring tests ---

describe("createDriftAlert", () => {
  it("creates an alert with computed hasHighSeverity and isEmpty", () => {
    const alert = createDriftAlert({
      agent_id: "agent-1",
      baseline_at: "2026-01-01T00:00:00Z",
      current_at: "2026-01-02T00:00:00Z",
      events: [
        {
          category: "tool_added",
          severity: "info",
          description: "Tool added",
          subject: "t1",
          detected_at: "2026-01-02T00:00:00Z",
        },
      ],
    });
    expect(alert.agent_id).toBe("agent-1");
    expect(alert.isEmpty()).toBe(false);
    expect(alert.hasHighSeverity()).toBe(false);
  });

  it("isEmpty returns true for empty events", () => {
    const alert = createDriftAlert({
      agent_id: "agent-1",
      baseline_at: "2026-01-01T00:00:00Z",
      current_at: "2026-01-02T00:00:00Z",
      events: [],
    });
    expect(alert.isEmpty()).toBe(true);
  });

  it("hasHighSeverity returns true when a critical event exists", () => {
    const alert = createDriftAlert({
      agent_id: "agent-1",
      baseline_at: "2026-01-01T00:00:00Z",
      current_at: "2026-01-02T00:00:00Z",
      events: [
        {
          category: "risk_introduced",
          severity: "critical",
          description: "Critical risk",
          subject: "r1",
          detected_at: "2026-01-02T00:00:00Z",
        },
      ],
    });
    expect(alert.hasHighSeverity()).toBe(true);
  });

  it("hasHighSeverity returns true when a high event exists", () => {
    const alert = createDriftAlert({
      agent_id: "agent-1",
      baseline_at: "2026-01-01T00:00:00Z",
      current_at: "2026-01-02T00:00:00Z",
      events: [
        {
          category: "permission_escalation",
          severity: "high",
          description: "Permission escalated",
          subject: "t1",
          detected_at: "2026-01-02T00:00:00Z",
        },
      ],
    });
    expect(alert.hasHighSeverity()).toBe(true);
  });
});

describe("classifyDriftEvents", () => {
  it("produces empty alert for identical BOMs", () => {
    const diff = diffAgentBOM(BASE_BOM, { ...BASE_BOM });
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    expect(alert.isEmpty()).toBe(true);
    expect(alert.hasHighSeverity()).toBe(false);
  });

  it("classifies tool_added events with appropriate severity", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        ...BASE_BOM.tool_layer,
        {
          tool_id: "http-get",
          tool_name: "fetch_url",
          source: "builtin",
          permissions: ["http:get"],
          risk_signals: [],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    expect(alert.isEmpty()).toBe(false);
    const addedEvents = alert.events.filter((e) => e.category === "tool_added");
    expect(addedEvents).toHaveLength(1);
    expect(addedEvents[0].subject).toBe("http-get");
    expect(addedEvents[0].severity).toBe("medium");
  });

  it("classifies tool_added events with high severity when permission matches a wildcard", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        ...BASE_BOM.tool_layer,
        {
          tool_id: "net-fetch",
          tool_name: "fetch_url",
          source: "builtin",
          permissions: ["network:outbound"],
          risk_signals: [],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const addedEvents = alert.events.filter((e) => e.category === "tool_added");
    expect(addedEvents).toHaveLength(1);
    expect(addedEvents[0].subject).toBe("net-fetch");
    expect(addedEvents[0].severity).toBe("high");
  });

  it("classifies tool_added with critical severity for tools with command_execution risk signal", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        ...BASE_BOM.tool_layer,
        {
          tool_id: "dangerous-tool",
          tool_name: "dangerous",
          source: "builtin",
          permissions: ["network:*"],
          risk_signals: ["command_execution"],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const criticalEvents = alert.events.filter(
      (e) => e.category === "tool_added" && e.severity === "critical",
    );
    expect(criticalEvents).toHaveLength(1);
    expect(criticalEvents[0].subject).toBe("dangerous-tool");
  });

  it("classifies tool_removed events as info", () => {
    const newBom = { ...BASE_BOM, tool_layer: [BASE_BOM.tool_layer[0]] };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const removedEvents = alert.events.filter(
      (e) => e.category === "tool_removed",
    );
    expect(removedEvents).toHaveLength(1);
    expect(removedEvents[0].severity).toBe("info");
    expect(removedEvents[0].subject).toBe("bash-exec");
  });

  it("classifies permission_escalation events as high", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        {
          tool_id: "fs-read",
          tool_name: "read_file",
          source: "builtin",
          permissions: ["fs:read", "fs:write"],
          risk_signals: [],
        },
        {
          tool_id: "bash-exec",
          tool_name: "bash",
          source: "builtin",
          permissions: ["process:exec"],
          risk_signals: ["command_execution"],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const escalationEvents = alert.events.filter(
      (e) => e.category === "permission_escalation",
    );
    expect(escalationEvents).toHaveLength(1);
    expect(escalationEvents[0].severity).toBe("high");
    expect(escalationEvents[0].subject).toBe("fs-read");
  });

  it("classifies permission_reduction events as info", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        {
          tool_id: "fs-read",
          tool_name: "read_file",
          source: "builtin",
          permissions: [],
          risk_signals: [],
        },
        {
          tool_id: "bash-exec",
          tool_name: "bash",
          source: "builtin",
          permissions: ["process:exec"],
          risk_signals: ["command_execution"],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const reductionEvents = alert.events.filter(
      (e) => e.category === "permission_reduction",
    );
    expect(reductionEvents).toHaveLength(1);
    expect(reductionEvents[0].severity).toBe("info");
  });

  it("classifies risk_introduced events with matching severity", () => {
    const newBom = {
      ...BASE_BOM,
      risk_layer: [
        ...BASE_BOM.risk_layer,
        {
          risk_id: "risk-002",
          severity: "critical",
          category: "exfiltration",
          description: "data exfiltration risk",
          status: "open",
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const riskEvents = alert.events.filter(
      (e) => e.category === "risk_introduced",
    );
    expect(riskEvents).toHaveLength(1);
    expect(riskEvents[0].severity).toBe("critical");
    expect(riskEvents[0].subject).toBe("risk-002");
  });

  it("classifies risk_resolved events as info", () => {
    const newBom = { ...BASE_BOM, risk_layer: [] };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const resolvedEvents = alert.events.filter(
      (e) => e.category === "risk_resolved",
    );
    expect(resolvedEvents).toHaveLength(1);
    expect(resolvedEvents[0].severity).toBe("info");
  });

  it("classifies risk_escalated events when severity increases", () => {
    const newBom = {
      ...BASE_BOM,
      risk_layer: [
        {
          risk_id: "risk-001",
          severity: "critical",
          category: "command_execution",
          description: "bash allows arbitrary execution",
          status: "accepted",
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const escalatedEvents = alert.events.filter(
      (e) => e.category === "risk_escalated",
    );
    expect(escalatedEvents).toHaveLength(1);
    expect(escalatedEvents[0].severity).toBe("critical");
    expect(escalatedEvents[0].description).toContain("medium");
    expect(escalatedEvents[0].description).toContain("critical");
  });

  it("does not classify risk_escalated when severity decreases", () => {
    const criticalBom = {
      ...BASE_BOM,
      risk_layer: [
        {
          risk_id: "risk-001",
          severity: "critical",
          category: "command_execution",
          description: "bash allows arbitrary execution",
          status: "accepted",
        },
      ],
    };
    const newBom = {
      ...BASE_BOM,
      risk_layer: [
        {
          risk_id: "risk-001",
          severity: "low",
          category: "command_execution",
          description: "bash allows arbitrary execution",
          status: "accepted",
        },
      ],
    };
    const diff = diffAgentBOM(criticalBom, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const escalatedEvents = alert.events.filter(
      (e) => e.category === "risk_escalated",
    );
    expect(escalatedEvents).toHaveLength(0);
  });

  it("classifies scope_expanded events as high", () => {
    const newBom = {
      ...BASE_BOM,
      permission_layer: {
        granted_scopes: ["fs:read", "process:exec", "network:outbound"],
        data_access: ["local_workspace"],
        credential_references: [],
      },
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const expandedEvents = alert.events.filter(
      (e) => e.category === "scope_expanded",
    );
    expect(expandedEvents).toHaveLength(1);
    expect(expandedEvents[0].severity).toBe("high");
    expect(expandedEvents[0].subject).toBe("network:outbound");
  });

  it("classifies scope_restricted events as info", () => {
    const newBom = {
      ...BASE_BOM,
      permission_layer: {
        granted_scopes: ["fs:read"],
        data_access: ["local_workspace"],
        credential_references: [],
      },
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const restrictedEvents = alert.events.filter(
      (e) => e.category === "scope_restricted",
    );
    expect(restrictedEvents).toHaveLength(1);
    expect(restrictedEvents[0].severity).toBe("info");
  });

  it("populates agent_id and timestamps on the alert", () => {
    const diff = diffAgentBOM(BASE_BOM, { ...BASE_BOM });
    const alert = classifyDriftEvents(
      diff,
      "my-agent",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    expect(alert.agent_id).toBe("my-agent");
    expect(alert.baseline_at).toBe("2026-01-01T00:00:00Z");
    expect(alert.current_at).toBe("2026-01-02T00:00:00Z");
  });

  it("each event has an ISO 8601 detected_at timestamp", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        ...BASE_BOM.tool_layer,
        {
          tool_id: "new-tool",
          tool_name: "new_tool",
          source: "builtin",
          permissions: [],
          risk_signals: [],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    for (const event of alert.events) {
      expect(event.detected_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    }
  });

  it("detects multiple event types in a single diff", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        ...BASE_BOM.tool_layer,
        {
          tool_id: "net-fetch",
          tool_name: "fetch_url",
          source: "builtin",
          permissions: ["network:outbound"],
          risk_signals: [],
        },
      ],
      permission_layer: {
        granted_scopes: ["fs:read", "process:exec", "network:outbound"],
        data_access: ["local_workspace"],
        credential_references: [],
      },
      risk_layer: [
        ...BASE_BOM.risk_layer,
        {
          risk_id: "risk-002",
          severity: "high",
          category: "exfiltration",
          description: "data exfiltration risk",
          status: "open",
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const categories = new Set(alert.events.map((e) => e.category));
    expect(categories.has("tool_added")).toBe(true);
    expect(categories.has("scope_expanded")).toBe(true);
    expect(categories.has("risk_introduced")).toBe(true);
    expect(alert.hasHighSeverity()).toBe(true);
  });
});

describe("agent_collaboration schema extension", () => {
  it("accepts valid agent_collaboration with all sub-objects", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        peer_agents: [
          {
            agent_id: "peer-001",
            agent_name: "Reviewer Agent",
            role: "supervisor",
            trust_level: "full",
            agentbom_ref: "https://example.com/boms/peer-001.json",
          },
          {
            agent_id: "peer-002",
            role: "delegate",
            trust_level: "restricted",
          },
        ],
        delegation_boundaries: [
          {
            boundary_id: "b-001",
            direction: "outbound",
            constraint_type: "tool_delegation",
            description: "Can delegate file read to reviewer",
            target_agents: ["peer-001"],
            allowed_actions: ["fs:read"],
            max_delegation_depth: 0,
          },
        ],
        shared_resources: [
          {
            resource_id: "res-001",
            resource_type: "datastore",
            access_pattern: "read_write",
            description: "Shared task queue",
            accessing_agents: ["peer-001", "peer-002"],
            isolation_level: "partitioned",
          },
        ],
      },
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("accepts minimal agent_collaboration (empty arrays)", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        peer_agents: [],
        delegation_boundaries: [],
        shared_resources: [],
      },
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("accepts agent_collaboration with only some sub-objects", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        peer_agents: [
          {
            agent_id: "peer-001",
            role: "peer",
          },
        ],
      },
    });
    expect(result.valid).toBe(true);
  });

  it("rejects invalid peer agent role", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        peer_agents: [
          {
            agent_id: "peer-001",
            role: "unknown_role",
          },
        ],
      },
    });
    expect(result.valid).toBe(false);
    const roleErr = result.errorDetails.find((e) =>
      e.field.includes("agent_collaboration"),
    );
    expect(roleErr).toBeDefined();
    expect(roleErr?.keyword).toBe("enum");
  });

  it("rejects missing required fields on peer_agents items", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        peer_agents: [
          {
            agent_name: "No ID or Role",
          },
        ],
      },
    });
    expect(result.valid).toBe(false);
    const errors = result.errorDetails.filter((e) =>
      e.field.includes("agent_collaboration"),
    );
    expect(errors.length).toBeGreaterThanOrEqual(2);
  });

  it("rejects missing required fields on delegation_boundaries items", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        delegation_boundaries: [
          {
            boundary_id: "b-001",
          },
        ],
      },
    });
    expect(result.valid).toBe(false);
    const errors = result.errorDetails.filter((e) =>
      e.field.includes("agent_collaboration"),
    );
    expect(errors.length).toBeGreaterThanOrEqual(2);
  });

  it("rejects invalid direction in delegation_boundaries", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        delegation_boundaries: [
          {
            boundary_id: "b-001",
            direction: "sideways",
            constraint_type: "tool_delegation",
          },
        ],
      },
    });
    expect(result.valid).toBe(false);
    const dirErr = result.errorDetails.find((e) =>
      e.field.includes("agent_collaboration"),
    );
    expect(dirErr).toBeDefined();
    expect(dirErr?.keyword).toBe("enum");
  });

  it("rejects negative max_delegation_depth", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        delegation_boundaries: [
          {
            boundary_id: "b-001",
            direction: "outbound",
            constraint_type: "tool_delegation",
            max_delegation_depth: -1,
          },
        ],
      },
    });
    expect(result.valid).toBe(false);
    const depthErr = result.errorDetails.find((e) =>
      e.field.includes("agent_collaboration"),
    );
    expect(depthErr).toBeDefined();
    expect(depthErr?.keyword).toBe("minimum");
  });

  it("rejects missing required fields on shared_resources items", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        shared_resources: [
          {
            resource_id: "res-001",
          },
        ],
      },
    });
    expect(result.valid).toBe(false);
    const errors = result.errorDetails.filter((e) =>
      e.field.includes("agent_collaboration"),
    );
    expect(errors.length).toBeGreaterThanOrEqual(2);
  });

  it("rejects invalid access_pattern in shared_resources", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        shared_resources: [
          {
            resource_id: "res-001",
            resource_type: "datastore",
            access_pattern: "full_access",
          },
        ],
      },
    });
    expect(result.valid).toBe(false);
    const patErr = result.errorDetails.find((e) =>
      e.field.includes("agent_collaboration"),
    );
    expect(patErr).toBeDefined();
    expect(patErr?.keyword).toBe("enum");
  });

  it("rejects additional properties on agent_collaboration", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        peer_agents: [],
        extra_field: "not_allowed",
      },
    });
    expect(result.valid).toBe(false);
    const extraErr = result.errorDetails.find((e) =>
      e.field.includes("agent_collaboration"),
    );
    expect(extraErr).toBeDefined();
    expect(extraErr?.keyword).toBe("additionalProperties");
  });

  it("rejects invalid trust_level on peer agents", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        peer_agents: [
          {
            agent_id: "peer-001",
            role: "peer",
            trust_level: "super_trusted",
          },
        ],
      },
    });
    expect(result.valid).toBe(false);
    const trustErr = result.errorDetails.find((e) =>
      e.field.includes("agent_collaboration"),
    );
    expect(trustErr).toBeDefined();
    expect(trustErr?.keyword).toBe("enum");
  });

  it("rejects invalid isolation_level on shared_resources", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      agent_collaboration: {
        shared_resources: [
          {
            resource_id: "res-001",
            resource_type: "datastore",
            access_pattern: "read_only",
            isolation_level: "connected",
          },
        ],
      },
    });
    expect(result.valid).toBe(false);
    const isoErr = result.errorDetails.find((e) =>
      e.field.includes("agent_collaboration"),
    );
    expect(isoErr).toBeDefined();
    expect(isoErr?.keyword).toBe("enum");
  });
});

describe("formatDriftAlert", () => {
  it("formats empty alert with no drift message", () => {
    const alert = classifyDriftEvents(
      diffAgentBOM(BASE_BOM, { ...BASE_BOM }),
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const output = formatDriftAlert(alert);
    expect(output).toContain("agent-1");
    expect(output).toContain("No drift events");
  });

  it("includes agent_id and timestamps in output", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        ...BASE_BOM.tool_layer,
        {
          tool_id: "new-tool",
          tool_name: "new_tool",
          source: "builtin",
          permissions: [],
          risk_signals: [],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const output = formatDriftAlert(alert);
    expect(output).toContain("agent-1");
    expect(output).toContain("2026-01-01T00:00:00Z");
    expect(output).toContain("2026-01-02T00:00:00Z");
  });

  it("groups events by severity", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        ...BASE_BOM.tool_layer,
        {
          tool_id: "dangerous-tool",
          tool_name: "dangerous",
          source: "builtin",
          permissions: ["credential:*"],
          risk_signals: ["credential_access"],
        },
      ],
      permission_layer: {
        granted_scopes: ["fs:read", "process:exec", "network:outbound"],
        data_access: ["local_workspace"],
        credential_references: [],
      },
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const output = formatDriftAlert(alert);
    expect(output).toContain("[CRITICAL]");
    expect(output).toContain("[HIGH]");
    expect(output).toContain("Events:");
  });

  it("includes event category and description in output", () => {
    const newBom = {
      ...BASE_BOM,
      tool_layer: [
        ...BASE_BOM.tool_layer,
        {
          tool_id: "new-tool",
          tool_name: "new_tool",
          source: "builtin",
          permissions: [],
          risk_signals: [],
        },
      ],
    };
    const diff = diffAgentBOM(BASE_BOM, newBom);
    const alert = classifyDriftEvents(
      diff,
      "agent-1",
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    const output = formatDriftAlert(alert);
    expect(output).toContain("tool_added");
    expect(output).toContain("new_tool");
  });
});

describe("validateAgentBOM — workflow_layer (action_pathway) field validation", () => {
  it("accepts a valid workflow_layer with steps", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      workflow_layer: [
        {
          workflow_id: "wf-001",
          workflow_name: "Data Processing Pipeline",
          description: "Reads data, processes it, and outputs results",
          version: "1.0.0",
          steps: [
            {
              step_id: "step-1",
              action: "read_file",
              description: "Read input data",
              allowed_tools: ["fs-read"],
            },
            {
              step_id: "step-2",
              action: "process_data",
              description: "Process the data",
              depends_on: ["step-1"],
              allowed_tools: ["data-processor"],
            },
            {
              step_id: "step-3",
              action: "write_output",
              depends_on: ["step-2"],
            },
          ],
        },
      ],
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("accepts a minimal workflow with just required fields", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      workflow_layer: [
        {
          workflow_id: "wf-min",
          workflow_name: "Minimal Workflow",
          steps: [{ step_id: "s1", action: "tool_call" }],
        },
      ],
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("accepts empty workflow_layer array", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      workflow_layer: [],
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("accepts multiple workflows in the action_pathway", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      workflow_layer: [
        {
          workflow_id: "wf-001",
          workflow_name: "Ingest",
          steps: [{ step_id: "s1", action: "ingest_data" }],
        },
        {
          workflow_id: "wf-002",
          workflow_name: "Transform",
          steps: [
            { step_id: "s1", action: "transform_data", depends_on: [] },
            { step_id: "s2", action: "validate_output", depends_on: ["s1"] },
          ],
        },
      ],
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("rejects workflow missing required workflow_id", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      workflow_layer: [
        {
          workflow_name: "No ID Workflow",
          steps: [{ step_id: "s1", action: "do_something" }],
        },
      ],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    const idErr = result.errorDetails.find(
      (e) => e.field.includes("workflow_layer") && e.keyword === "required",
    );
    expect(idErr).toBeDefined();
  });

  it("rejects workflow missing required workflow_name", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      workflow_layer: [
        {
          workflow_id: "wf-no-name",
          steps: [{ step_id: "s1", action: "do_something" }],
        },
      ],
    });
    expect(result.valid).toBe(false);
    const nameErr = result.errorDetails.find(
      (e) => e.field.includes("workflow_layer") && e.keyword === "required",
    );
    expect(nameErr).toBeDefined();
  });

  it("rejects workflow missing required steps array", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      workflow_layer: [
        {
          workflow_id: "wf-no-steps",
          workflow_name: "No Steps",
        },
      ],
    });
    expect(result.valid).toBe(false);
    const stepsErr = result.errorDetails.find(
      (e) => e.field.includes("workflow_layer") && e.keyword === "required",
    );
    expect(stepsErr).toBeDefined();
  });

  it("rejects a step missing required step_id", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      workflow_layer: [
        {
          workflow_id: "wf-bad-step",
          workflow_name: "Bad Step Workflow",
          steps: [{ action: "do_something" }],
        },
      ],
    });
    expect(result.valid).toBe(false);
    const stepIdErr = result.errorDetails.find(
      (e) => e.field.includes("workflow_layer") && e.keyword === "required",
    );
    expect(stepIdErr).toBeDefined();
  });

  it("rejects a step missing required action", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      workflow_layer: [
        {
          workflow_id: "wf-no-action",
          workflow_name: "No Action Workflow",
          steps: [{ step_id: "s1" }],
        },
      ],
    });
    expect(result.valid).toBe(false);
    const actionErr = result.errorDetails.find(
      (e) => e.field.includes("workflow_layer") && e.keyword === "required",
    );
    expect(actionErr).toBeDefined();
  });

  it("accepts workflow steps with depends_on referencing other steps", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      workflow_layer: [
        {
          workflow_id: "wf-deps",
          workflow_name: "Dependency Workflow",
          steps: [
            { step_id: "step-a", action: "fetch_data" },
            {
              step_id: "step-b",
              action: "process_data",
              depends_on: ["step-a"],
            },
            {
              step_id: "step-c",
              action: "write_output",
              depends_on: ["step-a", "step-b"],
            },
          ],
        },
      ],
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("accepts workflow integrated with tool_layer references", () => {
    const result = validateAgentBOM({
      ...VALID_AGENTBOM,
      tool_layer: [
        {
          tool_id: "web-search",
          tool_name: "Web Search",
          source: "builtin",
          permissions: ["network:outbound"],
        },
        {
          tool_id: "summarizer",
          tool_name: "Summarizer",
          source: "builtin",
          permissions: [],
        },
      ],
      workflow_layer: [
        {
          workflow_id: "wf-search-summarize",
          workflow_name: "Search and Summarize",
          description: "Searches the web and summarizes results",
          steps: [
            {
              step_id: "search",
              action: "web-search",
              allowed_tools: ["web-search"],
              description: "Execute web search",
            },
            {
              step_id: "summarize",
              action: "summarizer",
              depends_on: ["search"],
              allowed_tools: ["summarizer"],
              description: "Summarize search results",
            },
          ],
        },
      ],
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });
});
