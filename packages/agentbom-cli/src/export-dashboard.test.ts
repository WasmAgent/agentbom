/**
 * Fleet Trust Analytics Dashboard — tests for the Milestone 8 bullet:
 * "Trust analytics dashboard — web UI for visualizing trust posture across agent
 * fleets, BOM dependency graphs, compliance heatmaps, and audit log search with
 * temporal filtering".
 */
import { describe, expect, it, spyOn } from "bun:test";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateAgentBOM } from "@wasmagent/agentbom-core";
import {
  type AgentBOM,
  assessControls,
  buildDependencyGraph,
  exportFleetDashboardCommand,
  generateFleetDashboardHTML,
  maxSeverity,
  mergeAuditEntries,
  postureScore,
  renderDependencyGraphSVG,
} from "./export-dashboard.js";
import { runCommand } from "./index.js";

const BOM_A: AgentBOM = {
  agentbom_version: "0.1",
  identity: {
    agent_id: "fleet-a",
    agent_name: "Fleet Agent A",
    agent_version: "1.0.0",
    deployment_context: "production",
    generated_at: "2026-07-20T00:00:00Z",
  },
  model_layer: {
    provider: "anthropic",
    model_id: "claude-fable-5",
    model_version: "2026-07",
    capabilities: ["tool_use"],
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
      tool_id: "gh-mcp",
      tool_name: "create_pr",
      source: "mcp",
      mcp_server_id: "github",
      permissions: ["network:outbound"],
      risk_signals: ["privilege_escalation"],
    },
  ],
  permission_layer: {
    granted_scopes: ["fs:read", "network:outbound"],
    data_access: [],
    credential_references: [],
  },
  evidence_layer: {
    aep_references: ["aep-1"],
    evidence_hashes: [
      {
        type: "system_prompt",
        hash: "sha256:abc",
        timestamp: "2026-07-20T00:00:00Z",
      },
    ],
  },
  risk_layer: [
    {
      risk_id: "r1",
      severity: "high",
      category: "privilege_escalation",
      description: "PR creation risk",
      status: "open",
    },
  ],
  audit_log: [
    {
      timestamp: "2026-07-20T10:00:00Z",
      event_type: "tool.invoke",
      actor: "agent-a",
      resource: "read_file",
      outcome: "success",
    },
    {
      timestamp: "2026-07-20T11:00:00Z",
      event_type: "tool.invoke",
      actor: "agent-a",
      resource: "create_pr",
      outcome: "failure",
      details: { reason: "forbidden" },
    },
  ],
  attestation: { generator: "trust-cli", generator_version: "0.0.0-research" },
};

const BOM_B: AgentBOM = {
  agentbom_version: "0.1",
  identity: {
    agent_id: "fleet-b",
    agent_name: "Fleet Agent B",
    agent_version: "0.9.0",
    deployment_context: "staging",
    generated_at: "2026-07-19T00:00:00Z",
  },
  tool_layer: [
    {
      tool_id: "grep",
      tool_name: "grep",
      source: "builtin",
      permissions: ["fs:read"],
      risk_signals: [],
    },
  ],
  permission_layer: {
    granted_scopes: ["fs:read"],
    data_access: [],
    credential_references: [],
  },
  risk_layer: [],
  audit_log: [
    {
      timestamp: "2026-07-18T09:00:00Z",
      event_type: "startup",
      actor: "system",
      resource: "agent-b",
      outcome: "success",
    },
  ],
  attestation: { generator: "trust-cli", generator_version: "0.0.0-research" },
};

const FLEET = [
  { bom: BOM_A, source: "agent-a.json" },
  { bom: BOM_B, source: "agent-b.json" },
];

describe("fleet dashboard fixtures are valid AgentBOMs", () => {
  it("BOM_A and BOM_B pass schema validation", () => {
    expect(validateAgentBOM(BOM_A).valid).toBe(true);
    expect(validateAgentBOM(BOM_B).valid).toBe(true);
  });
});

describe("assessControls", () => {
  it("returns a control result for each of the six trust controls", () => {
    const controls = assessControls(BOM_A);
    expect(controls).toHaveLength(6);
    expect(controls.map((c) => c.name)).toEqual([
      "identity",
      "tools",
      "risks",
      "permissions",
      "evidence",
      "attestation",
    ]);
  });

  it("flags privilege-escalation tool signals as a warning", () => {
    const tools = assessControls(BOM_A).find((c) => c.name === "tools");
    expect(tools?.status).toBe("warn");
  });

  it("flags a single open high risk as a warning (not a failure)", () => {
    const risks = assessControls(BOM_A).find((c) => c.name === "risks");
    expect(risks?.status).toBe("warn");
  });

  it("fails evidence control when no evidence or AEP references exist", () => {
    const evidence = assessControls(BOM_B).find((c) => c.name === "evidence");
    expect(evidence?.status).toBe("fail");
  });
});

describe("postureScore", () => {
  it("returns an integer between 0 and 100", () => {
    const score = postureScore(BOM_A);
    expect(Number.isInteger(score)).toBe(true);
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });

  it("scores a clean agent higher than one with open warnings", () => {
    expect(postureScore(BOM_B)).toBeGreaterThan(postureScore(BOM_A));
  });
});

describe("maxSeverity", () => {
  it("returns the highest severity among risks", () => {
    expect(maxSeverity(BOM_A)).toBe("high");
  });

  it("returns an empty string when there are no risks", () => {
    expect(maxSeverity(BOM_B)).toBe("");
  });
});

describe("buildDependencyGraph", () => {
  it("links the agent to its model, MCP servers, tool groups, and scopes", () => {
    const { nodes, edges } = buildDependencyGraph(BOM_A);
    const labels = nodes.map((n) => n.label);
    const agentId = BOM_A.identity?.agent_id as string;
    expect(labels).toEqual(
      expect.arrayContaining([
        "claude-fable-5",
        "github",
        "fs:read",
        "network:outbound",
      ]),
    );
    expect(labels.some((l) => l.startsWith("builtin tools"))).toBe(true);
    // Every dependent node has an edge back to the agent.
    for (const n of nodes) {
      if (n.id === agentId) continue;
      expect(edges.some((e) => e.from === agentId && e.to === n.id)).toBe(true);
    }
  });
});

describe("renderDependencyGraphSVG", () => {
  it("emits an inline SVG with edges and nodes", () => {
    const svg = renderDependencyGraphSVG(BOM_A);
    expect(svg).toContain("<svg");
    expect(svg).toContain("<line");
    expect(svg).toContain("<circle");
    expect(svg).toContain("<rect");
  });
});

describe("mergeAuditEntries", () => {
  it("merges audit logs across the fleet sorted oldest-first", () => {
    const entries = mergeAuditEntries(FLEET);
    expect(entries).toHaveLength(3);
    // BOM_B's startup event is the oldest and should sort first.
    expect(entries[0].event_type).toBe("startup");
    expect(entries[0].agent).toBe("Fleet Agent B");
    // Remaining entries are BOM_A's, in chronological order.
    expect(entries[1].resource).toBe("read_file");
    expect(entries[2].resource).toBe("create_pr");
  });
});

describe("generateFleetDashboardHTML", () => {
  const html = generateFleetDashboardHTML(FLEET);

  it("renders the four required analytics sections", () => {
    expect(html).toContain("Fleet Trust Analytics Dashboard");
    expect(html).toContain("Trust Posture Across the Fleet");
    expect(html).toContain("Compliance Heatmap");
    expect(html).toContain("BOM Dependency Graphs");
    expect(html).toContain("Audit Log Search");
  });

  it("renders the fleet aggregate stats", () => {
    expect(html).toContain("2 agent(s)");
    expect(html).toContain("Open Critical/High");
  });

  it("renders a dependency graph SVG per agent", () => {
    expect(html).toContain("<svg");
    expect(html).toContain("Fleet Agent A");
    expect(html).toContain("Fleet Agent B");
  });

  it("renders the compliance heatmap cells", () => {
    expect(html).toContain("hm-pass");
    expect(html).toContain("hm-warn");
    expect(html).toContain("hm-fail");
  });

  it("wires up temporal (date-range) audit filtering in-browser", () => {
    // Temporal filter inputs + the in-browser filter routine.
    expect(html).toContain('id="f-from"');
    expect(html).toContain('id="f-to"');
    expect(html).toContain("filterAudit");
    // Audit rows carry epoch-ms timestamps used by the date-range filter.
    expect(html).toContain('data-ts="');
    expect(html).toContain("audit-body");
  });

  it("escapes agent-controlled content in audit details", () => {
    expect(html).toContain("create_pr");
    expect(html).not.toContain("<script>forbidden");
  });
});

describe("exportFleetDashboardCommand", () => {
  let tmpDir: string;

  function setup(): string {
    tmpDir = join(
      tmpdir(),
      `fleet-dash-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    mkdirSync(tmpDir, { recursive: true });
    return tmpDir;
  }

  function writeFleet(dir: string): void {
    writeFileSync(join(dir, "agent-a.json"), JSON.stringify(BOM_A), "utf-8");
    writeFileSync(join(dir, "agent-b.json"), JSON.stringify(BOM_B), "utf-8");
    // Non-JSON files must be ignored by the fleet loader.
    writeFileSync(join(dir, "README.md"), "# not a bom", "utf-8");
  }

  it("shows help and returns 0", () => {
    const spy = spyOn(console, "log");
    expect(exportFleetDashboardCommand(["--help"])).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("fleet <dir>");
    expect(output).toContain("Compliance heatmap");
  });

  it("writes fleet-dashboard.html from every AgentBOM in the directory", () => {
    const dir = setup();
    writeFleet(dir);
    const outDir = join(dir, "out");
    const spy = spyOn(console, "log");

    const code = exportFleetDashboardCommand([dir, "--output", outDir]);

    expect(code).toBe(0);
    const outFile = join(outDir, "fleet-dashboard.html");
    expect(existsSync(outFile)).toBe(true);
    const html = readFileSync(outFile, "utf-8");
    expect(html).toContain("Fleet Agent A");
    expect(html).toContain("Fleet Agent B");
    expect(html).toContain("Compliance Heatmap");

    const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("Fleet dashboard generated");
    expect(output).toContain("2 agents");

    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("is reachable via runCommand export-dashboard fleet", () => {
    const dir = setup();
    writeFleet(dir);
    const outDir = join(dir, "out2");

    const code = runCommand([
      "export-dashboard",
      "fleet",
      dir,
      "--output",
      outDir,
    ]);

    expect(code).toBe(0);
    expect(existsSync(join(outDir, "fleet-dashboard.html"))).toBe(true);

    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns 1 when the fleet directory cannot be read", () => {
    const spy = spyOn(console, "error");
    const code = exportFleetDashboardCommand([
      "/nonexistent/fleet-dir",
      "--output",
      "/tmp/out",
    ]);
    expect(code).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("cannot read fleet directory");
  });

  it("returns 1 when --output is missing", () => {
    const dir = setup();
    writeFleet(dir);
    const spy = spyOn(console, "error");
    const code = exportFleetDashboardCommand([dir]);
    expect(code).toBe(1);
    expect(spy.mock.calls.map((c) => c.join(" ")).join("\n")).toContain(
      "--output",
    );
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns 1 when the directory has no JSON files", () => {
    const dir = setup();
    const spy = spyOn(console, "error");
    const code = exportFleetDashboardCommand([
      dir,
      "--output",
      join(dir, "out"),
    ]);
    expect(code).toBe(1);
    expect(spy.mock.calls.map((c) => c.join(" ")).join("\n")).toContain(
      "no AgentBOM",
    );
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns 1 when a JSON file is not a valid AgentBOM", () => {
    const dir = setup();
    writeFileSync(
      join(dir, "bad.json"),
      JSON.stringify({ agentbom_version: "0.1" }),
      "utf-8",
    );
    const spy = spyOn(console, "error");
    const code = exportFleetDashboardCommand([
      dir,
      "--output",
      join(dir, "out"),
    ]);
    expect(code).toBe(1);
    expect(spy.mock.calls.map((c) => c.join(" ")).join("\n")).toContain(
      "invalid AgentBOM",
    );
    rmSync(tmpDir, { recursive: true, force: true });
  });
});
