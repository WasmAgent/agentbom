import { describe, expect, it } from "bun:test";
import { validateAgentBOM } from "@wasmagent/agentbom-core";
import { generateAgentBOM } from "./index.js";

describe("langchain-agentbom generateAgentBOM", () => {
  it("produces a valid AgentBOM with minimal config", () => {
    const bom = generateAgentBOM({
      agent_id: "lc-agent-001",
      agent_name: "Research Agent",
    });

    expect(bom.agentbom_version).toBe("0.1");
    expect(bom.identity.agent_id).toBe("lc-agent-001");
    expect(bom.identity.agent_name).toBe("Research Agent");
    expect(bom.identity.generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(bom.attestation.generator).toBe("@wasmagent/langchain-agentbom");

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("maps tools to tool_layer with correct structure", () => {
    const bom = generateAgentBOM({
      agent_id: "lc-agent-002",
      agent_name: "Tool Agent",
      tools: [
        {
          name: "Web Search",
          description: "Search the web",
          permissions: ["network:outbound"],
          risk_signals: ["ssrf"],
        },
        {
          name: "Code Editor",
          description: "Edit code files",
          permissions: ["fs:read", "fs:write"],
          source: "plugin",
        },
      ],
    });

    expect(bom.tool_layer).toHaveLength(2);
    expect(bom.tool_layer?.[0].tool_id).toBe("web-search");
    expect(bom.tool_layer?.[0].tool_name).toBe("Search the web");
    expect(bom.tool_layer?.[0].source).toBe("builtin");
    expect(bom.tool_layer?.[0].permissions).toEqual(["network:outbound"]);
    expect(bom.tool_layer?.[1].source).toBe("plugin");
    expect(bom.tool_layer?.[1].tool_id).toBe("code-editor");

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("maps LLM config to model_layer", () => {
    const bom = generateAgentBOM({
      agent_id: "lc-agent-003",
      agent_name: "GPT Agent",
      llm: {
        provider: "openai",
        model_id: "gpt-4o",
        model_version: "2024-08",
        capabilities: ["tool_use", "code_generation"],
      },
    });

    expect(bom.model_layer).toBeDefined();
    expect(bom.model_layer?.provider).toBe("openai");
    expect(bom.model_layer?.model_id).toBe("gpt-4o");
    expect(bom.model_layer?.capabilities).toEqual([
      "tool_use",
      "code_generation",
    ]);

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("maps prompt and permission layers", () => {
    const bom = generateAgentBOM({
      agent_id: "lc-agent-004",
      agent_name: "Full Agent",
      deployment_context: "production",
      system_prompt_hash: "sha256:abc123",
      prompt_version: "v2.1",
      template_ids: ["research-v1", "qa-v3"],
      granted_scopes: ["fs:read", "network:outbound"],
      data_access: ["postgres://db", "s3://bucket"],
      credential_references: ["aws_key", "db_password"],
    });

    expect(bom.identity.deployment_context).toBe("production");
    expect(bom.prompt_layer?.system_prompt_hash).toBe("sha256:abc123");
    expect(bom.prompt_layer?.template_ids).toEqual(["research-v1", "qa-v3"]);
    expect(bom.permission_layer?.granted_scopes).toEqual([
      "fs:read",
      "network:outbound",
    ]);
    expect(bom.permission_layer?.credential_references).toEqual([
      "aws_key",
      "db_password",
    ]);

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("slugs complex tool names into valid tool_ids", () => {
    const bom = generateAgentBOM({
      agent_id: "lc-agent-005",
      agent_name: "Slug Test",
      tools: [{ name: "GitHub Create PR" }, { name: "SQL Query Runner!!!" }],
    });

    expect(bom.tool_layer?.[0].tool_id).toBe("github-create-pr");
    expect(bom.tool_layer?.[1].tool_id).toBe("sql-query-runner");

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("supports explicit tool id override", () => {
    const bom = generateAgentBOM({
      agent_id: "lc-agent-006",
      agent_name: "Override Test",
      tools: [{ name: "Web Search", id: "custom-tool-001" }],
    });

    expect(bom.tool_layer?.[0].tool_id).toBe("custom-tool-001");

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("handles MCP tool source with server ID", () => {
    const bom = generateAgentBOM({
      agent_id: "lc-agent-007",
      agent_name: "MCP Agent",
      tools: [
        {
          name: "GitHub API",
          source: "mcp",
          mcp_server_id: "github-mcp",
          permissions: ["network:outbound", "api:github"],
          risk_signals: ["exfiltration"],
        },
      ],
    });

    expect(bom.tool_layer?.[0].source).toBe("mcp");
    expect(bom.tool_layer?.[0].mcp_server_id).toBe("github-mcp");

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("produces a full-featured AgentBOM matching the demo fixture shape", () => {
    const bom = generateAgentBOM({
      agent_id: "langchain-rag-agent",
      agent_name: "RAG Research Agent",
      agent_version: "1.2.0",
      deployment_context: "production",
      tools: [
        { name: "Vector Search", permissions: ["db:read"], risk_signals: [] },
        {
          name: "Web Fetch",
          permissions: ["network:outbound"],
          risk_signals: ["ssrf"],
        },
        { name: "PDF Parser", source: "plugin", permissions: ["fs:read"] },
      ],
      llm: {
        provider: "anthropic",
        model_id: "claude-sonnet-4-5",
        model_version: "2025-06",
        capabilities: ["tool_use", "code_generation", "analysis"],
      },
      system_prompt_hash: "sha256:deadbeef",
      prompt_version: "v3.0",
      granted_scopes: ["db:read", "fs:read", "network:outbound"],
      data_access: ["pinecone://index", "s3://docs"],
      credential_references: ["anthropic_api_key"],
    });

    // Verify all layers are populated
    expect(bom.tool_layer).toHaveLength(3);
    expect(bom.model_layer).toBeDefined();
    expect(bom.prompt_layer).toBeDefined();
    expect(bom.permission_layer).toBeDefined();

    // Must validate against the schema
    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });
});
