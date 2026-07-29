import { describe, expect, it } from "bun:test";
import { validateAgentBOM } from "@wasmagent/agentbom-core";
import { generateAgentBOM } from "./index.js";

describe("llamaindex-agentbom generateAgentBOM", () => {
  it("produces a valid AgentBOM with minimal config", () => {
    const bom = generateAgentBOM({
      agent_id: "li-agent-001",
      agent_name: "Query Agent",
    });

    expect(bom.agentbom_version).toBe("0.1");
    expect(bom.identity.agent_id).toBe("li-agent-001");
    expect(bom.identity.agent_name).toBe("Query Agent");
    expect(bom.identity.generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(bom.attestation.generator).toBe("@wasmagent/llamaindex-agentbom");

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("maps tools to tool_layer with correct structure", () => {
    const bom = generateAgentBOM({
      agent_id: "li-agent-002",
      agent_name: "Indexing Agent",
      tools: [
        {
          name: "Query Engine",
          description: "Run queries against index",
          permissions: ["db:read"],
          risk_signals: [],
        },
        {
          name: "PDF Reader",
          description: "Read PDF documents",
          permissions: ["fs:read"],
          source: "plugin",
        },
      ],
    });

    expect(bom.tool_layer).toHaveLength(2);
    expect(bom.tool_layer?.[0].tool_id).toBe("query-engine");
    expect(bom.tool_layer?.[0].tool_name).toBe("Run queries against index");
    expect(bom.tool_layer?.[0].source).toBe("builtin");
    expect(bom.tool_layer?.[1].source).toBe("plugin");
    expect(bom.tool_layer?.[1].tool_id).toBe("pdf-reader");

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("maps LLM config to model_layer", () => {
    const bom = generateAgentBOM({
      agent_id: "li-agent-003",
      agent_name: "Claude Agent",
      llm: {
        provider: "anthropic",
        model_id: "claude-opus-4-8",
        model_version: "2025-06",
        capabilities: ["tool_use", "reasoning"],
      },
    });

    expect(bom.model_layer).toBeDefined();
    expect(bom.model_layer?.provider).toBe("anthropic");
    expect(bom.model_layer?.model_id).toBe("claude-opus-4-8");
    expect(bom.model_layer?.capabilities).toEqual(["tool_use", "reasoning"]);

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("maps prompt and permission layers", () => {
    const bom = generateAgentBOM({
      agent_id: "li-agent-004",
      agent_name: "Enterprise Agent",
      deployment_context: "staging",
      system_prompt_hash: "sha256:fedcba",
      prompt_version: "v1.0",
      template_ids: ["rag-v2"],
      granted_scopes: ["db:read", "fs:read"],
      data_access: ["chromadb://collection"],
      credential_references: [],
    });

    expect(bom.identity.deployment_context).toBe("staging");
    expect(bom.prompt_layer?.system_prompt_hash).toBe("sha256:fedcba");
    expect(bom.permission_layer?.granted_scopes).toEqual([
      "db:read",
      "fs:read",
    ]);

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("slugs complex tool names into valid tool_ids", () => {
    const bom = generateAgentBOM({
      agent_id: "li-agent-005",
      agent_name: "Slug Test",
      tools: [{ name: "Vector Store Query Tool" }],
    });

    expect(bom.tool_layer?.[0].tool_id).toBe("vector-store-query-tool");

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("produces a full-featured AgentBOM matching typical LlamaIndex usage", () => {
    const bom = generateAgentBOM({
      agent_id: "llamaindex-rag-agent",
      agent_name: "LlamaIndex RAG Agent",
      agent_version: "0.8.0",
      deployment_context: "production",
      tools: [
        {
          name: "VectorIndexQuery",
          permissions: ["db:read"],
          skills: ["semantic_search"],
        },
        {
          name: "WikipediaTool",
          source: "plugin",
          permissions: ["network:outbound"],
          risk_signals: ["ssrf"],
        },
      ],
      llm: {
        provider: "openai",
        model_id: "gpt-4o",
        capabilities: ["tool_use", "reasoning"],
      },
      system_prompt_hash: "sha256:cafe01",
      prompt_version: "v1.2",
      granted_scopes: ["db:read", "network:outbound"],
      data_access: ["pinecone://vectors", "wikipedia"],
    });

    expect(bom.tool_layer).toHaveLength(2);
    expect(bom.model_layer).toBeDefined();
    expect(bom.prompt_layer).toBeDefined();
    expect(bom.permission_layer).toBeDefined();

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });
});
