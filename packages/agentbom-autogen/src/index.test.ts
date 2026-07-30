import { describe, expect, it } from "bun:test";
import { validateAgentBOM } from "@wasmagent/agentbom-core";
import { generateAgentBOM } from "./index.js";

describe("autogen-agentbom generateAgentBOM", () => {
  it("produces a valid AgentBOM with minimal config", () => {
    const bom = generateAgentBOM({
      agent_id: "ag-agent-001",
      agent_name: "Assistant",
    });

    expect(bom.agentbom_version).toBe("0.1");
    expect(bom.identity.agent_id).toBe("ag-agent-001");
    expect(bom.identity.agent_name).toBe("Assistant");
    expect(bom.identity.generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(bom.attestation.generator).toBe("@wasmagent/autogen-agentbom");

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("maps tools to tool_layer with correct structure", () => {
    const bom = generateAgentBOM({
      agent_id: "ag-agent-002",
      agent_name: "Coder Agent",
      tools: [
        {
          name: "run_python",
          description: "Execute Python code",
          permissions: ["process:exec"],
          risk_signals: ["code_execution"],
        },
        {
          name: "shell_command",
          description: "Run shell commands",
          permissions: ["process:exec", "fs:read"],
          risk_signals: ["command_execution"],
        },
      ],
    });

    expect(bom.tool_layer).toHaveLength(2);
    expect(bom.tool_layer?.[0].tool_id).toBe("run-python");
    expect(bom.tool_layer?.[0].tool_name).toBe("Execute Python code");
    expect(bom.tool_layer?.[0].source).toBe("builtin");
    expect(bom.tool_layer?.[0].permissions).toEqual(["process:exec"]);
    expect(bom.tool_layer?.[1].tool_id).toBe("shell-command");

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("maps LLM config to model_layer", () => {
    const bom = generateAgentBOM({
      agent_id: "ag-agent-003",
      agent_name: "GPT Agent",
      llm: {
        provider: "openai",
        model_id: "gpt-4o",
        model_version: "2024-08",
        capabilities: ["function_calling", "json_mode"],
      },
    });

    expect(bom.model_layer).toBeDefined();
    expect(bom.model_layer?.provider).toBe("openai");
    expect(bom.model_layer?.model_id).toBe("gpt-4o");
    expect(bom.model_layer?.capabilities).toEqual([
      "function_calling",
      "json_mode",
    ]);

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("maps prompt and permission layers", () => {
    const bom = generateAgentBOM({
      agent_id: "ag-agent-004",
      agent_name: "Group Chat Agent",
      deployment_context: "development",
      system_prompt_hash: "sha256:123abc",
      prompt_version: "v1.0",
      granted_scopes: ["process:exec", "network:outbound"],
      data_access: ["local_fs"],
      credential_references: ["openai_api_key"],
    });

    expect(bom.identity.deployment_context).toBe("development");
    expect(bom.prompt_layer?.system_prompt_hash).toBe("sha256:123abc");
    expect(bom.permission_layer?.granted_scopes).toEqual([
      "process:exec",
      "network:outbound",
    ]);

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("slugs complex tool names into valid tool_ids", () => {
    const bom = generateAgentBOM({
      agent_id: "ag-agent-005",
      agent_name: "Slug Test",
      tools: [{ name: "HTTP Request Handler" }],
    });

    expect(bom.tool_layer?.[0].tool_id).toBe("http-request-handler");

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("produces a full-featured AgentBOM matching typical AutoGen multi-agent usage", () => {
    const bom = generateAgentBOM({
      agent_id: "autogen-coder-agent",
      agent_name: "AutoGen Coding Assistant",
      agent_version: "0.4.0",
      deployment_context: "production",
      tools: [
        {
          name: "execute_code",
          permissions: ["process:exec", "fs:read", "fs:write"],
          risk_signals: ["code_execution", "filesystem_write"],
        },
        {
          name: "web_search",
          permissions: ["network:outbound"],
          risk_signals: ["ssrf"],
        },
        {
          name: "file_transfer",
          source: "plugin",
          permissions: ["network:outbound", "fs:write"],
          risk_signals: ["exfiltration"],
        },
      ],
      llm: {
        provider: "azure_openai",
        model_id: "gpt-4o-2024-08-06",
        model_version: "2024-08",
        capabilities: ["function_calling", "json_mode", "code_generation"],
      },
      system_prompt_hash: "sha256:aabbcc",
      prompt_version: "v2.3",
      granted_scopes: [
        "process:exec",
        "fs:read",
        "fs:write",
        "network:outbound",
      ],
      data_access: ["local_workspace", "azure_storage"],
      credential_references: ["azure_openai_key"],
    });

    expect(bom.tool_layer).toHaveLength(3);
    expect(bom.model_layer).toBeDefined();
    expect(bom.prompt_layer).toBeDefined();
    expect(bom.permission_layer).toBeDefined();

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("maps workflow definitions to workflow_layer", () => {
    const bom = generateAgentBOM({
      agent_id: "ag-agent-006",
      agent_name: "Workflow Agent",
      workflows: [
        {
          workflow_id: "wf-001",
          workflow_name: "Search and Summarize",
          description: "Search the web and summarize results",
          version: "1.0.0",
          steps: [
            {
              step_id: "step-search",
              action: "web_search",
              description: "Execute web search",
              allowed_tools: ["web-search"],
            },
            {
              step_id: "step-summarize",
              action: "summarize",
              description: "Summarize results",
              depends_on: ["step-search"],
            },
          ],
        },
      ],
    });

    expect(bom.workflow_layer).toBeDefined();
    expect(bom.workflow_layer).toHaveLength(1);
    expect(bom.workflow_layer?.[0].workflow_id).toBe("wf-001");
    expect(bom.workflow_layer?.[0].workflow_name).toBe("Search and Summarize");
    expect(bom.workflow_layer?.[0].description).toBe(
      "Search the web and summarize results",
    );
    expect(bom.workflow_layer?.[0].version).toBe("1.0.0");
    expect(bom.workflow_layer?.[0].steps).toHaveLength(2);
    expect(bom.workflow_layer?.[0].steps[0].step_id).toBe("step-search");
    expect(bom.workflow_layer?.[0].steps[1].depends_on).toEqual([
      "step-search",
    ]);

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("omits workflow_layer when no workflows provided", () => {
    const bom = generateAgentBOM({
      agent_id: "ag-agent-007",
      agent_name: "No Workflow Agent",
    });
    expect(bom.workflow_layer).toBeUndefined();

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
  });

  it("maps multiple workflows for multi-agent AutoGen usage", () => {
    const bom = generateAgentBOM({
      agent_id: "ag-multiagent-001",
      agent_name: "AutoGen Group Chat Orchestrator",
      agent_version: "0.4.0",
      deployment_context: "production",
      tools: [
        {
          name: "code_executor",
          permissions: ["process:exec", "fs:write"],
          risk_signals: ["code_execution"],
        },
        {
          name: "web_browser",
          permissions: ["network:outbound"],
        },
      ],
      workflows: [
        {
          workflow_id: "wf-code-review",
          workflow_name: "Code Review Pipeline",
          steps: [
            { step_id: "write", action: "code_executor" },
            { step_id: "test", action: "code_executor", depends_on: ["write"] },
            {
              step_id: "review",
              action: "decision",
              depends_on: ["test"],
              allowed_tools: [],
            },
          ],
        },
        {
          workflow_id: "wf-research",
          workflow_name: "Research Pipeline",
          steps: [
            {
              step_id: "search",
              action: "web_browser",
              allowed_tools: ["web-browser"],
            },
            {
              step_id: "summarize",
              action: "decision",
              depends_on: ["search"],
            },
          ],
        },
      ],
    });

    expect(bom.workflow_layer).toHaveLength(2);
    expect(bom.tool_layer).toHaveLength(2);

    const result = validateAgentBOM(bom);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });
});
