/**
 * Shared AgentBOM manifest generator.
 *
 * Builds an AgentBOM v0.1 manifest from a normalized agent description.
 * The framework adapter packages (langchain, autogen, llamaindex) map their
 * framework-specific config types onto the input shape below and delegate
 * here, so the manifest construction logic lives in exactly one place.
 */

// ─── Input types ─────────────────────────────────────────────────

export interface AgentBOMToolInput {
  /** Tool name (maps to `tool_id` if `id` is not supplied). */
  name: string;
  /** Human-readable description — used for `tool_name`. */
  description?: string;
  /** Optional override for the AgentBOM `tool_id`. */
  id?: string;
  /** AgentBOM tool source: `"mcp"` | `"builtin"` | `"plugin"`. */
  source?: "mcp" | "builtin" | "plugin";
  /** MCP server identifier when `source === "mcp"`. */
  mcp_server_id?: string;
  /** Skills this tool contributes to the agent. */
  skills?: string[];
  /** Permission scopes the tool requires. */
  permissions?: string[];
  /** Known risk signals. */
  risk_signals?: string[];
}

export interface AgentBOMLLMInput {
  provider: string;
  model_id: string;
  model_version?: string;
  capabilities?: string[];
}

export interface AgentBOMWorkflowStepInput {
  /** Unique step identifier within the workflow. */
  step_id: string;
  /** Action to perform (tool_id, prompt name, sub_workflow, or decision). */
  action: string;
  /** Human-readable step description. */
  description?: string;
  /** Step IDs this step depends on. */
  depends_on?: string[];
  /** Tool IDs allowed at this step. */
  allowed_tools?: string[];
}

export interface AgentBOMWorkflowInput {
  /** Unique workflow identifier. */
  workflow_id: string;
  /** Human-readable workflow name. */
  workflow_name: string;
  /** Workflow description. */
  description?: string;
  /** Workflow version (semver). */
  version?: string;
  /** Ordered steps. */
  steps: AgentBOMWorkflowStepInput[];
}

export interface AgentBOMGenerateInput {
  agent_id: string;
  agent_name: string;
  agent_version?: string;
  deployment_context?: "development" | "staging" | "production";
  tools?: AgentBOMToolInput[];
  llm?: AgentBOMLLMInput;
  system_prompt_hash?: string;
  prompt_version?: string;
  template_ids?: string[];
  granted_scopes?: string[];
  data_access?: string[];
  credential_references?: string[];
  /** Workflow / action pathway definitions. */
  workflows?: AgentBOMWorkflowInput[];
}

// ─── Output type ─────────────────────────────────────────────────

/** The shape of a generated AgentBOM document. */
export interface AgentBOMRecord {
  agentbom_version: string;
  identity: {
    agent_id: string;
    agent_name: string;
    agent_version?: string;
    deployment_context?: string;
    generated_at: string;
  };
  model_layer?: {
    provider: string;
    model_id: string;
    model_version?: string;
    capabilities?: string[];
  };
  tool_layer?: Array<{
    tool_id: string;
    tool_name: string;
    source: "mcp" | "builtin" | "plugin";
    mcp_server_id?: string;
    skills?: string[];
    permissions?: string[];
    risk_signals?: string[];
  }>;
  prompt_layer?: {
    system_prompt_hash?: string;
    prompt_version?: string;
    template_ids?: string[];
  };
  permission_layer?: {
    granted_scopes?: string[];
    data_access?: string[];
    credential_references?: string[];
  };
  workflow_layer?: Array<{
    workflow_id: string;
    workflow_name: string;
    description?: string;
    version?: string;
    steps: Array<{
      step_id: string;
      action: string;
      description?: string;
      depends_on?: string[];
      allowed_tools?: string[];
    }>;
  }>;
  attestation: {
    generator: string;
    generator_version: string;
  };
}

// ─── Generator ───────────────────────────────────────────────────

/**
 * Convert a normalized agent configuration into an AgentBOM v0.1 manifest.
 *
 * The returned object is guaranteed to include all required fields
 * (`agentbom_version`, `identity`, `attestation`) and will validate
 * against the canonical AgentBOM schema.
 */
export function buildAgentBOM(
  config: AgentBOMGenerateInput,
  attestation: { generator: string; generator_version: string },
): AgentBOMRecord {
  const now = new Date().toISOString();

  const tool_layer = (config.tools ?? []).map((t) => ({
    tool_id: t.id ?? slugify(t.name),
    tool_name: t.description ?? t.name,
    source: t.source ?? "builtin",
    ...(t.mcp_server_id ? { mcp_server_id: t.mcp_server_id } : {}),
    ...(t.skills?.length ? { skills: t.skills } : {}),
    ...(t.permissions?.length ? { permissions: t.permissions } : {}),
    ...(t.risk_signals?.length ? { risk_signals: t.risk_signals } : {}),
  }));

  const bom: AgentBOMRecord = {
    agentbom_version: "0.1",
    identity: {
      agent_id: config.agent_id,
      agent_name: config.agent_name,
      ...(config.agent_version ? { agent_version: config.agent_version } : {}),
      ...(config.deployment_context
        ? { deployment_context: config.deployment_context }
        : {}),
      generated_at: now,
    },
    ...(config.llm
      ? {
          model_layer: {
            provider: config.llm.provider,
            model_id: config.llm.model_id,
            ...(config.llm.model_version
              ? { model_version: config.llm.model_version }
              : {}),
            ...(config.llm.capabilities?.length
              ? { capabilities: config.llm.capabilities }
              : {}),
          },
        }
      : {}),
    ...(tool_layer.length ? { tool_layer } : {}),
    ...(config.system_prompt_hash ||
    config.prompt_version ||
    config.template_ids?.length
      ? {
          prompt_layer: {
            ...(config.system_prompt_hash
              ? { system_prompt_hash: config.system_prompt_hash }
              : {}),
            ...(config.prompt_version
              ? { prompt_version: config.prompt_version }
              : {}),
            ...(config.template_ids?.length
              ? { template_ids: config.template_ids }
              : {}),
          },
        }
      : {}),
    ...(config.granted_scopes?.length ||
    config.data_access?.length ||
    config.credential_references?.length
      ? {
          permission_layer: {
            ...(config.granted_scopes?.length
              ? { granted_scopes: config.granted_scopes }
              : {}),
            ...(config.data_access?.length
              ? { data_access: config.data_access }
              : {}),
            ...(config.credential_references?.length
              ? { credential_references: config.credential_references }
              : {}),
          },
        }
      : {}),
    ...(config.workflows?.length
      ? {
          workflow_layer: config.workflows.map((wf) => ({
            workflow_id: wf.workflow_id,
            workflow_name: wf.workflow_name,
            ...(wf.description ? { description: wf.description } : {}),
            ...(wf.version ? { version: wf.version } : {}),
            steps: wf.steps.map((s) => ({
              step_id: s.step_id,
              action: s.action,
              ...(s.description ? { description: s.description } : {}),
              ...(s.depends_on?.length ? { depends_on: s.depends_on } : {}),
              ...(s.allowed_tools?.length
                ? { allowed_tools: s.allowed_tools }
                : {}),
            })),
          })),
        }
      : {}),
    attestation: {
      generator: attestation.generator,
      generator_version: attestation.generator_version,
    },
  };

  return bom;
}

// ─── Helpers ─────────────────────────────────────────────────────

/** Convert a human-readable name to a URL-friendly slug for use as `tool_id`. */
function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}
