/**
 * AutoGen → AgentBOM adapter.
 *
 * Inspects an AutoGen agent definition (tools, LLM config, metadata) and
 * produces an AgentBOM v0.1 manifest that validates against the
 * `specs/agentbom/schema.json` schema.
 *
 * This package does **not** import `autogen` — it accepts plain config
 * objects so version conflicts are avoided.  Users of `autogen` (Microsoft
 * AutoGen) pass the relevant fields from their runtime agent instance.
 */

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Mirrors the subset of an AutoGen function-tool / tool definition that
 *  is relevant for an AgentBOM tool_layer entry. */
export interface AutoGenToolConfig {
  /** Tool / function name (maps to `tool_id` if `id` is not supplied). */
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

export interface AutoGenLLMConfig {
  provider: string;
  model_id: string;
  model_version?: string;
  capabilities?: string[];
}

export interface AutoGenAgentConfig {
  agent_id: string;
  agent_name: string;
  agent_version?: string;
  deployment_context?: "development" | "staging" | "production";
  tools?: AutoGenToolConfig[];
  llm?: AutoGenLLMConfig;
  system_prompt_hash?: string;
  prompt_version?: string;
  template_ids?: string[];
  granted_scopes?: string[];
  data_access?: string[];
  credential_references?: string[];
}

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
  attestation: {
    generator: string;
    generator_version: string;
  };
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

const GENERATOR = "@wasmagent/autogen-agentbom";
const GENERATOR_VERSION = "0.0.0-research";

/**
 * Convert an AutoGen agent configuration into an AgentBOM v0.1 manifest.
 *
 * The returned object is guaranteed to include all required fields
 * (`agentbom_version`, `identity`, `attestation`) and will validate
 * against `specs/agentbom/schema.json`.
 */
export function generateAgentBOM(config: AutoGenAgentConfig): AgentBOMRecord {
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
    attestation: {
      generator: GENERATOR,
      generator_version: GENERATOR_VERSION,
    },
  };

  return bom;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convert a human-readable name to a URL-friendly slug for use as `tool_id`. */
function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}
