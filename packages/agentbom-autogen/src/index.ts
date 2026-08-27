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

import { type AgentBOMRecord, buildAgentBOM } from "@wasmagent/agentbom-core";

export type { AgentBOMRecord } from "@wasmagent/agentbom-core";

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
  /** Workflow / action pathway definitions. */
  workflows?: AutoGenWorkflowConfig[];
}

export interface AutoGenWorkflowStep {
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

export interface AutoGenWorkflowConfig {
  /** Unique workflow identifier. */
  workflow_id: string;
  /** Human-readable workflow name. */
  workflow_name: string;
  /** Workflow description. */
  description?: string;
  /** Workflow version (semver). */
  version?: string;
  /** Ordered steps. */
  steps: AutoGenWorkflowStep[];
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
  return buildAgentBOM(config, {
    generator: GENERATOR,
    generator_version: GENERATOR_VERSION,
  });
}
