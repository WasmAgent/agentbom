/**
 * LangChain → AgentBOM adapter.
 *
 * Inspects a LangChain agent definition (tools, LLM config, metadata) and
 * produces an AgentBOM v0.1 manifest that validates against the
 * `specs/agentbom/schema.json` schema.
 *
 * This package does **not** import `langchain` — it accepts plain config
 * objects so version conflicts are avoided.  Users of `langchain` (or
 * `@langchain/core`) pass the relevant fields from their runtime agent
 * instance.
 */

import { type AgentBOMRecord, buildAgentBOM } from "@wasmagent/agentbom-core";

export type { AgentBOMRecord } from "@wasmagent/agentbom-core";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Mirrors the subset of a LangChain `BaseTool` / `StructuredTool` that
 *  is relevant for an AgentBOM tool_layer entry. */
export interface LangChainToolConfig {
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

export interface LangChainLLMConfig {
  provider: string;
  model_id: string;
  model_version?: string;
  capabilities?: string[];
}

export interface LangChainAgentConfig {
  agent_id: string;
  agent_name: string;
  agent_version?: string;
  deployment_context?: "development" | "staging" | "production";
  tools?: LangChainToolConfig[];
  llm?: LangChainLLMConfig;
  system_prompt_hash?: string;
  prompt_version?: string;
  template_ids?: string[];
  granted_scopes?: string[];
  data_access?: string[];
  credential_references?: string[];
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

const GENERATOR = "@wasmagent/langchain-agentbom";
const GENERATOR_VERSION = "0.0.0-research";

/**
 * Convert a LangChain agent configuration into an AgentBOM v0.1 manifest.
 *
 * The returned object is guaranteed to include all required fields
 * (`agentbom_version`, `identity`, `attestation`) and will validate
 * against `specs/agentbom/schema.json`.
 */
export function generateAgentBOM(config: LangChainAgentConfig): AgentBOMRecord {
  return buildAgentBOM(config, {
    generator: GENERATOR,
    generator_version: GENERATOR_VERSION,
  });
}
