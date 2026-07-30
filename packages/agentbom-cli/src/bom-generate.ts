import {
  existsSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, join, resolve } from "node:path";
import { validateAgentBOM } from "@wasmagent/agentbom-core";

interface GenerateOptions {
  agentPath: string;
  outputPath?: string;
}

interface ToolDefinition {
  tool_id: string;
  tool_name: string;
  source: "mcp" | "builtin" | "plugin";
  mcp_server_id?: string;
  permissions: string[];
  risk_signals: string[];
}

interface AgentInfo {
  agent_id: string;
  agent_name: string;
  agent_version?: string;
  deployment_context?: "development" | "staging" | "production";
}

interface ParsedGenerateArgs {
  agentPath: string;
  outputPath?: string;
}

const USAGE = "Usage: agent-trust generate bom --agent <path> [--out <path>]";

function parseGenerateArgs(args: string[]): ParsedGenerateArgs | null {
  let agentPath: string | undefined;
  let outputPath: string | undefined;

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--agent") {
      agentPath = args[i + 1];
      i += 1;
    } else if (arg === "--out") {
      outputPath = args[i + 1];
      i += 1;
    } else {
      return null;
    }
  }

  if (!agentPath) return null;
  return { agentPath, outputPath };
}

/**
 * Extract basic agent information from package.json or directory name
 */
function extractAgentInfo(agentPath: string): AgentInfo {
  const pkgPath = resolve(agentPath, "package.json");
  let agentId = basename(agentPath).replace(/[^a-zA-Z0-9-]/g, "-");
  let agentName = agentId;
  let agentVersion: string | undefined;
  const deploymentContext: "development" | "staging" | "production" =
    "development";

  try {
    const pkgContent = readFileSync(pkgPath, "utf-8");
    const pkg = JSON.parse(pkgContent);

    if (pkg.name) {
      agentName = pkg.name.replace(/^@[^/]+\//, "");
      agentId = agentName;
    }
    if (pkg.version) {
      agentVersion = pkg.version;
    }
  } catch {
    // No package.json or couldn't parse it, use directory name
  }

  // Generate a more specific agent_id
  const timestamp = Date.now();
  agentId = `${agentId}-${timestamp}`;

  return {
    agent_id: agentId,
    agent_name: agentName,
    agent_version: agentVersion,
    deployment_context: deploymentContext,
  };
}

/**
 * Scan agent directory for MCP servers, plugins, and tools
 */
function scanAgentDirectory(agentPath: string): ToolDefinition[] {
  const tools: ToolDefinition[] = [];

  try {
    const entries = readdirSync(agentPath);

    // Look for MCP server definitions
    for (const entry of entries) {
      const fullPath = resolve(agentPath, entry);
      const stat = statSync(fullPath);

      if (stat.isDirectory()) {
        // Check for MCP server patterns
        const mcpConfigPath = join(fullPath, "mcp.config.json");
        try {
          const mcpConfig = JSON.parse(readFileSync(mcpConfigPath, "utf-8"));
          if (mcpConfig.tools && Array.isArray(mcpConfig.tools)) {
            for (const tool of mcpConfig.tools) {
              tools.push({
                tool_id: `mcp-${entry}-${tool.name}`,
                tool_name: tool.name,
                source: "mcp",
                mcp_server_id: entry,
                permissions: tool.permissions || [],
                risk_signals: [],
              });
            }
          }
        } catch {
          // No MCP config here, continue
        }
      }
    }
  } catch {
    // Couldn't read directory
  }

  return tools;
}

/**
 * Generate standard tool inventory for a typical agent
 */
function generateStandardToolInventory(): ToolDefinition[] {
  return [
    {
      tool_id: "file-read",
      tool_name: "Read",
      source: "builtin",
      permissions: ["fs:read"],
      risk_signals: [],
    },
    {
      tool_id: "file-write",
      tool_name: "Write",
      source: "builtin",
      permissions: ["fs:write"],
      risk_signals: [],
    },
    {
      tool_id: "file-edit",
      tool_name: "Edit",
      source: "builtin",
      permissions: ["fs:read", "fs:write"],
      risk_signals: [],
    },
    {
      tool_id: "bash-exec",
      tool_name: "Bash",
      source: "builtin",
      permissions: ["process:exec", "fs:read", "fs:write"],
      risk_signals: ["command_execution"],
    },
    {
      tool_id: "content-grep",
      tool_name: "Grep",
      source: "builtin",
      permissions: ["fs:read"],
      risk_signals: [],
    },
    {
      tool_id: "file-glob",
      tool_name: "Glob",
      source: "builtin",
      permissions: ["fs:read"],
      risk_signals: [],
    },
  ];
}

/**
 * Extract all unique permissions from tool inventory
 */
function extractPermissionScope(toolLayer: ToolDefinition[]): string[] {
  const permissionSet = new Set<string>();

  for (const tool of toolLayer) {
    for (const perm of tool.permissions) {
      permissionSet.add(perm);
    }
  }

  return Array.from(permissionSet).sort();
}

/**
 * Generate basic risk assessment for tools
 */
function generateRiskAssessment(toolLayer: ToolDefinition[]): Array<{
  risk_id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  status: "open" | "mitigated" | "accepted";
}> {
  const risks: Array<{
    risk_id: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    category: string;
    description: string;
    status: "open" | "mitigated" | "accepted";
  }> = [];

  for (const tool of toolLayer) {
    // Check for high-risk tools
    if (tool.tool_id === "bash-exec" || tool.tool_id.includes("exec")) {
      risks.push({
        risk_id: `risk-${tool.tool_id}-001`,
        severity: "medium",
        category: "command_execution",
        description: `${tool.tool_name} tool allows arbitrary process execution`,
        status: "accepted",
      });
    }

    // Check for network-related tools
    if (
      tool.source === "mcp" &&
      tool.permissions.some((p) => p.includes("network"))
    ) {
      risks.push({
        risk_id: `risk-${tool.tool_id}-001`,
        severity: "high",
        category: "ssrf",
        description: `${tool.tool_name} makes outbound network requests`,
        status: "open",
      });
    }

    // Check for file write operations
    if (tool.permissions.includes("fs:write")) {
      risks.push({
        risk_id: `risk-${tool.tool_id}-002`,
        severity: "low",
        category: "data_modification",
        description: `${tool.tool_name} can modify files in the workspace`,
        status: "accepted",
      });
    }
  }

  return risks;
}

/**
 * Generate AgentBOM JSON from agent path
 */
export function generateAgentBOM(
  options: GenerateOptions,
): Record<string, unknown> {
  const { agentPath } = options;

  // Extract agent information
  const agentInfo = extractAgentInfo(agentPath);

  // Scan for tools
  const discoveredTools = scanAgentDirectory(agentPath);
  const standardTools = generateStandardToolInventory();

  // Merge tool inventories, avoiding duplicates
  const toolMap = new Map<string, ToolDefinition>();
  for (const tool of [...discoveredTools, ...standardTools]) {
    toolMap.set(tool.tool_id, tool);
  }
  const toolLayer = Array.from(toolMap.values());

  // Extract permission scopes
  const grantedScopes = extractPermissionScope(toolLayer);

  // Generate risk assessment
  const riskLayer = generateRiskAssessment(toolLayer);

  // Build AgentBOM
  const agentbom: Record<string, unknown> = {
    agentbom_version: "0.1",
    identity: {
      agent_id: agentInfo.agent_id,
      agent_name: agentInfo.agent_name,
      generated_at: new Date().toISOString(),
    },
    tool_layer: toolLayer,
    permission_layer: {
      granted_scopes: grantedScopes,
      data_access: ["local_workspace"],
      credential_references: [],
    },
    risk_layer: riskLayer,
    attestation: {
      generator: "@wasmagent/agent-trust-cli",
      generator_version: "0.0.0-research",
    },
  };

  // Add optional fields if available
  if (agentInfo.agent_version) {
    (agentbom.identity as Record<string, unknown>).agent_version =
      agentInfo.agent_version;
  }
  if (agentInfo.deployment_context) {
    (agentbom.identity as Record<string, unknown>).deployment_context =
      agentInfo.deployment_context;
  }

  return agentbom;
}

/**
 * Main command function for generating AgentBOM
 */
export function generateAgentBOMCommand(args: string[]): number {
  const parsed = parseGenerateArgs(args);
  if (!parsed) {
    console.error(USAGE);
    return 1;
  }

  const agentPath = resolve(parsed.agentPath);
  if (!existsSync(agentPath) || !statSync(agentPath).isDirectory()) {
    console.error(`Error: agent path is not a directory: ${agentPath}`);
    return 1;
  }

  // Generate AgentBOM
  const agentbom = generateAgentBOM({ agentPath });

  // Validate the generated AgentBOM
  const validation = validateAgentBOM(agentbom);
  if (!validation.valid) {
    console.error("Error: Generated AgentBOM is invalid:");
    for (const err of validation.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  // Output the AgentBOM JSON
  const output = `${JSON.stringify(agentbom, null, 2)}\n`;
  if (parsed.outputPath) {
    writeFileSync(resolve(parsed.outputPath), output, "utf-8");
  } else {
    console.log(output.trimEnd());
  }

  return 0;
}
