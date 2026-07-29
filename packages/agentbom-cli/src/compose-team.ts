import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { validateAgentBOM } from '@wasmagent/agentbom-core';

/** Composite trust manifest produced by compose-team */
interface CompositeManifest {
  schema: 'composite-trust-manifest/v1';
  generated_at: string;
  agent_count: number;
  agents: Array<{ agent_id: string; agent_name: string; bom_path: string }>;
  aggregated_capabilities: string[];
  trust_relationships: Array<{ from: string; to: string; type: string }>;
}

/**
 * Compose multiple AgentBOMs into a composite trust manifest.
 * Requires at least 2 BOM file paths.
 */
export function composeTeamCommand(args: string[]): number {
  if (args.length < 2) {
    console.error('Error: compose-team requires at least 2 agent BOM files');
    return 1;
  }

  const boms: Array<{ data: Record<string, unknown>; path: string }> = [];

  for (const filePath of args) {
    const resolvedPath = resolve(filePath);

    // Read file
    let raw: string;
    try {
      raw = readFileSync(resolvedPath, 'utf-8');
    } catch {
      console.error(`Error: Cannot read BOM file: ${resolvedPath}`);
      return 1;
    }

    // Parse JSON
    let data: unknown;
    try {
      data = JSON.parse(raw);
    } catch {
      console.error(`Error: Invalid BOM format in file: ${resolvedPath}: not valid JSON`);
      return 1;
    }

    // Validate against AgentBOM schema
    const result = validateAgentBOM(data);
    if (!result.valid) {
      console.error(`Error: Invalid BOM format in file: ${resolvedPath}: ${result.errors[0]}`);
      return 1;
    }

    boms.push({ data: data as Record<string, unknown>, path: resolvedPath });
  }

  // Build composite manifest
  const agents: CompositeManifest['agents'] = [];
  const allCapabilities = new Set<string>();
  const trustRelationships: CompositeManifest['trust_relationships'] = [];

  for (const { data, path } of boms) {
    // Extract identity
    const identity = data.identity as Record<string, unknown> | undefined;
    const agentId = String(identity?.agent_id ?? 'unknown');
    const agentName = String(identity?.agent_name ?? 'unnamed');

    agents.push({ agent_id: agentId, agent_name: agentName, bom_path: path });

    // Collect capabilities from model_layer.capabilities
    const modelLayer = data.model_layer as Record<string, unknown> | undefined;
    const capabilities = modelLayer?.capabilities;
    if (Array.isArray(capabilities)) {
      for (const cap of capabilities) {
        if (typeof cap === 'string') {
          allCapabilities.add(cap);
        }
      }
    }

    // Collect trust relationships from agent_collaboration.peer_agents
    const collab = data.agent_collaboration as Record<string, unknown> | undefined;
    const peerAgents = collab?.peer_agents;
    if (Array.isArray(peerAgents)) {
      for (const peer of peerAgents) {
        const p = peer as Record<string, unknown>;
        trustRelationships.push({
          from: agentId,
          to: String(p.agent_id ?? 'unknown'),
          type: String(p.role ?? 'peer'),
        });
      }
    }
  }

  const manifest: CompositeManifest = {
    schema: 'composite-trust-manifest/v1',
    generated_at: new Date().toISOString(),
    agent_count: boms.length,
    agents,
    aggregated_capabilities: Array.from(allCapabilities).sort(),
    trust_relationships: trustRelationships,
  };

  console.log(JSON.stringify(manifest, null, 2));
  return 0;
}
