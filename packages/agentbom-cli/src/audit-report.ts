#!/usr/bin/env bun
import { readdirSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { validateAgentBOM } from "@wasmagent/agentbom-core";

/** Audit log entry structure */
interface AuditLogEntry {
  timestamp: string;
  event_type: string;
  actor: string;
  resource?: string;
  outcome?: "success" | "failure" | "partial";
  details?: Record<string, unknown>;
}

/** Evidence hash entry structure */
interface EvidenceHash {
  type: string;
  hash: string;
  timestamp?: string;
}

/** Evidence layer structure */
interface EvidenceLayer {
  aep_references?: string[];
  evidence_hashes?: EvidenceHash[];
}

/** Peer agent in a collaboration topology */
interface PeerAgent {
  agent_id: string;
  agent_name?: string;
  role: string;
  trust_level?: string;
  agentbom_ref?: string;
}

/** Delegation boundary rule */
interface DelegationBoundary {
  boundary_id: string;
  direction: string;
  constraint_type: string;
  description?: string;
  target_agents?: string[];
  allowed_actions?: string[];
  max_delegation_depth?: number;
}

/** Shared resource across agent boundaries */
interface SharedResource {
  resource_id: string;
  resource_type: string;
  access_pattern: string;
  description?: string;
  accessing_agents?: string[];
  isolation_level?: string;
}

/** Agent collaboration topology */
interface AgentCollaboration {
  peer_agents?: PeerAgent[];
  delegation_boundaries?: DelegationBoundary[];
  shared_resources?: SharedResource[];
}

/** AgentBOM structure (partial) */
interface AgentBOM {
  agentbom_version: string;
  identity?: {
    agent_id?: string;
    agent_name?: string;
    generated_at?: string;
  };
  audit_log?: AuditLogEntry[];
  evidence_layer?: EvidenceLayer;
  risk_layer?: Array<{
    risk_id: string;
    severity: string;
    category: string;
    description: string;
    status: string;
  }>;
  agent_collaboration?: AgentCollaboration;
}

export function generateAuditReport(bom: AgentBOM): string {
  const lines: string[] = [];

  // Header
  lines.push(
    "════════════════════════════════════════════════════════════════════════════════",
  );
  lines.push("                              AGENT TRUST AUDIT REPORT");
  lines.push(
    "════════════════════════════════════════════════════════════════════════════════",
  );

  // Agent Identity
  const identity = bom.identity;
  if (identity) {
    lines.push("");
    lines.push("Agent Identity:");
    lines.push(`  Agent ID:     ${identity.agent_id ?? "unknown"}`);
    lines.push(`  Agent Name:   ${identity.agent_name ?? "unknown"}`);
    lines.push(`  Generated At: ${identity.generated_at ?? "unknown"}`);
  }

  // Audit Summary Statistics
  const auditLogs = bom.audit_log ?? [];
  const evidenceLayer = bom.evidence_layer;
  const riskLayer = bom.risk_layer ?? [];

  lines.push("");
  lines.push(
    "────────────────────────────────────────────────────────────────────────────────────",
  );
  lines.push("                              AUDIT SUMMARY");
  lines.push(
    "────────────────────────────────────────────────────────────────────────────────────",
  );

  // Event statistics by outcome
  const outcomeStats = {
    success: 0,
    failure: 0,
    partial: 0,
    unknown: 0,
  };

  for (const log of auditLogs) {
    const outcome = log.outcome;
    if (outcome === "success") outcomeStats.success++;
    else if (outcome === "failure") outcomeStats.failure++;
    else if (outcome === "partial") outcomeStats.partial++;
    else outcomeStats.unknown++;
  }

  lines.push(`  Total Audit Events:       ${auditLogs.length}`);
  lines.push(`  Successful Events:        ${outcomeStats.success}`);
  lines.push(`  Failed Events:            ${outcomeStats.failure}`);
  lines.push(`  Partial Success Events:   ${outcomeStats.partial}`);
  lines.push(
    `  Evidence Hashes:          ${evidenceLayer?.evidence_hashes?.length ?? 0}`,
  );
  lines.push(
    `  AEP References:           ${evidenceLayer?.aep_references?.length ?? 0}`,
  );
  lines.push(
    `  Open Risk Findings:       ${riskLayer.filter((r) => r.status === "open").length}`,
  );

  // Risk Summary
  if (riskLayer.length > 0) {
    lines.push("");
    lines.push("Risk Summary:");
    const riskBySeverity = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const risk of riskLayer) {
      const severity =
        risk.severity.toLowerCase() as keyof typeof riskBySeverity;
      if (severity in riskBySeverity) {
        riskBySeverity[severity]++;
      }
    }

    lines.push(`  Critical: ${riskBySeverity.critical}`);
    lines.push(`  High:     ${riskBySeverity.high}`);
    lines.push(`  Medium:   ${riskBySeverity.medium}`);
    lines.push(`  Low:      ${riskBySeverity.low}`);
    lines.push(`  Info:     ${riskBySeverity.info}`);
  }

  // Evidence Citations
  if (evidenceLayer) {
    lines.push("");
    lines.push(
      "────────────────────────────────────────────────────────────────────────────────────",
    );
    lines.push("                              EVIDENCE CITATIONS");
    lines.push(
      "────────────────────────────────────────────────────────────────────────────────────",
    );

    if (
      evidenceLayer.evidence_hashes &&
      evidenceLayer.evidence_hashes.length > 0
    ) {
      lines.push("");
      lines.push("Evidence Hashes:");
      for (const evidence of evidenceLayer.evidence_hashes) {
        const timestamp = evidence.timestamp ?? "unknown";
        lines.push(`  [${timestamp}] ${evidence.type}: ${evidence.hash}`);
      }
    }

    if (
      evidenceLayer.aep_references &&
      evidenceLayer.aep_references.length > 0
    ) {
      lines.push("");
      lines.push("AEP Event References:");
      for (const ref of evidenceLayer.aep_references) {
        lines.push(`  → ${ref}`);
      }
    }

    if (
      (!evidenceLayer.evidence_hashes ||
        evidenceLayer.evidence_hashes.length === 0) &&
      (!evidenceLayer.aep_references ||
        evidenceLayer.aep_references.length === 0)
    ) {
      lines.push("");
      lines.push("  No evidence citations found.");
    }
  }

  // Audit Log Entries
  if (auditLogs.length > 0) {
    lines.push("");
    lines.push(
      "────────────────────────────────────────────────────────────────────────────────────",
    );
    lines.push("                              AUDIT TRAIL");
    lines.push(
      "────────────────────────────────────────────────────────────────────────────────────",
    );

    // Group by event type for better readability
    const logsByEventType = new Map<string, AuditLogEntry[]>();
    for (const log of auditLogs) {
      const eventType = log.event_type ?? "unknown";
      if (!logsByEventType.has(eventType)) {
        logsByEventType.set(eventType, []);
      }
      logsByEventType.get(eventType)?.push(log);
    }

    // Display events sorted by timestamp (most recent first)
    const sortedEventTypes = Array.from(logsByEventType.keys()).sort();

    for (const eventType of sortedEventTypes) {
      const events = logsByEventType.get(eventType) ?? [];

      lines.push("");
      lines.push(`${eventType} (${events.length} events):`);

      // Sort events by timestamp
      const sortedEvents = events.sort(
        (a, b) =>
          new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
      );

      for (const event of sortedEvents) {
        const timestamp = event.timestamp;
        const actor = event.actor;
        const resource = event.resource ?? "N/A";
        const outcome = event.outcome ?? "unknown";
        const outcomeSymbol =
          outcome === "success" ? "✓" : outcome === "failure" ? "✗" : "○";

        lines.push(`  ${outcomeSymbol} [${timestamp}]`);
        lines.push(`      Actor: ${actor}`);
        lines.push(`      Resource: ${resource}`);
        lines.push(`      Outcome: ${outcome}`);

        if (event.details && Object.keys(event.details).length > 0) {
          lines.push(`      Details: ${JSON.stringify(event.details)}`);
        }
      }
    }
  } else {
    lines.push("");
    lines.push(
      "────────────────────────────────────────────────────────────────────────────────────",
    );
    lines.push("                              AUDIT TRAIL");
    lines.push(
      "────────────────────────────────────────────────────────────────────────────────────",
    );
    lines.push("");
    lines.push("  No audit log entries found.");
  }

  // Footer
  lines.push("");
  lines.push(
    "════════════════════════════════════════════════════════════════════════════════",
  );
  lines.push(`Report Generated: ${new Date().toISOString()}`);
  lines.push(
    "════════════════════════════════════════════════════════════════════════════════",
  );

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Multi-agent audit report with causal chain reconstruction
// ---------------------------------------------------------------------------

/** A reconstructed causal chain step */
interface CausalStep {
  agent_id: string;
  agent_name: string;
  event_type: string;
  timestamp: string;
  resource?: string;
  outcome?: string;
  details?: Record<string, unknown>;
}

/** A full causal chain connecting agents through delegation/tool access */
interface CausalChain {
  chain_id: string;
  steps: CausalStep[];
  summary: string;
}

/**
 * Build a lookup map from agent_id → AgentBOM for quick access across the team.
 */
function buildAgentMap(boms: AgentBOM[]): Map<string, AgentBOM> {
  const map = new Map<string, AgentBOM>();
  for (const bom of boms) {
    const id = bom.identity?.agent_id;
    if (id) map.set(id, bom);
  }
  return map;
}

/**
 * Build a peer-agent name lookup: agent_id → display name.
 * Falls back to agent_id if no name is set.
 */
function buildNameLookup(boms: AgentBOM[]): Map<string, string> {
  const names = new Map<string, string>();
  for (const bom of boms) {
    const id = bom.identity?.agent_id;
    const name = bom.identity?.agent_name;
    if (id) names.set(id, name ?? id);
    // Also index peer names from collaboration data
    const peers = bom.agent_collaboration?.peer_agents ?? [];
    for (const peer of peers) {
      if (peer.agent_id) {
        names.set(peer.agent_id, peer.agent_name ?? peer.agent_id);
      }
    }
  }
  return names;
}

/**
 * Detect causal links between agents by cross-referencing audit log entries
 * with the agent_collaboration topology.
 *
 * A causal link is identified when:
 * - An audit entry's `actor` matches a peer agent's agent_id
 * - An audit entry's `details` contains `delegated_from` or `delegated_to`
 * - An audit entry's `resource` is a shared resource accessed by multiple agents
 */
function reconstructCausalChains(boms: AgentBOM[]): CausalChain[] {
  const agentMap = buildAgentMap(boms);
  const nameLookup = buildNameLookup(boms);

  // Collect all shared resource IDs across the team
  const sharedResourceIds = new Set<string>();
  for (const bom of boms) {
    for (const sr of bom.agent_collaboration?.shared_resources ?? []) {
      sharedResourceIds.add(sr.resource_id);
    }
  }

  // Gather all audit entries with their source agent
  interface TaggedEntry {
    entry: AuditLogEntry;
    source_agent_id: string;
    source_agent_name: string;
  }
  const allEntries: TaggedEntry[] = [];
  for (const bom of boms) {
    const aid = bom.identity?.agent_id ?? "unknown";
    const aname = bom.identity?.agent_name ?? aid;
    for (const entry of bom.audit_log ?? []) {
      allEntries.push({
        entry,
        source_agent_id: aid,
        source_agent_name: aname,
      });
    }
  }

  // Sort all entries chronologically
  allEntries.sort(
    (a, b) =>
      new Date(a.entry.timestamp).getTime() -
      new Date(b.entry.timestamp).getTime(),
  );

  // Build causal chains by following delegation / shared-resource links
  const chains: CausalChain[] = [];
  const assigned = new Set<number>(); // indices into allEntries already in a chain
  let chainCounter = 0;

  for (let i = 0; i < allEntries.length; i++) {
    if (assigned.has(i)) continue;

    const start = allEntries[i];
    const steps: CausalStep[] = [
      {
        agent_id: start.source_agent_id,
        agent_name: start.source_agent_name,
        event_type: start.entry.event_type,
        timestamp: start.entry.timestamp,
        resource: start.entry.resource,
        outcome: start.entry.outcome,
        details: start.entry.details,
      },
    ];
    assigned.add(i);

    // Try to extend the chain forward
    let currentIdx = i;
    for (let j = i + 1; j < allEntries.length; j++) {
      if (assigned.has(j)) continue;

      const prev = allEntries[currentIdx];
      const candidate = allEntries[j];

      if (isCausallyLinked(prev, candidate, sharedResourceIds, agentMap)) {
        steps.push({
          agent_id: candidate.source_agent_id,
          agent_name: candidate.source_agent_name,
          event_type: candidate.entry.event_type,
          timestamp: candidate.entry.timestamp,
          resource: candidate.entry.resource,
          outcome: candidate.entry.outcome,
          details: candidate.entry.details,
        });
        assigned.add(j);
        currentIdx = j;
      }
    }

    // Only emit chains with 2+ steps (cross-agent interaction)
    if (steps.length >= 2) {
      chainCounter++;
      const summary = buildChainSummary(steps, nameLookup);
      chains.push({ chain_id: `chain-${chainCounter}`, steps, summary });
    }
  }

  return chains;
}

/**
 * Determine whether two tagged audit entries are causally linked.
 */
function isCausallyLinked(
  prev: { entry: AuditLogEntry; source_agent_id: string },
  candidate: { entry: AuditLogEntry; source_agent_id: string },
  sharedResourceIds: Set<string>,
  agentMap: Map<string, AgentBOM>,
): boolean {
  const pe = prev.entry;
  const ce = candidate.entry;

  // Same agent — not a cross-agent link
  if (prev.source_agent_id === candidate.source_agent_id) return false;

  // 1. Delegation via details field
  const delegatedFrom = pe.details?.delegated_from as string | undefined;
  const delegatedTo = pe.details?.delegated_to as string | undefined;
  if (delegatedTo === candidate.source_agent_id) return true;
  if (delegatedFrom === candidate.source_agent_id) return true;

  // 2. Candidate's actor matches the previous agent (direct invocation)
  if (ce.actor === prev.source_agent_id) return true;

  // 3. Both access the same shared resource
  if (
    pe.resource &&
    ce.resource &&
    pe.resource === ce.resource &&
    sharedResourceIds.has(pe.resource)
  ) {
    return true;
  }

  // 4. Candidate's actor is a peer of the previous agent
  const prevBom = agentMap.get(prev.source_agent_id);
  if (prevBom) {
    const peers = prevBom.agent_collaboration?.peer_agents ?? [];
    for (const peer of peers) {
      if (peer.agent_id === candidate.source_agent_id) {
        // Peer relationship + temporal proximity (within 60s)
        const timeDiff =
          new Date(ce.timestamp).getTime() - new Date(pe.timestamp).getTime();
        if (timeDiff >= 0 && timeDiff <= 60_000) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Build a human-readable summary string for a causal chain.
 * Example: "Agent A delegated to Agent B which accessed tool C"
 */
function buildChainSummary(
  steps: CausalStep[],
  nameLookup: Map<string, string>,
): string {
  if (steps.length === 0) return "";

  const parts: string[] = [];
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const name = nameLookup.get(step.agent_id) ?? step.agent_id;

    if (i === 0) {
      parts.push(name);
    } else {
      const prevStep = steps[i - 1];
      if (step.event_type.includes("delegat")) {
        parts.push(`delegated to ${name}`);
      } else if (step.resource) {
        parts.push(`${name} accessed ${step.resource}`);
      } else {
        parts.push(`${name} performed ${step.event_type}`);
      }
    }
  }

  return parts.join(" which ");
}

/**
 * Generate a unified multi-agent audit report spanning multiple AgentBOMs.
 */
export function generateMultiAgentAuditReport(boms: AgentBOM[]): string {
  const lines: string[] = [];

  // Header
  lines.push(
    "════════════════════════════════════════════════════════════════════════════════",
  );
  lines.push("                     MULTI-AGENT TRUST AUDIT REPORT");
  lines.push(
    "════════════════════════════════════════════════════════════════════════════════",
  );
  lines.push(`Report Generated: ${new Date().toISOString()}`);
  lines.push(`Agents in Scope:  ${boms.length}`);

  // Agent roster
  lines.push("");
  lines.push(
    "────────────────────────────────────────────────────────────────────────────────────",
  );
  lines.push("                              AGENT ROSTER");
  lines.push(
    "────────────────────────────────────────────────────────────────────────────────────",
  );

  for (const bom of boms) {
    const id = bom.identity?.agent_id ?? "unknown";
    const name = bom.identity?.agent_name ?? "unnamed";
    const peers = bom.agent_collaboration?.peer_agents?.length ?? 0;
    const sharedRes = bom.agent_collaboration?.shared_resources?.length ?? 0;
    lines.push(`  ${name} (${id})`);
    lines.push(
      `    Peers: ${peers}  |  Shared Resources: ${sharedRes}  |  Audit Entries: ${bom.audit_log?.length ?? 0}`,
    );
  }

  // Collaboration topology summary
  const totalPeers = new Set<string>();
  const totalShared = new Set<string>();
  const totalBoundaries: DelegationBoundary[] = [];
  for (const bom of boms) {
    for (const peer of bom.agent_collaboration?.peer_agents ?? []) {
      totalPeers.add(peer.agent_id);
    }
    for (const sr of bom.agent_collaboration?.shared_resources ?? []) {
      totalShared.add(sr.resource_id);
    }
    for (const b of bom.agent_collaboration?.delegation_boundaries ?? []) {
      totalBoundaries.push(b);
    }
  }

  lines.push("");
  lines.push(
    "────────────────────────────────────────────────────────────────────────────────────",
  );
  lines.push("                         COLLABORATION TOPOLOGY");
  lines.push(
    "────────────────────────────────────────────────────────────────────────────────────",
  );
  lines.push(`  Unique Peer Agents:       ${totalPeers.size}`);
  lines.push(`  Shared Resources:         ${totalShared.size}`);
  lines.push(`  Delegation Boundaries:    ${totalBoundaries.length}`);

  // Delegation boundary details
  if (totalBoundaries.length > 0) {
    lines.push("");
    lines.push("  Delegation Boundaries:");
    for (const b of totalBoundaries) {
      const targets = b.target_agents?.length
        ? ` → [${b.target_agents.join(", ")}]`
        : " → [all peers]";
      lines.push(
        `    ${b.boundary_id} (${b.direction}, ${b.constraint_type})${targets}`,
      );
      if (b.description) lines.push(`      ${b.description}`);
      if (b.max_delegation_depth !== undefined) {
        lines.push(`      Max delegation depth: ${b.max_delegation_depth}`);
      }
    }
  }

  // Shared resource details
  if (totalShared.size > 0) {
    lines.push("");
    lines.push("  Shared Resources:");
    const seen = new Set<string>();
    for (const bom of boms) {
      for (const sr of bom.agent_collaboration?.shared_resources ?? []) {
        if (seen.has(sr.resource_id)) continue;
        seen.add(sr.resource_id);
        const agents = sr.accessing_agents?.join(", ") ?? "unspecified";
        lines.push(
          `    ${sr.resource_id} (${sr.resource_type}, ${sr.access_pattern})`,
        );
        lines.push(`      Accessed by: ${agents}`);
        if (sr.isolation_level)
          lines.push(`      Isolation: ${sr.isolation_level}`);
      }
    }
  }

  // Cross-agent causal chains
  const chains = reconstructCausalChains(boms);

  lines.push("");
  lines.push(
    "────────────────────────────────────────────────────────────────────────────────────",
  );
  lines.push("                         CAUSAL CHAIN ANALYSIS");
  lines.push(
    "────────────────────────────────────────────────────────────────────────────────────",
  );

  if (chains.length === 0) {
    lines.push("");
    lines.push("  No cross-agent causal chains detected.");
  } else {
    lines.push(`  Reconstructed Causal Chains: ${chains.length}`);
    lines.push("");

    for (const chain of chains) {
      lines.push(`  ┌─ ${chain.chain_id}: ${chain.summary}`);
      for (const step of chain.steps) {
        const name = step.agent_name;
        const outcome = step.outcome ?? "unknown";
        const symbol =
          outcome === "success" ? "✓" : outcome === "failure" ? "✗" : "○";
        const resource = step.resource ? ` → ${step.resource}` : "";
        lines.push(
          `  │  ${symbol} [${step.timestamp}] ${name}: ${step.event_type}${resource}`,
        );
      }
      lines.push(`  └${"─".repeat(Math.max(2, chain.summary.length + 12))}`);
      lines.push("");
    }
  }

  // Combined audit summary statistics
  lines.push(
    "────────────────────────────────────────────────────────────────────────────────────",
  );
  lines.push("                         COMBINED AUDIT SUMMARY");
  lines.push(
    "────────────────────────────────────────────────────────────────────────────────────",
  );

  const combinedStats = { success: 0, failure: 0, partial: 0, unknown: 0 };
  const eventTypeCounts = new Map<string, number>();
  let totalRisks = 0;
  const riskBySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const bom of boms) {
    for (const log of bom.audit_log ?? []) {
      const outcome = log.outcome;
      if (outcome === "success") combinedStats.success++;
      else if (outcome === "failure") combinedStats.failure++;
      else if (outcome === "partial") combinedStats.partial++;
      else combinedStats.unknown++;

      eventTypeCounts.set(
        log.event_type,
        (eventTypeCounts.get(log.event_type) ?? 0) + 1,
      );
    }
    for (const risk of bom.risk_layer ?? []) {
      totalRisks++;
      const sev = risk.severity.toLowerCase() as keyof typeof riskBySeverity;
      if (sev in riskBySeverity) riskBySeverity[sev]++;
    }
  }

  const totalEvents =
    combinedStats.success +
    combinedStats.failure +
    combinedStats.partial +
    combinedStats.unknown;
  lines.push(`  Total Audit Events:       ${totalEvents}`);
  lines.push(`  Successful Events:        ${combinedStats.success}`);
  lines.push(`  Failed Events:            ${combinedStats.failure}`);
  lines.push(`  Partial Success Events:   ${combinedStats.partial}`);
  lines.push(`  Unknown Outcome Events:   ${combinedStats.unknown}`);
  lines.push(`  Open Risk Findings:       ${totalRisks}`);
  lines.push(`  Unique Event Types:       ${eventTypeCounts.size}`);

  // Per-event-type breakdown
  if (eventTypeCounts.size > 0) {
    lines.push("");
    lines.push("  Events by Type:");
    const sortedTypes = Array.from(eventTypeCounts.entries()).sort(
      (a, b) => b[1] - a[1],
    );
    for (const [type, count] of sortedTypes) {
      lines.push(`    ${type}: ${count}`);
    }
  }

  // Risk severity summary
  if (totalRisks > 0) {
    lines.push("");
    lines.push("  Risk Severity Distribution:");
    lines.push(`    Critical: ${riskBySeverity.critical}`);
    lines.push(`    High:     ${riskBySeverity.high}`);
    lines.push(`    Medium:   ${riskBySeverity.medium}`);
    lines.push(`    Low:      ${riskBySeverity.low}`);
    lines.push(`    Info:     ${riskBySeverity.info}`);
  }

  // Per-agent risk summary
  lines.push("");
  lines.push("  Risk per Agent:");
  for (const bom of boms) {
    const id = bom.identity?.agent_id ?? "unknown";
    const name = bom.identity?.agent_name ?? "unnamed";
    const risks = bom.risk_layer ?? [];
    const open = risks.filter((r) => r.status === "open").length;
    const critical = risks.filter(
      (r) => r.severity.toLowerCase() === "critical",
    ).length;
    lines.push(
      `    ${name}: ${risks.length} total, ${open} open, ${critical} critical`,
    );
  }

  // Footer
  lines.push("");
  lines.push(
    "════════════════════════════════════════════════════════════════════════════════",
  );
  lines.push(`Report Generated: ${new Date().toISOString()}`);
  lines.push(
    "════════════════════════════════════════════════════════════════════════════════",
  );

  return lines.join("\n");
}

/**
 * Load and validate a single AgentBOM from a file path.
 */
function loadAgentBOM(filePath: string): {
  bom: AgentBOM | null;
  error: string | null;
} {
  const resolved = resolve(filePath);
  let content: string;
  try {
    content = readFileSync(resolved, "utf-8");
  } catch {
    return { bom: null, error: `cannot read file "${resolved}"` };
  }

  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch {
    return { bom: null, error: `"${resolved}" is not valid JSON` };
  }

  const bom = data as AgentBOM;
  const validation = validateAgentBOM(bom);
  if (!validation.valid) {
    return {
      bom: null,
      error: `Invalid AgentBOM: ${validation.errors.join("; ")}`,
    };
  }

  return { bom, error: null };
}

/**
 * CLI command for multi-agent audit report.
 *
 * Usage: agent-trust audit-report multi <bom1.json> [bom2.json ...]
 */
export function multiAgentAuditReportCommand(args: string[]): number {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    console.log(
      [
        "Usage: agent-trust audit-report multi <bom1.json> [bom2.json ...]",
        "",
        "Generates a unified multi-agent audit report with causal chain reconstruction",
        "across a team of agents described by their AgentBOM files.",
        "",
        "The report includes:",
        "  - Agent roster with collaboration topology",
        "  - Delegation boundary analysis",
        "  - Shared resource access patterns",
        '  - Causal chain reconstruction (e.g., "Agent A delegated to Agent B which accessed tool C")',
        "  - Combined audit summary statistics",
        "  - Per-agent risk breakdown",
      ].join("\n"),
    );
    return 0;
  }

  // Support --dir <directory> to load all .json files from a directory
  const filePaths: string[] = [];
  let dirPath: string | null = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--dir" && i + 1 < args.length) {
      dirPath = args[++i];
    } else if (!args[i].startsWith("--")) {
      filePaths.push(args[i]);
    }
  }

  if (dirPath) {
    const resolvedDir = resolve(dirPath);
    let entries: string[];
    try {
      entries = readdirSync(resolvedDir);
    } catch {
      console.error(`Error: cannot read directory "${resolvedDir}"`);
      return 1;
    }
    for (const entry of entries) {
      if (entry.endsWith(".json")) {
        const fullPath = resolve(resolvedDir, entry);
        if (statSync(fullPath).isFile()) {
          filePaths.push(fullPath);
        }
      }
    }
  }

  if (filePaths.length === 0) {
    console.error(
      "Error: no AgentBOM files provided. Use: audit-report multi <bom1.json> [bom2.json ...] or --dir <directory>",
    );
    return 1;
  }

  const boms: AgentBOM[] = [];
  for (const filePath of filePaths) {
    const { bom, error } = loadAgentBOM(filePath);
    if (error) {
      console.error(`Error: ${error}`);
      return 1;
    }
    if (bom) boms.push(bom);
  }

  if (boms.length === 0) {
    console.error("Error: no valid AgentBOM files found");
    return 1;
  }

  const report = generateMultiAgentAuditReport(boms);
  console.log(report);
  return 0;
}

export function auditReportCommand(args: string[]): number {
  // Dispatch to multi-agent subcommand
  if (args.length > 0 && args[0] === "multi") {
    return multiAgentAuditReportCommand(args.slice(1));
  }

  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    console.log(
      [
        "Usage: agent-trust audit-report <bom.json>",
        "       agent-trust audit-report multi <bom1.json> [bom2.json ...]",
        "       agent-trust audit-report multi --dir <directory>",
        "",
        "Generates a human-readable audit summary with evidence citations from an AgentBOM file.",
        'Use "multi" subcommand for unified multi-agent audit reports with causal chain reconstruction.',
        "",
        "Arguments:",
        "  <bom.json>  Path to the AgentBOM JSON file",
        "",
        "Output includes:",
        "  - Agent identity information",
        "  - Audit summary statistics",
        "  - Risk summary by severity",
        "  - Evidence citations (hashes and AEP references)",
        "  - Detailed audit trail grouped by event type",
      ].join("\n"),
    );
    return 0;
  }

  const bomPath = args[0];
  try {
    const content = readFileSync(resolve(bomPath), "utf-8");
    const data = JSON.parse(content) as AgentBOM;

    // Validate the AgentBOM
    const validation = validateAgentBOM(data);
    if (!validation.valid) {
      console.error("Error: Invalid AgentBOM file:");
      for (const error of validation.errors) {
        console.error(`  ${error}`);
      }
      return 1;
    }

    // Generate and print the audit report
    const report = generateAuditReport(data);
    console.log(report);
    return 0;
  } catch (err) {
    console.error(
      `Error: Failed to read or parse AgentBOM file: ${err instanceof Error ? err.message : String(err)}`,
    );
    return 1;
  }
}
