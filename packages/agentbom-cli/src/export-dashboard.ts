#!/usr/bin/env bun
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { validateAgentBOM } from "@wasmagent/agentbom-core";

/** AgentBOM structure for dashboard generation */
export interface AgentBOM {
  agentbom_version: string;
  identity?: {
    agent_id?: string;
    agent_name?: string;
    agent_version?: string;
    deployment_context?: string;
    generated_at?: string;
  };
  model_layer?: {
    provider?: string;
    model_id?: string;
    model_version?: string;
    capabilities?: string[];
  };
  tool_layer?: Array<{
    tool_id?: string;
    tool_name?: string;
    source?: string;
    permissions?: string[];
    risk_signals?: string[];
    mcp_server_id?: string;
  }>;
  prompt_layer?: {
    system_prompt_hash?: string;
    template_ids?: string[];
  };
  permission_layer?: {
    granted_scopes?: string[];
    data_access?: string[];
    credential_references?: string[];
  };
  evidence_layer?: {
    aep_references?: string[];
    evidence_hashes?: Array<{
      type?: string;
      hash?: string;
      timestamp?: string;
    }>;
  };
  risk_layer?: Array<{
    risk_id?: string;
    severity?: string;
    category?: string;
    description?: string;
    status?: string;
  }>;
  audit_log?: Array<{
    timestamp?: string;
    event_type?: string;
    actor?: string;
    resource?: string;
    outcome?: string;
    details?: Record<string, unknown>;
  }>;
  attestation?: {
    generator?: string;
    generator_version?: string;
  };
}

/** Generate HTML dashboard from AgentBOM data */
export function generateDashboardHTML(bom: AgentBOM): string {
  const identity = bom.identity || {};
  const modelLayer = bom.model_layer || {};
  const toolLayer = bom.tool_layer || [];
  const permissionLayer = bom.permission_layer || {};
  const evidenceLayer = bom.evidence_layer || {};
  const riskLayer = bom.risk_layer || [];
  const auditLog = bom.audit_log || [];
  const attestation = bom.attestation || {};

  // Calculate statistics
  const totalTools = toolLayer.length;
  const builtInTools = toolLayer.filter((t) => t.source === "builtin").length;
  const mcpTools = toolLayer.filter((t) => t.source === "mcp").length;
  const pluginTools = toolLayer.filter((t) => t.source === "plugin").length;

  const riskStats = {
    critical: riskLayer.filter((r) => r.severity === "critical").length,
    high: riskLayer.filter((r) => r.severity === "high").length,
    medium: riskLayer.filter((r) => r.severity === "medium").length,
    low: riskLayer.filter((r) => r.severity === "low").length,
    info: riskLayer.filter((r) => r.severity === "info").length,
  };

  const openRisks = riskLayer.filter((r) => r.status === "open").length;
  const acceptedRisks = riskLayer.filter((r) => r.status === "accepted").length;
  const mitigatedRisks = riskLayer.filter(
    (r) => r.status === "mitigated",
  ).length;

  const auditEvents = auditLog.length;
  const successfulEvents = auditLog.filter(
    (a) => a.outcome === "success",
  ).length;
  const failedEvents = auditLog.filter((a) => a.outcome === "failure").length;

  const severityColor = (severity: string): string => {
    const colors = {
      critical: "#dc2626",
      high: "#ea580c",
      medium: "#ca8a04",
      low: "#16a34a",
      info: "#2563eb",
    };
    return colors[severity as keyof typeof colors] || "#6b7280";
  };

  const statusBadge = (status: string): string => {
    const badges = {
      open: '<span class="badge badge-open">Open</span>',
      accepted: '<span class="badge badge-accepted">Accepted</span>',
      mitigated: '<span class="badge badge-mitigated">Mitigated</span>',
    };
    return (
      badges[status as keyof typeof badges] ||
      `<span class="badge badge-unknown">${status}</span>`
    );
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Agent Trust Dashboard - ${identity.agent_name || "Unknown Agent"}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      padding: 20px;
      line-height: 1.6;
    }

    .container {
      max-width: 1400px;
      margin: 0 auto;
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      overflow: hidden;
    }

    .header {
      background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
      color: white;
      padding: 40px;
      text-align: center;
    }

    .header h1 {
      font-size: 2.5em;
      margin-bottom: 10px;
      font-weight: 700;
    }

    .header .subtitle {
      font-size: 1.1em;
      opacity: 0.9;
      margin-top: 10px;
    }

    .header .meta {
      margin-top: 20px;
      padding-top: 20px;
      border-top: 1px solid rgba(255, 255, 255, 0.2);
      font-size: 0.9em;
      opacity: 0.8;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      padding: 40px;
      background: #f8fafc;
    }

    .stat-card {
      background: white;
      padding: 24px;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
      text-align: center;
      transition: transform 0.2s;
    }

    .stat-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    }

    .stat-value {
      font-size: 2.5em;
      font-weight: 700;
      color: #1e3a8a;
      margin-bottom: 8px;
    }

    .stat-label {
      font-size: 0.9em;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .section {
      padding: 40px;
      border-bottom: 1px solid #e5e7eb;
    }

    .section:last-child {
      border-bottom: none;
    }

    .section-title {
      font-size: 1.8em;
      color: #1e293b;
      margin-bottom: 24px;
      font-weight: 600;
    }

    .info-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 20px;
    }

    .info-card {
      background: #f8fafc;
      padding: 20px;
      border-radius: 8px;
      border-left: 4px solid #3b82f6;
    }

    .info-card .label {
      font-size: 0.85em;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }

    .info-card .value {
      font-size: 1.1em;
      color: #1e293b;
      font-weight: 500;
      word-break: break-word;
    }

    .tools-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 16px;
    }

    .tool-card {
      background: #f8fafc;
      padding: 20px;
      border-radius: 8px;
      border: 1px solid #e5e7eb;
    }

    .tool-card .tool-name {
      font-weight: 600;
      color: #1e293b;
      margin-bottom: 8px;
      font-size: 1.1em;
    }

    .tool-card .tool-id {
      font-size: 0.85em;
      color: #64748b;
      margin-bottom: 12px;
    }

    .tool-card .badges {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }

    .tool-card .permissions {
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px solid #e5e7eb;
    }

    .tool-card .permissions-title {
      font-size: 0.85em;
      color: #64748b;
      margin-bottom: 6px;
    }

    .tool-card .permission-tags {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }

    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 0.75em;
      font-weight: 600;
      text-transform: uppercase;
    }

    .badge.builtin {
      background: #dbeafe;
      color: #1e40af;
    }

    .badge.mcp {
      background: #fef3c7;
      color: #92400e;
    }

    .badge.plugin {
      background: #e0e7ff;
      color: #3730a3;
    }

    .badge-risk {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.75em;
      font-weight: 600;
      background: #fee2e2;
      color: #991b1b;
    }

    .permission-tag {
      background: #f1f5f9;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 0.75em;
      color: #475569;
    }

    .risk-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }

    .risk-table th,
    .risk-table td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #e5e7eb;
    }

    .risk-table th {
      background: #f8fafc;
      font-weight: 600;
      color: #475569;
      font-size: 0.85em;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .risk-table tr:hover {
      background: #f8fafc;
    }

    .risk-table .severity-indicator {
      display: inline-block;
      width: 12px;
      height: 12px;
      border-radius: 50%;
      margin-right: 8px;
    }

    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 0.75em;
      font-weight: 600;
      text-transform: uppercase;
    }

    .badge-open {
      background: #fee2e2;
      color: #991b1b;
    }

    .badge-accepted {
      background: #dcfce7;
      color: #166534;
    }

    .badge-mitigated {
      background: #dbeafe;
      color: #1e40af;
    }

    .audit-log {
      max-height: 400px;
      overflow-y: auto;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
    }

    .audit-entry {
      padding: 16px;
      border-bottom: 1px solid #e5e7eb;
    }

    .audit-entry:last-child {
      border-bottom: none;
    }

    .audit-entry .timestamp {
      font-size: 0.85em;
      color: #64748b;
      margin-bottom: 8px;
    }

    .audit-entry .event-type {
      font-weight: 600;
      color: #1e293b;
      margin-bottom: 8px;
    }

    .audit-entry .details {
      font-size: 0.9em;
      color: #475569;
      margin-top: 8px;
    }

    .audit-entry .outcome {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 0.75em;
      font-weight: 600;
      margin-left: 8px;
    }

    .audit-entry .outcome.success {
      background: #dcfce7;
      color: #166534;
    }

    .audit-entry .outcome.failure {
      background: #fee2e2;
      color: #991b1b;
    }

    .evidence-list {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 16px;
    }

    .evidence-item {
      background: #f8fafc;
      padding: 16px;
      border-radius: 8px;
      border: 1px solid #e5e7eb;
    }

    .evidence-item .type {
      font-weight: 600;
      color: #1e293b;
      margin-bottom: 8px;
    }

    .evidence-item .hash {
      font-family: monospace;
      font-size: 0.85em;
      color: #64748b;
      word-break: break-all;
    }

    .evidence-item .timestamp {
      font-size: 0.75em;
      color: #94a3b8;
      margin-top: 8px;
    }

    .footer {
      background: #1e293b;
      color: #94a3b8;
      padding: 20px;
      text-align: center;
      font-size: 0.9em;
    }

    .empty-state {
      text-align: center;
      padding: 40px;
      color: #64748b;
    }

    .capabilities-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 8px;
    }

    .capability-tag {
      background: #e0f2fe;
      color: #0369a1;
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 0.8em;
      font-weight: 500;
    }

    @media (max-width: 768px) {
      .header h1 {
        font-size: 1.8em;
      }

      .stats-grid {
        grid-template-columns: repeat(2, 1fr);
      }

      .tools-grid {
        grid-template-columns: 1fr;
      }

      .info-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔒 Agent Trust Dashboard</h1>
      <div class="subtitle">${identity.agent_name || "Unknown Agent"}</div>
      <div class="meta">
        Agent ID: ${identity.agent_id || "N/A"} |
        Version: ${identity.agent_version || "N/A"} |
        Generated: ${identity.generated_at ? new Date(identity.generated_at).toLocaleDateString() : "N/A"}
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">${totalTools}</div>
        <div class="stat-label">Total Tools</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${openRisks}</div>
        <div class="stat-label">Open Risks</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${auditEvents}</div>
        <div class="stat-label">Audit Events</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${evidenceLayer.evidence_hashes?.length || 0}</div>
        <div class="stat-label">Evidence Items</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${successfulEvents}</div>
        <div class="stat-label">Successful Operations</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${failedEvents}</div>
        <div class="stat-label">Failed Operations</div>
      </div>
    </div>

    <div class="section">
      <h2 class="section-title">🤖 Model Information</h2>
      <div class="info-grid">
        <div class="info-card">
          <div class="label">Provider</div>
          <div class="value">${modelLayer.provider || "N/A"}</div>
        </div>
        <div class="info-card">
          <div class="label">Model ID</div>
          <div class="value">${modelLayer.model_id || "N/A"}</div>
        </div>
        <div class="info-card">
          <div class="label">Model Version</div>
          <div class="value">${modelLayer.model_version || "N/A"}</div>
        </div>
        <div class="info-card">
          <div class="label">Capabilities</div>
          <div class="value">
            <div class="capabilities-list">
              ${(modelLayer.capabilities || [])
                .map((cap) => `<span class="capability-tag">${cap}</span>`)
                .join("")}
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="section">
      <h2 class="section-title">🛠️ Tool Layer (${totalTools} tools)</h2>
      <div class="tools-grid">
        ${toolLayer
          .map(
            (tool) => `
          <div class="tool-card">
            <div class="tool-name">${tool.tool_name || "Unnamed Tool"}</div>
            <div class="tool-id">${tool.tool_id || "No ID"}</div>
            <div class="badges">
              <span class="badge ${tool.source || "builtin"}">${tool.source || "builtin"}</span>
              ${(tool.risk_signals || [])
                .map((signal) => `<span class="badge-risk">⚠️ ${signal}</span>`)
                .join("")}
            </div>
            <div class="permissions">
              <div class="permissions-title">Permissions:</div>
              <div class="permission-tags">
                ${(tool.permissions || [])
                  .map((perm) => `<span class="permission-tag">${perm}</span>`)
                  .join("")}
              </div>
            </div>
          </div>
        `,
          )
          .join("")}
      </div>
      ${toolLayer.length === 0 ? '<div class="empty-state">No tools configured</div>' : ""}
    </div>

    <div class="section">
      <h2 class="section-title">⚠️ Risk Assessment</h2>
      <div class="info-grid" style="margin-bottom: 20px;">
        <div class="info-card" style="border-left-color: #dc2626;">
          <div class="label">Critical</div>
          <div class="value">${riskStats.critical}</div>
        </div>
        <div class="info-card" style="border-left-color: #ea580c;">
          <div class="label">High</div>
          <div class="value">${riskStats.high}</div>
        </div>
        <div class="info-card" style="border-left-color: #ca8a04;">
          <div class="label">Medium</div>
          <div class="value">${riskStats.medium}</div>
        </div>
        <div class="info-card" style="border-left-color: #16a34a;">
          <div class="label">Low</div>
          <div class="value">${riskStats.low}</div>
        </div>
      </div>
      ${
        riskLayer.length > 0
          ? `
        <table class="risk-table">
          <thead>
            <tr>
              <th>Risk ID</th>
              <th>Severity</th>
              <th>Category</th>
              <th>Description</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${riskLayer
              .map(
                (risk) => `
              <tr>
                <td>${risk.risk_id || "N/A"}</td>
                <td>
                  <span class="severity-indicator" style="background: ${severityColor(risk.severity || "info")}"></span>
                  ${risk.severity || "N/A"}
                </td>
                <td>${risk.category || "N/A"}</td>
                <td>${risk.description || "No description"}</td>
                <td>${statusBadge(risk.status || "unknown")}</td>
              </tr>
            `,
              )
              .join("")}
          </tbody>
        </table>
      `
          : '<div class="empty-state">No risks identified</div>'
      }
    </div>

    <div class="section">
      <h2 class="section-title">🔐 Permissions & Access</h2>
      <div class="info-grid">
        <div class="info-card">
          <div class="label">Granted Scopes</div>
          <div class="value">
            <div class="permission-tags" style="margin-top: 8px;">
              ${(permissionLayer.granted_scopes || [])
                .map((scope) => `<span class="permission-tag">${scope}</span>`)
                .join("")}
            </div>
          </div>
        </div>
        <div class="info-card">
          <div class="label">Data Access</div>
          <div class="value">
            <div class="permission-tags" style="margin-top: 8px;">
              ${(permissionLayer.data_access || [])
                .map(
                  (access) => `<span class="permission-tag">${access}</span>`,
                )
                .join("")}
            </div>
          </div>
        </div>
        <div class="info-card">
          <div class="label">Credential References</div>
          <div class="value">
            <div class="permission-tags" style="margin-top: 8px;">
              ${(permissionLayer.credential_references || [])
                .map((cred) => `<span class="permission-tag">${cred}</span>`)
                .join("")}
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="section">
      <h2 class="section-title">🔍 Evidence & Attestation</h2>
      <div class="evidence-list">
        ${(evidenceLayer.evidence_hashes || [])
          .map(
            (evidence) => `
          <div class="evidence-item">
            <div class="type">${evidence.type || "Unknown"}</div>
            <div class="hash">${evidence.hash || "No hash"}</div>
            <div class="timestamp">${evidence.timestamp ? new Date(evidence.timestamp).toLocaleString() : "No timestamp"}</div>
          </div>
        `,
          )
          .join("")}
      </div>
      ${!evidenceLayer.evidence_hashes || evidenceLayer.evidence_hashes.length === 0 ? '<div class="empty-state">No evidence hashes found</div>' : ""}

      ${
        evidenceLayer.aep_references && evidenceLayer.aep_references.length > 0
          ? `
        <div style="margin-top: 24px;">
          <h3 style="font-size: 1.2em; color: #475569; margin-bottom: 16px;">AEP References</h3>
          <div class="permission-tags">
            ${evidenceLayer.aep_references
              .map((ref) => `<span class="permission-tag">${ref}</span>`)
              .join("")}
          </div>
        </div>
      `
          : ""
      }
    </div>

    ${
      auditLog.length > 0
        ? `
    <div class="section">
      <h2 class="section-title">📋 Audit Log</h2>
      <div class="audit-log">
        ${auditLog
          .map(
            (entry) => `
          <div class="audit-entry">
            <div class="timestamp">${entry.timestamp || "No timestamp"}</div>
            <div class="event-type">
              ${entry.event_type || "Unknown Event"}
              <span class="outcome ${entry.outcome || ""}">${entry.outcome || "unknown"}</span>
            </div>
            <div class="details">
              Actor: ${entry.actor || "Unknown"} | Resource: ${entry.resource || "N/A"}
              ${entry.details ? `<br>Details: <code>${JSON.stringify(entry.details)}</code>` : ""}
            </div>
          </div>
        `,
          )
          .join("")}
      </div>
    </div>
    `
        : ""
    }

    <div class="footer">
      <div>Generated by ${attestation.generator || "Unknown"} v${attestation.generator_version || "N/A"}</div>
      <div style="margin-top: 8px;">Report generated: ${new Date().toISOString()}</div>
    </div>
  </div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Fleet trust analytics dashboard
// ---------------------------------------------------------------------------
// Generates a fleet-level dashboard covering the four capabilities called out
// in the Milestone 8 "Trust analytics dashboard" bullet:
//   1. Trust posture across an agent fleet (aggregate + per-agent overview)
//   2. BOM dependency graphs (agent -> model / MCP servers / tools / scopes)
//   3. Compliance heatmap (per-agent x trust-control posture grid)
//   4. Audit log search with temporal (date-range) + text + event-type filters
// ---------------------------------------------------------------------------

/** Escape a value for safe interpolation into HTML. */
function escapeHtml(value: unknown): string {
  const s = value === undefined || value === null ? "" : String(value);
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

type ControlStatus = "pass" | "warn" | "fail";

interface ControlResult {
  name: string;
  status: ControlStatus;
  detail: string;
}

const CONTROL_LABELS: Record<string, string> = {
  identity: "Identity",
  tools: "Tool Inventory",
  risks: "Risk Mgmt",
  permissions: "Permissions",
  evidence: "Evidence",
  attestation: "Attestation",
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function assessIdentity(bom: AgentBOM): ControlResult {
  const id = bom.identity || {};
  const fields = [
    id.agent_id,
    id.agent_name,
    id.agent_version,
    id.deployment_context,
  ];
  const present = fields.filter(
    (f) => f !== undefined && String(f).trim() !== "",
  ).length;
  if (!bom.identity || present === 0) {
    return { name: "identity", status: "fail", detail: "No identity metadata" };
  }
  if (present === fields.length) {
    return {
      name: "identity",
      status: "pass",
      detail: "Complete identity record",
    };
  }
  return {
    name: "identity",
    status: "warn",
    detail: `${present}/${fields.length} identity fields present`,
  };
}

function assessTools(bom: AgentBOM): ControlResult {
  const tools = bom.tool_layer || [];
  if (tools.length === 0) {
    return { name: "tools", status: "fail", detail: "No tool inventory" };
  }
  const dangerous = tools.filter((t) => {
    const sig = t.risk_signals || [];
    return (
      sig.includes("command_execution") || sig.includes("privilege_escalation")
    );
  }).length;
  if (dangerous === 0) {
    return {
      name: "tools",
      status: "pass",
      detail: `${tools.length} tools, no high-risk signals`,
    };
  }
  return {
    name: "tools",
    status: "warn",
    detail: `${tools.length} tools, ${dangerous} with high-risk signals`,
  };
}

function assessRisks(bom: AgentBOM): ControlResult {
  const risks = bom.risk_layer || [];
  if (risks.length === 0) {
    return { name: "risks", status: "pass", detail: "No risks recorded" };
  }
  const open = risks.filter((r) => r.status === "open");
  const openCritical = open.filter((r) => r.severity === "critical").length;
  const openHigh = open.filter((r) => r.severity === "high").length;
  if (openCritical > 0) {
    return {
      name: "risks",
      status: "fail",
      detail: `${openCritical} open critical risk(s)`,
    };
  }
  if (openHigh > 2) {
    return {
      name: "risks",
      status: "fail",
      detail: `${openHigh} open high risk(s)`,
    };
  }
  if (openHigh > 0) {
    return {
      name: "risks",
      status: "warn",
      detail: `${openHigh} open high risk(s)`,
    };
  }
  return {
    name: "risks",
    status: "pass",
    detail: "All risks mitigated or accepted",
  };
}

function assessPermissions(bom: AgentBOM): ControlResult {
  const scopes = bom.permission_layer?.granted_scopes || [];
  if (scopes.length === 0) {
    return {
      name: "permissions",
      status: "fail",
      detail: "No permission scopes documented",
    };
  }
  const highRisk = scopes.filter(
    (s) => s === "process:exec" || s === "network:outbound",
  ).length;
  if (highRisk > 0) {
    return {
      name: "permissions",
      status: "warn",
      detail: `${scopes.length} scopes incl. ${highRisk} high-risk`,
    };
  }
  return {
    name: "permissions",
    status: "pass",
    detail: `${scopes.length} documented scopes`,
  };
}

function assessEvidence(bom: AgentBOM): ControlResult {
  const ev = bom.evidence_layer || {};
  const hashes = ev.evidence_hashes?.length || 0;
  const aep = ev.aep_references?.length || 0;
  if (hashes === 0 && aep === 0) {
    return {
      name: "evidence",
      status: "fail",
      detail: "No evidence or AEP references",
    };
  }
  if (hashes === 0 || aep === 0) {
    return {
      name: "evidence",
      status: "warn",
      detail: "Partial evidence coverage",
    };
  }
  return {
    name: "evidence",
    status: "pass",
    detail: `${hashes} evidence hash(es), ${aep} AEP ref(s)`,
  };
}

function assessAttestation(bom: AgentBOM): ControlResult {
  const att = bom.attestation || {};
  if (!att.generator) {
    return {
      name: "attestation",
      status: "fail",
      detail: "No attestation generator",
    };
  }
  if (!att.generator_version) {
    return {
      name: "attestation",
      status: "warn",
      detail: "Generator recorded, version missing",
    };
  }
  return {
    name: "attestation",
    status: "pass",
    detail: `${att.generator} v${att.generator_version}`,
  };
}

/** Assess a single AgentBOM against the fleet trust-posture controls. */
export function assessControls(bom: AgentBOM): ControlResult[] {
  return [
    assessIdentity(bom),
    assessTools(bom),
    assessRisks(bom),
    assessPermissions(bom),
    assessEvidence(bom),
    assessAttestation(bom),
  ];
}

const STATUS_WEIGHT: Record<ControlStatus, number> = {
  pass: 2,
  warn: 1,
  fail: 0,
};

/** Compute a 0-100 trust posture score for an AgentBOM from its control results. */
export function postureScore(bom: AgentBOM): number {
  const controls = assessControls(bom);
  const total = controls.length * 2;
  const earned = controls.reduce((acc, c) => acc + STATUS_WEIGHT[c.status], 0);
  return total > 0 ? Math.round((earned / total) * 100) : 0;
}

/** Highest severity label among an AgentBOM's risks ('' when there are none). */
export function maxSeverity(bom: AgentBOM): string {
  let max = "";
  let rank = -1;
  for (const r of bom.risk_layer || []) {
    const r2 = SEVERITY_RANK[r.severity || ""] ?? -1;
    if (r2 > rank) {
      rank = r2;
      max = r.severity || "";
    }
  }
  return max;
}

function truncateLabel(value: string, max = 16): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

interface GraphNode {
  id: string;
  label: string;
  kind: string;
}

interface GraphEdge {
  from: string;
  to: string;
}

const GRAPH_KIND_COLORS: Record<string, string> = {
  agent: "#1e3a8a",
  model: "#0f766e",
  mcp: "#b45309",
  builtin: "#475569",
  plugin: "#6d28d9",
  permission: "#be123c",
};

/** Derive a BOM dependency graph: agent -> model, MCP servers, tool groups, scopes. */
export function buildDependencyGraph(bom: AgentBOM): {
  nodes: GraphNode[];
  edges: GraphEdge[];
} {
  const agentId = bom.identity?.agent_id || "agent";
  const nodes: GraphNode[] = [
    { id: agentId, label: bom.identity?.agent_name || "agent", kind: "agent" },
  ];
  const edges: GraphEdge[] = [];

  if (bom.model_layer?.model_id) {
    nodes.push({ id: "model", label: bom.model_layer.model_id, kind: "model" });
    edges.push({ from: agentId, to: "model" });
  }

  const servers = new Set<string>();
  for (const t of bom.tool_layer || []) {
    if (t.source === "mcp" && t.mcp_server_id) servers.add(t.mcp_server_id);
  }
  for (const s of servers) {
    const id = `srv:${s}`;
    nodes.push({ id, label: s, kind: "mcp" });
    edges.push({ from: agentId, to: id });
  }

  const tools = bom.tool_layer || [];
  const builtin = tools.filter(
    (t) => (t.source || "builtin") === "builtin",
  ).length;
  const plugin = tools.filter((t) => t.source === "plugin").length;
  if (builtin > 0) {
    nodes.push({
      id: "builtin",
      label: `builtin tools (${builtin})`,
      kind: "builtin",
    });
    edges.push({ from: agentId, to: "builtin" });
  }
  if (plugin > 0) {
    nodes.push({
      id: "plugin",
      label: `plugin tools (${plugin})`,
      kind: "plugin",
    });
    edges.push({ from: agentId, to: "plugin" });
  }

  const scopes = (bom.permission_layer?.granted_scopes || []).slice(0, 8);
  for (const sc of scopes) {
    const id = `perm:${sc}`;
    nodes.push({ id, label: sc, kind: "permission" });
    edges.push({ from: agentId, to: id });
  }

  return { nodes, edges };
}

/** Render a single agent's dependency graph as a self-contained inline SVG. */
export function renderDependencyGraphSVG(bom: AgentBOM): string {
  const { nodes, edges } = buildDependencyGraph(bom);
  const agentId = bom.identity?.agent_id || "agent";
  const dependents = nodes.filter((n) => n.id !== agentId);
  const width = 480;
  const agentX = 90;
  const depX = 350;
  const rowH = 38;
  const height = Math.max(140, dependents.length * rowH + 40);
  const agentY = height / 2;

  const pos = new Map<string, { x: number; y: number }>();
  pos.set(agentId, { x: agentX, y: agentY });
  dependents.forEach((n, i) => {
    pos.set(n.id, { x: depX, y: 30 + i * rowH + rowH / 2 });
  });

  const edgeSvg = edges
    .map((e) => {
      const a = pos.get(e.from);
      const b = pos.get(e.to);
      if (!a || !b) return "";
      return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#cbd5e1" stroke-width="1.5"/>`;
    })
    .join("");

  const nodeSvg = nodes
    .map((n) => {
      const p = pos.get(n.id);
      if (!p) return "";
      const fill = GRAPH_KIND_COLORS[n.kind] || "#475569";
      const text = escapeHtml(truncateLabel(n.label));
      if (n.id === agentId) {
        return `<circle cx="${p.x}" cy="${p.y}" r="34" fill="${fill}"/><text x="${p.x}" y="${p.y + 4}" text-anchor="middle" fill="white" font-size="9" font-weight="700">${text}</text>`;
      }
      return `<rect x="${p.x - 70}" y="${p.y - 14}" width="140" height="28" rx="6" fill="${fill}" opacity="0.92"/><text x="${p.x}" y="${p.y + 4}" text-anchor="middle" fill="white" font-size="10">${text}</text>`;
    })
    .join("");

  return `<svg viewBox="0 0 ${width} ${height}" width="100%" height="${height}" role="img" aria-label="BOM dependency graph">${edgeSvg}${nodeSvg}</svg>`;
}

interface FleetAuditEntry {
  agent: string;
  timestamp?: string;
  event_type?: string;
  actor?: string;
  resource?: string;
  outcome?: string;
  details?: Record<string, unknown>;
}

function parseTs(t?: string): number {
  if (!t) return 0;
  const n = Date.parse(t);
  return Number.isNaN(n) ? 0 : n;
}

/** Merge audit logs across a fleet, sorted oldest-first by timestamp. */
export function mergeAuditEntries(
  boms: { bom: AgentBOM; source: string }[],
): FleetAuditEntry[] {
  const out: FleetAuditEntry[] = [];
  for (const { bom } of boms) {
    const agent =
      bom.identity?.agent_name || bom.identity?.agent_id || "unknown";
    for (const e of bom.audit_log || []) {
      out.push({ agent, ...e });
    }
  }
  out.sort((a, b) => parseTs(a.timestamp) - parseTs(b.timestamp));
  return out;
}

const HEATMAP_CELL_CLASS: Record<ControlStatus, string> = {
  pass: "hm-pass",
  warn: "hm-warn",
  fail: "hm-fail",
};

const SEVERITY_BADGE_CLASS: Record<string, string> = {
  critical: "risk-critical",
  high: "risk-high",
  medium: "risk-med",
  low: "risk-low",
};

/** Generate a fleet trust analytics dashboard HTML document. */
export function generateFleetDashboardHTML(
  boms: { bom: AgentBOM; source: string }[],
): string {
  let totalTools = 0;
  let openRisks = 0;
  let openCriticalHigh = 0;
  let withAttestation = 0;
  for (const { bom } of boms) {
    totalTools += (bom.tool_layer || []).length;
    const open = (bom.risk_layer || []).filter((r) => r.status === "open");
    openRisks += open.length;
    openCriticalHigh += open.filter(
      (r) => r.severity === "critical" || r.severity === "high",
    ).length;
    if (bom.attestation?.generator) withAttestation += 1;
  }
  const audit = mergeAuditEntries(boms);
  const eventTypes = Array.from(
    new Set(audit.map((a) => a.event_type).filter(Boolean)),
  );
  const generatedAt = new Date().toISOString();

  const postureRows = boms
    .map(({ bom, source }) => {
      const sev = maxSeverity(bom);
      const score = postureScore(bom);
      const sevClass = SEVERITY_BADGE_CLASS[sev] || "risk-low";
      const open = (bom.risk_layer || []).filter(
        (r) => r.status === "open",
      ).length;
      return `<tr>
            <td>${escapeHtml(bom.identity?.agent_name || "unnamed")}</td>
            <td><code>${escapeHtml(bom.identity?.agent_id || "N/A")}</code></td>
            <td>${escapeHtml(bom.identity?.deployment_context || "N/A")}</td>
            <td>${(bom.tool_layer || []).length}</td>
            <td><span class="badge ${sevClass}">${sev || "none"}</span></td>
            <td>${open}</td>
            <td><strong>${score}</strong></td>
            <td><code>${escapeHtml(source)}</code></td>
          </tr>`;
    })
    .join("");

  const heatmapHeader = Object.values(CONTROL_LABELS)
    .map((label) => `<th>${label}</th>`)
    .join("");

  const heatmapRows = boms
    .map(({ bom }) => {
      const controls = assessControls(bom);
      const cells = controls
        .map(
          (c) =>
            `<td class="${HEATMAP_CELL_CLASS[c.status]}" title="${escapeHtml(c.detail)}"><span class="hm-glyph">${c.status[0].toUpperCase()}</span></td>`,
        )
        .join("");
      const score = postureScore(bom);
      return `<tr>
            <td class="hm-agent">${escapeHtml(bom.identity?.agent_name || "unnamed")}</td>
            ${cells}
            <td class="hm-score">${score}</td>
          </tr>`;
    })
    .join("");

  const graphCards = boms
    .map(({ bom }) => {
      const name = escapeHtml(bom.identity?.agent_name || "unnamed");
      return `<div class="graph-card">
            <div class="graph-title">${name}</div>
            ${renderDependencyGraphSVG(bom)}
          </div>`;
    })
    .join("");

  const eventTypeOptions = eventTypes
    .map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`)
    .join("");

  const auditBlock =
    audit.length === 0
      ? '<div class="empty-state">No audit events recorded across the fleet.</div>'
      : `<div class="audit-filters">
            <label>From <input type="date" id="f-from" /></label>
            <label>To <input type="date" id="f-to" /></label>
            <label>Search <input type="text" id="f-text" placeholder="agent, actor, resource…" /></label>
            <label>Event
              <select id="f-type">
                <option value="">(all)</option>
                ${eventTypeOptions}
              </select>
            </label>
            <span id="audit-count" class="audit-count"></span>
          </div>
          <div class="audit-scroll">
            <table class="audit-table">
              <thead>
                <tr>
                  <th>Timestamp</th><th>Agent</th><th>Event</th><th>Actor</th>
                  <th>Resource</th><th>Outcome</th><th>Details</th>
                </tr>
              </thead>
              <tbody id="audit-body">
                ${audit
                  .map((e) => {
                    const ts = e.timestamp || "";
                    const ms = parseTs(ts);
                    const text = [
                      e.agent,
                      e.event_type,
                      e.actor,
                      e.resource,
                      e.outcome,
                      JSON.stringify(e.details || {}),
                    ]
                      .join(" ")
                      .toLowerCase();
                    const outcomeClass =
                      e.outcome === "success"
                        ? "outcome-success"
                        : e.outcome === "failure"
                          ? "outcome-failure"
                          : "outcome-unknown";
                    const details = e.details
                      ? `<br><code>${escapeHtml(JSON.stringify(e.details))}</code>`
                      : "";
                    return `<tr data-ts="${ms}" data-type="${escapeHtml(e.event_type || "")}" data-text="${escapeHtml(text)}">
                      <td>${escapeHtml(ts)}</td>
                      <td>${escapeHtml(e.agent)}</td>
                      <td>${escapeHtml(e.event_type || "")}</td>
                      <td>${escapeHtml(e.actor || "")}</td>
                      <td>${escapeHtml(e.resource || "")}</td>
                      <td><span class="outcome ${outcomeClass}">${escapeHtml(e.outcome || "unknown")}</span></td>
                      <td>${details}</td>
                    </tr>`;
                  })
                  .join("")}
              </tbody>
            </table>
          </div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Fleet Trust Analytics — ${boms.length} agents</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a; color: #e2e8f0; line-height: 1.55; padding: 24px;
    }
    .wrap { max-width: 1280px; margin: 0 auto; }
    .header { margin-bottom: 28px; }
    .header h1 { font-size: 1.8em; font-weight: 700; color: #f8fafc; }
    .header .sub { color: #94a3b8; margin-top: 6px; font-size: 0.95em; }
    .stats-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 16px; margin-bottom: 32px;
    }
    .stat-card {
      background: #1e293b; border: 1px solid #334155; border-radius: 10px;
      padding: 18px;
    }
    .stat-card .v { font-size: 1.9em; font-weight: 700; color: #f8fafc; }
    .stat-card .l {
      font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.6px;
      color: #94a3b8; margin-top: 4px;
    }
    .stat-card.alert .v { color: #fca5a5; }
    section { margin-bottom: 36px; }
    h2 { font-size: 1.3em; color: #f1f5f9; margin-bottom: 14px; font-weight: 600; }
    .hint { color: #94a3b8; font-size: 0.88em; margin-bottom: 12px; }
    table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; font-size: 0.9em; }
    th { background: #0f172a; color: #94a3b8; text-transform: uppercase; font-size: 0.74em; letter-spacing: 0.5px; }
    td code { font-family: monospace; color: #93c5fd; font-size: 0.85em; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.72em; font-weight: 600; text-transform: uppercase; }
    .risk-critical { background: #7f1d1d; color: #fecaca; }
    .risk-high { background: #7c2d12; color: #fed7aa; }
    .risk-med { background: #713f12; color: #fde68a; }
    .risk-low { background: #14532d; color: #bbf7d0; }
    .heatmap th, .heatmap td { text-align: center; }
    .heatmap td.hm-agent, .heatmap th:first-child { text-align: left; }
    .hm-pass { background: #14532d; }
    .hm-warn { background: #713f12; }
    .hm-fail { background: #7f1d1d; }
    .hm-glyph { color: #f8fafc; font-weight: 700; font-size: 0.8em; }
    .hm-score { font-weight: 700; color: #f8fafc; }
    .graph-grid {
      display: grid; grid-template-columns: repeat(auto-fill, minmax(480px, 1fr)); gap: 16px;
    }
    .graph-card {
      background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 14px;
    }
    .graph-title { font-weight: 600; color: #f1f5f9; margin-bottom: 8px; }
    .graph-card svg { display: block; background: #0f172a; border-radius: 6px; }
    .audit-filters {
      display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin-bottom: 12px;
    }
    .audit-filters label { color: #cbd5e1; font-size: 0.85em; display: flex; flex-direction: column; gap: 4px; }
    .audit-filters input, .audit-filters select {
      background: #0f172a; border: 1px solid #334155; color: #e2e8f0; border-radius: 6px;
      padding: 6px 8px; font-size: 0.9em;
    }
    .audit-count { color: #94a3b8; font-size: 0.85em; margin-left: auto; }
    .audit-scroll { max-height: 460px; overflow: auto; border-radius: 10px; border: 1px solid #334155; }
    .audit-table th { position: sticky; top: 0; }
    .outcome { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72em; font-weight: 600; }
    .outcome-success { background: #14532d; color: #bbf7d0; }
    .outcome-failure { background: #7f1d1d; color: #fecaca; }
    .outcome-unknown { background: #334155; color: #cbd5e1; }
    .empty-state { color: #94a3b8; padding: 24px; text-align: center; background: #1e293b; border-radius: 10px; }
    .footer { color: #64748b; font-size: 0.82em; margin-top: 32px; text-align: center; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <h1>📊 Fleet Trust Analytics Dashboard</h1>
      <div class="sub">${boms.length} agent(s) · ${totalTools} tools fleet-wide · ${openRisks} open risk(s) · generated ${generatedAt}</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card"><div class="v">${boms.length}</div><div class="l">Agents</div></div>
      <div class="stat-card"><div class="v">${totalTools}</div><div class="l">Tools (fleet)</div></div>
      <div class="stat-card"><div class="v">${openRisks}</div><div class="l">Open Risks</div></div>
      <div class="stat-card alert"><div class="v">${openCriticalHigh}</div><div class="l">Open Critical/High</div></div>
      <div class="stat-card"><div class="v">${audit.length}</div><div class="l">Audit Events</div></div>
      <div class="stat-card"><div class="v">${withAttestation}/${boms.length}</div><div class="l">Attested</div></div>
    </div>

    <section>
      <h2>🛡️ Trust Posture Across the Fleet</h2>
      <div class="hint">Per-agent posture snapshot. Score blends identity, tool, risk, permission, evidence, and attestation controls.</div>
      <table>
        <thead>
          <tr>
            <th>Agent</th><th>Agent ID</th><th>Context</th><th>Tools</th>
            <th>Max Severity</th><th>Open Risks</th><th>Posture Score</th><th>Source</th>
          </tr>
        </thead>
        <tbody>${postureRows}</tbody>
      </table>
    </section>

    <section>
      <h2>🔥 Compliance Heatmap</h2>
      <div class="hint">P = pass, W = warn, F = fail. Hover a cell for detail.</div>
      <table class="heatmap">
        <thead>
          <tr><th>Agent</th>${heatmapHeader}<th>Score</th></tr>
        </thead>
        <tbody>${heatmapRows}</tbody>
      </table>
    </section>

    <section>
      <h2>🕸️ BOM Dependency Graphs</h2>
      <div class="hint">Agent → model, MCP servers, tool groups, and granted permission scopes.</div>
      <div class="graph-grid">${graphCards}</div>
    </section>

    <section>
      <h2>🔍 Audit Log Search</h2>
      <div class="hint">Temporal filtering by date range plus free-text and event-type search (runs in-browser).</div>
      ${auditBlock}
    </section>

    <div class="footer">Fleet trust analytics dashboard · @wasmagent/agent-trust-cli</div>
  </div>
  <script>
    (function () {
      var body = document.getElementById('audit-body');
      if (!body) return;
      var rows = body.querySelectorAll('tr');
      var countEl = document.getElementById('audit-count');
      function parseMs(dateStr, endOfDay) {
        if (!dateStr) return null;
        var suffix = endOfDay ? 'T23:59:59Z' : 'T00:00:00Z';
        var n = Date.parse(dateStr + suffix);
        return Number.isNaN(n) ? null : n;
      }
      function filterAudit() {
        var fromMs = parseMs(document.getElementById('f-from').value, false);
        var toMs = parseMs(document.getElementById('f-to').value, true);
        var text = (document.getElementById('f-text').value || '').toLowerCase();
        var type = document.getElementById('f-type').value;
        var visible = 0;
        for (var i = 0; i < rows.length; i++) {
          var r = rows[i];
          var ts = parseInt(r.getAttribute('data-ts'), 10);
          var rowText = r.getAttribute('data-text');
          var rowType = r.getAttribute('data-type');
          var keep = true;
          if (fromMs !== null && ts < fromMs) keep = false;
          if (toMs !== null && ts > toMs) keep = false;
          if (text && rowText.indexOf(text) === -1) keep = false;
          if (type && rowType !== type) keep = false;
          r.style.display = keep ? '' : 'none';
          if (keep) visible++;
        }
        if (countEl) countEl.textContent = visible + ' / ' + rows.length + ' entries';
      }
      var ids = ['f-from', 'f-to', 'f-text', 'f-type'];
      for (var j = 0; j < ids.length; j++) {
        var el = document.getElementById(ids[j]);
        if (el) {
          el.addEventListener('input', filterAudit);
          el.addEventListener('change', filterAudit);
        }
      }
      filterAudit();
    })();
  </script>
</body>
</html>`;
}

/** Command handler for `export-dashboard fleet <dir> --output <dir>`. */
export function exportFleetDashboardCommand(args: string[]): number {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    console.log(
      [
        "Usage: agent-trust export-dashboard fleet <dir> --output <dir>",
        "",
        "Generates a fleet trust analytics dashboard from every AgentBOM (*.json) in <dir>.",
        "",
        "Arguments:",
        "  <dir>            Directory containing AgentBOM JSON files (one per agent)",
        "  --output <dir>   Directory to write fleet-dashboard.html (required)",
        "",
        "The dashboard visualizes:",
        "  - Trust posture across the agent fleet (per-agent overview + scores)",
        "  - BOM dependency graphs (agent -> model / MCP servers / tools / scopes)",
        "  - Compliance heatmap (per-agent x trust-control posture grid)",
        "  - Audit log search with temporal (date-range), text, and event-type filters",
      ].join("\n"),
    );
    return 0;
  }

  let inputDir = "";
  let outputDir = "";
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--output" && i + 1 < args.length) {
      outputDir = args[i + 1];
      i++;
    } else if (!args[i].startsWith("--")) {
      inputDir = args[i];
    }
  }

  if (!inputDir) {
    console.error("Error: Missing required argument <dir>");
    return 1;
  }
  if (!outputDir) {
    console.error("Error: Missing required argument --output <dir>");
    return 1;
  }

  let entries: string[];
  try {
    entries = readdirSync(resolve(inputDir)).filter((f) => f.endsWith(".json"));
  } catch {
    console.error(`Error: cannot read fleet directory "${resolve(inputDir)}"`);
    return 1;
  }
  if (entries.length === 0) {
    console.error(
      `Error: no AgentBOM (*.json) files found in "${resolve(inputDir)}"`,
    );
    return 1;
  }

  const boms: { bom: AgentBOM; source: string }[] = [];
  for (const f of entries.sort()) {
    const filePath = resolve(inputDir, f);
    let content: string;
    try {
      content = readFileSync(filePath, "utf-8");
    } catch {
      console.warn(`Warning: skipping unreadable file "${f}"`);
      continue;
    }
    let data: unknown;
    try {
      data = JSON.parse(content);
    } catch {
      console.error(`Error: "${filePath}" is not valid JSON`);
      return 1;
    }
    const validation = validateAgentBOM(data);
    if (!validation.valid) {
      console.error(`Error: invalid AgentBOM in "${f}":`);
      for (const error of validation.errors) console.error(`  ${error}`);
      return 1;
    }
    boms.push({ bom: data as AgentBOM, source: f });
  }

  if (boms.length === 0) {
    console.error("Error: no valid AgentBOM files found in fleet directory");
    return 1;
  }

  const html = generateFleetDashboardHTML(boms);

  const outputPath = resolve(outputDir);
  try {
    mkdirSync(outputPath, { recursive: true });
  } catch {
    // Directory may already exist
  }
  const outputFile = resolve(outputPath, "fleet-dashboard.html");
  writeFileSync(outputFile, html, "utf-8");

  console.log(
    `✅ Fleet dashboard generated: ${outputFile} (${boms.length} agents)`,
  );
  return 0;
}

/** Command handler for export-dashboard */
export function exportDashboardCommand(args: string[]): number {
  if (args[0] === "fleet") {
    return exportFleetDashboardCommand(args.slice(1));
  }
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    console.log(
      [
        "Usage: agent-trust export-dashboard <bom.json> --output <dir>",
        "",
        "Generates a static HTML dashboard from an AgentBOM file.",
        "",
        "Arguments:",
        "  <bom.json>  Path to the AgentBOM JSON file",
        "  --output <dir>  Directory to write the HTML dashboard (required)",
        "",
        "The dashboard includes:",
        "  - Agent identity and model information",
        "  - Tool inventory with permissions and risk signals",
        "  - Risk assessment with severity breakdown",
        "  - Permissions and access overview",
        "  - Evidence and attestation data",
        "  - Audit log entries (if available)",
      ].join("\n"),
    );
    return 0;
  }

  let bomPath = "";
  let outputDir = "";

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--output" && i + 1 < args.length) {
      outputDir = args[i + 1];
      i++;
    } else if (!args[i].startsWith("--")) {
      bomPath = args[i];
    }
  }

  if (!bomPath) {
    console.error("Error: Missing required argument <bom.json>");
    return 1;
  }

  if (!outputDir) {
    console.error("Error: Missing required argument --output <dir>");
    return 1;
  }

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

    // Generate HTML
    const html = generateDashboardHTML(data);

    // Create output directory if it doesn't exist
    const outputPath = resolve(outputDir);
    try {
      mkdirSync(dirname(outputPath), { recursive: true });
    } catch {
      // Directory might already exist
    }

    // Write HTML file
    const outputFile = resolve(outputPath, "dashboard.html");
    writeFileSync(outputFile, html, "utf-8");

    console.log(`✅ Dashboard generated successfully: ${outputFile}`);
    return 0;
  } catch (err) {
    console.error(
      `Error: Failed to generate dashboard: ${err instanceof Error ? err.message : String(err)}`,
    );
    return 1;
  }
}
