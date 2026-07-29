#!/usr/bin/env bun
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateAgentBOM } from '@wasmagent/agentbom-core';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Supported regulatory frameworks */
type FrameworkId = 'soc2' | 'iso27001' | 'ai-act';

const SUPPORTED_FRAMEWORKS: FrameworkId[] = ['soc2', 'iso27001', 'ai-act'];

/** Maps CLI framework id to the compliance profile file */
const FRAMEWORK_TO_PROFILE: Record<FrameworkId, string> = {
  soc2: 'soc2-2024',
  iso27001: 'iso27001-2022',
  'ai-act': 'eu-ai-act-annex-iv',
};

/** Framework display names */
const FRAMEWORK_DISPLAY: Record<FrameworkId, string> = {
  soc2: 'SOC 2 Type II (2024)',
  iso27001: 'ISO/IEC 27001:2022',
  'ai-act': 'EU AI Act — High-Risk AI Systems',
};

/** Evidence detail level */
type EvidenceLevel = 'summary' | 'detailed';

/** Output format */
type ReportFormat = 'text' | 'json';

interface ComplianceProfile {
  profile_version: string;
  profile_id: string;
  framework: {
    name: string;
    version: string;
    description?: string;
  };
  rules: {
    identity?: {
      required_fields?: string[];
      allowed_contexts?: string[];
      requires_version?: boolean;
    };
    tool_layer?: {
      max_severity?: string;
      requires_tool_inventory?: boolean;
      blocked_permissions?: string[];
      blocked_sources?: string[];
    };
    risk_layer?: {
      requires_risk_assessment?: boolean;
      max_unmitigated_critical?: number;
      max_unmitigated_high?: number;
      max_unmitigated_medium?: number;
      requires_mitigation_for?: string[];
    };
    attestation?: {
      requires_signature?: boolean;
      requires_timestamp?: boolean;
    };
  };
  metadata?: {
    author?: string;
    documentation_url?: string;
  };
}

/** A single control objective in the report */
interface ControlObjective {
  id: string;
  title: string;
  description: string;
  status: 'satisfied' | 'partial' | 'not_satisfied' | 'not_applicable';
  evidence: EvidenceCitation[];
  findings: string[];
}

/** Evidence citation linking AgentBOM data to a control */
interface EvidenceCitation {
  source: string;
  description: string;
  timestamp?: string;
}

/** The full regulatory report */
interface RegulatoryReport {
  report_metadata: {
    framework: string;
    framework_version: string;
    period?: string;
    generated_at: string;
    agent_id?: string;
    agent_name?: string;
    evidence_level: EvidenceLevel;
  };
  executive_summary: {
    overall_status: 'compliant' | 'partial' | 'non_compliant';
    controls_assessed: number;
    controls_satisfied: number;
    controls_partial: number;
    controls_not_satisfied: number;
    evidence_citations: number;
  };
  control_objectives: ControlObjective[];
  evidence_inventory: EvidenceCitation[];
}

// ---------------------------------------------------------------------------
// Control objective definitions per framework
// ---------------------------------------------------------------------------

interface ControlDef {
  id: string;
  title: string;
  description: string;
  /** Which AgentBOM section(s) provide evidence */
  assess: (
    bom: Record<string, unknown>,
    profile: ComplianceProfile,
  ) => {
    status: ControlObjective['status'];
    evidence: EvidenceCitation[];
    findings: string[];
  };
}

function getControlDefs(framework: FrameworkId, evidenceLevel: EvidenceLevel): ControlDef[] {
  switch (framework) {
    case 'soc2':
      return soc2Controls(evidenceLevel);
    case 'iso27001':
      return iso27001Controls(evidenceLevel);
    case 'ai-act':
      return aiActControls(evidenceLevel);
  }
}

function soc2Controls(ev: EvidenceLevel): ControlDef[] {
  return [
    {
      id: 'SOC2.CC6.1',
      title: 'Logical and Physical Access Controls',
      description:
        'The entity implements logical and physical access controls over information technology resources.',
      assess: (bom, profile) => assessIdentityAccess(bom, profile, ev),
    },
    {
      id: 'SOC2.CC6.2',
      title: 'User Authentication',
      description:
        'The entity authenticates users and authorizes access to facilitate accountability.',
      assess: (bom, profile) => assessIdentityAuth(bom, profile, ev),
    },
    {
      id: 'SOC2.CC6.3',
      title: 'Role-Based Access',
      description:
        'The entity authorizes, modifies, and removes access to data and resources based on roles.',
      assess: (bom, profile) => assessToolPermissions(bom, profile, ev),
    },
    {
      id: 'SOC2.CC7.1',
      title: 'Detection and Monitoring',
      description:
        'The entity detects and monitors system defects, potential attacks, and intrusions.',
      assess: (bom, profile) => assessRiskMonitoring(bom, profile, ev),
    },
    {
      id: 'SOC2.CC7.2',
      title: 'Incident Response',
      description: 'The entity responds to identified incidents to mitigate impact.',
      assess: (bom, profile) => assessRiskIncidentResponse(bom, profile, ev),
    },
    {
      id: 'SOC2.CC8.1',
      title: 'Change Management',
      description:
        'The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes.',
      assess: (bom, profile) => assessChangeManagement(bom, profile, ev),
    },
    {
      id: 'SOC2.A1.2',
      title: 'Attestation Integrity',
      description:
        'Management provides an assertion that includes a description of the system and a description of the complementary subservices.',
      assess: (bom, profile) => assessAttestation(bom, profile, ev),
    },
  ];
}

function iso27001Controls(ev: EvidenceLevel): ControlDef[] {
  return [
    {
      id: 'ISO27001.A.5.15',
      title: 'Access Control',
      description:
        'Rules to control physical and logical access to information and other associated assets.',
      assess: (bom, profile) => assessIdentityAccess(bom, profile, ev),
    },
    {
      id: 'ISO27001.A.5.16',
      title: 'Identity Management',
      description: 'Identity management life cycle for people and non-person entities.',
      assess: (bom, profile) => assessIdentityAuth(bom, profile, ev),
    },
    {
      id: 'ISO27001.A.8.9',
      title: 'Configuration Management',
      description: 'Secure configuration of hardware, software, services and networks.',
      assess: (bom, profile) => assessToolPermissions(bom, profile, ev),
    },
    {
      id: 'ISO27001.A.8.20',
      title: 'Networks Security',
      description: 'Security of networks and network devices.',
      assess: (bom, profile) => assessToolPermissions(bom, profile, ev),
    },
    {
      id: 'ISO27001.A.6.1',
      title: 'Risk Assessment',
      description: 'Risk assessment process defined and applied.',
      assess: (bom, profile) => assessRiskMonitoring(bom, profile, ev),
    },
    {
      id: 'ISO27001.A.6.8',
      title: 'Information Security Event Management',
      description: 'Information security events and weaknesses to be reported and managed.',
      assess: (bom, profile) => assessRiskIncidentResponse(bom, profile, ev),
    },
    {
      id: 'ISO27001.A.8.25',
      title: 'Secure Development Lifecycle',
      description: 'Rules for secure development of software and systems.',
      assess: (bom, profile) => assessChangeManagement(bom, profile, ev),
    },
    {
      id: 'ISO27001.A.5.35',
      title: 'Independent Security Review',
      description: 'Independent review of information security to be performed.',
      assess: (bom, profile) => assessAttestation(bom, profile, ev),
    },
  ];
}

function aiActControls(ev: EvidenceLevel): ControlDef[] {
  return [
    {
      id: 'AI-ACT.ANNEX-IV.1',
      title: 'System Overview and Architecture',
      description:
        'Technical documentation shall include a general description of the high-risk AI system.',
      assess: (bom, profile) => assessIdentityAccess(bom, profile, ev),
    },
    {
      id: 'AI-ACT.ANNEX-IV.2',
      title: 'Data Governance and Training',
      description: 'Description of data collection, preparation, and training processes.',
      assess: (bom, profile) => assessAIActData(bom, profile, ev),
    },
    {
      id: 'AI-ACT.ANNEX-IV.3',
      title: 'Transparency and Human Oversight',
      description: 'Design and development choices for enabling effective oversight of the system.',
      assess: (bom, profile) => assessAIActOversight(bom, profile, ev),
    },
    {
      id: 'AI-ACT.ANNEX-IV.4',
      title: 'Risk Management',
      description: 'Risk management system and mitigation measures implemented.',
      assess: (bom, profile) => assessRiskMonitoring(bom, profile, ev),
    },
    {
      id: 'AI-ACT.ANNEX-IV.5',
      title: 'Performance Metrics and Accuracy',
      description: 'Performance metrics for accuracy, robustness, and cybersecurity of the system.',
      assess: (bom, profile) => assessRiskIncidentResponse(bom, profile, ev),
    },
    {
      id: 'AI-ACT.ANNEX-IV.6',
      title: 'Conformity Assessment',
      description: 'Evidence of conformity assessment and technical documentation.',
      assess: (bom, profile) => assessAttestation(bom, profile, ev),
    },
  ];
}

// ---------------------------------------------------------------------------
// Control assessment functions
// ---------------------------------------------------------------------------

function assessIdentityAccess(
  bom: Record<string, unknown>,
  profile: ComplianceProfile,
  ev: EvidenceLevel,
): { status: ControlObjective['status']; evidence: EvidenceCitation[]; findings: string[] } {
  const evidence: EvidenceCitation[] = [];
  const findings: string[] = [];
  const identity = bom.identity as Record<string, unknown> | undefined;

  if (!identity) {
    findings.push('Identity section missing — cannot verify agent identity or access controls');
    return { status: 'not_satisfied', evidence, findings };
  }

  // Agent ID present
  if (identity.agent_id) {
    evidence.push({
      source: 'agentbom.identity.agent_id',
      description: `Agent identity: ${identity.agent_id}`,
    });
  } else {
    findings.push('agent_id missing from identity section');
  }

  // Check deployment context
  const allowedContexts = profile.rules.identity?.allowed_contexts ?? [];
  const context = String(identity.deployment_context ?? '');
  if (context && (allowedContexts.length === 0 || allowedContexts.includes(context))) {
    evidence.push({
      source: 'agentbom.identity.deployment_context',
      description: `Deployment context: ${context}`,
    });
  } else if (allowedContexts.length > 0) {
    findings.push(
      `Deployment context "${context}" not in allowed list [${allowedContexts.join(', ')}]`,
    );
  }

  // Version check
  if (identity.agent_version) {
    evidence.push({
      source: 'agentbom.identity.agent_version',
      description: `Agent version: ${identity.agent_version}`,
    });
  } else if (profile.rules.identity?.requires_version) {
    findings.push('agent_version required but missing');
  }

  // Timestamp for evidence
  const generatedAt = String(identity.generated_at ?? '');
  if (generatedAt && ev === 'detailed') {
    evidence.push({
      source: 'agentbom.identity.generated_at',
      description: `BOM generated at: ${generatedAt}`,
      timestamp: generatedAt,
    });
  }

  const status: ControlObjective['status'] =
    findings.length === 0 ? 'satisfied' : evidence.length > 0 ? 'partial' : 'not_satisfied';
  return { status, evidence, findings };
}

function assessIdentityAuth(
  bom: Record<string, unknown>,
  _profile: ComplianceProfile,
  ev: EvidenceLevel,
): { status: ControlObjective['status']; evidence: EvidenceCitation[]; findings: string[] } {
  const evidence: EvidenceCitation[] = [];
  const findings: string[] = [];
  const identity = bom.identity as Record<string, unknown> | undefined;

  if (!identity) {
    findings.push('Identity section missing — cannot verify authentication mechanism');
    return { status: 'not_satisfied', evidence, findings };
  }

  // Agent name provides identity accountability
  if (identity.agent_name) {
    evidence.push({
      source: 'agentbom.identity.agent_name',
      description: `Named agent: ${identity.agent_name}`,
    });
  }

  if (identity.agent_version) {
    evidence.push({
      source: 'agentbom.identity.agent_version',
      description: `Versioned release: ${identity.agent_version}`,
    });
  }

  if (ev === 'detailed' && identity.generated_at) {
    evidence.push({
      source: 'agentbom.identity.generated_at',
      description: `Identity established at: ${identity.generated_at}`,
      timestamp: String(identity.generated_at),
    });
  }

  return {
    status: evidence.length > 0 ? 'satisfied' : 'not_satisfied',
    evidence,
    findings,
  };
}

function assessToolPermissions(
  bom: Record<string, unknown>,
  profile: ComplianceProfile,
  ev: EvidenceLevel,
): { status: ControlObjective['status']; evidence: EvidenceCitation[]; findings: string[] } {
  const evidence: EvidenceCitation[] = [];
  const findings: string[] = [];
  const toolLayer = bom.tool_layer as unknown[] | undefined;

  if (!toolLayer || toolLayer.length === 0) {
    findings.push('Tool layer missing or empty — cannot assess permission controls');
    return { status: 'not_satisfied', evidence, findings };
  }

  evidence.push({
    source: 'agentbom.tool_layer',
    description: `${toolLayer.length} tool(s) inventoried`,
  });

  const blockedPerms = new Set(profile.rules.tool_layer?.blocked_permissions ?? []);
  const blockedSources = new Set(profile.rules.tool_layer?.blocked_sources ?? []);

  for (const tool of toolLayer) {
    if (typeof tool !== 'object' || tool === null) continue;
    const t = tool as Record<string, unknown>;

    // Check permissions
    const permissions = (t.permissions as string[] | undefined) ?? [];
    const hasBlocked = permissions.some((p) =>
      Array.from(blockedPerms).some((bp) => p.toLowerCase().includes(bp.toLowerCase())),
    );
    if (hasBlocked) {
      findings.push(`Tool "${t.tool_name}" has blocked permission(s)`);
    } else if (ev === 'detailed') {
      evidence.push({
        source: `agentbom.tool_layer[${t.tool_name}].permissions`,
        description: `Permissions reviewed: [${permissions.join(', ')}]`,
      });
    }

    // Check source
    const source = String(t.source ?? '');
    const isBlocked = Array.from(blockedSources).some((bs) =>
      source.toLowerCase().includes(bs.toLowerCase()),
    );
    if (isBlocked) {
      findings.push(`Tool "${t.tool_name}" has blocked source "${source}"`);
    } else if (ev === 'detailed') {
      evidence.push({
        source: `agentbom.tool_layer[${t.tool_name}].source`,
        description: `Source: ${source || 'internal'}`,
      });
    }
  }

  const status: ControlObjective['status'] =
    findings.length === 0 ? 'satisfied' : evidence.length > 0 ? 'partial' : 'not_satisfied';
  return { status, evidence, findings };
}

function assessRiskMonitoring(
  bom: Record<string, unknown>,
  profile: ComplianceProfile,
  ev: EvidenceLevel,
): { status: ControlObjective['status']; evidence: EvidenceCitation[]; findings: string[] } {
  const evidence: EvidenceCitation[] = [];
  const findings: string[] = [];
  const riskLayer = bom.risk_layer as unknown[] | undefined;

  if (!riskLayer || riskLayer.length === 0) {
    if (profile.rules.risk_layer?.requires_risk_assessment) {
      findings.push('Risk assessment required but risk_layer is empty');
      return { status: 'not_satisfied', evidence, findings };
    }
    return { status: 'not_applicable', evidence, findings };
  }

  evidence.push({
    source: 'agentbom.risk_layer',
    description: `${riskLayer.length} risk(s) assessed`,
  });

  // Count unmitigated by severity
  const unmitigated: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const mitigatedCount = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const risk of riskLayer) {
    if (typeof risk !== 'object' || risk === null) continue;
    const r = risk as Record<string, unknown>;
    const severity = String(r.severity ?? '').toLowerCase();
    const status = String(r.status ?? '').toLowerCase();
    const isMitigated = status === 'mitigated' || status === 'accepted';

    if (severity in unmitigated) {
      if (isMitigated) {
        mitigatedCount[severity]++;
      } else {
        unmitigated[severity]++;
      }
    }

    if (ev === 'detailed') {
      evidence.push({
        source: `agentbom.risk_layer[${r.risk_id}]`,
        description: `${r.description ?? r.risk_id}: ${severity} — ${status}`,
      });
    }
  }

  // Check thresholds from profile
  const maxCritical =
    profile.rules.risk_layer?.max_unmitigated_critical ?? Number.POSITIVE_INFINITY;
  const maxHigh = profile.rules.risk_layer?.max_unmitigated_high ?? Number.POSITIVE_INFINITY;
  const maxMedium = profile.rules.risk_layer?.max_unmitigated_medium ?? Number.POSITIVE_INFINITY;

  if (unmitigated.critical > maxCritical) {
    findings.push(
      `${unmitigated.critical} unmitigated critical risk(s) exceeds threshold (${maxCritical})`,
    );
  }
  if (unmitigated.high > maxHigh) {
    findings.push(`${unmitigated.high} unmitigated high risk(s) exceeds threshold (${maxHigh})`);
  }
  if (unmitigated.medium > maxMedium) {
    findings.push(
      `${unmitigated.medium} unmitigated medium risk(s) exceeds threshold (${maxMedium})`,
    );
  }

  if (ev === 'detailed') {
    evidence.push({
      source: 'agentbom.risk_layer (aggregate)',
      description: `Mitigated: ${Object.values(mitigatedCount).reduce((a, b) => a + b, 0)} / Unmitigated: ${Object.values(unmitigated).reduce((a, b) => a + b, 0)}`,
    });
  }

  const resultStatus: ControlObjective['status'] =
    findings.length === 0 ? 'satisfied' : evidence.length > 0 ? 'partial' : 'not_satisfied';
  return { status: resultStatus, evidence, findings };
}

function assessRiskIncidentResponse(
  bom: Record<string, unknown>,
  _profile: ComplianceProfile,
  ev: EvidenceLevel,
): { status: ControlObjective['status']; evidence: EvidenceCitation[]; findings: string[] } {
  const evidence: EvidenceCitation[] = [];
  const findings: string[] = [];
  const auditLog = bom.audit_log as unknown[] | undefined;

  if (!auditLog || auditLog.length === 0) {
    findings.push('No audit log entries — cannot verify incident detection and response');
    return { status: 'not_satisfied', evidence, findings };
  }

  evidence.push({
    source: 'agentbom.audit_log',
    description: `${auditLog.length} audit event(s) recorded`,
  });

  // Count events by outcome
  const outcomes = { success: 0, failure: 0, partial: 0 };
  for (const entry of auditLog) {
    if (typeof entry !== 'object' || entry === null) continue;
    const e = entry as Record<string, unknown>;
    const outcome = String(e.outcome ?? '');
    if (outcome in outcomes) {
      (outcomes as Record<string, number>)[outcome]++;
    }
    if (ev === 'detailed') {
      evidence.push({
        source: `agentbom.audit_log[${e.timestamp ?? 'unknown'}]`,
        description: `${e.event_type ?? 'unknown'} by ${e.actor ?? 'unknown'} — ${outcome}`,
        timestamp: String(e.timestamp ?? ''),
      });
    }
  }

  if (outcomes.failure > 0) {
    evidence.push({
      source: 'agentbom.audit_log (aggregate)',
      description: `${outcomes.failure} failure(s) detected and logged`,
    });
  }

  return {
    status: evidence.length > 0 ? 'satisfied' : 'not_satisfied',
    evidence,
    findings,
  };
}

function assessChangeManagement(
  bom: Record<string, unknown>,
  _profile: ComplianceProfile,
  ev: EvidenceLevel,
): { status: ControlObjective['status']; evidence: EvidenceCitation[]; findings: string[] } {
  const evidence: EvidenceCitation[] = [];
  const findings: string[] = [];
  const identity = bom.identity as Record<string, unknown> | undefined;

  if (!identity) {
    findings.push('Identity section missing — cannot assess versioning and change tracking');
    return { status: 'not_satisfied', evidence, findings };
  }

  if (identity.agent_version) {
    evidence.push({
      source: 'agentbom.identity.agent_version',
      description: `Version tracked: ${identity.agent_version}`,
    });
  } else {
    findings.push('No agent_version — change management cannot be verified');
  }

  if (identity.generated_at) {
    evidence.push({
      source: 'agentbom.identity.generated_at',
      description: `BOM generated: ${identity.generated_at}`,
      timestamp: String(identity.generated_at),
    });
  }

  // Check for tool layer which shows current inventory state
  const toolLayer = bom.tool_layer as unknown[] | undefined;
  if (toolLayer && toolLayer.length > 0) {
    evidence.push({
      source: 'agentbom.tool_layer',
      description: `Tool inventory snapshot: ${toolLayer.length} tool(s)`,
    });
  }

  if (ev === 'detailed') {
    const agentbomVersion = String(bom.agentbom_version ?? 'unknown');
    evidence.push({
      source: 'agentbom.agentbom_version',
      description: `Schema version: ${agentbomVersion}`,
    });
  }

  const status: ControlObjective['status'] = evidence.length > 0 ? 'satisfied' : 'not_satisfied';
  return { status, evidence, findings };
}

function assessAttestation(
  bom: Record<string, unknown>,
  profile: ComplianceProfile,
  ev: EvidenceLevel,
): { status: ControlObjective['status']; evidence: EvidenceCitation[]; findings: string[] } {
  const evidence: EvidenceCitation[] = [];
  const findings: string[] = [];
  const attestation = bom.attestation as Record<string, unknown> | undefined;

  if (!attestation) {
    if (
      profile.rules.attestation?.requires_signature ||
      profile.rules.attestation?.requires_timestamp
    ) {
      findings.push('Attestation section missing — required for independent review');
      return { status: 'not_satisfied', evidence, findings };
    }
    return { status: 'not_applicable', evidence, findings };
  }

  // Signature check
  if (attestation.signature) {
    evidence.push({
      source: 'agentbom.attestation.signature',
      description: 'Signed attestation present',
    });
  } else if (profile.rules.attestation?.requires_signature) {
    findings.push('Attestation signature required but missing');
  }

  // Timestamp check
  if (attestation.timestamp) {
    evidence.push({
      source: 'agentbom.attestation.timestamp',
      description: `Attested at: ${attestation.timestamp}`,
      timestamp: String(attestation.timestamp),
    });
  } else if (profile.rules.attestation?.requires_timestamp) {
    findings.push('Attestation timestamp required but missing');
  }

  if (ev === 'detailed' && attestation.authority) {
    evidence.push({
      source: 'agentbom.attestation.authority',
      description: `Attesting authority: ${attestation.authority}`,
    });
  }

  const status: ControlObjective['status'] =
    findings.length === 0 ? 'satisfied' : evidence.length > 0 ? 'partial' : 'not_satisfied';
  return { status, evidence, findings };
}

function assessAIActData(
  bom: Record<string, unknown>,
  _profile: ComplianceProfile,
  _ev: EvidenceLevel,
): { status: ControlObjective['status']; evidence: EvidenceCitation[]; findings: string[] } {
  const evidence: EvidenceCitation[] = [];
  const findings: string[] = [];
  const toolLayer = bom.tool_layer as unknown[] | undefined;

  // For AI Act data governance, look at tool layer sources and permissions
  // as proxy indicators for data handling practices
  if (toolLayer && toolLayer.length > 0) {
    evidence.push({
      source: 'agentbom.tool_layer',
      description: `${toolLayer.length} tool(s) — data handling can be assessed per tool`,
    });
  } else {
    findings.push('No tool inventory — data governance scope cannot be assessed');
  }

  // Check if evidence layer exists (AEP references indicate evidence trail)
  const evidenceLayer = bom.evidence_layer as Record<string, unknown> | undefined;
  if (evidenceLayer) {
    const aepRefs = (evidenceLayer.aep_references as string[] | undefined) ?? [];
    if (aepRefs.length > 0) {
      evidence.push({
        source: 'agentbom.evidence_layer.aep_references',
        description: `${aepRefs.length} AEP evidence reference(s) — training data provenance trail`,
      });
    }
  }

  return {
    status: evidence.length > 0 ? 'satisfied' : 'not_satisfied',
    evidence,
    findings,
  };
}

function assessAIActOversight(
  bom: Record<string, unknown>,
  _profile: ComplianceProfile,
  _ev: EvidenceLevel,
): { status: ControlObjective['status']; evidence: EvidenceCitation[]; findings: string[] } {
  const evidence: EvidenceCitation[] = [];
  const findings: string[] = [];
  const attestation = bom.attestation as Record<string, unknown> | undefined;
  const identity = bom.identity as Record<string, unknown> | undefined;

  if (attestation?.signature) {
    evidence.push({
      source: 'agentbom.attestation.signature',
      description: 'Attestation signature present — supports human oversight chain',
    });
  }

  if (identity?.agent_name) {
    evidence.push({
      source: 'agentbom.identity.agent_name',
      description: `Agent "${identity.agent_name}" — identifiable for oversight`,
    });
  }

  if (evidence.length === 0) {
    findings.push('Insufficient evidence for human oversight assessment');
  }

  return {
    status: evidence.length > 0 ? 'satisfied' : 'not_satisfied',
    evidence,
    findings,
  };
}

// ---------------------------------------------------------------------------
// Profile loading
// ---------------------------------------------------------------------------

function loadProfile(profileId: string): ComplianceProfile | null {
  const profilesDir = resolve(dirname(fileURLToPath(import.meta.url)), '../profiles');
  const profilePath = resolve(profilesDir, `${profileId}.json`);
  try {
    const raw = readFileSync(profilePath, 'utf-8');
    return JSON.parse(raw) as ComplianceProfile;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

function buildReport(
  framework: FrameworkId,
  bom: Record<string, unknown>,
  profile: ComplianceProfile,
  period: string | undefined,
  evidenceLevel: EvidenceLevel,
): RegulatoryReport {
  const controlDefs = getControlDefs(framework, evidenceLevel);
  const controlObjectives: ControlObjective[] = [];

  const allEvidence: EvidenceCitation[] = [];

  for (const def of controlDefs) {
    const result = def.assess(bom, profile);
    controlObjectives.push({
      id: def.id,
      title: def.title,
      description: def.description,
      status: result.status,
      evidence: result.evidence,
      findings: result.findings,
    });
    allEvidence.push(...result.evidence);
  }

  const satisfied = controlObjectives.filter((c) => c.status === 'satisfied').length;
  const partial = controlObjectives.filter((c) => c.status === 'partial').length;
  const notSatisfied = controlObjectives.filter((c) => c.status === 'not_satisfied').length;

  const overallStatus: RegulatoryReport['executive_summary']['overall_status'] =
    notSatisfied === 0 && partial === 0
      ? 'compliant'
      : notSatisfied === 0
        ? 'partial'
        : partial > notSatisfied
          ? 'partial'
          : 'non_compliant';

  const identity = bom.identity as Record<string, unknown> | undefined;

  return {
    report_metadata: {
      framework: FRAMEWORK_DISPLAY[framework],
      framework_version: profile.framework.version,
      period,
      generated_at: new Date().toISOString(),
      agent_id: String(identity?.agent_id ?? ''),
      agent_name: String(identity?.agent_name ?? ''),
      evidence_level: evidenceLevel,
    },
    executive_summary: {
      overall_status: overallStatus,
      controls_assessed: controlObjectives.length,
      controls_satisfied: satisfied,
      controls_partial: partial,
      controls_not_satisfied: notSatisfied,
      evidence_citations: allEvidence.length,
    },
    control_objectives: controlObjectives,
    evidence_inventory: allEvidence,
  };
}

// ---------------------------------------------------------------------------
// Text formatter
// ---------------------------------------------------------------------------

function formatReportText(report: RegulatoryReport): string {
  const lines: string[] = [];
  const meta = report.report_metadata;
  const summary = report.executive_summary;

  lines.push('════════════════════════════════════════════════════════════════════════════════');
  lines.push('                          REGULATORY COMPLIANCE REPORT');
  lines.push('════════════════════════════════════════════════════════════════════════════════');
  lines.push('');
  lines.push(`  Framework:     ${meta.framework} (${meta.framework_version})`);
  if (meta.period) lines.push(`  Period:        ${meta.period}`);
  if (meta.agent_id) lines.push(`  Agent ID:      ${meta.agent_id}`);
  if (meta.agent_name) lines.push(`  Agent Name:    ${meta.agent_name}`);
  lines.push(`  Generated:     ${meta.generated_at}`);
  lines.push(`  Evidence Level: ${meta.evidence_level}`);
  lines.push('');

  // Executive summary
  lines.push(
    '────────────────────────────────────────────────────────────────────────────────────',
  );
  lines.push('                              EXECUTIVE SUMMARY');
  lines.push(
    '────────────────────────────────────────────────────────────────────────────────────',
  );
  lines.push('');

  const statusIcon =
    summary.overall_status === 'compliant' ? '✓' : summary.overall_status === 'partial' ? '⚠' : '✗';
  const statusLabel = summary.overall_status.replace('_', ' ').toUpperCase();
  lines.push(`  Overall Status:    ${statusIcon} ${statusLabel}`);
  lines.push(`  Controls Assessed: ${summary.controls_assessed}`);
  lines.push(`    Satisfied:       ${summary.controls_satisfied}`);
  lines.push(`    Partial:         ${summary.controls_partial}`);
  lines.push(`    Not Satisfied:   ${summary.controls_not_satisfied}`);
  lines.push(`  Evidence Citations: ${summary.evidence_citations}`);
  lines.push('');

  // Control objectives
  lines.push(
    '────────────────────────────────────────────────────────────────────────────────────',
  );
  lines.push('                           CONTROL OBJECTIVES');
  lines.push(
    '────────────────────────────────────────────────────────────────────────────────────',
  );
  lines.push('');

  for (const control of report.control_objectives) {
    const icon =
      control.status === 'satisfied'
        ? '✓'
        : control.status === 'partial'
          ? '⚠'
          : control.status === 'not_applicable'
            ? '—'
            : '✗';
    const statusLabel = control.status.replace('_', ' ').toUpperCase();

    lines.push(`  ${icon} [${control.id}] ${control.title} — ${statusLabel}`);
    lines.push(`      ${control.description}`);
    lines.push('');

    if (control.evidence.length > 0) {
      lines.push('      Evidence:');
      for (const ev of control.evidence) {
        lines.push(`        → ${ev.source}: ${ev.description}`);
      }
      lines.push('');
    }

    if (control.findings.length > 0) {
      lines.push('      Findings:');
      for (const finding of control.findings) {
        lines.push(`        ⚠ ${finding}`);
      }
      lines.push('');
    }
  }

  // Footer
  lines.push('════════════════════════════════════════════════════════════════════════════════');
  lines.push(`Report generated by Agent Trust Infrastructure — ${meta.generated_at}`);
  lines.push('════════════════════════════════════════════════════════════════════════════════');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// CLI command
// ---------------------------------------------------------------------------

export function reportCommand(args: string[]): number {
  // Parse arguments
  let framework: FrameworkId | undefined;
  let period: string | undefined;
  let format: ReportFormat = 'text';
  let evidenceLevel: EvidenceLevel = 'summary';
  let bomPath: string | undefined;
  let showHelp = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--help' || args[i] === '-h') {
      showHelp = true;
    } else if (args[i] === '--framework' && i + 1 < args.length) {
      framework = args[++i] as FrameworkId;
    } else if (args[i] === '--period' && i + 1 < args.length) {
      period = args[++i];
    } else if (args[i] === '--format' && i + 1 < args.length) {
      const val = args[++i];
      if (val !== 'text' && val !== 'json') {
        console.error(`Error: invalid --format "${val}"; use text or json`);
        return 1;
      }
      format = val as ReportFormat;
    } else if (args[i] === '--evidence-level' && i + 1 < args.length) {
      const val = args[++i];
      if (val !== 'summary' && val !== 'detailed') {
        console.error(`Error: invalid --evidence-level "${val}"; use summary or detailed`);
        return 1;
      }
      evidenceLevel = val as EvidenceLevel;
    } else if (!args[i].startsWith('--')) {
      bomPath = args[i];
    }
  }

  if (showHelp) {
    console.log(
      [
        'Usage: agent-trust report <bom.json> --framework <soc2|iso27001|ai-act> [--period <period>] [--format text|json] [--evidence-level summary|detailed]',
        '',
        'Generates a compliance-ready regulatory report from AgentBOM data,',
        'mapping trust artifacts to framework-specific control objectives with evidence citations.',
        '',
        'Arguments:',
        '  <bom.json>              Path to the AgentBOM JSON file',
        '',
        'Required options:',
        '  --framework <id>       Regulatory framework: soc2, iso27001, ai-act',
        '',
        'Optional options:',
        '  --period <period>      Reporting period (e.g., Q1-2026, FY2025)',
        '  --format <fmt>         Output format: text (default) or json',
        '  --evidence-level <l>  Evidence detail: summary (default) or detailed',
        '',
        'Supported frameworks:',
        '  soc2      SOC 2 Type II (2024) — security, availability, confidentiality',
        '  iso27001  ISO/IEC 27001:2022 — information security management',
        '  ai-act    EU AI Act — high-risk AI systems (Art. 11, Annex IV)',
      ].join('\n'),
    );
    return 0;
  }

  // Validate required args
  if (!bomPath) {
    console.error('Error: report requires a <bom.json> argument');
    console.error('Usage: agent-trust report <bom.json> --framework <soc2|iso27001|ai-act>');
    return 1;
  }

  if (!framework) {
    console.error('Error: report requires --framework <soc2|iso27001|ai-act>');
    return 1;
  }

  if (!SUPPORTED_FRAMEWORKS.includes(framework)) {
    console.error(
      `Error: unsupported framework "${framework}"; must be one of: ${SUPPORTED_FRAMEWORKS.join(', ')}`,
    );
    return 1;
  }

  // Load AgentBOM
  const resolvedPath = resolve(bomPath);
  let bomRaw: string;
  try {
    bomRaw = readFileSync(resolvedPath, 'utf-8');
  } catch {
    console.error(`Error: cannot read file "${resolvedPath}"`);
    return 1;
  }

  let bomData: unknown;
  try {
    bomData = JSON.parse(bomRaw);
  } catch {
    console.error(`Error: "${resolvedPath}" is not valid JSON`);
    return 1;
  }

  // Validate AgentBOM
  const validation = validateAgentBOM(bomData);
  if (!validation.valid) {
    console.error(`Error: AgentBOM validation failed for "${resolvedPath}":`);
    for (const err of validation.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  // Load compliance profile
  const profileId = FRAMEWORK_TO_PROFILE[framework];

  // Load compliance profile from file
  let profile: ComplianceProfile;
  const loaded = loadProfile(profileId);
  if (!loaded) {
    console.error(`Error: cannot load compliance profile "${profileId}"`);
    console.error(`Expected file: profiles/${profileId}.json`);
    return 1;
  }
  profile = loaded;

  // Build report
  const report = buildReport(
    framework,
    bomData as Record<string, unknown>,
    profile,
    period,
    evidenceLevel,
  );

  // Output
  if (format === 'json') {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatReportText(report));
  }

  return report.executive_summary.overall_status === 'non_compliant' ? 1 : 0;
}
