/**
 * Compliance profile checker for AgentBOM.
 *
 * Evaluates an AgentBOM document against a structured compliance profile
 * (SOC 2, ISO 27001, EU AI Act, eIDAS, etc.) and returns a scored result.
 *
 * This module contains only pure library logic — no file I/O, no CLI output.
 * CLI wrappers (file loading, console output) live in the CLI package.
 */

// ─── Types ──────────────────────────────────────────────────────

export interface ComplianceResult {
  compliant: boolean;
  profile_id: string;
  framework_name: string;
  framework_version: string;
  score: number;
  threshold: number;
  errors: string[];
  warnings: string[];
  passed_checks: string[];
}

export interface ComplianceProfile {
  profile_version: string;
  profile_id: string;
  framework: {
    name: string;
    version: string;
    description?: string;
  };
  rules: {
    identity?: {
      weight?: number;
      required_fields?: string[];
      allowed_contexts?: string[];
      requires_version?: boolean;
    };
    tool_layer?: {
      weight?: number;
      max_severity?: "low" | "medium" | "high" | "critical";
      requires_tool_inventory?: boolean;
      blocked_permissions?: string[];
      blocked_sources?: string[];
    };
    risk_layer?: {
      weight?: number;
      requires_risk_assessment?: boolean;
      max_unmitigated_critical?: number;
      max_unmitigated_high?: number;
      max_unmitigated_medium?: number;
      requires_mitigation_for?: ("critical" | "high" | "medium" | "low")[];
    };
    attestation?: {
      weight?: number;
      requires_signature?: boolean;
      requires_timestamp?: boolean;
    };
  };
  metadata?: {
    author?: string;
    created_at?: string;
    updated_at?: string;
    documentation_url?: string;
  };
}

// ─── Internal helpers ────────────────────────────────────────────

const DEFAULT_RULE_WEIGHT = 1;

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

function severityLevel(severity: string): number {
  return SEVERITY_ORDER[severity as keyof typeof SEVERITY_ORDER] || 0;
}

// ─── Section checkers ─────────────────────────────────────────────

function checkIdentity(
  data: Record<string, unknown>,
  profile: ComplianceProfile,
): { errors: string[]; warnings: string[]; passed: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const passed: string[] = [];

  const identity = data.identity as Record<string, unknown> | undefined;

  if (!identity) {
    errors.push("identity section is missing");
    return { errors, warnings, passed };
  }

  const rules = profile.rules.identity;
  if (!rules) {
    passed.push("identity: no rules defined");
    return { errors, warnings, passed };
  }

  if (rules.required_fields) {
    for (const field of rules.required_fields) {
      if (
        !(field in identity) ||
        identity[field] === undefined ||
        identity[field] === null
      ) {
        errors.push(`identity: missing required field "${field}"`);
      } else {
        passed.push(`identity: field "${field}" present`);
      }
    }
  }

  if (rules.allowed_contexts && rules.allowed_contexts.length > 0) {
    const context = String(identity.deployment_context ?? "");
    if (!rules.allowed_contexts.includes(context)) {
      errors.push(
        `identity: deployment_context "${context}" not in allowed contexts [${rules.allowed_contexts.join(", ")}]`,
      );
    } else {
      passed.push(`identity: deployment_context "${context}" is allowed`);
    }
  }

  if (rules.requires_version) {
    if (
      !identity.agent_version ||
      String(identity.agent_version).trim() === ""
    ) {
      errors.push("identity: agent_version is required but missing or empty");
    } else {
      passed.push(
        `identity: agent_version "${identity.agent_version}" present`,
      );
    }
  }

  return { errors, warnings, passed };
}

function checkToolLayer(
  data: Record<string, unknown>,
  profile: ComplianceProfile,
): { errors: string[]; warnings: string[]; passed: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const passed: string[] = [];

  const toolLayer = data.tool_layer as unknown[] | undefined;

  const rules = profile.rules.tool_layer;
  if (!rules) {
    passed.push("tool_layer: no rules defined");
    return { errors, warnings, passed };
  }

  if (rules.requires_tool_inventory) {
    if (!toolLayer || toolLayer.length === 0) {
      errors.push(
        "tool_layer: tool inventory is required but missing or empty",
      );
    } else {
      passed.push(
        `tool_layer: tool inventory present (${toolLayer.length} tools)`,
      );
    }
  }

  if (!toolLayer || toolLayer.length === 0) {
    return { errors, warnings, passed };
  }

  if (rules.max_severity) {
    const maxLevel = severityLevel(rules.max_severity);
    for (const tool of toolLayer) {
      if (typeof tool === "object" && tool !== null) {
        const t = tool as Record<string, unknown>;
        const riskSignals = t.risk_signals as string[] | undefined;
        if (riskSignals) {
          for (const signal of riskSignals) {
            const severity = signal.split(":")[0]?.toLowerCase();
            if (severity && severityLevel(severity) > maxLevel) {
              errors.push(
                `tool_layer: tool "${t.tool_name}" has risk signal "${signal}" exceeding max severity "${rules.max_severity}"`,
              );
            }
          }
        }
      }
    }
    if (errors.filter((e) => e.startsWith("tool_layer: tool")).length === 0) {
      passed.push(
        `tool_layer: all tools within max severity "${rules.max_severity}"`,
      );
    }
  }

  if (rules.blocked_permissions && rules.blocked_permissions.length > 0) {
    const blockedPermissions = rules.blocked_permissions;
    for (const tool of toolLayer) {
      if (typeof tool === "object" && tool !== null) {
        const t = tool as Record<string, unknown>;
        const permissions = t.permissions as string[] | undefined;
        if (permissions) {
          for (const perm of permissions) {
            for (const blocked of blockedPermissions) {
              if (perm.toLowerCase().includes(blocked.toLowerCase())) {
                errors.push(
                  `tool_layer: tool "${t.tool_name}" has blocked permission "${perm}" (matches "${blocked}")`,
                );
              }
            }
          }
        }
      }
    }
  }

  if (rules.blocked_sources && rules.blocked_sources.length > 0) {
    const blockedSources = rules.blocked_sources;
    for (const tool of toolLayer) {
      if (typeof tool === "object" && tool !== null) {
        const t = tool as Record<string, unknown>;
        const source = String(t.source ?? "");
        for (const blocked of blockedSources) {
          if (source.toLowerCase().includes(blocked.toLowerCase())) {
            errors.push(
              `tool_layer: tool "${t.tool_name}" has blocked source "${source}"`,
            );
          }
        }
      }
    }
  }

  if (errors.filter((e) => e.startsWith("tool_layer:")).length === 0) {
    passed.push("tool_layer: no blocked permissions or sources found");
  }

  return { errors, warnings, passed };
}

function checkRiskLayer(
  data: Record<string, unknown>,
  profile: ComplianceProfile,
): { errors: string[]; warnings: string[]; passed: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const passed: string[] = [];

  const riskLayer = data.risk_layer as unknown[] | undefined;

  const rules = profile.rules.risk_layer;
  if (!rules) {
    passed.push("risk_layer: no rules defined");
    return { errors, warnings, passed };
  }

  if (rules.requires_risk_assessment) {
    if (!riskLayer || riskLayer.length === 0) {
      errors.push(
        "risk_layer: risk assessment is required but missing or empty",
      );
    } else {
      passed.push(
        `risk_layer: risk assessment present (${riskLayer.length} risks)`,
      );
    }
  }

  if (!riskLayer || riskLayer.length === 0) {
    return { errors, warnings, passed };
  }

  const unmitigatedCounts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  for (const risk of riskLayer) {
    if (typeof risk === "object" && risk !== null) {
      const r = risk as Record<string, unknown>;
      const severity = String(r.severity ?? "").toLowerCase();
      const status = String(r.status ?? "").toLowerCase();

      if (status !== "mitigated" && status !== "accepted") {
        if (severity in unmitigatedCounts) {
          unmitigatedCounts[severity]++;
        }
      }
    }
  }

  if (rules.max_unmitigated_critical !== undefined) {
    const count = unmitigatedCounts.critical;
    if (count > rules.max_unmitigated_critical) {
      errors.push(
        `risk_layer: ${count} unmitigated critical risks (max allowed: ${rules.max_unmitigated_critical})`,
      );
    } else {
      passed.push(
        `risk_layer: unmitigated critical risks within limit (${count}/${rules.max_unmitigated_critical})`,
      );
    }
  }

  if (rules.max_unmitigated_high !== undefined) {
    const count = unmitigatedCounts.high;
    if (count > rules.max_unmitigated_high) {
      errors.push(
        `risk_layer: ${count} unmitigated high risks (max allowed: ${rules.max_unmitigated_high})`,
      );
    } else {
      passed.push(
        `risk_layer: unmitigated high risks within limit (${count}/${rules.max_unmitigated_high})`,
      );
    }
  }

  if (rules.max_unmitigated_medium !== undefined) {
    const count = unmitigatedCounts.medium;
    if (count > rules.max_unmitigated_medium) {
      errors.push(
        `risk_layer: ${count} unmitigated medium risks (max allowed: ${rules.max_unmitigated_medium})`,
      );
    } else {
      passed.push(
        `risk_layer: unmitigated medium risks within limit (${count}/${rules.max_unmitigated_medium})`,
      );
    }
  }

  if (
    rules.requires_mitigation_for &&
    rules.requires_mitigation_for.length > 0
  ) {
    for (const risk of riskLayer) {
      if (typeof risk === "object" && risk !== null) {
        const r = risk as Record<string, unknown>;
        const severity = String(r.severity ?? "").toLowerCase();
        const status = String(r.status ?? "").toLowerCase();

        if (
          rules.requires_mitigation_for?.includes(
            severity as "critical" | "high" | "medium" | "low",
          )
        ) {
          if (status !== "mitigated" && status !== "accepted") {
            warnings.push(
              `risk_layer: risk "${r.risk_id}" has severity "${severity}" without mitigation status`,
            );
          }
        }
      }
    }
  }

  return { errors, warnings, passed };
}

function checkAttestation(
  data: Record<string, unknown>,
  profile: ComplianceProfile,
): { errors: string[]; warnings: string[]; passed: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const passed: string[] = [];

  const attestation = data.attestation as Record<string, unknown> | undefined;

  if (!attestation) {
    errors.push("attestation section is missing");
    return { errors, warnings, passed };
  }

  const rules = profile.rules.attestation;
  if (!rules) {
    passed.push("attestation: no rules defined");
    return { errors, warnings, passed };
  }

  if (rules.requires_signature) {
    const signature = attestation.signature;
    if (!signature || String(signature).trim() === "") {
      errors.push("attestation: signature is required but missing or empty");
    } else {
      passed.push("attestation: signature present");
    }
  }

  if (rules.requires_timestamp) {
    const timestamp = attestation.timestamp;
    if (!timestamp || String(timestamp).trim() === "") {
      errors.push("attestation: timestamp is required but missing or empty");
    } else {
      passed.push("attestation: timestamp present");
    }
  }

  return { errors, warnings, passed };
}

/**
 * Compute a weighted compliance score from check results.
 *
 * Each rule section carries an optional `weight` (float >= 0, default: 1).
 * A section is passing if it produced no errors.
 * Returns a value in [0, 1] where 1 means every enabled rule section passed.
 */
export function computeWeightedScore(
  checkResults: { errors: string[]; warnings: string[]; passed: string[] }[],
  profile: ComplianceProfile,
): number {
  const ruleKeys: (keyof typeof profile.rules)[] = [
    "identity",
    "tool_layer",
    "risk_layer",
    "attestation",
  ];
  let totalWeight = 0;
  let passedWeight = 0;

  for (let i = 0; i < ruleKeys.length; i++) {
    const key = ruleKeys[i];
    const section = profile.rules[key];
    const weight =
      section && typeof section === "object" && "weight" in section
        ? ((section as { weight?: number }).weight ?? DEFAULT_RULE_WEIGHT)
        : DEFAULT_RULE_WEIGHT;

    if (weight <= 0) continue;

    totalWeight += weight;
    if (checkResults[i].errors.length === 0) {
      passedWeight += weight;
    }
  }

  return totalWeight > 0 ? passedWeight / totalWeight : 1;
}

/**
 * Check an AgentBOM document against a compliance profile.
 *
 * The `data` parameter should be a parsed AgentBOM object (already validated
 * against the schema). The `profile` parameter is the compliance profile to
 * evaluate against. `minScore` defaults to 1.0 (full compliance required).
 *
 * Returns a `ComplianceResult` with a score, pass/fail status, and details.
 */
export function checkCompliance(
  data: Record<string, unknown>,
  profile: ComplianceProfile,
  minScore = 1.0,
): ComplianceResult {
  const checks = [
    checkIdentity(data, profile),
    checkToolLayer(data, profile),
    checkRiskLayer(data, profile),
    checkAttestation(data, profile),
  ];

  const score = computeWeightedScore(checks, profile);

  const result: ComplianceResult = {
    compliant: score >= minScore,
    profile_id: profile.profile_id,
    framework_name: profile.framework.name,
    framework_version: profile.framework.version,
    score,
    threshold: minScore,
    errors: [],
    warnings: [],
    passed_checks: [],
  };

  for (const check of checks) {
    result.errors.push(...check.errors);
    result.warnings.push(...check.warnings);
    result.passed_checks.push(...check.passed);
  }

  return result;
}
