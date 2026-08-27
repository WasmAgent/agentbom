import { getSchema } from "@wasmagent/protocol";
import type { ErrorObject, ValidateFunction } from "ajv";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

export interface ValidationError {
  /** Dot-notation path to the offending field, e.g. "identity.agent_id". "(root)" for the document itself. */
  field: string;
  /** Human-readable description of the failure. */
  message: string;
  /** AJV keyword that failed, e.g. "required", "enum", "type". */
  keyword: string;
}

export interface ValidationResult {
  valid: boolean;
  /** Human-readable error strings, each prefixed with the field path. */
  errors: string[];
  /** Structured errors with field paths. */
  errorDetails: ValidationError[];
}

// Load schema from @wasmagent/protocol — the canonical SSOT for AgentBOM.
let validateSchema: ValidateFunction | null = null;

function getValidator(): ValidateFunction {
  if (validateSchema) return validateSchema;
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  // Register ajv-formats so that format keywords like "uri", "email", etc.
  // are validated instead of silently ignored.
  addFormats(ajv);
  const schema = getSchema("agentbom");
  validateSchema = ajv.compile(schema as import("ajv").AnySchema);
  if (!validateSchema) throw new Error("Failed to compile AgentBOM schema");
  return validateSchema;
}

/** Convert an AJV instancePath (JSON pointer) into a dot-notation field path. */
function toFieldPath(instancePath: string, extra?: string): string {
  let path = instancePath.startsWith("/")
    ? instancePath.slice(1)
    : instancePath;
  path = path.replace(/\//g, ".");
  if (extra) path = path ? `${path}.${extra}` : extra;
  return path || "(root)";
}

/** For errors that name a specific property, return it so it can be folded into the field path. */
function namedProperty(err: ErrorObject): string | undefined {
  if (err.keyword === "required") {
    return (err.params as { missingProperty?: string } | undefined)
      ?.missingProperty;
  }
  if (err.keyword === "additionalProperties") {
    return (err.params as { additionalProperty?: string } | undefined)
      ?.additionalProperty;
  }
  return undefined;
}

export function validateAgentBOM(data: unknown): ValidationResult {
  const validate = getValidator();

  let valid = false;
  try {
    valid = validate(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      valid: false,
      errors: [`(root): schema validation crashed: ${message}`],
      errorDetails: [
        {
          field: "(root)",
          message: `schema validation crashed: ${message}`,
          keyword: "exception",
        },
      ],
    };
  }

  const errorDetails: ValidationError[] = (validate.errors ?? []).map((err) => {
    const field = toFieldPath(err.instancePath, namedProperty(err));
    return {
      field,
      message: err.message ?? `failed constraint "${err.keyword}"`,
      keyword: err.keyword,
    };
  });
  const errors = errorDetails.map((e) => `${e.field}: ${e.message}`);

  return { valid, errors, errorDetails };
}

export function inspectAgentBOM(data: Record<string, unknown>): string {
  const identity = data.identity as Record<string, string> | undefined;
  const toolLayer = (data.tool_layer as unknown[]) ?? [];
  const riskLayer = (data.risk_layer as unknown[]) ?? [];
  return [
    `AgentBOM v${data.agentbom_version}`,
    `  Agent:   ${identity?.agent_name ?? "unknown"} (${identity?.agent_id ?? "?"})`,
    `  Context: ${identity?.deployment_context ?? "unset"}`,
    `  Tools:   ${toolLayer.length}`,
    `  Risks:   ${riskLayer.length}`,
  ].join("\n");
}

// --- AgentBOM Diff types and logic ---

export interface ToolEntry {
  tool_id: string;
  tool_name: string;
  source: string;
  permissions?: string[];
  risk_signals?: string[];
}

export interface ToolModification {
  tool_id: string;
  field: string;
  old: string;
  new: string;
}

export interface RiskEntry {
  risk_id: string;
  severity: string;
  category: string;
  description: string;
  status?: string;
}

export interface RiskModification {
  risk_id: string;
  field: string;
  old: string;
  new: string;
}

export interface AgentBOMDiff {
  tools: {
    added: ToolEntry[];
    removed: ToolEntry[];
    modified: ToolModification[];
  };
  permissions: {
    added: string[];
    removed: string[];
  };
  risks: {
    added: RiskEntry[];
    removed: RiskEntry[];
    modified: RiskModification[];
  };
  isEmpty(): boolean;
}

export function createAgentBOMDiff(
  partial: Omit<AgentBOMDiff, "isEmpty">,
): AgentBOMDiff {
  const isEmpty = (): boolean =>
    partial.tools.added.length === 0 &&
    partial.tools.removed.length === 0 &&
    partial.tools.modified.length === 0 &&
    partial.permissions.added.length === 0 &&
    partial.permissions.removed.length === 0 &&
    partial.risks.added.length === 0 &&
    partial.risks.removed.length === 0 &&
    partial.risks.modified.length === 0;

  return { ...partial, isEmpty };
}

function toArray(val: unknown): unknown[] {
  return Array.isArray(val) ? val : [];
}

function parseTools(toolLayer: unknown): Map<string, ToolEntry> {
  const tools = new Map<string, ToolEntry>();
  for (const item of toArray(toolLayer)) {
    if (typeof item === "object" && item !== null) {
      const t = item as Record<string, unknown>;
      if (typeof t.tool_id === "string") {
        tools.set(t.tool_id, {
          tool_id: t.tool_id,
          tool_name: String(t.tool_name ?? ""),
          source: String(t.source ?? ""),
          permissions: toArray(t.permissions).map(String),
          risk_signals: toArray(t.risk_signals).map(String),
        });
      }
    }
  }
  return tools;
}

function parseRisks(riskLayer: unknown): Map<string, RiskEntry> {
  const risks = new Map<string, RiskEntry>();
  for (const item of toArray(riskLayer)) {
    if (typeof item === "object" && item !== null) {
      const r = item as Record<string, unknown>;
      if (typeof r.risk_id === "string") {
        risks.set(r.risk_id, {
          risk_id: r.risk_id,
          severity: String(r.severity ?? ""),
          category: String(r.category ?? ""),
          description: String(r.description ?? ""),
          status: String(r.status ?? ""),
        });
      }
    }
  }
  return risks;
}

function diffStringArrays(
  oldArr: string[],
  newArr: string[],
): { added: string[]; removed: string[] } {
  const oldSet = new Set(oldArr);
  const newSet = new Set(newArr);
  const added = newArr.filter((s) => !oldSet.has(s));
  const removed = oldArr.filter((s) => !newSet.has(s));
  return { added, removed };
}

export function diffAgentBOM(
  oldData: Record<string, unknown>,
  newData: Record<string, unknown>,
): AgentBOMDiff {
  const oldTools = parseTools(oldData.tool_layer);
  const newTools = parseTools(newData.tool_layer);

  const toolsAdded: ToolEntry[] = [];
  const toolsRemoved: ToolEntry[] = [];
  const toolsModified: ToolModification[] = [];

  for (const [id, tool] of newTools) {
    if (!oldTools.has(id)) {
      toolsAdded.push(tool);
    }
  }
  for (const [id, tool] of oldTools) {
    if (!newTools.has(id)) {
      toolsRemoved.push(tool);
    }
  }
  for (const [id, newTool] of newTools) {
    const oldTool = oldTools.get(id);
    if (!oldTool) continue;

    const permDiff = diffStringArrays(
      oldTool.permissions ?? [],
      newTool.permissions ?? [],
    );
    for (const p of permDiff.added) {
      toolsModified.push({
        tool_id: id,
        field: "permissions",
        old: "",
        new: p,
      });
    }
    for (const p of permDiff.removed) {
      toolsModified.push({
        tool_id: id,
        field: "permissions",
        old: p,
        new: "",
      });
    }

    if (oldTool.tool_name !== newTool.tool_name) {
      toolsModified.push({
        tool_id: id,
        field: "tool_name",
        old: oldTool.tool_name,
        new: newTool.tool_name,
      });
    }
    if (oldTool.source !== newTool.source) {
      toolsModified.push({
        tool_id: id,
        field: "source",
        old: oldTool.source,
        new: newTool.source,
      });
    }
  }

  const oldPerms = toArray(
    (oldData.permission_layer as Record<string, unknown> | undefined)
      ?.granted_scopes,
  ).map(String);
  const newPerms = toArray(
    (newData.permission_layer as Record<string, unknown> | undefined)
      ?.granted_scopes,
  ).map(String);
  const permChanges = diffStringArrays(oldPerms, newPerms);

  const oldRisks = parseRisks(oldData.risk_layer);
  const newRisks = parseRisks(newData.risk_layer);

  const risksAdded: RiskEntry[] = [];
  const risksRemoved: RiskEntry[] = [];
  const risksModified: RiskModification[] = [];

  for (const [id, risk] of newRisks) {
    if (!oldRisks.has(id)) {
      risksAdded.push(risk);
    }
  }
  for (const [id, risk] of oldRisks) {
    if (!newRisks.has(id)) {
      risksRemoved.push(risk);
    }
  }
  for (const [id, newRisk] of newRisks) {
    const oldRisk = oldRisks.get(id);
    if (!oldRisk) continue;

    if (oldRisk.severity !== newRisk.severity) {
      risksModified.push({
        risk_id: id,
        field: "severity",
        old: oldRisk.severity,
        new: newRisk.severity,
      });
    }
    if (oldRisk.status !== newRisk.status) {
      risksModified.push({
        risk_id: id,
        field: "status",
        old: oldRisk.status ?? "",
        new: newRisk.status ?? "",
      });
    }
    if (oldRisk.category !== newRisk.category) {
      risksModified.push({
        risk_id: id,
        field: "category",
        old: oldRisk.category,
        new: newRisk.category,
      });
    }
  }

  return createAgentBOMDiff({
    tools: {
      added: toolsAdded,
      removed: toolsRemoved,
      modified: toolsModified,
    },
    permissions: { added: permChanges.added, removed: permChanges.removed },
    risks: {
      added: risksAdded,
      removed: risksRemoved,
      modified: risksModified,
    },
  });
}

export function formatAgentBOMDiff(diff: AgentBOMDiff): string {
  const lines: string[] = [];

  if (diff.tools.added.length > 0) {
    lines.push(`Tools added (${diff.tools.added.length}):`);
    for (const t of diff.tools.added) {
      lines.push(`  + ${t.tool_name} (${t.tool_id}) [${t.source}]`);
    }
  }

  if (diff.tools.removed.length > 0) {
    lines.push(`Tools removed (${diff.tools.removed.length}):`);
    for (const t of diff.tools.removed) {
      lines.push(`  - ${t.tool_name} (${t.tool_id}) [${t.source}]`);
    }
  }

  if (diff.tools.modified.length > 0) {
    lines.push(`Tools changed (${diff.tools.modified.length}):`);
    for (const m of diff.tools.modified) {
      if (m.field === "permissions") {
        if (m.new) {
          lines.push(`  ~ ${m.tool_id}: permission added: ${m.new}`);
        } else {
          lines.push(`  ~ ${m.tool_id}: permission removed: ${m.old}`);
        }
      } else {
        lines.push(`  ~ ${m.tool_id}: ${m.field}: ${m.old} → ${m.new}`);
      }
    }
  }

  if (diff.permissions.added.length > 0) {
    lines.push(`Permission scopes added (${diff.permissions.added.length}):`);
    for (const s of diff.permissions.added) {
      lines.push(`  + ${s}`);
    }
  }

  if (diff.permissions.removed.length > 0) {
    lines.push(
      `Permission scopes removed (${diff.permissions.removed.length}):`,
    );
    for (const s of diff.permissions.removed) {
      lines.push(`  - ${s}`);
    }
  }

  if (diff.risks.added.length > 0) {
    lines.push(`Risk entries added (${diff.risks.added.length}):`);
    for (const r of diff.risks.added) {
      lines.push(`  + [${r.severity}] ${r.risk_id}: ${r.description}`);
    }
  }

  if (diff.risks.removed.length > 0) {
    lines.push(`Risk entries removed (${diff.risks.removed.length}):`);
    for (const r of diff.risks.removed) {
      lines.push(`  - [${r.severity}] ${r.risk_id}: ${r.description}`);
    }
  }

  if (diff.risks.modified.length > 0) {
    lines.push(`Risk entries changed (${diff.risks.modified.length}):`);
    for (const m of diff.risks.modified) {
      lines.push(`  ~ ${m.risk_id}: ${m.field}: ${m.old} → ${m.new}`);
    }
  }

  if (lines.length === 0) {
    lines.push("No differences found between the two AgentBOMs.");
  }

  return lines.join("\n");
}

// --- Semver utilities ---

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease?: string;
  build?: string;
}

export function parseSemver(version: string): SemVer | null {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:-([\w.]+))?(?:\+([\w.]+))?$/.exec(
    version,
  );
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    ...(match[4] ? { prerelease: match[4] } : {}),
    ...(match[5] ? { build: match[5] } : {}),
  };
}

export function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) throw new Error(`Invalid semver: ${!pa ? a : b}`);
  if (pa.major !== pb.major) return pa.major - pb.major;
  if (pa.minor !== pb.minor) return pa.minor - pb.minor;
  if (pa.patch !== pb.patch) return pa.patch - pb.patch;
  if (pa.prerelease && !pb.prerelease) return -1;
  if (!pa.prerelease && pb.prerelease) return 1;
  if (pa.prerelease && pb.prerelease)
    return pa.prerelease.localeCompare(pb.prerelease);
  return 0;
}

export function isVersionInRange(version: string, range: string): boolean {
  if (range.startsWith(">="))
    return compareSemver(version, range.slice(2)) >= 0;
  if (range.startsWith("<="))
    return compareSemver(version, range.slice(2)) <= 0;
  if (range.startsWith(">")) return compareSemver(version, range.slice(1)) > 0;
  if (range.startsWith("<")) return compareSemver(version, range.slice(1)) < 0;
  return version === range;
}

// --- Migration framework ---

export type MigrationFn = (
  data: Record<string, unknown>,
) => Record<string, unknown>;

export interface MigrationStep {
  fromVersion: string;
  toVersion: string;
  migrate: MigrationFn;
  description: string;
  breaking: boolean;
}

export interface MigrationResult {
  success: boolean;
  fromVersion: string;
  toVersion: string;
  data: Record<string, unknown>;
  stepsApplied: MigrationStep[];
  warnings: string[];
  errors: string[];
}

export interface DeprecationNotice {
  version: string;
  message: string;
  severity: "info" | "warn" | "deprecated";
}

export interface VersionedValidationResult extends ValidationResult {
  version_warnings: DeprecationNotice[];
  detected_version: string | null;
}

/** Currently supported AgentBOM schema versions. */
const SUPPORTED_VERSIONS: readonly string[] = ["0.1"];
const LATEST_VERSION = "0.1";
const DEPRECATED_VERSIONS: Map<string, DeprecationNotice> = new Map();
const MIGRATION_REGISTRY: MigrationStep[] = [];

export function getSupportedVersions(): string[] {
  return [...SUPPORTED_VERSIONS];
}

export function getLatestVersion(): string {
  return LATEST_VERSION;
}

/** Register a migration step. Call at module init time to extend the framework. */
export function registerMigration(step: MigrationStep): void {
  MIGRATION_REGISTRY.push(step);
}

/** Find the shortest migration path from `from` to `to` via registered steps (BFS). */
export function getMigrationPath(
  fromVersion: string,
  toVersion: string,
): MigrationStep[] {
  const visited = new Set<string>([fromVersion]);
  const queue: Array<{ version: string; path: MigrationStep[] }> = [
    { version: fromVersion, path: [] },
  ];

  while (queue.length > 0) {
    const entry = queue.shift();
    if (!entry) break;
    const { version, path } = entry;
    if (version === toVersion) return path;

    for (const step of MIGRATION_REGISTRY) {
      if (step.fromVersion === version && !visited.has(step.toVersion)) {
        visited.add(step.toVersion);
        queue.push({ version: step.toVersion, path: [...path, step] });
      }
    }
  }

  return [];
}

/** Mark a version as deprecated with a notice consumers should surface. */
export function deprecateVersion(notice: DeprecationNotice): void {
  DEPRECATED_VERSIONS.set(notice.version, notice);
}

/** Migrate an AgentBOM document to a target schema version. */
export function migrateAgentBOM(
  data: Record<string, unknown>,
  targetVersion?: string,
): MigrationResult {
  const fromVersion = String(data.agentbom_version ?? "unknown");
  const target = targetVersion ?? LATEST_VERSION;

  if (fromVersion === target) {
    return {
      success: true,
      fromVersion,
      toVersion: target,
      data,
      stepsApplied: [],
      warnings: [],
      errors: [],
    };
  }

  const path = getMigrationPath(fromVersion, target);
  if (path.length === 0) {
    return {
      success: false,
      fromVersion,
      toVersion: target,
      data,
      stepsApplied: [],
      warnings: [],
      errors: [`No migration path from ${fromVersion} to ${target}`],
    };
  }

  let current = { ...data };
  const warnings: string[] = [];
  const applied: MigrationStep[] = [];

  for (const step of path) {
    if (step.breaking) {
      warnings.push(
        `Breaking migration: ${step.description} (${step.fromVersion} → ${step.toVersion})`,
      );
    }
    try {
      current = step.migrate(current);
      applied.push(step);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        fromVersion,
        toVersion: target,
        data: current,
        stepsApplied: applied,
        warnings,
        errors: [
          `Migration failed at step ${step.fromVersion} → ${step.toVersion}: ${message}`,
        ],
      };
    }
  }

  return {
    success: true,
    fromVersion,
    toVersion: target,
    data: current,
    stepsApplied: applied,
    warnings,
    errors: [],
  };
}

/** Detect deprecation notices for a given version string. */
export function detectVersionWarnings(version: string): DeprecationNotice[] {
  const notices: DeprecationNotice[] = [];
  const notice = DEPRECATED_VERSIONS.get(version);
  if (notice) {
    notices.push(notice);
  } else if (!SUPPORTED_VERSIONS.includes(version)) {
    notices.push({
      version,
      message: `AgentBOM version ${version} is not in the supported set (${SUPPORTED_VERSIONS.join(", ")})`,
      severity: "warn",
    });
  }
  return notices;
}

/** Validate an AgentBOM and return version-aware diagnostics (deprecation notices, etc.). */
export function validateAgentBOMWithVersioning(
  data: unknown,
): VersionedValidationResult {
  const raw = data as Record<string, unknown> | null;
  const version = (raw?.agentbom_version as string | undefined) ?? null;
  const versionWarnings = detectVersionWarnings(version ?? "unknown");

  const baseResult = validateAgentBOM(data);

  return {
    ...baseResult,
    version_warnings: versionWarnings,
    detected_version: version,
  };
}

// --- Compliance Profile Schema Compatibility ---

/** Describes a field in the AgentBOM schema for compatibility tracking. */
export interface SchemaFieldDescriptor {
  /** Dot-path to the field, e.g. "identity.agent_version" */
  path: string;
  /** JSON schema type */
  type: "string" | "number" | "boolean" | "array" | "object";
  /** Whether required in the schema */
  required: boolean;
  /** Schema version where this field was introduced */
  since: string;
  /** If removed/deprecated, the schema version */
  removed_in?: string;
  /** Human-readable description */
  description: string;
}

/** A suggested mapping update for a compliance profile. */
export interface MappingUpdate {
  /** Severity of the update needed */
  type: "breaking" | "recommended" | "optional";
  /** The profile rule section affected */
  profile_section: string;
  /** Human-readable description of what changed */
  description: string;
  /** Suggested action to update the profile */
  action: string;
}

/** Result of checking a compliance profile against an AgentBOM schema version. */
export interface ProfileCompatibilityResult {
  /** Whether the profile is fully compatible (no breaking issues) */
  compatible: boolean;
  /** The profile's declared version */
  profile_version: string;
  /** The AgentBOM schema version checked against */
  agentbom_version: string;
  /** Breaking issues — profile references fields removed from the schema */
  breaking: Array<{ field: string; section: string; message: string }>;
  /** Coverage gaps — schema fields/sections not covered by any profile rule */
  gaps: Array<{ path: string; description: string }>;
  /** Suggested mapping updates to bring the profile in line with the schema */
  mapping_updates: MappingUpdate[];
}

/**
 * Minimal profile shape accepted by compatibility checking.
 *
 * Designed to accept both the CLI's `ComplianceProfile` and raw JSON objects
 * without coupling to the CLI module.
 */
export interface CompatibilityProfileInput {
  profile_version?: string;
  rules: {
    identity?: {
      required_fields?: string[];
      allowed_contexts?: string[];
      requires_version?: boolean;
      [key: string]: unknown;
    };
    tool_layer?: {
      max_severity?: string;
      requires_tool_inventory?: boolean;
      blocked_permissions?: string[];
      blocked_sources?: string[];
      [key: string]: unknown;
    };
    risk_layer?: {
      requires_risk_assessment?: boolean;
      max_unmitigated_critical?: number;
      max_unmitigated_high?: number;
      max_unmitigated_medium?: number;
      requires_mitigation_for?: string[];
      [key: string]: unknown;
    };
    attestation?: {
      requires_signature?: boolean;
      requires_timestamp?: boolean;
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
}

/** Known schema fields for AgentBOM v0.1. */
const SCHEMA_FIELDS_V0_1: SchemaFieldDescriptor[] = [
  {
    path: "agentbom_version",
    type: "string",
    required: true,
    since: "0.1",
    description: "Schema version identifier",
  },
  {
    path: "identity",
    type: "object",
    required: true,
    since: "0.1",
    description: "Agent identity section",
  },
  {
    path: "identity.agent_id",
    type: "string",
    required: true,
    since: "0.1",
    description: "Unique agent identifier",
  },
  {
    path: "identity.agent_name",
    type: "string",
    required: true,
    since: "0.1",
    description: "Human-readable agent name",
  },
  {
    path: "identity.agent_version",
    type: "string",
    required: false,
    since: "0.1",
    description: "Semantic version",
  },
  {
    path: "identity.deployment_context",
    type: "string",
    required: false,
    since: "0.1",
    description: "Deployment environment",
  },
  {
    path: "identity.generated_at",
    type: "string",
    required: true,
    since: "0.1",
    description: "Generation timestamp",
  },
  {
    path: "model_layer",
    type: "object",
    required: false,
    since: "0.1",
    description: "Model provider and capabilities",
  },
  {
    path: "tool_layer",
    type: "array",
    required: false,
    since: "0.1",
    description: "Registered tools and permissions",
  },
  {
    path: "tool_layer[].tool_id",
    type: "string",
    required: true,
    since: "0.1",
    description: "Tool identifier",
  },
  {
    path: "tool_layer[].tool_name",
    type: "string",
    required: true,
    since: "0.1",
    description: "Tool name",
  },
  {
    path: "tool_layer[].source",
    type: "string",
    required: true,
    since: "0.1",
    description: "Tool source type",
  },
  {
    path: "tool_layer[].permissions",
    type: "array",
    required: false,
    since: "0.1",
    description: "Tool permission scopes",
  },
  {
    path: "tool_layer[].risk_signals",
    type: "array",
    required: false,
    since: "0.1",
    description: "Tool risk signals",
  },
  {
    path: "prompt_layer",
    type: "object",
    required: false,
    since: "0.1",
    description: "System prompt references",
  },
  {
    path: "permission_layer",
    type: "object",
    required: false,
    since: "0.1",
    description: "Granted permission scopes",
  },
  {
    path: "policy_definitions",
    type: "array",
    required: false,
    since: "0.1",
    description: "Governance policies",
  },
  {
    path: "evidence_layer",
    type: "object",
    required: false,
    since: "0.1",
    description: "AEP event references",
  },
  {
    path: "audit_log",
    type: "array",
    required: false,
    since: "0.1",
    description: "Audit trail entries",
  },
  {
    path: "risk_layer",
    type: "array",
    required: false,
    since: "0.1",
    description: "Known risk signals",
  },
  {
    path: "risk_layer[].risk_id",
    type: "string",
    required: true,
    since: "0.1",
    description: "Risk identifier",
  },
  {
    path: "risk_layer[].severity",
    type: "string",
    required: true,
    since: "0.1",
    description: "Risk severity level",
  },
  {
    path: "risk_layer[].category",
    type: "string",
    required: true,
    since: "0.1",
    description: "Risk category",
  },
  {
    path: "risk_layer[].description",
    type: "string",
    required: true,
    since: "0.1",
    description: "Risk description",
  },
  {
    path: "risk_layer[].status",
    type: "string",
    required: true,
    since: "0.1",
    description: "Risk status",
  },
  {
    path: "workflow_layer",
    type: "array",
    required: false,
    since: "0.1",
    description: "Action pathway definitions",
  },
  {
    path: "workflow_layer[].workflow_id",
    type: "string",
    required: true,
    since: "0.1",
    description: "Unique workflow identifier",
  },
  {
    path: "workflow_layer[].workflow_name",
    type: "string",
    required: true,
    since: "0.1",
    description: "Human-readable workflow name",
  },
  {
    path: "workflow_layer[].steps",
    type: "array",
    required: true,
    since: "0.1",
    description: "Ordered list of steps in this workflow",
  },
  {
    path: "workflow_layer[].steps[].step_id",
    type: "string",
    required: true,
    since: "0.1",
    description: "Unique step identifier within the workflow",
  },
  {
    path: "workflow_layer[].steps[].action",
    type: "string",
    required: true,
    since: "0.1",
    description:
      "Action to perform: tool_id, prompt name, sub_workflow, or decision",
  },
  {
    path: "workflow_layer[].steps[].allowed_tools",
    type: "array",
    required: false,
    since: "0.1",
    description: "Tool IDs allowed at this step",
  },
  {
    path: "agent_collaboration",
    type: "object",
    required: false,
    since: "0.1",
    description:
      "Multi-agent collaboration topology — peer agents, delegation boundaries, and shared resource access patterns",
  },
  {
    path: "agent_collaboration.peer_agents",
    type: "array",
    required: false,
    since: "0.1",
    description: "Known peer agents this agent collaborates with",
  },
  {
    path: "agent_collaboration.peer_agents[].agent_id",
    type: "string",
    required: true,
    since: "0.1",
    description: "Unique identifier of the peer agent",
  },
  {
    path: "agent_collaboration.peer_agents[].role",
    type: "string",
    required: true,
    since: "0.1",
    description: "Collaboration role relative to this agent",
  },
  {
    path: "agent_collaboration.peer_agents[].trust_level",
    type: "string",
    required: false,
    since: "0.1",
    description: "Trust level assigned to this peer agent",
  },
  {
    path: "agent_collaboration.peer_agents[].agentbom_ref",
    type: "string",
    required: false,
    since: "0.1",
    description: "URI or hash reference to the peer agent's AgentBOM",
  },
  {
    path: "agent_collaboration.delegation_boundaries",
    type: "array",
    required: false,
    since: "0.1",
    description: "Rules governing delegation to/from peers",
  },
  {
    path: "agent_collaboration.delegation_boundaries[].boundary_id",
    type: "string",
    required: true,
    since: "0.1",
    description: "Unique boundary identifier",
  },
  {
    path: "agent_collaboration.delegation_boundaries[].direction",
    type: "string",
    required: true,
    since: "0.1",
    description: "Direction of the delegation boundary",
  },
  {
    path: "agent_collaboration.delegation_boundaries[].constraint_type",
    type: "string",
    required: true,
    since: "0.1",
    description: "Type of constraint",
  },
  {
    path: "agent_collaboration.delegation_boundaries[].max_delegation_depth",
    type: "number",
    required: false,
    since: "0.1",
    description: "Maximum depth of transitive delegation",
  },
  {
    path: "agent_collaboration.shared_resources",
    type: "array",
    required: false,
    since: "0.1",
    description: "Resources shared across agent collaboration boundaries",
  },
  {
    path: "agent_collaboration.shared_resources[].resource_id",
    type: "string",
    required: true,
    since: "0.1",
    description: "Unique resource identifier",
  },
  {
    path: "agent_collaboration.shared_resources[].resource_type",
    type: "string",
    required: true,
    since: "0.1",
    description: "Type of shared resource",
  },
  {
    path: "agent_collaboration.shared_resources[].access_pattern",
    type: "string",
    required: true,
    since: "0.1",
    description: "Access pattern for the shared resource",
  },
  {
    path: "agent_collaboration.shared_resources[].isolation_level",
    type: "string",
    required: false,
    since: "0.1",
    description: "Resource isolation level between agents",
  },
  {
    path: "distribution",
    type: "object",
    required: false,
    since: "0.1",
    description: "Artifact lifecycle management",
  },
  {
    path: "attestation",
    type: "object",
    required: true,
    since: "0.1",
    description: "Generator, timestamp, hash, signature",
  },
  {
    path: "attestation.generator",
    type: "string",
    required: true,
    since: "0.1",
    description: "BOM generator tool",
  },
  {
    path: "attestation.signature",
    type: "string",
    required: false,
    since: "0.1",
    description: "Cryptographic signature",
  },
  {
    path: "attestation.timestamp",
    type: "string",
    required: false,
    since: "0.1",
    description: "Attestation timestamp",
  },
];

const SCHEMA_FIELDS_MAP = new Map<string, SchemaFieldDescriptor[]>([
  ["0.1", SCHEMA_FIELDS_V0_1],
]);

/**
 * Get schema field descriptors for a given AgentBOM version.
 * Returns empty array if the version is unknown.
 */
export function getSchemaFieldDescriptors(
  version: string,
): SchemaFieldDescriptor[] {
  return SCHEMA_FIELDS_MAP.get(version) ?? [];
}

/**
 * Check backward compatibility of a compliance profile against an AgentBOM schema version.
 *
 * Verifies that all fields referenced by profile rules exist in the target schema,
 * reports coverage gaps for schema sections not checked by the profile, and produces
 * suggested mapping updates to align the profile with the current schema.
 *
 * This enables automated detection of breaking changes when the AgentBOM schema evolves
 * and provides actionable recommendations for updating compliance profiles.
 */
export function checkProfileSchemaCompatibility(
  profile: CompatibilityProfileInput,
  agentbomVersion: string,
): ProfileCompatibilityResult {
  const fields = getSchemaFieldDescriptors(agentbomVersion);
  const fieldSet = new Map(fields.map((f) => [f.path, f]));

  const breaking: ProfileCompatibilityResult["breaking"] = [];
  const gaps: ProfileCompatibilityResult["gaps"] = [];
  const mappingUpdates: MappingUpdate[] = [];

  // --- Check identity rules ---
  const identityRules = profile.rules.identity;
  if (identityRules?.required_fields) {
    for (const fieldName of identityRules.required_fields) {
      const fieldPath = `identity.${fieldName}`;
      const descriptor = fieldSet.get(fieldPath);
      if (!descriptor) {
        breaking.push({
          field: fieldPath,
          section: "identity",
          message: `Profile requires field "${fieldPath}" which does not exist in AgentBOM schema v${agentbomVersion}`,
        });
        mappingUpdates.push({
          type: "breaking",
          profile_section: "identity",
          description: `Field "${fieldPath}" does not exist in schema v${agentbomVersion}`,
          action: `Remove "${fieldName}" from identity.required_fields or map it to an equivalent field`,
        });
      } else if (descriptor.removed_in) {
        breaking.push({
          field: fieldPath,
          section: "identity",
          message: `Profile requires field "${fieldPath}" which was removed in schema v${descriptor.removed_in}`,
        });
        mappingUpdates.push({
          type: "breaking",
          profile_section: "identity",
          description: `Field "${fieldPath}" was removed in schema v${descriptor.removed_in}`,
          action: `Remove "${fieldName}" from identity.required_fields or update the mapping to an equivalent field`,
        });
      }
    }
  }

  // --- Check attestation rules ---
  const attestationRules = profile.rules.attestation;
  if (attestationRules?.requires_signature) {
    const sigField = fieldSet.get("attestation.signature");
    if (!sigField) {
      breaking.push({
        field: "attestation.signature",
        section: "attestation",
        message: `Profile requires attestation.signature but it does not exist in AgentBOM schema v${agentbomVersion}`,
      });
      mappingUpdates.push({
        type: "breaking",
        profile_section: "attestation",
        description: `attestation.signature does not exist in schema v${agentbomVersion}`,
        action:
          "Disable requires_signature or update to the replacement attestation mechanism",
      });
    } else if (sigField.removed_in) {
      breaking.push({
        field: "attestation.signature",
        section: "attestation",
        message: `Profile requires attestation.signature which was removed in schema v${sigField.removed_in}`,
      });
      mappingUpdates.push({
        type: "breaking",
        profile_section: "attestation",
        description: `attestation.signature was removed in schema v${sigField.removed_in}`,
        action:
          "Disable requires_signature or update to the replacement attestation mechanism",
      });
    }
  }

  if (attestationRules?.requires_timestamp) {
    const tsField = fieldSet.get("attestation.timestamp");
    if (!tsField) {
      breaking.push({
        field: "attestation.timestamp",
        section: "attestation",
        message: `Profile requires attestation.timestamp but it does not exist in AgentBOM schema v${agentbomVersion}`,
      });
      mappingUpdates.push({
        type: "breaking",
        profile_section: "attestation",
        description: `attestation.timestamp does not exist in schema v${agentbomVersion}`,
        action:
          "Disable requires_timestamp or update to the replacement timestamp mechanism",
      });
    } else if (tsField.removed_in) {
      breaking.push({
        field: "attestation.timestamp",
        section: "attestation",
        message: `Profile requires attestation.timestamp which was removed in schema v${tsField.removed_in}`,
      });
      mappingUpdates.push({
        type: "breaking",
        profile_section: "attestation",
        description: `attestation.timestamp was removed in schema v${tsField.removed_in}`,
        action:
          "Disable requires_timestamp or update to the replacement timestamp mechanism",
      });
    }
  }

  // --- Check tool_layer rules ---
  const toolRules = profile.rules.tool_layer;
  if (toolRules) {
    if (!fieldSet.has("tool_layer")) {
      breaking.push({
        field: "tool_layer",
        section: "tool_layer",
        message: `Profile has tool_layer rules but tool_layer does not exist in AgentBOM schema v${agentbomVersion}`,
      });
      mappingUpdates.push({
        type: "breaking",
        profile_section: "tool_layer",
        description: `tool_layer section does not exist in schema v${agentbomVersion}`,
        action:
          "Remove tool_layer rules or map them to the replacement section in the new schema",
      });
    } else {
      if (
        toolRules.blocked_permissions?.length &&
        !fieldSet.get("tool_layer[].permissions")
      ) {
        breaking.push({
          field: "tool_layer[].permissions",
          section: "tool_layer",
          message: `Profile checks tool permissions but tool_layer[].permissions does not exist in schema v${agentbomVersion}`,
        });
        mappingUpdates.push({
          type: "breaking",
          profile_section: "tool_layer",
          description: `tool_layer[].permissions does not exist in schema v${agentbomVersion}`,
          action:
            "Remove blocked_permissions rules or map to the new permissions field",
        });
      }
      if (
        toolRules.blocked_sources?.length &&
        !fieldSet.get("tool_layer[].source")
      ) {
        breaking.push({
          field: "tool_layer[].source",
          section: "tool_layer",
          message: `Profile checks tool sources but tool_layer[].source does not exist in schema v${agentbomVersion}`,
        });
        mappingUpdates.push({
          type: "breaking",
          profile_section: "tool_layer",
          description: `tool_layer[].source does not exist in schema v${agentbomVersion}`,
          action: "Remove blocked_sources rules or map to the new source field",
        });
      }
      if (
        toolRules.max_severity &&
        !fieldSet.get("tool_layer[].risk_signals")
      ) {
        breaking.push({
          field: "tool_layer[].risk_signals",
          section: "tool_layer",
          message: `Profile checks tool severity but tool_layer[].risk_signals does not exist in schema v${agentbomVersion}`,
        });
        mappingUpdates.push({
          type: "breaking",
          profile_section: "tool_layer",
          description: `tool_layer[].risk_signals does not exist in schema v${agentbomVersion}`,
          action:
            "Remove max_severity rule or map to the new risk signal field",
        });
      }
    }
  }

  // --- Check risk_layer rules ---
  const riskRules = profile.rules.risk_layer;
  if (riskRules) {
    if (!fieldSet.has("risk_layer")) {
      breaking.push({
        field: "risk_layer",
        section: "risk_layer",
        message: `Profile has risk_layer rules but risk_layer does not exist in AgentBOM schema v${agentbomVersion}`,
      });
      mappingUpdates.push({
        type: "breaking",
        profile_section: "risk_layer",
        description: `risk_layer section does not exist in schema v${agentbomVersion}`,
        action:
          "Remove risk_layer rules or map them to the replacement section in the new schema",
      });
    } else {
      if (
        riskRules.requires_mitigation_for?.length &&
        !fieldSet.get("risk_layer[].status")
      ) {
        breaking.push({
          field: "risk_layer[].status",
          section: "risk_layer",
          message: `Profile checks risk status but risk_layer[].status does not exist in schema v${agentbomVersion}`,
        });
        mappingUpdates.push({
          type: "breaking",
          profile_section: "risk_layer",
          description: `risk_layer[].status does not exist in schema v${agentbomVersion}`,
          action:
            "Remove requires_mitigation_for rules or map to the new status field",
        });
      }
    }
  }

  // --- Coverage gaps: schema sections not covered by profile rules ---
  const coveredSections = new Set<string>();
  if (profile.rules.identity) coveredSections.add("identity");
  if (profile.rules.tool_layer) coveredSections.add("tool_layer");
  if (profile.rules.risk_layer) coveredSections.add("risk_layer");
  if (profile.rules.attestation) coveredSections.add("attestation");

  const governableSections = [
    "model_layer",
    "prompt_layer",
    "permission_layer",
    "policy_definitions",
    "evidence_layer",
    "audit_log",
    "workflow_layer",
    "agent_collaboration",
    "distribution",
  ];

  for (const section of governableSections) {
    const desc = fieldSet.get(section);
    if (!coveredSections.has(section) && desc) {
      gaps.push({
        path: section,
        description: desc.description,
      });
      mappingUpdates.push({
        type: "optional",
        profile_section: section,
        description: `Schema includes "${section}" section (${desc.description}) not covered by any profile rule`,
        action: `Consider adding a "${section}" rule section to the profile to govern ${desc.description.toLowerCase()}`,
      });
    }
  }

  return {
    compatible: breaking.length === 0,
    profile_version: profile.profile_version ?? "unknown",
    agentbom_version: agentbomVersion,
    breaking,
    gaps,
    mapping_updates: mappingUpdates,
  };
}

// --- Automated Profile Mapping Upgrade ---

/** Result of automatically upgrading a compliance profile's mappings. */
export interface ProfileUpgradeResult {
  /** Whether any breaking-change fixes were applied. */
  changes_applied: boolean;
  /** The upgraded profile with breaking mappings resolved. */
  upgraded_profile: CompatibilityProfileInput;
  /** Compatibility check performed *before* the upgrade. */
  compatibility: ProfileCompatibilityResult;
  /** Human-readable descriptions of each auto-applied fix. */
  applied_updates: string[];
  /** Mapping updates that could not be auto-resolved (need manual review). */
  unresolved: MappingUpdate[];
}

/**
 * Automatically upgrade a compliance profile's mappings to be compatible with
 * a target AgentBOM schema version.
 *
 * Runs `checkProfileSchemaCompatibility` and then resolves every breaking issue
 * that has a known automated fix:
 *
 * - `identity.required_fields` referencing removed/deprecated fields → removed
 * - `attestation.requires_signature` when `attestation.signature` gone → `false`
 * - `attestation.requires_timestamp` when `attestation.timestamp` gone → `false`
 * - `tool_layer` rules when the section itself is removed → cleared
 * - `tool_layer.blocked_permissions` when `tool_layer[].permissions` gone → `[]`
 * - `tool_layer.blocked_sources` when `tool_layer[].source` gone → `[]`
 * - `tool_layer.max_severity` when `tool_layer[].risk_signals` gone → removed
 * - `risk_layer` rules when the section itself is removed → cleared
 * - `risk_layer.requires_mitigation_for` when `risk_layer[].status` gone → `[]`
 *
 * Returns the upgraded profile together with a summary of applied fixes and any
 * issues that still require manual review.
 */
export function upgradeProfileMappings(
  profile: CompatibilityProfileInput,
  agentbomVersion: string,
): ProfileUpgradeResult {
  const compatibility = checkProfileSchemaCompatibility(
    profile,
    agentbomVersion,
  );

  if (compatibility.compatible) {
    return {
      changes_applied: false,
      upgraded_profile: profile,
      compatibility,
      applied_updates: [],
      unresolved: [],
    };
  }

  // Deep-clone for mutation
  const upgraded: CompatibilityProfileInput = JSON.parse(
    JSON.stringify(profile),
  );
  const applied: string[] = [];

  const fields = getSchemaFieldDescriptors(agentbomVersion);
  const fieldSet = new Map(fields.map((f) => [f.path, f]));

  // --- Auto-resolve identity.required_fields ---
  if (upgraded.rules.identity?.required_fields?.length) {
    const before = upgraded.rules.identity.required_fields.length;
    upgraded.rules.identity.required_fields =
      upgraded.rules.identity.required_fields.filter((fieldName: string) => {
        const descriptor = fieldSet.get(`identity.${fieldName}`);
        return descriptor && !descriptor.removed_in;
      });
    const removed = before - upgraded.rules.identity.required_fields.length;
    if (removed > 0) {
      applied.push(
        `identity.required_fields: removed ${removed} reference(s) to non-existent fields`,
      );
    }
  }

  // --- Auto-resolve attestation rules ---
  if (upgraded.rules.attestation?.requires_signature) {
    const sigField = fieldSet.get("attestation.signature");
    if (!sigField || sigField.removed_in) {
      upgraded.rules.attestation.requires_signature = false;
      applied.push(
        "attestation.requires_signature: set to false (field removed from schema)",
      );
    }
  }

  if (upgraded.rules.attestation?.requires_timestamp) {
    const tsField = fieldSet.get("attestation.timestamp");
    if (!tsField || tsField.removed_in) {
      upgraded.rules.attestation.requires_timestamp = false;
      applied.push(
        "attestation.requires_timestamp: set to false (field removed from schema)",
      );
    }
  }

  // --- Auto-resolve tool_layer rules ---
  if (upgraded.rules.tool_layer) {
    if (!fieldSet.has("tool_layer")) {
      upgraded.rules.tool_layer = undefined;
      applied.push(
        "tool_layer: cleared all rules (section removed from schema)",
      );
    } else {
      if (
        upgraded.rules.tool_layer.blocked_permissions?.length &&
        !fieldSet.get("tool_layer[].permissions")
      ) {
        upgraded.rules.tool_layer.blocked_permissions = [];
        applied.push(
          "tool_layer.blocked_permissions: cleared (tool_layer[].permissions removed from schema)",
        );
      }
      if (
        upgraded.rules.tool_layer.blocked_sources?.length &&
        !fieldSet.get("tool_layer[].source")
      ) {
        upgraded.rules.tool_layer.blocked_sources = [];
        applied.push(
          "tool_layer.blocked_sources: cleared (tool_layer[].source removed from schema)",
        );
      }
      if (
        upgraded.rules.tool_layer.max_severity &&
        !fieldSet.get("tool_layer[].risk_signals")
      ) {
        upgraded.rules.tool_layer.max_severity = undefined;
        applied.push(
          "tool_layer.max_severity: removed (tool_layer[].risk_signals removed from schema)",
        );
      }
    }
  }

  // --- Auto-resolve risk_layer rules ---
  if (upgraded.rules.risk_layer) {
    if (!fieldSet.has("risk_layer")) {
      upgraded.rules.risk_layer = undefined;
      applied.push(
        "risk_layer: cleared all rules (section removed from schema)",
      );
    } else if (
      upgraded.rules.risk_layer.requires_mitigation_for?.length &&
      !fieldSet.get("risk_layer[].status")
    ) {
      upgraded.rules.risk_layer.requires_mitigation_for = [];
      applied.push(
        "risk_layer.requires_mitigation_for: cleared (risk_layer[].status removed from schema)",
      );
    }
  }

  // Re-check to find anything still unresolved after auto-fixes
  const afterCheck = checkProfileSchemaCompatibility(upgraded, agentbomVersion);
  const unresolved: MappingUpdate[] = [];
  for (const update of afterCheck.mapping_updates) {
    if (update.type === "breaking") {
      unresolved.push(update);
    }
  }

  return {
    changes_applied: applied.length > 0,
    upgraded_profile: upgraded,
    compatibility,
    applied_updates: applied,
    unresolved,
  };
}

// --- Continuous Trust Monitoring ---

/** Severity levels for trust monitoring events. */
export type TrustEventSeverity =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

/** Categories of trust events produced by drift monitoring. */
export type TrustEventCategory =
  | "tool_added"
  | "tool_removed"
  | "permission_escalation"
  | "permission_reduction"
  | "risk_introduced"
  | "risk_resolved"
  | "risk_escalated"
  | "scope_expanded"
  | "scope_restricted";

/** A single trust event produced by continuous monitoring of BOM drift. */
export interface TrustEvent {
  /** Machine-readable event category. */
  category: TrustEventCategory;
  /** Severity of the event. */
  severity: TrustEventSeverity;
  /** Human-readable description of the event. */
  description: string;
  /** The affected entity (tool_id, risk_id, or permission scope). */
  subject: string;
  /** ISO 8601 timestamp when the event was detected. */
  detected_at: string;
}

/** A drift alert groups trust events produced by comparing two AgentBOM snapshots. */
export interface DriftAlert {
  /** The agent_id of the monitored agent. */
  agent_id: string;
  /** ISO 8601 timestamp of the baseline (old) snapshot. */
  baseline_at: string;
  /** ISO 8601 timestamp of the current (new) snapshot. */
  current_at: string;
  /** Trust events produced by drift analysis. */
  events: TrustEvent[];
  /** Whether this alert contains any high or critical events. */
  hasHighSeverity(): boolean;
  /** Whether this alert is empty (no events). */
  isEmpty(): boolean;
}

/** Create a DriftAlert with computed helper methods. */
export function createDriftAlert(
  partial: Omit<DriftAlert, "hasHighSeverity" | "isEmpty">,
): DriftAlert {
  const hasHighSeverity = (): boolean =>
    partial.events.some(
      (e) => e.severity === "high" || e.severity === "critical",
    );
  const isEmpty = (): boolean => partial.events.length === 0;
  return { ...partial, hasHighSeverity, isEmpty };
}

/** Severity for a tool based on its permissions and risk signals. */
function toolEventSeverity(tool: ToolEntry): TrustEventSeverity {
  const riskyPerms = ["network:*", "fs:write", "process:exec", "credential:*"];
  const hasRiskyPerm = (tool.permissions ?? []).some((p) =>
    riskyPerms.some(
      (rp) => p === rp || (rp.endsWith(":*") && p.startsWith(rp.slice(0, -1))),
    ),
  );
  const hasCriticalSignal = (tool.risk_signals ?? []).some((s) =>
    ["command_execution", "credential_access", "exfiltration"].includes(s),
  );
  if (hasCriticalSignal) return "critical";
  if (hasRiskyPerm) return "high";
  return "medium";
}

/** Severity for a risk entry based on its severity field. */
function riskEventSeverity(severity: string): TrustEventSeverity {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    default:
      return "low";
  }
}

/**
 * Classify trust events from an AgentBOM diff for continuous monitoring.
 *
 * Analyzes the diff between two BOM snapshots and produces a `DriftAlert`
 * containing `TrustEvent` entries for:
 * - Tool additions and removals
 * - Permission escalation (new permissions added to existing tools)
 * - Permission reductions (permissions removed from existing tools)
 * - New risk entries introduced
 * - Risk escalations (severity increased)
 * - Risk resolutions (risk entries removed)
 * - Scope expansions (new permission scopes granted)
 * - Scope restrictions (permission scopes removed)
 */
export function classifyDriftEvents(
  diff: AgentBOMDiff,
  agentId: string,
  baselineAt: string,
  currentAt: string,
): DriftAlert {
  const now = new Date().toISOString();
  const events: TrustEvent[] = [];

  // Tool additions
  for (const tool of diff.tools.added) {
    events.push({
      category: "tool_added",
      severity: toolEventSeverity(tool),
      description: `Tool "${tool.tool_name}" (${tool.tool_id}) added from ${tool.source}`,
      subject: tool.tool_id,
      detected_at: now,
    });
  }

  // Tool removals
  for (const tool of diff.tools.removed) {
    events.push({
      category: "tool_removed",
      severity: "info",
      description: `Tool "${tool.tool_name}" (${tool.tool_id}) removed`,
      subject: tool.tool_id,
      detected_at: now,
    });
  }

  // Permission changes on tools
  for (const mod of diff.tools.modified) {
    if (mod.field === "permissions") {
      if (mod.new) {
        events.push({
          category: "permission_escalation",
          severity: "high",
          description: `Permission "${mod.new}" added to tool ${mod.tool_id}`,
          subject: mod.tool_id,
          detected_at: now,
        });
      } else if (mod.old) {
        events.push({
          category: "permission_reduction",
          severity: "info",
          description: `Permission "${mod.old}" removed from tool ${mod.tool_id}`,
          subject: mod.tool_id,
          detected_at: now,
        });
      }
    }
  }

  // Risk changes
  for (const risk of diff.risks.added) {
    events.push({
      category: "risk_introduced",
      severity: riskEventSeverity(risk.severity),
      description: `New risk "${risk.description}" (${risk.severity}/${risk.category})`,
      subject: risk.risk_id,
      detected_at: now,
    });
  }

  for (const risk of diff.risks.removed) {
    events.push({
      category: "risk_resolved",
      severity: "info",
      description: `Risk "${risk.risk_id}" (${risk.description}) removed`,
      subject: risk.risk_id,
      detected_at: now,
    });
  }

  for (const mod of diff.risks.modified) {
    if (mod.field === "severity") {
      const severityOrder: Record<string, number> = {
        low: 1,
        medium: 2,
        high: 3,
        critical: 4,
      };
      if ((severityOrder[mod.new] ?? 0) > (severityOrder[mod.old] ?? 0)) {
        events.push({
          category: "risk_escalated",
          severity: riskEventSeverity(mod.new),
          description: `Risk ${mod.risk_id} severity escalated from ${mod.old} to ${mod.new}`,
          subject: mod.risk_id,
          detected_at: now,
        });
      }
    }
  }

  // Permission scope changes
  for (const scope of diff.permissions.added) {
    events.push({
      category: "scope_expanded",
      severity: "high",
      description: `Permission scope "${scope}" granted`,
      subject: scope,
      detected_at: now,
    });
  }

  for (const scope of diff.permissions.removed) {
    events.push({
      category: "scope_restricted",
      severity: "info",
      description: `Permission scope "${scope}" removed`,
      subject: scope,
      detected_at: now,
    });
  }

  return createDriftAlert({
    agent_id: agentId,
    baseline_at: baselineAt,
    current_at: currentAt,
    events,
  });
}

/** Format a drift alert as a human-readable string for monitoring output. */
export function formatDriftAlert(alert: DriftAlert): string {
  const lines: string[] = [
    `Drift Alert — agent: ${alert.agent_id}`,
    `  Baseline: ${alert.baseline_at} → Current: ${alert.current_at}`,
    `  Events: ${alert.events.length}`,
  ];

  // Group events by severity
  const bySeverity = new Map<TrustEventSeverity, TrustEvent[]>();
  for (const event of alert.events) {
    const group = bySeverity.get(event.severity) ?? [];
    group.push(event);
    bySeverity.set(event.severity, group);
  }

  for (const [severity, events] of bySeverity) {
    lines.push("");
    lines.push(`  [${severity.toUpperCase()}] (${events.length})`);
    for (const event of events) {
      lines.push(`    • ${event.category}: ${event.description}`);
    }
  }

  if (alert.isEmpty()) {
    lines.push("  No drift events.");
  }

  return lines.join("\n");
}

// Compliance checker — exported from compliance.ts
export {
  type ComplianceProfile,
  type ComplianceResult,
  type ControlResult,
  checkCompliance,
  computeWeightedScore,
} from "./compliance.js";

// Shared manifest generator — exported from generate.ts
export {
  type AgentBOMGenerateInput,
  type AgentBOMLLMInput,
  type AgentBOMRecord,
  type AgentBOMToolInput,
  type AgentBOMWorkflowInput,
  type AgentBOMWorkflowStepInput,
  buildAgentBOM,
} from "./generate.js";
