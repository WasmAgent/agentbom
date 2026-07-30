#!/usr/bin/env bun
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  getLatestVersion as getLatestAgentBOMVersion,
  getSupportedVersions as getSupportedAgentBOMVersions,
  migrateAgentBOM,
} from "@wasmagent/agentbom-core";
import {
  getLatestVersion as getLatestPostureVersion,
  getSupportedVersions as getSupportedPostureVersions,
  migrateMCPPosture,
} from "@wasmagent/mcp-posture";
import { diffAgentBOMCommand } from "./agentbom-diff.js";
import { inspectAgentBOMCommand } from "./agentbom-inspect.js";
import { agentbomPipelineCommand } from "./agentbom-pipeline.js";
import { auditReportCommand } from "./audit-report.js";
import { generateAgentBOMCommand } from "./bom-generate.js";
import { chainCommand } from "./chain.js";
import {
  complianceCheckCommand,
  upgradeProfileCommand,
  verifyProfileCommand,
} from "./compliance-check.js";
import { composeTeamCommand } from "./compose-team.js";
import { exportDashboardCommand } from "./export-dashboard.js";
import { exportMarketplaceCommand } from "./export-marketplace.js";
import { diffMCPPostureCommand } from "./mcp-posture-diff.js";
import { inspectMCPPostureCommand } from "./mcp-posture-inspect.js";
import { validateMCPPostureCommand } from "./mcp-posture-validate.js";
import { inspectPassportCommand } from "./passport-inspect.js";
import { signPassportCommand } from "./passport-sign.js";
import { validatePassportCommand } from "./passport-validate.js";
import { verifySignedPassportCommand } from "./passport-verify-signed.js";
import { reportCommand } from "./regulatory-report.js";
import { verifySigstoreCommand } from "./sigstore-verify.js";
import { trustDiffCommand } from "./trust-diff.js";
import { publishCommand } from "./trust-publish.js";
import { pullCommand } from "./trust-pull.js";
import { subscribeCommand } from "./trust-subscribe.js";
import { verifyChainCommand } from "./trust-verify-chain.js";

const USAGE = [
  "Usage: agent-trust <command> [args]",
  "",
  "Commands:",
  "  chain [--example <dir>] [--out <path>]  Run the full trust chain end-to-end (offline)",
  "  passport validate <path>  Validate a trust passport file",
  "  passport inspect <path>    Inspect a trust passport file",
  "  passport sign <path> --key <key-path>  Sign a passport as JWT (EdDSA)",
  "  passport verify-signed <jwt-path> [--key <pubkey>]  Verify a signed passport JWT",
  "  passport verify-sigstore <bundle.json> [--artifact <path>] [--offline] [--fips] [--issuer <url>]  Verify with Sigstore bundle",
  "  agentbom inspect <path>    Inspect an AgentBOM file",
  "  agentbom diff <old> <new>  Diff two AgentBOM files",
  "  agentbom pipeline <path> [--partitions N] [--no-incremental]  Stream-process BOM artifacts",
  "  agentbom generate --agent <path>  Generate AgentBOM JSON from agent directory",
  "  generate bom --agent <path>  Generate AgentBOM JSON from agent directory (alias)",
  "  agentbom migrate <path> [--target <ver>] [--dry-run]  Migrate AgentBOM to target schema version",
  "  mcp-posture inspect <path>    Inspect an MCP posture file",
  "  mcp-posture validate <path>  Validate an MCP posture file",
  "  mcp-posture diff <old> <new> Diff two MCP posture snapshots",
  "  mcp-posture migrate <path> [--target <ver>] [--dry-run]  Migrate MCP Posture to target schema version",
  "  audit-report <bom.json>    Generate human-readable audit summary with evidence citations",
  "  audit-report multi <boms...> [--dir <dir>]  Generate multi-agent audit report with causal chain reconstruction",
  "  compliance-check <bom.json> --profile <name> [--min-score <score>]  Validate AgentBOM against compliance profile with adaptive weighted scoring",
  "  compliance-verify-profile <profile-id> [--schema-version <ver>]  Check profile backward compatibility against AgentBOM schema",
  "  compliance-upgrade-profile <profile-id> [--schema-version <ver>] [--dry-run]  Auto-resolve breaking mapping changes in a compliance profile",
  "  export-dashboard <bom.json> --output <dir>  Generate static HTML dashboard",
  "  export-dashboard fleet <dir> --output <dir>  Generate fleet trust analytics dashboard (posture, dependency graphs, compliance heatmap, audit search)",
  "  export-marketplace <bom.json> --output <dir>  Generate standardized marketplace trust package",
  "  enforce-policy <bom.json> --policy <policy.json> [--enforcement warn|block|quarantine] [--format json|text]  Validate agent artifacts against organization trust rules",
  "  subscribe <agent-id> --baseline <path> [--watch <dir>] [--callback <url>] [--interval <s>] [--once]  Monitor trust artifact drift for an agent",
  "  publish <artifact.json> [--registry <dir>] [--tag <tag>]  Publish trust artifact to registry with CAS identifier",
  "  pull <artifact-id> [--registry <dir>] [--output <path>] [--with-deps]  Retrieve trust artifact from registry with integrity verification",
  "  diff <artifact-a.json> <artifact-b.json> [--json]  Structured diff of trust artifacts (auto-detects type)",
  "  verify-chain <passport.jwt> --depth N [--key <pubkey>] [--registry <dir>]  Recursive trust chain verification with configurable depth and caching",
  "  compose-team <bom1.json> <bom2.json> [<bom3.json>...]  Compose multiple AgentBOMs into a composite trust manifest",
  "  report <bom.json> --framework <soc2|iso27001|ai-act> [--period <period>] [--format text|json] [--evidence-level summary|detailed]  Generate compliance-ready regulatory report with evidence citations",
].join("\n");

/** Parse --target and --dry-run flags from a CLI arg slice. */
function parseMigrateArgs(args: string[]): {
  filePath: string;
  target?: string;
  dryRun: boolean;
} {
  let filePath = "";
  let target: string | undefined;
  let dryRun = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--target" && i + 1 < args.length) {
      target = args[i + 1];
      i++;
    } else if (args[i] === "--dry-run") {
      dryRun = true;
    } else if (!args[i].startsWith("--")) {
      filePath = args[i];
    }
  }

  return { filePath, target, dryRun };
}

/** Read and parse a JSON file, returning an error code on failure. */
function readJsonFile(filePath: string): {
  data: Record<string, unknown>;
  error: number;
} {
  const resolved = resolve(filePath);
  let raw: string;
  try {
    raw = readFileSync(resolved, "utf-8");
  } catch {
    console.error(`Error: cannot read file "${resolved}"`);
    return { data: {}, error: 1 };
  }
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    console.error(`Error: "${resolved}" is not valid JSON`);
    return { data: {}, error: 1 };
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    console.error(`Error: "${resolved}" does not contain a JSON object`);
    return { data: {}, error: 1 };
  }
  return { data: data as Record<string, unknown>, error: 0 };
}

function agentbomMigrateCommand(args: string[]): number {
  const { filePath, target, dryRun } = parseMigrateArgs(args);
  if (!filePath) {
    console.error("Error: agentbom migrate requires a <path> argument");
    return 1;
  }

  const { data, error } = readJsonFile(filePath);
  if (error) return error;

  const agentbomLatest = `v${getLatestAgentBOMVersion()} (latest)`;
  console.log(
    `AgentBOM migration: v${data.agentbom_version ?? "unknown"} → ${target ?? agentbomLatest}`,
  );
  console.log(
    `  Supported versions: ${getSupportedAgentBOMVersions().join(", ")}`,
  );

  const result = migrateAgentBOM(data, target);

  if (!result.success) {
    console.error("  Migration failed:");
    for (const e of result.errors) console.error(`    - ${e}`);
    return 1;
  }

  if (result.stepsApplied.length === 0) {
    console.log("  Already at target version — no migration needed.");
  } else {
    for (const step of result.stepsApplied) {
      const breaking = step.breaking ? " (breaking)" : "";
      console.log(
        `  Step: ${step.fromVersion} → ${step.toVersion}: ${step.description}${breaking}`,
      );
    }
  }

  for (const w of result.warnings) {
    console.warn(`  Warning: ${w}`);
  }

  if (dryRun) {
    console.log("  (dry-run — no output written)");
    return 0;
  }

  console.log(JSON.stringify(result.data, null, 2));
  return 0;
}

function postureMigrateCommand(args: string[]): number {
  const { filePath, target, dryRun } = parseMigrateArgs(args);
  if (!filePath) {
    console.error("Error: mcp-posture migrate requires a <path> argument");
    return 1;
  }

  const { data, error } = readJsonFile(filePath);
  if (error) return error;

  const postureLatest = `v${getLatestPostureVersion()} (latest)`;
  console.log(
    `MCP Posture migration: v${data.posture_version ?? "unknown"} → ${target ?? postureLatest}`,
  );
  console.log(
    `  Supported versions: ${getSupportedPostureVersions().join(", ")}`,
  );

  const result = migrateMCPPosture(data, target);

  if (!result.success) {
    console.error("  Migration failed:");
    for (const e of result.errors) console.error(`    - ${e}`);
    return 1;
  }

  if (result.stepsApplied.length === 0) {
    console.log("  Already at target version — no migration needed.");
  } else {
    for (const step of result.stepsApplied) {
      const breaking = step.breaking ? " (breaking)" : "";
      console.log(
        `  Step: ${step.fromVersion} → ${step.toVersion}: ${step.description}${breaking}`,
      );
    }
  }

  for (const w of result.warnings) {
    console.warn(`  Warning: ${w}`);
  }

  if (dryRun) {
    console.log("  (dry-run — no output written)");
    return 0;
  }

  console.log(JSON.stringify(result.data, null, 2));
  return 0;
}

// --- Policy enforcement engine (mirrors cmd/policy-engine/main.go) ---

type EnforcementLevel = "warn" | "block" | "quarantine";

interface PolicyCondition {
  path: string;
  op: string;
  value?: unknown;
  values?: string[];
}

interface PolicyRule {
  id: string;
  description?: string;
  effect: string;
  when?: PolicyCondition;
  assert?: PolicyCondition;
  message?: string;
  severity?: string;
}

interface PolicyDocument {
  dsl_version?: string;
  policy_set_id: string;
  version: string;
  rules: PolicyRule[];
  includes?: PolicyDocument[];
}

interface RuleFinding {
  policy_set_id?: string;
  version?: string;
  rule_id: string;
  severity?: string;
  description?: string;
  message: string;
}

interface EvaluationResult {
  policy_set_id: string;
  version: string;
  allowed: boolean;
  violations: RuleFinding[];
  warnings: RuleFinding[];
  passed_rules: string[];
  metadata: Record<string, number>;
}

const SUPPORTED_DSL_VERSION = "1.0";

function scalarString(value: unknown): string {
  if (value === null || value === undefined) return "";
  return String(value);
}

function appendScalarValues(values: string[], node: unknown): string[] {
  if (Array.isArray(node)) {
    for (const item of node) {
      appendScalarValues(values, item);
    }
  } else if (typeof node === "object" && node !== null) {
    // nested object — not a scalar leaf
  } else {
    values.push(scalarString(node));
  }
  return values;
}

function appendArrayItems(items: unknown[], value: unknown): unknown[] {
  if (Array.isArray(value)) {
    return items.concat(value);
  }
  return items;
}

function valuesAtPath(root: unknown, path: string): string[] {
  if (!path) throw new Error("condition path is required");

  let nodes: unknown[] = [root];
  for (const segment of path.split(".")) {
    if (!segment) throw new Error(`invalid empty path segment in "${path}"`);

    const arrayMode = segment.endsWith("[]");
    const key = segment.slice(0, -2);
    const next: unknown[] = [];

    for (const node of nodes) {
      if (typeof node !== "object" || node === null || Array.isArray(node))
        continue;
      const obj = node as Record<string, unknown>;
      const value = obj[key];
      if (value === undefined) continue;
      if (arrayMode) {
        appendArrayItems(next, value);
      } else {
        next.push(value);
      }
    }
    nodes = next;
  }

  const values: string[] = [];
  for (const node of nodes) {
    appendScalarValues(values, node);
  }
  return values;
}

function anyValueIn(values: string[], expected: Set<string>): boolean {
  for (const v of values) {
    if (expected.has(v)) return true;
  }
  return false;
}

function allValuesIn(values: string[], expected: Set<string>): boolean {
  for (const v of values) {
    if (!expected.has(v)) return false;
  }
  return true;
}

function anyValueOutside(values: string[], expected: Set<string>): boolean {
  for (const v of values) {
    if (!expected.has(v)) return true;
  }
  return false;
}

function anyStringContains(values: string[], expected: Set<string>): boolean {
  for (const v of values) {
    for (const needle of expected) {
      if (v.includes(needle)) return true;
    }
  }
  return false;
}

function evaluateCondition(cond: PolicyCondition, artifact: unknown): boolean {
  const values = valuesAtPath(artifact, cond.path);

  const expected = cond.values ? new Set(cond.values) : null;
  const singleValue =
    cond.value !== undefined ? scalarString(cond.value) : null;

  switch (cond.op) {
    case "exists":
      return values.length > 0;
    case "missing":
      return values.length === 0;
    case "equals": {
      const set = new Set<string>();
      if (expected) for (const v of expected) set.add(v);
      if (singleValue !== null) set.add(singleValue);
      return anyValueIn(values, set);
    }
    case "not_equals": {
      const set = new Set<string>();
      if (expected) for (const v of expected) set.add(v);
      if (singleValue !== null) set.add(singleValue);
      return values.length > 0 && !anyValueIn(values, set);
    }
    case "in": {
      const set = new Set<string>();
      if (expected) for (const v of expected) set.add(v);
      if (singleValue !== null) set.add(singleValue);
      return values.length > 0 && allValuesIn(values, set);
    }
    case "not_in": {
      const set = new Set<string>();
      if (expected) for (const v of expected) set.add(v);
      if (singleValue !== null) set.add(singleValue);
      return anyValueOutside(values, set);
    }
    case "contains": {
      const set = new Set<string>();
      if (expected) for (const v of expected) set.add(v);
      if (singleValue !== null) set.add(singleValue);
      return anyStringContains(values, set);
    }
    case "intersects": {
      const set = new Set<string>();
      if (expected) for (const v of expected) set.add(v);
      if (singleValue !== null) set.add(singleValue);
      return anyValueIn(values, set);
    }
    default:
      throw new Error(`unsupported op "${cond.op}"`);
  }
}

function composePolicyRules(
  policy: PolicyDocument,
): { policySetId: string; version: string; rule: PolicyRule }[] {
  const rules: { policySetId: string; version: string; rule: PolicyRule }[] =
    [];
  if (policy.includes) {
    for (const included of policy.includes) {
      rules.push(...composePolicyRules(included));
    }
  }
  for (const rule of policy.rules) {
    rules.push({
      policySetId: policy.policy_set_id,
      version: policy.version,
      rule,
    });
  }
  return rules;
}

function countPolicyDocuments(policy: PolicyDocument): number {
  let count = 1;
  if (policy.includes) {
    for (const included of policy.includes) {
      count += countPolicyDocuments(included);
    }
  }
  return count;
}

function findingForRule(
  composed: { policySetId: string; version: string; rule: PolicyRule },
  fallback: string,
): RuleFinding {
  return {
    policy_set_id: composed.policySetId,
    version: composed.version,
    rule_id: composed.rule.id,
    severity: composed.rule.severity,
    description: composed.rule.description,
    message: composed.rule.message || fallback,
  };
}

function evaluatePolicy(
  policy: PolicyDocument,
  artifact: unknown,
): EvaluationResult {
  const rules = composePolicyRules(policy);
  const result: EvaluationResult = {
    policy_set_id: policy.policy_set_id,
    version: policy.version,
    allowed: true,
    violations: [],
    warnings: [],
    passed_rules: [],
    metadata: {
      policy_sets_composed: countPolicyDocuments(policy),
      rules_evaluated: rules.length,
    },
  };

  for (const composed of rules) {
    const rule = composed.rule;
    if (!rule.when) continue;

    const matches = evaluateCondition(rule.when, artifact);
    if (!matches) {
      result.passed_rules.push(rule.id);
      continue;
    }

    switch (rule.effect) {
      case "deny":
        result.allowed = false;
        result.violations.push(
          findingForRule(composed, "deny condition matched"),
        );
        break;
      case "warn":
        result.warnings.push(
          findingForRule(composed, "warn condition matched"),
        );
        result.passed_rules.push(rule.id);
        break;
      case "require":
        if (!rule.assert) {
          result.allowed = false;
          result.violations.push(
            findingForRule(composed, "required rule missing assert condition"),
          );
          break;
        }
        if (evaluateCondition(rule.assert, artifact)) {
          result.passed_rules.push(rule.id);
        } else {
          result.allowed = false;
          result.violations.push(
            findingForRule(composed, "required assertion failed"),
          );
        }
        break;
    }
  }

  result.passed_rules.sort();
  result.metadata.rules_passed = result.passed_rules.length;
  result.metadata.violations = result.violations.length;
  result.metadata.warnings = result.warnings.length;
  return result;
}

function validatePolicyDocument(policy: PolicyDocument): string | null {
  if (policy.dsl_version && policy.dsl_version !== SUPPORTED_DSL_VERSION) {
    return `policy "${policy.policy_set_id}" has unsupported dsl_version "${policy.dsl_version}"`;
  }
  if (!policy.policy_set_id) return "policy missing policy_set_id";
  if (!policy.version) return "policy missing version";
  if (
    (!policy.rules || policy.rules.length === 0) &&
    (!policy.includes || policy.includes.length === 0)
  ) {
    return "policy must contain at least one rule";
  }
  for (let i = 0; i < policy.rules.length; i++) {
    const rule = policy.rules[i] as PolicyRule;
    if (!rule.id) return `policy rule ${i} missing id`;
    switch (rule.effect) {
      case "deny":
      case "warn":
        if (!rule.when)
          return `policy rule "${rule.id}" missing when condition`;
        break;
      case "require":
        if (!rule.when || !rule.assert)
          return `policy rule "${rule.id}" requires both when and assert conditions`;
        break;
      default:
        return `policy rule "${rule.id}" has unsupported effect "${rule.effect}"`;
    }
  }
  if (policy.includes) {
    for (let i = 0; i < policy.includes.length; i++) {
      const err = validatePolicyDocument(policy.includes[i] as PolicyDocument);
      if (err) return `included policy ${i}: ${err}`;
    }
  }
  return null;
}

function enforcePolicyCommand(args: string[]): number {
  let artifactPath = "";
  let policyPath = "";
  let enforcement: EnforcementLevel = "block";
  let format = "json";

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--policy" && i + 1 < args.length) {
      policyPath = args[++i];
    } else if (args[i] === "--enforcement" && i + 1 < args.length) {
      const val = args[++i];
      if (val !== "warn" && val !== "block" && val !== "quarantine") {
        console.error(
          `Error: invalid --enforcement "${val}"; must be warn, block, or quarantine`,
        );
        return 1;
      }
      enforcement = val as EnforcementLevel;
    } else if (args[i] === "--format" && i + 1 < args.length) {
      format = args[++i];
    } else if (!args[i].startsWith("--")) {
      artifactPath = args[i];
    }
  }

  if (!artifactPath) {
    console.error("Error: enforce-policy requires a <bom.json> argument");
    return 1;
  }
  if (!policyPath) {
    console.error("Error: enforce-policy requires --policy <policy.json>");
    return 1;
  }

  const { data: policyData, error: policyErr } = readJsonFile(policyPath);
  if (policyErr) return policyErr;

  const { data: artifactData, error: artifactErr } = readJsonFile(artifactPath);
  if (artifactErr) return artifactErr;

  const policy = policyData as unknown as PolicyDocument;
  const artifact = artifactData;

  const validationErr = validatePolicyDocument(policy);
  if (validationErr) {
    console.error(`Error: ${validationErr}`);
    return 1;
  }

  let result: EvaluationResult;
  try {
    result = evaluatePolicy(policy, artifact);
  } catch (err) {
    console.error(`Error: policy evaluation failed: ${(err as Error).message}`);
    return 1;
  }

  switch (format) {
    case "json":
      console.log(JSON.stringify(result, null, 2));
      break;
    case "text": {
      const status = result.allowed ? "allowed" : "rejected";
      console.log(`${status} ${result.policy_set_id}@${result.version}`);
      for (const v of result.violations) {
        console.log(`violation ${v.rule_id}: ${v.message}`);
      }
      for (const w of result.warnings) {
        console.log(`warning ${w.rule_id}: ${w.message}`);
      }
      console.log(
        `  ${result.passed_rules.length} rules passed, ${result.violations.length} violations, ${result.warnings.length} warnings`,
      );
      break;
    }
    default:
      console.error(
        `Error: unsupported --format "${format}"; use json or text`,
      );
      return 1;
  }

  if (!result.allowed) {
    switch (enforcement) {
      case "warn":
        console.warn(
          "Policy violations detected (enforcement=warn: proceeding anyway)",
        );
        return 0;
      case "quarantine":
        console.error(
          "Policy violations detected (enforcement=quarantine: artifact quarantined)",
        );
        return 2;
      default:
        return 1;
    }
  }

  return 0;
}

export function runCommand(args: string[]): number | Promise<number> {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    console.log(USAGE);
    return 0;
  }

  if (args[0] === "chain") {
    return chainCommand(args.slice(1));
  }

  if (args[0] === "passport") {
    if (args[1] === "validate") {
      if (args.length < 3) {
        console.error("Error: passport validate requires a <path> argument");
        return 1;
      }
      return validatePassportCommand(args[2]);
    }
    if (args[1] === "inspect") {
      if (args.length < 3) {
        console.error("Error: passport inspect requires a <path> argument");
        return 1;
      }
      return inspectPassportCommand(args[2]);
    }
    if (args[1] === "sign") {
      return signPassportCommand(args.slice(2));
    }
    if (args[1] === "verify-signed") {
      return verifySignedPassportCommand(args.slice(2));
    }
    if (args[1] === "verify-sigstore") {
      return verifySigstoreCommand(args.slice(2));
    }
    console.error(`Error: unknown passport subcommand "${args[1]}"`);
    return 1;
  }

  if (args[0] === "agentbom") {
    if (args[1] === "inspect") {
      if (args.length < 3) {
        console.error("Error: agentbom inspect requires a <path> argument");
        return 1;
      }
      return inspectAgentBOMCommand(args[2]);
    }
    if (args[1] === "diff") {
      if (args.length < 4) {
        console.error(
          "Error: agentbom diff requires <old> and <new> path arguments",
        );
        return 1;
      }
      return diffAgentBOMCommand(args[2], args[3]);
    }
    if (args[1] === "generate") {
      return generateAgentBOMCommand(args.slice(2));
    }
    if (args[1] === "pipeline") {
      return agentbomPipelineCommand(args.slice(2));
    }
    if (args[1] === "migrate") {
      if (args.length < 3) {
        console.error("Error: agentbom migrate requires a <path> argument");
        return 1;
      }
      return agentbomMigrateCommand(args.slice(2));
    }
    console.error(`Error: unknown agentbom subcommand "${args[1]}"`);
    return 1;
  }

  if (args[0] === "mcp-posture") {
    if (args[1] === "inspect") {
      if (args.length < 3) {
        console.error("Error: mcp-posture inspect requires a <path> argument");
        return 1;
      }
      return inspectMCPPostureCommand(args[2]);
    }
    if (args[1] === "validate") {
      if (args.length < 3) {
        console.error("Error: mcp-posture validate requires a <path> argument");
        return 1;
      }
      return validateMCPPostureCommand(args[2]);
    }
    if (args[1] === "diff") {
      if (args.length < 4) {
        console.error(
          "Error: mcp-posture diff requires <old> and <new> path arguments",
        );
        return 1;
      }
      return diffMCPPostureCommand(args[2], args[3]);
    }
    if (args[1] === "migrate") {
      if (args.length < 3) {
        console.error("Error: mcp-posture migrate requires a <path> argument");
        return 1;
      }
      return postureMigrateCommand(args.slice(2));
    }
    console.error(`Error: unknown mcp-posture subcommand "${args[1]}"`);
    return 1;
  }

  if (args[0] === "generate") {
    if (args[1] === "bom") {
      return generateAgentBOMCommand(args.slice(2));
    }
    console.error(`Error: unknown generate subcommand "${args[1]}"`);
    return 1;
  }

  if (args[0] === "audit-report") {
    if (args.length < 2) {
      console.error("Error: audit-report requires a <bom.json> argument");
      return 1;
    }
    return auditReportCommand(args.slice(1));
  }

  if (args[0] === "compliance-check") {
    return complianceCheckCommand(args.slice(1));
  }

  if (args[0] === "compliance-verify-profile") {
    return verifyProfileCommand(args.slice(1));
  }

  if (args[0] === "compliance-upgrade-profile") {
    return upgradeProfileCommand(args.slice(1));
  }

  if (args[0] === "export-dashboard") {
    return exportDashboardCommand(args.slice(1));
  }

  if (args[0] === "enforce-policy" || args[0] === "enf") {
    return enforcePolicyCommand(args.slice(1));
  }

  if (args[0] === "publish") {
    return publishCommand(args.slice(1));
  }

  if (args[0] === "pull") {
    return pullCommand(args.slice(1));
  }

  if (args[0] === "diff") {
    return trustDiffCommand(args.slice(1));
  }

  if (args[0] === "subscribe") {
    return subscribeCommand(args.slice(1));
  }

  if (args[0] === "verify-chain") {
    return verifyChainCommand(args.slice(1));
  }

  if (args[0] === "report") {
    return reportCommand(args.slice(1));
  }

  if (args[0] === "export-marketplace") {
    return exportMarketplaceCommand(args.slice(1));
  }

  if (args[0] === "compose-team") {
    return composeTeamCommand(args.slice(1));
  }

  console.error(`Error: unknown command "${args[0]}"`);
  return 1;
}

// Only auto-run main when executed directly (not when imported for testing)
const isDirectRun =
  process.argv[1]?.endsWith("index.ts") ||
  process.argv[1]?.endsWith("index.js");
if (isDirectRun) {
  const args = process.argv.slice(2);
  const result = runCommand(args);
  if (result instanceof Promise) {
    result
      .then((code) => process.exit(code))
      .catch((err) => {
        console.error(err);
        process.exit(1);
      });
  } else {
    process.exit(result);
  }
}
