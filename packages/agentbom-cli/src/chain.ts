/**
 * agent-trust chain — end-to-end trust artifact chain runner.
 *
 * Walks the full Agent Trust Infrastructure chain in-process and offline:
 *
 *   bscode workload
 *         ↓ declare capabilities + emit evidence
 *   CapabilityManifest + AEP
 *         ↓ compose
 *   AgentBOM
 *         ↓ scan MCP surface
 *   MCP Posture
 *         ↓ validate evidence + map frameworks
 *   audit report
 *         ↓ summarize
 *   Trust Passport
 *
 * The runner reuses the existing `packages/*` validators (Zod-style schema
 * validators) and the existing fixtures under `examples/bscode-agent/`. It does
 * not touch the network. Each step records a `verdict`, a `duration_ms`, and a
 * deterministic `output_hash` so the result is reproducible.
 */
import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectTrustPassport, isExpired, validateTrustPassport } from '@openagentaudit/passport';
import { inspectAgentBOM, validateAgentBOM } from '@wasmagent/agentbom-core';
import {
  inspectMCPPosture,
  validateMCPPosture,
} from '@wasmagent/mcp-posture';

/** Per-step outcome written to `chain-report.json` and streamed to stdout. */
export interface ChainStepResult {
  /** Stable machine identifier for the step (matches the chain node). */
  step: string;
  /** Human-readable label. */
  label: string;
  /** "valid" when the step passed, "invalid" otherwise. */
  verdict: 'valid' | 'invalid';
  /** Wall-clock duration of the step in milliseconds. */
  duration_ms: number;
  /** Deterministic SHA-256 of the step's canonical output (`sha256:<hex>`). */
  output_hash: string;
  /** Structured detail about what the step checked / produced. */
  detail: Record<string, unknown>;
  /** Empty when the step is valid; human-readable failure reasons otherwise. */
  errors: string[];
}

/** Aggregate chain report persisted as `chain-report.json`. */
export interface ChainReport {
  /** ISO-8601 timestamp the chain was run. */
  timestamp: string;
  /** Repository sha at run time (`git rev-parse HEAD`), or `"unknown"` offline. */
  repo_sha: string;
  /** Absolute path of the example directory the chain ran against. */
  example: string;
  /** Roll-up of the per-step verdicts. */
  overall: {
    status: 'valid' | 'invalid';
    valid_steps: number;
    total_steps: number;
  };
  /** Ordered per-step results. */
  steps: ChainStepResult[];
}

/** Ordered step identifiers — the 6 chain nodes joined by 5 verifiable links. */
export const CHAIN_STEPS = [
  'manifest',
  'agentbom',
  'mcp-posture',
  'audit-report',
  'trust-passport',
] as const;

const DEFAULT_EXAMPLE_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../../examples/bscode-agent',
);

const CHAIN_USAGE = [
  'Usage: agent-trust chain [--example <dir>] [--out <path>]',
  '',
  'Runs the full Agent Trust Infrastructure chain in-process and fully offline:',
  '  bscode → CapabilityManifest + AEP → AgentBOM → MCP Posture → audit report → Trust Passport',
  '',
  'Emits one JSON object per step to stdout and writes chain-report.json.',
  '',
  'Options:',
  '  --example <dir>  Example directory containing agentbom.json, posture.json,',
  '                  and trust-passport.json (default: examples/bscode-agent).',
  '  --out <path>     Output path for chain-report.json (default: ./chain-report.json).',
  '',
  'Example:',
  '  agent-trust chain --example examples/bscode-agent --out chain-report.json',
].join('\n');

/** Deterministic JSON canonicalization: object keys sorted recursively. */
function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf-8').digest('hex');
}

function hashObject(value: unknown): string {
  return `sha256:${sha256Hex(canonicalize(value))}`;
}

function hashFile(path: string): string {
  return `sha256:${sha256Hex(readFileSync(path, 'utf-8'))}`;
}

function loadJSON<T = unknown>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf-8')) as T;
}

function repoSha(): string {
  try {
    return execSync('git rev-parse HEAD', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch {
    // Offline / non-git context: no sha available.
    return 'unknown';
  }
}

function now(): string {
  return new Date().toISOString();
}

type Timer = () => number;
const startTimer: Timer = () => Date.now();
const elapsedMs = (start: number): number => Date.now() - start;

function asRecord(value: unknown): Record<string, unknown> {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function stringArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/**
 * Step 1 — manifest: reconstruct the bscode CapabilityManifest + AEP surface
 * from the workload composition (AgentBOM) and verify it is well-formed.
 *
 * A real runtime emits the manifest before the AgentBOM exists; for this
 * offline demo we derive it from the existing fixture so the full chain can be
 * walked without a live wasmagent-js runtime.
 */
function runManifestStep(exampleDir: string): ChainStepResult {
  const start = startTimer();
  const errors: string[] = [];
  const bomPath = resolve(exampleDir, 'agentbom.json');
  let manifest: Record<string, unknown> = {};

  try {
    const bom = asRecord(loadJSON(bomPath));
    const identity = asRecord(bom.identity);
    const toolLayer = stringArray(bom.tool_layer);
    const permissionLayer = asRecord(bom.permission_layer);
    const modelLayer = asRecord(bom.model_layer);

    manifest = {
      manifest_version: '0.1',
      agent_id: identity.agent_id ?? null,
      capabilities: toolLayer.map((t) => asRecord(t).tool_id ?? null),
      permissions: stringArray(permissionLayer.granted_scopes),
      model: modelLayer.model_id ?? null,
      aep_evidence: true,
    };

    if (!manifest.agent_id) errors.push('manifest: missing agent_id');
    if (!Array.isArray(manifest.capabilities) || manifest.capabilities.length === 0) {
      errors.push('manifest: capability list is empty');
    }
  } catch (err) {
    errors.push(`manifest: ${err instanceof Error ? err.message : String(err)}`);
  }

  return {
    step: 'manifest',
    label: 'CapabilityManifest + AEP',
    verdict: errors.length === 0 ? 'valid' : 'invalid',
    duration_ms: elapsedMs(start),
    output_hash: hashObject(manifest),
    detail: { source: 'agentbom.json', reconstructed: true },
    errors,
  };
}

/** Step 2 — agentbom: validate the AgentBOM fixture against its schema. */
function runAgentBomStep(exampleDir: string): ChainStepResult {
  const start = startTimer();
  const errors: string[] = [];
  const bomPath = resolve(exampleDir, 'agentbom.json');
  let outputHash = '';
  let summary = '';

  try {
    const data = loadJSON<unknown>(bomPath);
    const result = validateAgentBOM(data);
    if (!result.valid) errors.push(...result.errors);
    outputHash = hashFile(bomPath);
    summary = inspectAgentBOM(asRecord(data));
  } catch (err) {
    errors.push(`agentbom: ${err instanceof Error ? err.message : String(err)}`);
  }

  return {
    step: 'agentbom',
    label: 'AgentBOM',
    verdict: errors.length === 0 ? 'valid' : 'invalid',
    duration_ms: elapsedMs(start),
    output_hash: outputHash,
    detail: { schema: 'specs/agentbom/schema.json', inspect: summary },
    errors,
  };
}

/** Step 3 — mcp-posture: validate the MCP Posture fixture. */
function runPostureStep(exampleDir: string): ChainStepResult {
  const start = startTimer();
  const errors: string[] = [];
  const posturePath = resolve(exampleDir, 'posture.json');
  let outputHash = '';
  let summary = '';

  try {
    const data = loadJSON<unknown>(posturePath);
    const result = validateMCPPosture(data);
    if (!result.valid) errors.push(...result.errors);
    outputHash = hashFile(posturePath);
    summary = inspectMCPPosture(asRecord(data));
  } catch (err) {
    errors.push(`mcp-posture: ${err instanceof Error ? err.message : String(err)}`);
  }

  return {
    step: 'mcp-posture',
    label: 'MCP Posture',
    verdict: errors.length === 0 ? 'valid' : 'invalid',
    duration_ms: elapsedMs(start),
    output_hash: outputHash,
    detail: { schema: 'specs/mcp-posture/schema.json', inspect: summary },
    errors,
  };
}

/**
 * Step 4 — audit-report: synthesize a deterministic audit-report reference from
 * the AgentBOM + MCP Posture (open findings, framework mapping). In production
 * this is produced by `open-agent-audit`; here it is a reproducible placeholder.
 */
function runAuditStep(exampleDir: string): ChainStepResult {
  const start = startTimer();
  const errors: string[] = [];
  let report: Record<string, unknown> = {};

  try {
    const bom = asRecord(loadJSON(resolve(exampleDir, 'agentbom.json')));
    const posture = asRecord(loadJSON(resolve(exampleDir, 'posture.json')));
    const bomIdentity = asRecord(bom.identity);
    const postureIdentity = asRecord(posture.identity);
    const permissionGraph = asRecord(posture.permission_graph);
    const risks = stringArray(bom.risk_layer);
    const openRisks = risks.filter((r) => asRecord(r).status === 'open');

    report = {
      report_id: 'audit-bscode-demo-001',
      agent_id: bomIdentity.agent_id ?? null,
      snapshot_id: postureIdentity.snapshot_id ?? null,
      generated_at: (bomIdentity.generated_at as string | undefined) ?? null,
      open_findings: openRisks.length,
      high_risk_tools: permissionGraph.high_risk_tools ?? 0,
      framework_mappings: [{ framework: 'OWASP-MCP-Top10', coverage: 'partial' }],
      note: 'Demo placeholder. Not a real audit.',
    };

    if (!report.agent_id) errors.push('audit-report: missing agent_id');
    if (
      bomIdentity.agent_id &&
      postureIdentity.agent_id &&
      bomIdentity.agent_id !== postureIdentity.agent_id
    ) {
      errors.push('audit-report: agent_id mismatch between AgentBOM and posture');
    }
  } catch (err) {
    errors.push(`audit-report: ${err instanceof Error ? err.message : String(err)}`);
  }

  return {
    step: 'audit-report',
    label: 'Audit report',
    verdict: errors.length === 0 ? 'valid' : 'invalid',
    duration_ms: elapsedMs(start),
    output_hash: hashObject(report),
    detail: { synthesized: true, reference: 'open-agent-audit (placeholder)' },
    errors,
  };
}

/** Step 5 — trust-passport: validate the Trust Passport and its cross-references. */
function runPassportStep(exampleDir: string): ChainStepResult {
  const start = startTimer();
  const errors: string[] = [];
  const passportPath = resolve(exampleDir, 'trust-passport.json');
  let outputHash = '';
  let summary = '';

  try {
    const bom = asRecord(loadJSON(resolve(exampleDir, 'agentbom.json')));
    const posture = asRecord(loadJSON(resolve(exampleDir, 'posture.json')));
    const passport = loadJSON<unknown>(passportPath);

    const result = validateTrustPassport(passport);
    if (!result.valid) errors.push(...result.errors);

    const passportObj = asRecord(passport);
    const agentbomRef = asRecord(passportObj.agentbom_ref);
    const postureRef = asRecord(passportObj.posture_ref);
    const bomIdentity = asRecord(bom.identity);
    const postureIdentity = asRecord(posture.identity);

    if (
      agentbomRef.agentbom_id &&
      bomIdentity.agent_id &&
      agentbomRef.agentbom_id !== bomIdentity.agent_id
    ) {
      errors.push(
        'trust-passport: agentbom_ref.agentbom_id does not match AgentBOM identity.agent_id',
      );
    }
    if (
      postureRef.snapshot_id &&
      postureIdentity.snapshot_id &&
      postureRef.snapshot_id !== postureIdentity.snapshot_id
    ) {
      errors.push(
        'trust-passport: posture_ref.snapshot_id does not match posture identity.snapshot_id',
      );
    }
    if (isExpired(passportObj)) {
      errors.push('trust-passport: passport has expired');
    }

    outputHash = hashFile(passportPath);
    summary = inspectTrustPassport(passportObj);
  } catch (err) {
    errors.push(`trust-passport: ${err instanceof Error ? err.message : String(err)}`);
  }

  return {
    step: 'trust-passport',
    label: 'Trust Passport',
    verdict: errors.length === 0 ? 'valid' : 'invalid',
    duration_ms: elapsedMs(start),
    output_hash: outputHash,
    detail: { schema: 'specs/trust-passport/schema.json', inspect: summary },
    errors,
  };
}

/**
 * Run the full chain in-process against an example directory. Pure: does not
 * print or write files. Use {@link chainCommand} for the CLI wrapper.
 */
export function runChain(exampleDir: string = DEFAULT_EXAMPLE_DIR): ChainReport {
  const resolved = resolve(exampleDir);
  const steps: ChainStepResult[] = [
    runManifestStep(resolved),
    runAgentBomStep(resolved),
    runPostureStep(resolved),
    runAuditStep(resolved),
    runPassportStep(resolved),
  ];

  const validSteps = steps.filter((s) => s.verdict === 'valid').length;
  return {
    timestamp: now(),
    repo_sha: repoSha(),
    example: resolved,
    overall: {
      status: validSteps === steps.length ? 'valid' : 'invalid',
      valid_steps: validSteps,
      total_steps: steps.length,
    },
    steps,
  };
}

/** CLI entry point for `agent-trust chain`. */
export function chainCommand(args: string[]): number {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(CHAIN_USAGE);
    return 0;
  }

  let exampleDir = DEFAULT_EXAMPLE_DIR;
  let outPath = 'chain-report.json';
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];
    if (arg === '--example' && next) {
      exampleDir = next;
      i++;
    } else if (arg === '--out' && next) {
      outPath = next;
      i++;
    } else {
      console.error(`Error: unknown chain argument "${arg}"`);
      console.error(CHAIN_USAGE);
      return 1;
    }
  }

  const report = runChain(exampleDir);

  // Logging contract: one JSON object per step on stdout.
  for (const step of report.steps) {
    console.log(JSON.stringify(step));
  }

  const resolvedOut = resolve(outPath);
  writeFileSync(resolvedOut, `${JSON.stringify(report, null, 2)}\n`, 'utf-8');

  if (report.overall.status !== 'valid') {
    const failed = report.steps
      .filter((s) => s.verdict !== 'valid')
      .map((s) => s.step)
      .join(', ');
    console.error(`Chain failed: ${failed}`);
    return 1;
  }

  console.error(
    `Chain valid: ${report.overall.valid_steps}/${report.overall.total_steps} steps → ${resolvedOut}`,
  );
  return 0;
}
