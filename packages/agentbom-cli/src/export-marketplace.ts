/**
 * `export-marketplace.ts` — data model and pure builder for marketplace trust
 * packages (schema `marketplace-trust-package/v1`).
 *
 * Split from #332 (marketplace trust export). This module owns only the data
 * model and the pure {@link buildMarketplacePackage} builder; the CLI command
 * wiring is a follow-up issue.
 *
 * The builder reads fields from an AgentBOM using safe property access and never
 * throws on missing or malformed input — absent fields fall back to documented
 * defaults. The caller computes the content-addressable identifier (`cas_id`)
 * of the source BOM (e.g. with `createHash('sha256')` over its canonical JSON,
 * mirroring `trust-publish.ts`) and passes it in; this module touches neither
 * the filesystem nor hashing.
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

// ---- Types ----

/** Schema version identifier for marketplace trust packages. */
export const MARKETPLACE_PACKAGE_SCHEMA = 'marketplace-trust-package/v1' as const;

/** A trust attestation referenced by a marketplace package. */
export interface TrustAttestation {
  /** Attestation type, e.g. 'passport', 'audit-log'. */
  type: string;
  /** Identifier or path to the attestation artifact. */
  reference: string;
}

/** Compliance summary surfaced in a marketplace package. */
export interface ComplianceSummary {
  /** Compliance framework IDs derived from the BOM's compliance mappings. */
  frameworks: string[];
  /** Number of compliance checks that passed. */
  passed_checks: number;
  /** Total number of compliance checks. */
  total_checks: number;
}

/** A marketplace trust package derived from an AgentBOM. */
export interface MarketplacePackage {
  schema: 'marketplace-trust-package/v1';
  /** ISO-8601 timestamp of package generation. */
  generated_at: string;
  agent_id: string;
  agent_name: string;
  /** From `bom.identity.agent_version` / `bom.agent_version`, or 'unknown'. */
  agent_version: string;
  /** From `bom.maintainer`, or 'unknown'. */
  publisher: string;
  /** From `bom.capabilities.declared` / `bom.model_layer.capabilities`, or []. */
  capabilities: string[];
  compliance_summary: ComplianceSummary;
  trust_attestations: TrustAttestation[];
  /** sha256 of the canonical JSON of the source BOM (passed in by the caller). */
  cas_id: string;
  /** Human-readable one-liner for operators. */
  verification_instructions: string;
}

// ---- Pure helpers ----

/**
 * Coerce an unknown value to a non-empty string, returning `fallback` when the
 * value is absent or not a usable string. Keeps field extraction resilient to
 * malformed BOM input.
 */
function asString(value: unknown, fallback = 'unknown'): string {
  return typeof value === 'string' && value.length > 0 ? value : fallback;
}

/**
 * Coerce an unknown value to an array of strings, dropping non-string entries.
 * Returns `fallback` (default `[]`) when the value is not an array.
 */
function asStringArray(value: unknown, fallback: string[] = []): string[] {
  if (!Array.isArray(value)) return fallback;
  return value.filter((entry): entry is string => typeof entry === 'string');
}

/**
 * Narrow an unknown value to a plain record.
 * Returns `undefined` when the value is absent, an array, or not an object.
 */
function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

/** One-liner shown to operators describing how to verify the package. */
const VERIFICATION_INSTRUCTIONS =
  'Run: trust-cli compliance-check <bom> --profile default to verify';

/**
 * Extract agent identity fields from a BOM.
 *
 * Supports both the canonical AgentBOM layout (`bom.identity.*`) and the flat
 * layout referenced in the marketplace export spec (`bom.agent_id`, etc.).
 * Falls back to `'unknown'` when neither is present.
 */
function extractIdentity(bom: Record<string, unknown>): {
  agent_id: string;
  agent_name: string;
  agent_version: string;
} {
  const identity = asRecord(bom.identity);
  return {
    agent_id: asString(identity?.agent_id ?? bom.agent_id),
    agent_name: asString(identity?.agent_name ?? bom.agent_name),
    agent_version: asString(identity?.agent_version ?? bom.agent_version),
  };
}

/**
 * Extract declared agent capabilities from a BOM.
 *
 * Supports the marketplace spec shape (`bom.capabilities.declared`), the
 * canonical AgentBOM model layer (`bom.model_layer.capabilities`), and a flat
 * array (`bom.capabilities`). Falls back to `[]` when absent.
 */
function extractCapabilities(bom: Record<string, unknown>): string[] {
  const capabilitiesObject = asRecord(bom.capabilities);
  const modelLayer = asRecord(bom.model_layer);
  return asStringArray(
    capabilitiesObject?.declared ?? modelLayer?.capabilities ?? bom.capabilities,
  );
}

/**
 * Extract the compliance summary from a BOM.
 *
 * Framework IDs are read from each entry of `bom.compliance_mappings[].framework_id`.
 * Pass/total check counts are not carried by the source BOM and default to `0`.
 */
function extractComplianceSummary(bom: Record<string, unknown>): ComplianceSummary {
  const mappings = Array.isArray(bom.compliance_mappings) ? bom.compliance_mappings : [];
  const frameworks: string[] = [];
  for (const entry of mappings) {
    const frameworkId = asString(asRecord(entry)?.framework_id, '');
    if (frameworkId) frameworks.push(frameworkId);
  }
  return { frameworks, passed_checks: 0, total_checks: 0 };
}

/**
 * Build a {@link MarketplacePackage} from an AgentBOM and its precomputed CAS ID.
 *
 * Pure data-layer function for the marketplace trust export. It extracts every
 * field using safe property access and never throws on missing or malformed
 * input — absent fields fall back to documented defaults:
 *
 * - `agent_id`, `agent_name`, `agent_version`, `publisher` → `'unknown'`
 * - `capabilities`, `frameworks`, `trust_attestations` → `[]`
 * - `passed_checks` / `total_checks` → `0`
 *
 * `cas_id` is the caller-computed SHA-256 of the source BOM's canonical JSON;
 * this function does not recompute it.
 */
export function buildMarketplacePackage(
  bom: Record<string, unknown>,
  bomCasId: string,
): MarketplacePackage {
  const identity = extractIdentity(bom);

  return {
    schema: MARKETPLACE_PACKAGE_SCHEMA,
    generated_at: new Date().toISOString(),
    agent_id: identity.agent_id,
    agent_name: identity.agent_name,
    agent_version: identity.agent_version,
    publisher: asString(bom.maintainer),
    capabilities: extractCapabilities(bom),
    compliance_summary: extractComplianceSummary(bom),
    trust_attestations: [],
    cas_id: bomCasId,
    verification_instructions: VERIFICATION_INSTRUCTIONS,
  };
}

// ---- CLI command ----

/**
 * CLI entry point for `agent-trust export-marketplace <bom.json> --output <dir>`.
 *
 * Reads an AgentBOM JSON file, builds a {@link MarketplacePackage} from it,
 * and writes `marketplace-package.json` to the requested output directory.
 */
export function exportMarketplaceCommand(args: string[]): number {
  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log(
      [
        'Usage: agent-trust export-marketplace <bom.json> --output <dir>',
        '',
        'Generates a standardized marketplace trust package from an AgentBOM file.',
        '',
        'Arguments:',
        '  <bom.json>      Path to the AgentBOM JSON file',
        '  --output <dir>  Directory to write the package (required)',
        '',
        'Output:',
        '  <dir>/marketplace-package.json  — the generated trust package',
        '',
        'The package contains agent identity, capabilities, compliance summary,',
        'and trust attestations in the marketplace-trust-package/v1 schema.',
      ].join('\n'),
    );
    return 0;
  }

  let bomPath = '';
  let outputDir = '';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output' && i + 1 < args.length) {
      outputDir = args[++i];
    } else if (!args[i].startsWith('--')) {
      bomPath = args[i];
    }
  }

  if (!bomPath) {
    console.error('Error: Missing required argument <bom.json>');
    return 1;
  }
  if (!outputDir) {
    console.error('Error: Missing required argument --output <dir>');
    return 1;
  }

  try {
    const content = readFileSync(resolve(bomPath), 'utf-8');
    const bom = JSON.parse(content) as Record<string, unknown>;
    const casId = `sha256:${createHash('sha256').update(content, 'utf-8').digest('hex')}`;
    const pkg = buildMarketplacePackage(bom, casId);

    mkdirSync(resolve(outputDir), { recursive: true });
    const outPath = resolve(outputDir, 'marketplace-package.json');
    writeFileSync(
      outPath,
      `${JSON.stringify(pkg, null, 2)}
`,
      'utf-8',
    );
    console.log(`Marketplace package written to ${outPath}`);
    return 0;
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}
