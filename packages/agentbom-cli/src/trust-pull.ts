/**
 * `trust-cli pull <artifact-id>` — retrieves trust artifacts from the registry
 * by CAS identifier with integrity verification and dependency resolution.
 *
 * Resolves an artifact ID (a content-addressable `sha256:` identifier or a tag
 * label), locates the stored object in the local registry, recomputes its
 * SHA-256 digest to verify content integrity against the CAS identifier, and
 * resolves declared dependencies (the `distribution.supersedes` chain and any
 * generic `dependencies` references). With `--with-deps` the declared
 * dependencies are themselves pulled and integrity-verified transitively
 * (cycle-safe via a visited set).
 *
 * The registry layout is owned by {@link ./trust-publish.ts}: objects are stored
 * at `<registry>/objects/<hex[0:2]>/<hex[2:4]>/<full-hex>.json`, the version
 * ledger lives at `<registry>/manifest.json`, and tag pointers live at
 * `<registry>/tags/<tag>.json`. This module reads that layout and must not
 * diverge from it.
 *
 * Usage:
 *   trust-cli pull <artifact-id> [--registry <dir>] [--output <path>] [--with-deps] [--help]
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  type ArtifactType,
  computeCasId,
  detectArtifactType,
  readRegistryManifest,
} from './trust-publish.js';

// ---- Types ----

/** Resolved configuration for the pull command. */
export interface PullConfig {
  /** Artifact identifier — either a `sha256:` CAS id or a tag label. */
  artifactId: string;
  /** Path to the local registry directory (default: ~/.trust-registry). */
  registryDir: string;
  /** Optional output file path. When set, the retrieved artifact is written here. */
  outputPath?: string;
  /** Recursively resolve and verify declared dependencies. */
  withDeps: boolean;
}

/** Outcome of resolving a single declared dependency. */
export interface ResolvedDependency {
  /** The dependency artifact id as declared by the parent artifact. */
  artifactId: string;
  /** Whether the dependency was found in the registry. */
  resolved: boolean;
  /** Resolved CAS identifier, when found. */
  casId?: string;
  /** Detected artifact type, when found. */
  artifactType?: ArtifactType;
  /** Whether the dependency's content hash matched its CAS id. */
  integrityVerified?: boolean;
  /** Version recorded in the registry manifest, when found. */
  version?: number;
  /** Reason the dependency could not be resolved, when unresolved. */
  error?: string;
  /** Transitively resolved dependencies (populated only with `--with-deps`). */
  dependencies?: ResolvedDependency[];
}

/** Result of a pull operation. */
export interface PullResult {
  /** Resolved CAS identifier (sha256:hex). */
  casId: string;
  /** How the artifact id was resolved. */
  resolvedVia: 'cas-id' | 'tag';
  /** Tag label used to resolve, if any. */
  viaTag?: string;
  /** Artifact type detected during validation. */
  artifactType: ArtifactType;
  /** Immutable version recorded in the registry manifest, if present. */
  version?: number;
  /** Size of the stored artifact in bytes. */
  sizeBytes: number;
  /** Whether the recomputed digest matched the CAS identifier. */
  integrityVerified: boolean;
  /** Digest recomputed from the stored content. */
  computedCasId: string;
  /** Absolute path to the artifact file in the registry. */
  registryPath: string;
  /** Artifact ids this artifact declares as dependencies / superseded. */
  dependencyIds: string[];
  /** Resolved dependencies (empty unless `withDeps`). */
  resolvedDependencies: ResolvedDependency[];
  /** The parsed artifact content. */
  artifact: Record<string, unknown>;
}

// ---- Pure helpers ----

/**
 * Compute the registry object path for a CAS identifier.
 *
 * Mirrors the layout written by {@link ./trust-publish.ts}: the hex digest is
 * sharded into `<hex[0:2]>/<hex[2:4]>/<full-hex>.json` under `objects/`.
 */
export function objectPathForCasId(casId: string, registryDir: string): string {
  const hexDigest = casId.replace(/^sha256:/, '');
  return resolve(
    registryDir,
    'objects',
    hexDigest.slice(0, 2),
    hexDigest.slice(2, 4),
    `${hexDigest}.json`,
  );
}

/**
 * Test whether an artifact id is a CAS identifier (`sha256:<hex>`).
 */
export function isCasId(artifactId: string): boolean {
  return /^sha256:[a-f0-9]{64}$/.test(artifactId);
}

/**
 * Resolve a tag label to its CAS identifier by reading the registry tag pointer.
 *
 * Returns the CAS id, or `null` if the tag is unknown or its pointer is malformed.
 */
export function resolveTagToCasId(registryDir: string, tag: string): string | null {
  const tagPath = resolve(registryDir, 'tags', `${tag}.json`);
  if (!existsSync(tagPath)) return null;
  try {
    const data = JSON.parse(readFileSync(tagPath, 'utf-8'));
    if (
      typeof data === 'object' &&
      data !== null &&
      !Array.isArray(data) &&
      typeof data.cas_id === 'string' &&
      isCasId(data.cas_id)
    ) {
      return data.cas_id;
    }
  } catch {
    // Corrupted tag pointer — treat as unknown
  }
  return null;
}

/**
 * Resolve an artifact id (CAS id or tag label) to a CAS identifier.
 *
 * CAS ids are used verbatim; anything else is treated as a tag label and
 * resolved via the registry's tag pointers. Returns `null` when the id cannot
 * be resolved.
 */
export function resolveArtifactId(
  artifactId: string,
  registryDir: string,
): { casId: string; viaTag?: string } | null {
  if (isCasId(artifactId)) {
    return { casId: artifactId };
  }
  const casId = resolveTagToCasId(registryDir, artifactId);
  if (casId) return { casId, viaTag: artifactId };
  return null;
}

/**
 * Recompute the SHA-256 digest of stored content and compare it to the expected
 * CAS identifier. Integrity verification for content-addressable retrieval.
 */
export function verifyIntegrity(
  rawContent: string,
  expectedCasId: string,
): { ok: boolean; computedCasId: string } {
  const computedCasId = computeCasId(rawContent);
  return { ok: computedCasId === expectedCasId, computedCasId };
}

/**
 * Extract declared dependency artifact ids from a parsed artifact.
 *
 * Recognizes:
 *  - `distribution.supersedes` (AgentBOM artifact lifecycle — artifact ids this
 *    publication supersedes)
 *  - a top-level `dependencies` array (generic, forward-compatible — artifact
 *    ids or `{ id }` objects the artifact depends on)
 *
 * Returns a de-duplicated list preserving first-seen order.
 */
export function extractDependencyIds(data: Record<string, unknown>): string[] {
  const ids: string[] = [];
  const seen = new Set<string>();

  const push = (id: unknown): void => {
    if (typeof id === 'string' && id.length > 0 && !seen.has(id)) {
      seen.add(id);
      ids.push(id);
    }
  };

  const distribution = data.distribution as Record<string, unknown> | undefined;
  if (distribution && Array.isArray(distribution.supersedes)) {
    for (const id of distribution.supersedes) push(id);
  }

  if (Array.isArray(data.dependencies)) {
    for (const dep of data.dependencies) {
      if (typeof dep === 'string') {
        push(dep);
      } else if (dep && typeof dep === 'object' && !Array.isArray(dep)) {
        const id = (dep as Record<string, unknown>).id;
        push(id);
      }
    }
  }

  return ids;
}

/**
 * Resolve a single declared dependency, optionally recursing into its own
 * dependencies. Cycle-safe via the `visited` set of already-resolved CAS ids.
 *
 * Pure with respect to the filesystem: reads only. Never throws — unresolved or
 * corrupt dependencies are reported via the `error`/`resolved` fields.
 */
function resolveSingleDependency(
  depId: string,
  registryDir: string,
  visited: Set<string>,
  recurse: boolean,
): ResolvedDependency {
  const base: ResolvedDependency = { artifactId: depId, resolved: false };

  const resolved = resolveArtifactId(depId, registryDir);
  if (!resolved) {
    return { ...base, error: 'artifact id not found in registry (not a CAS id or known tag)' };
  }

  const casId = resolved.casId;
  if (visited.has(casId)) {
    return { ...base, resolved: true, casId, error: 'cycle — already resolved' };
  }
  visited.add(casId);

  const objectPath = objectPathForCasId(casId, registryDir);
  if (!existsSync(objectPath)) {
    return { ...base, resolved: false, casId, error: 'object not present in registry' };
  }

  let raw: string;
  try {
    raw = readFileSync(objectPath, 'utf-8');
  } catch {
    return { ...base, resolved: false, casId, error: 'cannot read object file' };
  }

  const { ok, computedCasId } = verifyIntegrity(raw, casId);
  let parsed: Record<string, unknown>;
  try {
    const data = JSON.parse(raw);
    if (typeof data !== 'object' || data === null || Array.isArray(data)) {
      return {
        ...base,
        resolved: true,
        casId,
        integrityVerified: false,
        error: 'object is not a JSON object',
      };
    }
    parsed = data as Record<string, unknown>;
  } catch {
    return {
      ...base,
      resolved: true,
      casId,
      integrityVerified: false,
      error: 'object is not valid JSON',
    };
  }

  const manifest = readRegistryManifest(registryDir);
  const result: ResolvedDependency = {
    ...base,
    resolved: true,
    casId,
    artifactType: detectArtifactType(parsed),
    integrityVerified: ok,
    version: manifest[casId],
  };

  if (recurse) {
    const childIds = extractDependencyIds(parsed);
    result.dependencies = childIds.map((id) =>
      resolveSingleDependency(id, registryDir, visited, recurse),
    );
  }

  return result;
}

/**
 * Resolve all declared dependencies of an artifact.
 *
 * When `recurse` is true, each dependency's own dependencies are resolved
 * transitively (cycle-safe). Returns one {@link ResolvedDependency} per
 * declared id, in declaration order.
 */
export function resolveDependencies(
  dependencyIds: string[],
  registryDir: string,
  recurse: boolean,
): ResolvedDependency[] {
  const visited = new Set<string>();
  return dependencyIds.map((id) => resolveSingleDependency(id, registryDir, visited, recurse));
}

/**
 * Pull an artifact from the local registry.
 *
 * This is the core pure-logic function. It:
 * 1. Resolves the artifact id (CAS id or tag) to a CAS identifier
 * 2. Locates and reads the stored object
 * 3. Recomputes the SHA-256 digest and verifies it against the CAS id
 * 4. Looks up the immutable version in the registry manifest
 * 5. Detects the artifact type
 * 6. Extracts declared dependency ids
 * 7. Optionally resolves dependencies transitively (when `withDeps`)
 *
 * Returns a {@link PullResult} on success, or an error string when the artifact
 * cannot be found, read, or parsed. Integrity mismatch is NOT a hard error
 * here — it is reported via `integrityVerified: false` so callers can inspect
 * the discrepancy; the CLI layer treats it as a non-zero exit.
 */
export function pullArtifact(
  artifactId: string,
  registryDir: string,
  withDeps = false,
): PullResult | string {
  const resolved = resolveArtifactId(artifactId, registryDir);
  if (!resolved) {
    return `Error: artifact id "${artifactId}" could not be resolved (not a CAS id or known tag)`;
  }

  const casId = resolved.casId;
  const objectPath = objectPathForCasId(casId, registryDir);
  if (!existsSync(objectPath)) {
    return `Error: artifact "${casId}" is not present in registry "${registryDir}"`;
  }

  let raw: string;
  try {
    raw = readFileSync(objectPath, 'utf-8');
  } catch {
    return `Error: cannot read artifact at "${objectPath}"`;
  }

  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return `Error: artifact at "${objectPath}" is not valid JSON`;
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return `Error: artifact at "${objectPath}" is not a JSON object`;
  }
  const artifact = data as Record<string, unknown>;

  const { ok, computedCasId } = verifyIntegrity(raw, casId);
  const manifest = readRegistryManifest(registryDir);
  const dependencyIds = extractDependencyIds(artifact);

  let sizeBytes = 0;
  try {
    sizeBytes = Buffer.byteLength(raw, 'utf-8');
  } catch {
    sizeBytes = raw.length;
  }

  const result: PullResult = {
    casId,
    resolvedVia: resolved.viaTag ? 'tag' : 'cas-id',
    viaTag: resolved.viaTag,
    artifactType: detectArtifactType(artifact),
    version: manifest[casId],
    sizeBytes,
    integrityVerified: ok,
    computedCasId,
    registryPath: objectPath,
    dependencyIds,
    resolvedDependencies: withDeps ? resolveDependencies(dependencyIds, registryDir, true) : [],
    artifact,
  };

  return result;
}

// ---- CLI command ----

const PULL_USAGE = [
  'Usage: agent-trust pull <artifact-id> [options]',
  '',
  'Retrieve a trust artifact from the local distribution registry by CAS',
  'identifier, with integrity verification and dependency resolution.',
  '',
  'Arguments:',
  '  <artifact-id>     CAS identifier (sha256:<hex>) or a tag label (e.g. latest)',
  '',
  'Options:',
  '  --registry <dir>  Path to the local registry directory',
  '                     (default: ~/.trust-registry)',
  '  --output <path>   Write the retrieved artifact JSON to this file',
  '  --with-deps       Recursively resolve and verify declared dependencies',
  '  --help, -h        Show this help message',
  '',
  'Examples:',
  '  agent-trust pull sha256:abc123...',
  '  agent-trust pull latest',
  '  agent-trust pull latest --registry ./my-registry --output agentbom.json',
  '  agent-trust pull sha256:abc123... --with-deps',
  '',
  'Output:',
  '  On success, prints a JSON object with the resolved CAS id, artifact type,',
  '  version, integrity status, and declared dependencies. Exits non-zero if',
  '  the artifact is missing or its stored content fails integrity verification.',
].join('\n');

/**
 * Parse pull command arguments into a {@link PullConfig}.
 * Returns the config on success, or a usage/error string on failure.
 */
export function parsePullArgs(args: string[]): PullConfig | string {
  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    return PULL_USAGE;
  }

  const artifactId = args[0];
  let registryDir: string | undefined;
  let outputPath: string | undefined;
  let withDeps = false;

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];

    if (arg === '--registry' && next) {
      registryDir = next;
      i++;
    } else if (arg === '--output' && next) {
      outputPath = next;
      i++;
    } else if (arg === '--with-deps') {
      withDeps = true;
    } else {
      return `Error: unknown argument "${arg}"`;
    }
  }

  const homeRegistry = resolve(
    process.env.HOME ?? process.env.USERPROFILE ?? '~',
    '.trust-registry',
  );

  return {
    artifactId,
    registryDir: registryDir ? resolve(registryDir) : homeRegistry,
    outputPath: outputPath ? resolve(outputPath) : undefined,
    withDeps,
  };
}

/**
 * CLI entry point for `agent-trust pull`.
 *
 * Returns exit code (0 = success, 1 = error or integrity failure).
 */
export function pullCommand(args: string[]): number {
  const parsed = parsePullArgs(args);
  if (typeof parsed === 'string') {
    if (parsed.startsWith('Usage:')) {
      console.log(parsed);
      return 0;
    }
    console.error(parsed);
    return 1;
  }

  const config = parsed;

  const result = pullArtifact(config.artifactId, config.registryDir, config.withDeps);
  if (typeof result === 'string') {
    console.error(result);
    return 1;
  }

  if (!result.integrityVerified) {
    console.error(
      `Error: integrity verification failed for "${result.casId}" — ` +
        `expected ${result.casId} but stored content hashes to ${result.computedCasId}`,
    );
    return 1;
  }

  // Persist the artifact if an output path was requested.
  if (config.outputPath) {
    try {
      writeFileSync(config.outputPath, JSON.stringify(result.artifact, null, 2), 'utf-8');
    } catch {
      console.error(`Error: cannot write artifact to "${config.outputPath}"`);
      return 1;
    }
  }

  console.log(JSON.stringify(result, null, 2));
  return 0;
}
