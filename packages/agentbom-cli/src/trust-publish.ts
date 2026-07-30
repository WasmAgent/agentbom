/**
 * `trust-cli publish <artifact.json>` — publishes signed trust artifacts to a
 * local distribution registry with content-addressable storage (CAS) identifiers
 * and immutable versioning.
 *
 * Reads a trust artifact JSON file, validates it against known schemas
 * (AgentBOM, MCP Posture, or Trust Passport), computes a SHA-256 CAS digest,
 * stores the artifact in a local registry directory, and assigns an immutable
 * version number.
 *
 * Usage:
 *   trust-cli publish <artifact.json> [--registry <dir>] [--tag <tag>] [--help]
 */
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";
import { validateTrustPassport } from "@openagentaudit/passport";
import {
  type ValidationResult,
  validateAgentBOM,
} from "@wasmagent/agentbom-core";
import { validateMCPPosture } from "@wasmagent/mcp-posture";

// ---- Types ----

/** Supported artifact types for publishing. */
export type ArtifactType =
  | "agentbom"
  | "mcp-posture"
  | "trust-passport"
  | "unknown";

/** Resolved configuration for the publish command. */
export interface PublishConfig {
  /** Path to the artifact JSON file to publish. */
  artifactPath: string;
  /** Path to the local registry directory (default: ~/.trust-registry). */
  registryDir: string;
  /** Optional tag to label the publication (e.g., 'latest', 'v1.0'). */
  tag?: string;
}

/** Result of a publication operation. */
export interface PublishResult {
  /** CAS identifier (sha256:hex). */
  casId: string;
  /** Artifact type detected during validation. */
  artifactType: ArtifactType;
  /** Immutable version number assigned to this publication. */
  version: number;
  /** ISO-8601 timestamp of publication. */
  publishedAt: string;
  /** Absolute path to the artifact file in the registry. */
  registryPath: string;
  /** Tag applied (if any). */
  tag?: string;
  /** Size of the artifact in bytes. */
  sizeBytes: number;
}

// ---- Pure helpers ----

/**
 * Compute a SHA-256 content-addressable identifier from a string.
 *
 * Returns `sha256:<hex-digest>`. The same content always yields the same
 * identifier, enabling content-addressable storage and deduplication.
 */
export function computeCasId(content: string): string {
  return `sha256:${createHash("sha256").update(content, "utf-8").digest("hex")}`;
}

/**
 * Detect the artifact type by attempting validation against each known schema.
 *
 * Returns the first matching type. If none match, returns 'unknown'.
 */
export function detectArtifactType(data: unknown): ArtifactType {
  if (validateAgentBOM(data).valid) return "agentbom";
  if (validateMCPPosture(data).valid) return "mcp-posture";
  if (validateTrustPassport(data).valid) return "trust-passport";
  return "unknown";
}

/**
 * Read and parse a JSON file into a typed record.
 * Returns `{ data, error }` — error is non-zero on failure.
 */
export function readArtifactFile(filePath: string): {
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

/**
 * Read the registry manifest from the registry directory.
 *
 * The manifest tracks version counters per CAS ID.
 * Returns an empty object if the manifest does not exist or cannot be read.
 */
export function readRegistryManifest(
  registryDir: string,
): Record<string, number> {
  const manifestPath = resolve(registryDir, "manifest.json");
  if (!existsSync(manifestPath)) return {};
  try {
    const raw = readFileSync(manifestPath, "utf-8");
    const data = JSON.parse(raw);
    if (typeof data === "object" && data !== null && !Array.isArray(data)) {
      return data as Record<string, number>;
    }
  } catch {
    // Corrupted manifest — start fresh
  }
  return {};
}

/**
 * Write the registry manifest back to disk.
 *
 * Creates the registry directory if it does not exist.
 */
export function writeRegistryManifest(
  registryDir: string,
  manifest: Record<string, number>,
): void {
  const manifestPath = resolve(registryDir, "manifest.json");
  mkdirSync(registryDir, { recursive: true });
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), "utf-8");
}

/**
 * Write a tag pointer file in the registry.
 *
 * Tag pointer files contain the CAS ID they point to, enabling label-based
 * lookups (e.g., 'latest' → 'sha256:abc...').
 */
export function writeTagPointer(
  registryDir: string,
  tag: string,
  casId: string,
): void {
  const tagsDir = resolve(registryDir, "tags");
  mkdirSync(tagsDir, { recursive: true });
  const tagPath = resolve(tagsDir, `${tag}.json`);
  writeFileSync(
    tagPath,
    JSON.stringify({ cas_id: casId, tagged_at: new Date().toISOString() }),
    "utf-8",
  );
}

/**
 * Publish an artifact to the local registry.
 *
 * This is the core pure-logic function. It:
 * 1. Ensures the registry directory exists
 * 2. Computes the CAS identifier from the canonical JSON content
 * 3. Assigns an immutable version number (monotonically increasing per CAS ID)
 * 4. Writes the artifact file to the registry under its CAS path
 * 5. Updates the registry manifest
 * 6. Optionally writes a tag pointer
 *
 * If the artifact content is identical to an already-published version (same
 * CAS ID), it returns the existing publication metadata without duplicating
 * storage — content-addressable deduplication.
 */
export function publishArtifact(
  artifactPath: string,
  registryDir: string,
  tag?: string,
): PublishResult | string {
  // Read the artifact
  const { data, error } = readArtifactFile(artifactPath);
  if (error) return `Error: failed to read artifact at "${artifactPath}"`;

  // Detect and validate
  const artifactType = detectArtifactType(data);
  if (artifactType === "unknown") {
    return "Error: artifact does not match any known schema (AgentBOM, MCP Posture, or Trust Passport)";
  }

  // Compute CAS identifier from the canonical JSON content
  const canonicalJson = JSON.stringify(data);
  const casId = computeCasId(canonicalJson);

  // Read manifest for version tracking
  const manifest = readRegistryManifest(registryDir);

  // Determine version: if this CAS ID was already published, reuse its version (immutable)
  const existingVersion = manifest[casId];
  const version = existingVersion ?? Object.keys(manifest).length + 1;

  // Store the artifact in the registry
  // Structure: <registry>/<objects>/<sha256>/<first-2-chars>/<full-hex>.json
  const hexDigest = casId.replace("sha256:", "");
  const objectDir = resolve(
    registryDir,
    "objects",
    hexDigest.slice(0, 2),
    hexDigest.slice(2, 4),
  );
  const objectPath = resolve(objectDir, `${hexDigest}.json`);
  mkdirSync(objectDir, { recursive: true });

  writeFileSync(objectPath, canonicalJson, "utf-8");

  // Update manifest (only if new)
  if (!existingVersion) {
    manifest[casId] = version;
    writeRegistryManifest(registryDir, manifest);
  }

  // Write tag pointer if requested
  if (tag) {
    writeTagPointer(registryDir, tag, casId);
  }

  const stat = statSync(objectPath);

  return {
    casId,
    artifactType,
    version,
    publishedAt: new Date().toISOString(),
    registryPath: objectPath,
    tag,
    sizeBytes: stat.size,
  };
}

// ---- CLI command ----

const PUBLISH_USAGE = [
  "Usage: agent-trust publish <artifact.json> [options]",
  "",
  "Publish a signed trust artifact to the local distribution registry with",
  "content-addressable storage (CAS) identifiers and immutable versioning.",
  "",
  "Arguments:",
  "  <artifact.json>     Path to the trust artifact JSON file to publish",
  "",
  "Options:",
  "  --registry <dir>    Path to the local registry directory",
  "                       (default: ~/.trust-registry)",
  "  --tag <tag>         Label this publication with a tag (e.g., latest, v1.0)",
  "  --help, -h          Show this help message",
  "",
  "Examples:",
  "  agent-trust publish agentbom.json",
  "  agent-trust publish agentbom.json --tag latest",
  "  agent-trust publish agentbom.json --registry ./my-registry",
  "",
  "Output:",
  "  On success, prints a JSON object with CAS ID, version, artifact type,",
  "  publication timestamp, registry path, and tag (if provided).",
].join("\n");

/**
 * Parse publish command arguments into a {@link PublishConfig}.
 * Returns the config on success, or a usage/error string on failure.
 */
export function parsePublishArgs(args: string[]): PublishConfig | string {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    return PUBLISH_USAGE;
  }

  const artifactPath = args[0];
  let registryDir: string | undefined;
  let tag: string | undefined;

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];

    if (arg === "--registry" && next) {
      registryDir = next;
      i++;
    } else if (arg === "--tag" && next) {
      tag = next;
      i++;
    } else {
      return `Error: unknown argument "${arg}"`;
    }
  }

  const homeRegistry = resolve(
    process.env.HOME ?? process.env.USERPROFILE ?? "~",
    ".trust-registry",
  );

  return {
    artifactPath: resolve(artifactPath),
    registryDir: registryDir ? resolve(registryDir) : homeRegistry,
    tag,
  };
}

/**
 * CLI entry point for `agent-trust publish`.
 *
 * Returns exit code (0 = success, 1 = error).
 */
export function publishCommand(args: string[]): number {
  const parsed = parsePublishArgs(args);
  if (typeof parsed === "string") {
    if (parsed.startsWith("Usage:")) {
      console.log(parsed);
      return 0;
    }
    console.error(parsed);
    return 1;
  }

  const config = parsed;

  const result = publishArtifact(
    config.artifactPath,
    config.registryDir,
    config.tag,
  );
  if (typeof result === "string") {
    console.error(result);
    return 1;
  }

  // Success — print structured JSON output
  console.log(JSON.stringify(result, null, 2));
  return 0;
}
