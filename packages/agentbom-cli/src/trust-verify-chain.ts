/**
 * `trust-cli verify-chain <passport.jwt> --depth N` — performs recursive trust
 * chain verification with configurable depth and caching for multi-hop trust
 * relationships.
 *
 * Given a signed Trust Passport JWT, this command:
 * 1. Verifies the JWT signature (EdDSA) and checks expiry / structure
 * 2. Extracts artifact references from the passport payload (agentbom_ref,
 *    posture_ref, dependencies)
 * 3. Resolves each referenced artifact from the local registry
 * 4. Validates each artifact against its known schema
 * 5. Recursively follows the chain of references up to the configured depth
 * 6. Caches verified artifacts to avoid redundant verification in multi-hop chains
 *
 * The result is a structured JSON report with per-node verification status,
 * depth tracking, and cache statistics.
 *
 * Usage:
 *   trust-cli verify-chain <passport.jwt> --depth N [--key <pubkey>] [--registry <dir>] [--help]
 */
import { resolve } from "node:path";
import { validateTrustPassport } from "@openagentaudit/passport";
import { validateAgentBOM } from "@wasmagent/agentbom-core";
import { validateMCPPosture } from "@wasmagent/mcp-posture";
import { verifySignedPassport } from "./passport-verify-signed.js";
import type { ArtifactType } from "./trust-publish.js";
import { pullArtifact, resolveArtifactId } from "./trust-pull.js";

// ---- Types ----

/** Resolved configuration for the verify-chain command. */
export interface VerifyChainConfig {
  /** Path to the signed Trust Passport JWT file. */
  jwtPath: string;
  /** Path to the Ed25519 public key for signature verification. */
  publicKeyPath?: string;
  /** Maximum recursion depth for chain traversal (default: 3). */
  maxDepth: number;
  /** Path to the local registry directory (default: ~/.trust-registry). */
  registryDir: string;
}

/** Verification status for a single node in the trust chain. */
export interface ChainNodeResult {
  /** Type of artifact this node represents. */
  nodeType: "passport" | "agentbom" | "mcp-posture" | "unknown";
  /** Reference identifier (CAS id, file path, or tag). */
  reference: string;
  /** Whether this node passed all verification checks. */
  valid: boolean;
  /** Depth at which this node was encountered (0 = root passport). */
  depth: number;
  /** Verification errors, if any. */
  errors: string[];
  /** Child nodes discovered by following this node's references. */
  children: ChainNodeResult[];
  /** Artifact type detected during schema validation. */
  artifactType?: ArtifactType;
  /** Whether the artifact's integrity was verified (CAS digest match). */
  integrityVerified?: boolean;
}

/** Complete result of a verify-chain operation. */
export interface VerifyChainResult {
  /** Overall chain validity — true only when every node is valid. */
  valid: boolean;
  /** Root passport verification details. */
  root: {
    signatureValid: boolean;
    expired: boolean;
    structureValid: boolean;
    payload: Record<string, unknown> | null;
    errors: string[];
  };
  /** Ordered chain nodes (root first, then children depth-first). */
  nodes: ChainNodeResult[];
  /** Total number of nodes visited in the chain. */
  totalNodes: number;
  /** Maximum depth actually reached during traversal. */
  depthReached: number;
  /** Number of cache hits (artifacts already verified). */
  cacheHits: number;
  /** Number of cache misses (artifacts verified for the first time). */
  cacheMisses: number;
}

// ---- Pure helpers ----

/**
 * Extract artifact reference IDs from a Trust Passport payload.
 *
 * Recognizes:
 *  - `agentbom_ref.agentbom_id` — the AgentBOM this passport attests
 *  - `posture_ref.snapshot_id` — the MCP Posture snapshot this passport references
 *  - `dependencies` — array of string ids or `{ id }` objects
 *
 * Returns a list of `{ id, label }` tuples preserving discovery order.
 */
function extractPassportReferences(
  payload: Record<string, unknown>,
): { id: string; label: string }[] {
  const refs: { id: string; label: string }[] = [];

  const agentbomRef = payload.agentbom_ref as
    | Record<string, unknown>
    | undefined;
  if (agentbomRef && typeof agentbomRef.agentbom_id === "string") {
    refs.push({ id: agentbomRef.agentbom_id as string, label: "agentbom_ref" });
  }

  const postureRef = payload.posture_ref as Record<string, unknown> | undefined;
  if (postureRef && typeof postureRef.snapshot_id === "string") {
    refs.push({ id: postureRef.snapshot_id as string, label: "posture_ref" });
  }

  if (Array.isArray(payload.dependencies)) {
    for (const dep of payload.dependencies) {
      if (typeof dep === "string" && dep.length > 0) {
        refs.push({ id: dep, label: "dependency" });
      } else if (
        dep &&
        typeof dep === "object" &&
        !Array.isArray(dep) &&
        typeof (dep as Record<string, unknown>).id === "string"
      ) {
        refs.push({
          id: (dep as Record<string, unknown>).id as string,
          label: "dependency",
        });
      }
    }
  }

  return refs;
}

/**
 * Extract artifact reference IDs from a non-passport artifact (AgentBOM, MCP Posture, etc.)
 *
 * Recognizes:
 *  - `distribution.supersedes` — predecessor artifact CAS ids
 *  - `dependencies` — generic dependency array
 *
 * Returns a list of `{ id, label }` tuples.
 */
function extractArtifactReferences(
  artifact: Record<string, unknown>,
): { id: string; label: string }[] {
  const refs: { id: string; label: string }[] = [];

  const distribution = artifact.distribution as
    | Record<string, unknown>
    | undefined;
  if (distribution && Array.isArray(distribution.supersedes)) {
    for (const id of distribution.supersedes) {
      if (typeof id === "string" && id.length > 0) {
        refs.push({ id, label: "supersedes" });
      }
    }
  }

  if (Array.isArray(artifact.dependencies)) {
    for (const dep of artifact.dependencies) {
      if (typeof dep === "string" && dep.length > 0) {
        refs.push({ id: dep, label: "dependency" });
      } else if (
        dep &&
        typeof dep === "object" &&
        !Array.isArray(dep) &&
        typeof (dep as Record<string, unknown>).id === "string"
      ) {
        refs.push({
          id: (dep as Record<string, unknown>).id as string,
          label: "dependency",
        });
      }
    }
  }

  return refs;
}

/**
 * Validate an artifact against known schemas.
 *
 * Returns `{ valid, nodeType, errors, artifactType }`.
 */
function validateArtifactNode(data: unknown): {
  valid: boolean;
  nodeType: ChainNodeResult["nodeType"];
  errors: string[];
  artifactType: ArtifactType;
} {
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    return {
      valid: false,
      nodeType: "unknown",
      errors: ["artifact is not a JSON object"],
      artifactType: "unknown",
    };
  }
  const obj = data as Record<string, unknown>;

  const passportResult = validateTrustPassport(data);
  const bomResult = validateAgentBOM(data);
  const postureResult = validateMCPPosture(data);

  if (bomResult.valid) {
    return {
      valid: true,
      nodeType: "agentbom",
      errors: [],
      artifactType: "agentbom",
    };
  }
  if (postureResult.valid) {
    return {
      valid: true,
      nodeType: "mcp-posture",
      errors: [],
      artifactType: "mcp-posture",
    };
  }
  if (passportResult.valid) {
    return {
      valid: true,
      nodeType: "passport",
      errors: [],
      artifactType: "trust-passport",
    };
  }

  // Return the best-guess error set
  if (obj.agentbom_version !== undefined) {
    return {
      valid: false,
      nodeType: "agentbom",
      errors: bomResult.errors,
      artifactType: "unknown",
    };
  }
  if (obj.posture_version !== undefined) {
    return {
      valid: false,
      nodeType: "mcp-posture",
      errors: postureResult.errors,
      artifactType: "unknown",
    };
  }
  if (obj.passport_version !== undefined) {
    return {
      valid: false,
      nodeType: "passport",
      errors: passportResult.errors,
      artifactType: "unknown",
    };
  }

  return {
    valid: false,
    nodeType: "unknown",
    errors: [
      "artifact does not match any known schema (AgentBOM, MCP Posture, or Trust Passport)",
    ],
    artifactType: "unknown",
  };
}

/** Cached per-CAS validation outcome, including integrity status. */
interface CachedValidation {
  valid: boolean;
  nodeType: ChainNodeResult["nodeType"];
  errors: string[];
  artifactType: ArtifactType;
  integrityVerified: boolean;
}

/**
 * Verify a single artifact node and recursively verify its references.
 *
 * Cycle-safe via the `visited` set. Depth-limited by `remainingDepth`.
 * Results are accumulated into `allNodes` and `stats`.
 *
 * @param artifactId  The artifact identifier to verify
 * @param registryDir Local registry directory
 * @param remainingDepth How many more hops to follow
 * @param visited     Set of already-visited CAS ids (prevents cycles)
 * @param cache       Map from CAS id → pre-computed validation result (prevents re-verification)
 * @param allNodes    Accumulator for all chain nodes
 * @param stats       Accumulator for cache statistics
 * @returns The chain node result for this artifact
 */
function verifyNode(
  artifactId: string,
  registryDir: string,
  currentDepth: number,
  remainingDepth: number,
  visited: Set<string>,
  cache: Map<string, CachedValidation>,
  allNodes: ChainNodeResult[],
  stats: { cacheHits: number; cacheMisses: number },
): ChainNodeResult {
  const node: ChainNodeResult = {
    nodeType: "unknown",
    reference: artifactId,
    valid: false,
    depth: currentDepth,
    errors: [],
    children: [],
  };

  // Resolve the artifact id
  const resolved = resolveArtifactId(artifactId, registryDir);
  if (!resolved) {
    node.errors.push(
      `artifact "${artifactId}" could not be resolved (not a CAS id or known tag)`,
    );
    allNodes.push(node);
    return node;
  }

  const casId = resolved.casId;

  // Cycle check
  if (visited.has(casId)) {
    node.errors.push("cycle — artifact already visited in this chain");
    node.valid = true; // Already verified earlier
    stats.cacheHits++;
    allNodes.push(node);
    return node;
  }
  visited.add(casId);

  // Cache check
  const cached = cache.get(casId);
  if (cached) {
    node.nodeType = cached.nodeType;
    node.valid = cached.valid;
    node.artifactType = cached.artifactType;
    node.integrityVerified = cached.integrityVerified;
    stats.cacheHits++;
    allNodes.push(node);
    return node;
  }
  stats.cacheMisses++;

  // Pull the artifact from registry
  const pullResult = pullArtifact(casId, registryDir);
  if (typeof pullResult === "string") {
    node.errors.push(pullResult);
    cache.set(casId, {
      valid: false,
      nodeType: "unknown",
      errors: node.errors,
      artifactType: "unknown",
      integrityVerified: false,
    });
    allNodes.push(node);
    return node;
  }

  if (!pullResult.integrityVerified) {
    node.errors.push(
      `integrity verification failed: expected ${casId} but stored content hashes to ${pullResult.computedCasId}`,
    );
    node.integrityVerified = false;
  } else {
    node.integrityVerified = true;
  }

  // Validate against known schemas
  const validation = validateArtifactNode(pullResult.artifact);
  node.nodeType = validation.nodeType;
  node.artifactType = validation.artifactType;
  if (!validation.valid) {
    node.errors.push(...validation.errors);
  }

  node.valid =
    pullResult.integrityVerified &&
    validation.valid &&
    node.errors.length === 0;

  // Cache the result
  cache.set(casId, {
    ...validation,
    integrityVerified: node.integrityVerified ?? false,
  });

  // Recurse into references (if depth allows)
  if (remainingDepth > 0) {
    // Passports reference artifacts via agentbom_ref/posture_ref/dependencies;
    // other artifacts via distribution.supersedes/dependencies.
    const refs =
      validation.nodeType === "passport"
        ? extractPassportReferences(pullResult.artifact)
        : extractArtifactReferences(pullResult.artifact);

    for (const ref of refs) {
      const child = verifyNode(
        ref.id,
        registryDir,
        currentDepth + 1,
        remainingDepth - 1,
        visited,
        cache,
        allNodes,
        stats,
      );
      node.children.push(child);
    }
  }

  allNodes.push(node);
  return node;
}

/**
 * Perform recursive trust chain verification.
 *
 * This is the core pure-logic function. It:
 * 1. Verifies the JWT passport (signature, expiry, structure)
 * 2. Extracts artifact references from the passport payload
 * 3. Resolves and validates each referenced artifact from the registry
 * 4. Recursively follows artifact references up to `maxDepth` hops
 * 5. Caches verified artifacts for multi-hop efficiency
 *
 * Returns a {@link VerifyChainResult} on success, or an error string when
 * the JWT cannot be read or parsed.
 */
export function verifyChain(
  config: VerifyChainConfig,
): VerifyChainResult | string {
  // Step 1: Verify the root passport JWT
  let verifyResult: ReturnType<typeof verifySignedPassport>;
  try {
    verifyResult = verifySignedPassport({
      jwtPath: config.jwtPath,
      publicKeyPath: config.publicKeyPath,
    });
  } catch (err) {
    return `failed to read JWT: ${err instanceof Error ? err.message : String(err)}`;
  }

  const root = {
    signatureValid: verifyResult.signatureValid,
    expired: verifyResult.expired,
    structureValid: verifyResult.structureValid,
    payload: verifyResult.payload,
    errors: verifyResult.errors,
  };

  // If payload is null, we can't follow any references
  if (!verifyResult.payload) {
    const firstError = verifyResult.errors[0] ?? "unknown error";
    return firstError;
  }

  const payload = verifyResult.payload;

  // Step 2: Extract references from the passport
  const refs = extractPassportReferences(payload);

  // Step 3: Resolve and validate each reference recursively (skip if depth is 0)
  const allNodes: ChainNodeResult[] = [];
  let cacheHits = 0;
  let cacheMisses = 0;
  let maxDepthReached = 0;

  if (config.maxDepth > 0) {
    const cache = new Map<string, CachedValidation>();
    const visited = new Set<string>();
    const stats = { cacheHits: 0, cacheMisses: 0 };

    for (const ref of refs) {
      const child = verifyNode(
        ref.id,
        config.registryDir,
        1,
        config.maxDepth - 1,
        visited,
        cache,
        allNodes,
        stats,
      );

      // Track depth across children
      const trackDepth = (node: ChainNodeResult): number => {
        if (node.children.length === 0) return node.depth;
        return Math.max(node.depth, ...node.children.map(trackDepth));
      };
      maxDepthReached = Math.max(maxDepthReached, trackDepth(child));
    }

    cacheHits = stats.cacheHits;
    cacheMisses = stats.cacheMisses;
  }

  // Step 4: Determine overall validity
  const allNodesValid = allNodes.every((n) => n.valid);
  const rootValid =
    root.signatureValid &&
    !root.expired &&
    root.structureValid &&
    root.errors.length === 0;
  const valid = rootValid && (refs.length === 0 || allNodesValid);

  return {
    valid,
    root,
    nodes: allNodes,
    totalNodes: allNodes.length,
    depthReached: maxDepthReached,
    cacheHits,
    cacheMisses,
  };
}

// ---- CLI command ----

const VERIFY_CHAIN_USAGE = [
  "Usage: agent-trust verify-chain <passport.jwt> [options]",
  "",
  "Perform recursive trust chain verification with configurable depth and",
  "caching for multi-hop trust relationships.",
  "",
  "Given a signed Trust Passport JWT, verifies the signature and structure,",
  "then follows artifact references (AgentBOM, MCP Posture) through the",
  "local registry, validating each node in the chain.",
  "",
  "Arguments:",
  "  <passport.jwt>    Path to a signed Trust Passport JWT file",
  "",
  "Options:",
  "  --depth <N>       Maximum recursion depth for chain traversal (default: 3)",
  "  --key <path>      Path to Ed25519 public key (PEM or 64-char hex)",
  "  --registry <dir>  Path to the local registry directory",
  "                     (default: ~/.trust-registry)",
  "  --help, -h        Show this help message",
  "",
  "Examples:",
  "  agent-trust verify-chain passport.jwt --key pubkey.pem",
  "  agent-trust verify-chain passport.jwt --depth 5 --key pubkey.pem",
  "  agent-trust verify-chain passport.jwt --depth 2 --key pubkey.pem --registry ./my-registry",
  "",
  "Output:",
  "  Prints a JSON object with root passport verification status, chain node",
  "  results, depth tracking, and cache statistics. Exits non-zero if the",
  "  chain is invalid.",
].join("\n");

/**
 * Parse verify-chain command arguments into a {@link VerifyChainConfig}.
 * Returns the config on success, or a usage/error string on failure.
 */
export function parseVerifyChainArgs(
  args: string[],
): VerifyChainConfig | string {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    return VERIFY_CHAIN_USAGE;
  }

  const jwtPath = args[0];
  let publicKeyPath: string | undefined;
  let maxDepth = 3;
  let registryDir: string | undefined;

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];

    if (arg === "--depth" && next) {
      const parsed = Number.parseInt(next, 10);
      if (Number.isNaN(parsed) || parsed < 0) {
        return `Error: --depth must be a non-negative integer, got "${next}"`;
      }
      maxDepth = parsed;
      i++;
    } else if (arg === "--key" && next) {
      publicKeyPath = next;
      i++;
    } else if (arg === "--registry" && next) {
      registryDir = next;
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
    jwtPath: resolve(jwtPath),
    publicKeyPath: publicKeyPath ? resolve(publicKeyPath) : undefined,
    maxDepth,
    registryDir: registryDir ? resolve(registryDir) : homeRegistry,
  };
}

/**
 * CLI entry point for `agent-trust verify-chain`.
 *
 * Returns exit code (0 = valid chain, 1 = verification failed or error).
 */
export function verifyChainCommand(args: string[]): number {
  const parsed = parseVerifyChainArgs(args);
  if (typeof parsed === "string") {
    if (parsed.startsWith("Usage:")) {
      console.log(parsed);
      return 0;
    }
    console.error(parsed);
    return 1;
  }

  const config = parsed;

  const result = verifyChain(config);
  if (typeof result === "string") {
    console.error(`Error: ${result}`);
    return 1;
  }

  console.log(JSON.stringify(result, null, 2));
  return result.valid ? 0 : 1;
}
