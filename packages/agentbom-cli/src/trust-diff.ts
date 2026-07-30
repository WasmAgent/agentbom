/**
 * `trust-cli diff <artifact-a.json> <artifact-b.json>` — generates a structured
 * diff report for trust artifacts that highlights changes to permissions, tool
 * additions, and policy modifications.
 *
 * Auto-detects the artifact type (AgentBOM, MCP Posture, Trust Passport) and
 * delegates to the type-specific diff engine. For Trust Passport artifacts,
 * uses a generic structured JSON diff since `trust-passport-core` is frozen.
 *
 * Usage:
 *   trust-cli diff <artifact-a.json> <artifact-b.json> [--json] [--help]
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { validateTrustPassport } from "@openagentaudit/passport";
import {
  diffAgentBOM,
  formatAgentBOMDiff,
  validateAgentBOM,
} from "@wasmagent/agentbom-core";
import {
  diffMCPPosture,
  formatPostureDiff,
  validateMCPPosture,
} from "@wasmagent/mcp-posture";
import {
  type ArtifactType,
  detectArtifactType,
  readArtifactFile,
} from "./trust-publish.js";

// ---- Types ----

/** A single field-level change between two versions of an artifact. */
export interface FieldChange {
  /** Dot-delimited path to the changed field (e.g., "identity.agent_name"). */
  path: string;
  /** Type of change: "added", "removed", or "modified". */
  type: "added" | "removed" | "modified";
  /** Value in the old artifact (absent for "added"). */
  old?: unknown;
  /** Value in the new artifact (absent for "removed"). */
  new?: unknown;
}

/** Structured diff result produced by {@link diffTrustArtifacts}. */
export interface TrustDiffResult {
  /** Detected artifact type. */
  artifactType: ArtifactType;
  /** Whether the two artifacts are identical. */
  isEmpty: boolean;
  /** Human-readable formatted diff string. */
  formatted: string;
  /** Structured field-level changes (always populated). */
  changes: FieldChange[];
}

// ---- Structured JSON diff (for Trust Passport) ----

/**
 * Recursively diff two JSON values, producing a list of {@link FieldChange} entries.
 *
 * Only primitive values and nested objects/arrays are compared. The `path`
 * parameter tracks the current location in the JSON tree.
 */
function diffValues(
  oldVal: unknown,
  newVal: unknown,
  path: string,
  changes: FieldChange[],
): void {
  // Both are objects (but not arrays) — recurse into keys
  if (isPlainObject(oldVal) && isPlainObject(newVal)) {
    const oldKeys = Object.keys(oldVal as Record<string, unknown>);
    const newKeys = Object.keys(newVal as Record<string, unknown>);
    const allKeys = new Set([...oldKeys, ...newKeys]);
    for (const key of allKeys) {
      const childPath = path ? `${path}.${key}` : key;
      if (!(key in oldVal)) {
        changes.push({
          path: childPath,
          type: "added",
          new: (newVal as Record<string, unknown>)[key],
        });
      } else if (!(key in newVal)) {
        changes.push({
          path: childPath,
          type: "removed",
          old: (oldVal as Record<string, unknown>)[key],
        });
      } else {
        diffValues(
          (oldVal as Record<string, unknown>)[key],
          (newVal as Record<string, unknown>)[key],
          childPath,
          changes,
        );
      }
    }
    return;
  }

  // Both are arrays — compare element-wise by index
  if (Array.isArray(oldVal) && Array.isArray(newVal)) {
    const maxLen = Math.max(oldVal.length, newVal.length);
    for (let i = 0; i < maxLen; i++) {
      const childPath = `${path}[${i}]`;
      if (i >= oldVal.length) {
        changes.push({ path: childPath, type: "added", new: newVal[i] });
      } else if (i >= newVal.length) {
        changes.push({ path: childPath, type: "removed", old: oldVal[i] });
      } else {
        diffValues(oldVal[i], newVal[i], childPath, changes);
      }
    }
    return;
  }

  // Values differ at this leaf
  if (JSON.stringify(oldVal) !== JSON.stringify(newVal)) {
    changes.push({ path, type: "modified", old: oldVal, new: newVal });
  }
}

/** Check if a value is a plain object (not null, not array). */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Format a generic structured diff into a human-readable string.
 *
 * Groups changes by type (added, removed, modified) and renders each change
 * with +/-/~ prefix and a JSON-encoded value.
 */
export function formatGenericDiff(changes: FieldChange[]): string {
  const added = changes.filter((c) => c.type === "added");
  const removed = changes.filter((c) => c.type === "removed");
  const modified = changes.filter((c) => c.type === "modified");

  const lines: string[] = [];

  if (added.length > 0) {
    lines.push(`Fields added (${added.length}):`);
    for (const c of added) {
      const val = JSON.stringify(c.new);
      lines.push(`  + ${c.path}: ${val}`);
    }
  }

  if (removed.length > 0) {
    lines.push(`Fields removed (${removed.length}):`);
    for (const c of removed) {
      const val = JSON.stringify(c.old);
      lines.push(`  - ${c.path}: ${val}`);
    }
  }

  if (modified.length > 0) {
    lines.push(`Fields changed (${modified.length}):`);
    for (const c of modified) {
      lines.push(
        `  ~ ${c.path}: ${JSON.stringify(c.old)} → ${JSON.stringify(c.new)}`,
      );
    }
  }

  if (lines.length === 0) {
    lines.push("No changes detected.");
  }

  return lines.join("\n");
}

// ---- Core diff logic ----

/**
 * Diff two trust artifacts of the same type.
 *
 * Auto-detects the artifact type from the *new* file. If the old and new
 * files are different artifact types, returns an error string.
 *
 * For AgentBOM and MCP Posture, delegates to the type-specific diff engines.
 * For Trust Passport, uses a generic structured JSON diff.
 *
 * Returns a {@link TrustDiffResult} on success, or an error string on failure.
 */
export function diffTrustArtifacts(
  oldFilePath: string,
  newFilePath: string,
): TrustDiffResult | string {
  const { data: oldData, error: oldError } = readArtifactFile(oldFilePath);
  if (oldError) return `Error: failed to read old artifact at "${oldFilePath}"`;

  const { data: newData, error: newError } = readArtifactFile(newFilePath);
  if (newError) return `Error: failed to read new artifact at "${newFilePath}"`;

  // Validate both artifacts
  const oldType = detectArtifactType(oldData);
  const newType = detectArtifactType(newData);

  if (oldType === "unknown") {
    return `Error: old artifact at "${oldFilePath}" does not match any known schema (AgentBOM, MCP Posture, or Trust Passport)`;
  }
  if (newType === "unknown") {
    return `Error: new artifact at "${newFilePath}" does not match any known schema (AgentBOM, MCP Posture, or Trust Passport)`;
  }

  if (oldType !== newType) {
    return `Error: artifact type mismatch — old is "${oldType}", new is "${newType}"`;
  }

  // ---- AgentBOM ----
  if (newType === "agentbom") {
    const oldResult = validateAgentBOM(oldData);
    if (!oldResult.valid) {
      return `Error: old AgentBOM validation failed: ${oldResult.errors.join("; ")}`;
    }
    const newResult = validateAgentBOM(newData);
    if (!newResult.valid) {
      return `Error: new AgentBOM validation failed: ${newResult.errors.join("; ")}`;
    }

    const diff = diffAgentBOM(oldData, newData);
    const formatted = formatAgentBOMDiff(diff);
    const changes = extractChangesFromFormatted(formatted);
    return {
      artifactType: "agentbom",
      isEmpty: diff.isEmpty(),
      formatted,
      changes,
    };
  }

  // ---- MCP Posture ----
  if (newType === "mcp-posture") {
    const oldResult = validateMCPPosture(oldData);
    if (!oldResult.valid) {
      return `Error: old MCP Posture validation failed: ${oldResult.errors.join("; ")}`;
    }
    const newResult = validateMCPPosture(newData);
    if (!newResult.valid) {
      return `Error: new MCP Posture validation failed: ${newResult.errors.join("; ")}`;
    }

    const diff = diffMCPPosture(oldData, newData);
    const formatted = formatPostureDiff(diff);
    const changes = extractChangesFromFormatted(formatted);
    return {
      artifactType: "mcp-posture",
      isEmpty: diff.isEmpty(),
      formatted,
      changes,
    };
  }

  // ---- Trust Passport ----
  if (newType === "trust-passport") {
    const oldResult = validateTrustPassport(oldData);
    if (!oldResult.valid) {
      return `Error: old Trust Passport validation failed: ${oldResult.errors.join("; ")}`;
    }
    const newResult = validateTrustPassport(newData);
    if (!newResult.valid) {
      return `Error: new Trust Passport validation failed: ${newResult.errors.join("; ")}`;
    }

    const changes: FieldChange[] = [];
    diffValues(oldData, newData, "", changes);
    const formatted = formatGenericDiff(changes);
    return {
      artifactType: "trust-passport",
      isEmpty: changes.length === 0,
      formatted,
      changes,
    };
  }

  // Should not reach here given the earlier checks
  return "Error: unexpected artifact type";
}

/**
 * Extract structured FieldChange entries from a formatted diff string.
 *
 * Parses the human-readable output from `formatAgentBOMDiff` and
 * `formatPostureDiff` into typed change records for the structured `changes`
 * array in the result.
 */
export function extractChangesFromFormatted(formatted: string): FieldChange[] {
  const changes: FieldChange[] = [];
  for (const line of formatted.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.startsWith("+ ")) {
      changes.push({ path: trimmed.slice(2), type: "added" });
    } else if (trimmed.startsWith("- ")) {
      changes.push({ path: trimmed.slice(2), type: "removed" });
    } else if (trimmed.startsWith("~ ")) {
      changes.push({ path: trimmed.slice(2), type: "modified" });
    }
  }
  return changes;
}

// ---- CLI command ----

const DIFF_USAGE = [
  "Usage: agent-trust diff <artifact-a.json> <artifact-b.json> [options]",
  "",
  "Generate a structured diff report for trust artifacts that highlights",
  "changes to permissions, tool additions, and policy modifications.",
  "",
  "Arguments:",
  "  <artifact-a.json>    Path to the old/baseline trust artifact",
  "  <artifact-b.json>    Path to the new trust artifact",
  "",
  "Options:",
  "  --json               Output structured JSON instead of human-readable text",
  "  --help, -h           Show this help message",
  "",
  "Supported artifact types:",
  "  AgentBOM, MCP Posture, Trust Passport (auto-detected)",
  "",
  "Examples:",
  "  agent-trust diff old-agentbom.json new-agentbom.json",
  "  agent-trust diff old-posture.json new-posture.json --json",
  "  agent-trust diff old-passport.json new-passport.json",
].join("\n");

/**
 * Parse diff command arguments.
 * Returns `--json` flag and the two file paths, or a usage/error string.
 */
export function parseDiffArgs(
  args: string[],
): { oldPath: string; newPath: string; json: boolean } | string {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    return DIFF_USAGE;
  }

  // Collect positional args and flags
  const positional: string[] = [];
  let json = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--json") {
      json = true;
    } else if (args[i].startsWith("--")) {
      return `Error: unknown argument "${args[i]}"`;
    } else {
      positional.push(args[i]);
    }
  }

  if (positional.length < 2) {
    return "Error: diff requires two file path arguments: <artifact-a.json> <artifact-b.json>";
  }

  return {
    oldPath: resolve(positional[0]),
    newPath: resolve(positional[1]),
    json,
  };
}

/**
 * CLI entry point for `agent-trust diff`.
 *
 * Returns exit code (0 = no changes, 1 = changes detected or error).
 */
export function trustDiffCommand(args: string[]): number {
  const parsed = parseDiffArgs(args);
  if (typeof parsed === "string") {
    if (parsed.startsWith("Usage:")) {
      console.log(parsed);
      return 0;
    }
    console.error(parsed);
    return 1;
  }

  const { oldPath, newPath, json } = parsed;

  const result = diffTrustArtifacts(oldPath, newPath);
  if (typeof result === "string") {
    console.error(result);
    return 1;
  }

  // Print artifact type header
  const typeLabel =
    {
      agentbom: "AgentBOM",
      "mcp-posture": "MCP Posture",
      "trust-passport": "Trust Passport",
      unknown: "Unknown",
    }[result.artifactType] ?? result.artifactType;

  if (!json) {
    console.log(`Comparing ${typeLabel} artifacts:`);
    console.log(`  old: ${oldPath}`);
    console.log(`  new: ${newPath}`);
    console.log();
    console.log(result.formatted);
  } else {
    console.log(
      JSON.stringify(
        {
          artifact_type: result.artifactType,
          artifact_type_label: typeLabel,
          old_path: oldPath,
          new_path: newPath,
          is_empty: result.isEmpty,
          change_count: result.changes.length,
          changes: result.changes,
        },
        null,
        2,
      ),
    );
  }

  return result.isEmpty ? 0 : 1;
}
