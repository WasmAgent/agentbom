/**
 * `trust-cli subscribe <agent-identity>` — continuous monitoring for trust artifact
 * updates from a specific agent publisher.
 *
 * Watches a directory for AgentBOM files belonging to the given agent identity,
 * compares them against a baseline snapshot, and produces drift alerts via
 * {@link classifyDriftEvents}.  Optionally POSTs notifications to a callback URL.
 *
 * Usage:
 *   trust-cli subscribe <agent-identity> --baseline <path> [--watch <dir>] \
 *       [--callback <url>] [--interval <seconds>] [--once]
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import {
  classifyDriftEvents,
  type DriftAlert,
  diffAgentBOM,
  formatDriftAlert,
  validateAgentBOM,
} from "@wasmagent/agentbom-core";

// ---- Types ----

/** Resolved configuration for the subscribe command. */
export interface SubscribeConfig {
  /** Agent identity (agent_id) to monitor. */
  agentIdentity: string;
  /** Path to the baseline AgentBOM snapshot. */
  baselinePath: string;
  /** Directory to watch for updated artifacts (default: directory containing baseline). */
  watchDir: string;
  /** Optional callback URL for drift notifications (best-effort HTTP POST). */
  callbackUrl?: string;
  /** Polling interval in seconds (default 30). */
  intervalSeconds: number;
  /** Run a single check and exit instead of polling. */
  once: boolean;
}

/** Result of a single drift-check cycle. */
export interface DriftCheckResult {
  /** Whether drift was detected in this cycle. */
  hasDrift: boolean;
  /** The drift alert (empty if no drift). */
  alert: DriftAlert;
  /** Human-readable formatted alert string. */
  formatted: string;
  /** Files that were scanned. */
  scannedFiles: string[];
}

// ---- Pure helpers ----

/**
 * Read and parse a JSON file into a typed record.
 * Returns `null` on any failure.
 */
function readJsonRecord(filePath: string): Record<string, unknown> | null {
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
  try {
    const data = JSON.parse(raw);
    if (typeof data === "object" && data !== null && !Array.isArray(data)) {
      return data as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Extract the agent_id from a parsed AgentBOM record, if present.
 */
function extractAgentId(data: Record<string, unknown>): string | undefined {
  const identity = data.identity as Record<string, unknown> | undefined;
  if (identity && typeof identity.agent_id === "string") {
    return identity.agent_id;
  }
  return undefined;
}

/**
 * Extract the generated_at timestamp from a parsed AgentBOM record.
 */
function extractTimestamp(data: Record<string, unknown>): string {
  const identity = data.identity as Record<string, unknown> | undefined;
  if (identity && typeof identity.generated_at === "string") {
    return identity.generated_at;
  }
  return new Date().toISOString();
}

/**
 * Scan a directory for JSON files and return paths of those that parse as
 * valid AgentBOM documents matching the given agent identity.
 */
export function findAgentBOMFiles(
  dir: string,
  agentIdentity: string,
): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }

  const matches: string[] = [];
  for (const entry of entries) {
    if (!entry.endsWith(".json")) continue;
    const fullPath = resolve(dir, entry);
    try {
      if (!statSync(fullPath).isFile()) continue;
    } catch {
      continue;
    }

    const data = readJsonRecord(fullPath);
    if (!data) continue;

    // Must be a valid AgentBOM
    const validation = validateAgentBOM(data);
    if (!validation.valid) continue;

    // Must match the target agent identity
    const id = extractAgentId(data);
    if (id === agentIdentity) {
      matches.push(fullPath);
    }
  }

  return matches;
}

/**
 * Run a single drift-check cycle: find artifacts matching the agent identity
 * in the watch directory, diff each against the baseline, and produce a
 * combined drift alert.
 *
 * Pure function — no side effects. Returns a structured result for the caller
 * to log or send via callback.
 */
export function runDriftCheck(config: SubscribeConfig): DriftCheckResult {
  // Load baseline
  const baselineData = readJsonRecord(config.baselinePath);
  if (!baselineData) {
    // Return an empty result — the caller should handle baseline-missing before calling
    return {
      hasDrift: false,
      alert: {
        agent_id: config.agentIdentity,
        baseline_at: "",
        current_at: new Date().toISOString(),
        events: [],
        hasHighSeverity: () => false,
        isEmpty: () => true,
      },
      formatted: `Error: cannot read baseline AgentBOM at "${config.baselinePath}"`,
      scannedFiles: [],
    };
  }

  const baselineAgentId = extractAgentId(baselineData) ?? config.agentIdentity;
  const baselineAt = extractTimestamp(baselineData);

  // Find current artifacts
  const currentFiles = findAgentBOMFiles(config.watchDir, config.agentIdentity);

  // If the only file found is the baseline itself, no drift to detect
  const nonBaselineFiles = currentFiles.filter(
    (f) => resolve(f) !== resolve(config.baselinePath),
  );

  // Combine all events from all non-baseline files
  const allAlerts: DriftAlert[] = [];

  for (const filePath of nonBaselineFiles) {
    const currentData = readJsonRecord(filePath);
    if (!currentData) continue;

    const currentAt = extractTimestamp(currentData);
    const diff = diffAgentBOM(baselineData, currentData);
    const alert = classifyDriftEvents(
      diff,
      baselineAgentId,
      baselineAt,
      currentAt,
    );
    allAlerts.push(alert);
  }

  // Merge all alerts into one
  const mergedEvents = allAlerts.flatMap((a) => a.events);
  const latestAt =
    allAlerts.length > 0
      ? allAlerts[allAlerts.length - 1].current_at
      : baselineAt;

  const mergedAlert: DriftAlert = {
    agent_id: baselineAgentId,
    baseline_at: baselineAt,
    current_at: latestAt,
    events: mergedEvents,
    hasHighSeverity: () =>
      mergedEvents.some(
        (e) => e.severity === "high" || e.severity === "critical",
      ),
    isEmpty: () => mergedEvents.length === 0,
  };

  return {
    hasDrift: !mergedAlert.isEmpty(),
    alert: mergedAlert,
    formatted: formatDriftAlert(mergedAlert),
    scannedFiles: currentFiles,
  };
}

/**
 * Send a drift notification to a callback URL via HTTP POST.
 *
 * Best-effort: logs warnings on failure but never throws.
 */
export async function notifyCallback(
  callbackUrl: string,
  result: DriftCheckResult,
): Promise<boolean> {
  try {
    const payload = {
      agent_id: result.alert.agent_id,
      has_drift: result.hasDrift,
      event_count: result.alert.events.length,
      has_high_severity: result.alert.hasHighSeverity(),
      alert: {
        agent_id: result.alert.agent_id,
        baseline_at: result.alert.baseline_at,
        current_at: result.alert.current_at,
        events: result.alert.events,
      },
      scanned_files: result.scannedFiles,
      notified_at: new Date().toISOString(),
    };

    const response = await fetch(callbackUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) {
      console.warn(
        `Callback warning: HTTP ${response.status} from ${callbackUrl}`,
      );
      return false;
    }
    return true;
  } catch (err) {
    console.warn(
      `Callback warning: ${err instanceof Error ? err.message : String(err)}`,
    );
    return false;
  }
}

/**
 * Sleep for the given number of milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

// ---- CLI command ----

const SUBSCRIBE_USAGE = [
  "Usage: agent-trust subscribe <agent-identity> --baseline <path> [options]",
  "",
  "Set up continuous monitoring for trust artifact updates from a specific",
  "agent publisher.  Watches for AgentBOM files matching the given identity,",
  "detects drift against a baseline, and optionally sends notification callbacks.",
  "",
  "Arguments:",
  "  <agent-identity>     Agent ID to monitor (matches AgentBOM identity.agent_id)",
  "",
  "Required:",
  "  --baseline <path>    Path to the baseline AgentBOM snapshot",
  "",
  "Options:",
  "  --watch <dir>        Directory to watch for updated artifacts",
  "                       (default: directory containing the baseline file)",
  "  --callback <url>     URL for drift notification callbacks (HTTP POST)",
  "  --interval <seconds> Polling interval in seconds (default: 30, min: 5)",
  "  --once               Run a single drift check and exit (no polling loop)",
  "  --help, -h           Show this help message",
  "",
  "Examples:",
  "  agent-trust subscribe my-agent --baseline ./baseline/agentbom.json --once",
  "  agent-trust subscribe my-agent --baseline ./baseline.json --watch ./artifacts --interval 60",
  "  agent-trust subscribe my-agent --baseline ./baseline.json --callback https://hooks.example.com/drift",
].join("\n");

/**
 * Parse subscribe command arguments into a {@link SubscribeConfig}.
 * Returns the config on success, or a usage string (error message) on failure.
 */
export function parseSubscribeArgs(args: string[]): SubscribeConfig | string {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    return SUBSCRIBE_USAGE;
  }

  const agentIdentity = args[0];
  let baselinePath: string | undefined;
  let watchDir: string | undefined;
  let callbackUrl: string | undefined;
  let intervalSeconds = 30;
  let once = false;

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];

    if (arg === "--baseline" && next) {
      baselinePath = next;
      i++;
    } else if (arg === "--watch" && next) {
      watchDir = next;
      i++;
    } else if (arg === "--callback" && next) {
      callbackUrl = next;
      i++;
    } else if (arg === "--interval" && next) {
      const n = Number.parseInt(next, 10);
      if (Number.isNaN(n) || n < 5) {
        return `Error: --interval must be an integer ≥ 5, got "${next}"`;
      }
      intervalSeconds = n;
      i++;
    } else if (arg === "--once") {
      once = true;
    } else {
      return `Error: unknown argument "${arg}"`;
    }
  }

  if (!baselinePath) {
    return "Error: --baseline <path> is required";
  }

  const resolvedBaseline = resolve(baselinePath);
  const resolvedWatchDir = watchDir
    ? resolve(watchDir)
    : resolve(resolvedBaseline, "..");

  return {
    agentIdentity,
    baselinePath: resolvedBaseline,
    watchDir: resolvedWatchDir,
    callbackUrl,
    intervalSeconds,
    once,
  };
}

/**
 * CLI entry point for `agent-trust subscribe`.
 *
 * Returns exit code (0 = no drift / success, 1 = drift detected or error).
 * In continuous mode, runs until interrupted (SIGINT/SIGTERM).
 */
export async function subscribeCommand(args: string[]): Promise<number> {
  const parsed = parseSubscribeArgs(args);
  if (typeof parsed === "string") {
    if (parsed.startsWith("Usage:") || parsed.startsWith("Error:")) {
      if (parsed.startsWith("Usage:")) {
        console.log(parsed);
        return 0;
      }
      console.error(parsed);
      return 1;
    }
    // Should not happen but handle gracefully
    console.error(parsed);
    return 1;
  }

  const config = parsed;

  // Validate baseline exists and is a valid AgentBOM
  const baselineData = readJsonRecord(config.baselinePath);
  if (!baselineData) {
    console.error(
      `Error: cannot read baseline AgentBOM at "${config.baselinePath}"`,
    );
    return 1;
  }

  const baselineValidation = validateAgentBOM(baselineData);
  if (!baselineValidation.valid) {
    console.error(
      `Error: baseline AgentBOM validation failed at "${config.baselinePath}":`,
    );
    for (const err of baselineValidation.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  const baselineAgentId = extractAgentId(baselineData) ?? config.agentIdentity;

  // Mode banner
  const modeLabel = config.once
    ? "single-check"
    : `continuous (interval: ${config.intervalSeconds}s)`;
  console.log(`Trust Subscribe — monitoring agent "${baselineAgentId}"`);
  console.log(`  Baseline:   ${config.baselinePath}`);
  console.log(`  Watch dir:  ${config.watchDir}`);
  console.log(`  Callback:   ${config.callbackUrl ?? "(none)"}`);
  console.log(`  Mode:       ${modeLabel}`);
  console.log("");

  if (config.once) {
    // Single-check mode
    const result = runDriftCheck(config);

    if (result.hasDrift) {
      console.log("DRIFT DETECTED");
    }
    console.log(result.formatted);

    if (result.hasDrift && config.callbackUrl) {
      console.log(`\nSending notification to ${config.callbackUrl}...`);
      const sent = await notifyCallback(config.callbackUrl, result);
      if (sent) {
        console.log("Notification sent successfully.");
      } else {
        console.warn("Notification delivery failed.");
      }
    }

    return result.hasDrift ? 1 : 0;
  }

  // Continuous mode
  let cycles = 0;
  let totalDriftAlerts = 0;

  // eslint-disable-next-line no-constant-condition
  while (true) {
    cycles++;
    const cycleLabel = `[cycle ${cycles}] ${new Date().toISOString()}`;
    const result = runDriftCheck(config);

    if (result.hasDrift) {
      totalDriftAlerts++;
      console.log(`\n${cycleLabel} — DRIFT DETECTED`);
      console.log(result.formatted);

      if (config.callbackUrl) {
        // Fire-and-forget callback
        notifyCallback(config.callbackUrl, result).then((sent) => {
          if (!sent) {
            console.warn("  Callback delivery failed.");
          }
        });
      }

      // Update baseline to the newest scanned artifact (by generated_at) to
      // avoid re-alerting on the same drift
      let latestFile: string | undefined;
      let latestTs = Number.NEGATIVE_INFINITY;
      for (const file of result.scannedFiles) {
        if (resolve(file) === resolve(config.baselinePath)) continue;
        const data = readJsonRecord(file);
        if (!data) continue;
        const ts = Date.parse(extractTimestamp(data));
        if (!Number.isNaN(ts) && ts > latestTs) {
          latestTs = ts;
          latestFile = file;
        }
      }
      if (latestFile) {
        config.baselinePath = latestFile;
      }
    } else {
      console.log(
        `${cycleLabel} — no drift (${result.scannedFiles.length} file(s) scanned)`,
      );
    }

    await sleep(config.intervalSeconds * 1000);
  }
}
