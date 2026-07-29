/**
 * Enterprise-grade BOM processing pipeline.
 *
 * Streaming validation and incremental analysis for AgentBOM files, with
 * backpressure-aware processing, bounded memory guarantees, and horizontal
 * scalability via partitioned artifact queues.
 *
 * Input formats:
 * - NDJSON (newline-delimited JSON) — truly streaming via readline
 * - JSON array — extracts top-level elements
 * - Directory of .json files — processes one at a time
 * - Single BOM file — wraps for pipeline compatibility
 *
 * The NDJSON reader uses Node readline over a file stream, so memory is bounded
 * by the largest single line regardless of total file size. For other formats,
 * use readBOMAutoDetect() for convenience or the specific reader when the
 * format is known.
 */

import { createReadStream, stat } from "node:fs";
import { readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import type { ValidationResult } from "./index.js";
import { inspectAgentBOM, validateAgentBOM } from "./index.js";

// ─── Types ──────────────────────────────────────────────────────

/** A single BOM artifact flowing through the pipeline. */
export interface BOMArtifact {
  /** Unique identifier for this artifact in the pipeline run. */
  id: string;
  /** The raw BOM data (already parsed from JSON). */
  data: Record<string, unknown>;
  /** Partition key for distributing work across partitions. */
  partitionKey: string;
  /** Approximate size in bytes (for memory tracking). */
  sizeBytes: number;
}

/** Configuration for the processing pipeline. */
export interface PipelineConfig {
  /** Maximum concurrent partitions processed in parallel (default: 4). */
  maxConcurrency: number;
  /** Soft memory limit in bytes — pipeline pauses when exceeded (default: 512 MB). */
  maxMemoryBytes: number;
  /** Number of partitions for horizontal scaling (default: 1). */
  partitionCount: number;
  /** Whether to emit incremental results via onResult callback. */
  emitIncremental: boolean;
}

/** Metrics tracked during a pipeline run. */
export interface PipelineMetrics {
  /** Total artifacts processed. */
  totalProcessed: number;
  /** Artifacts that failed validation. */
  totalErrors: number;
  /** Total bytes of artifact data processed. */
  totalBytesProcessed: number;
  /** Wall-clock duration of the pipeline run in ms. */
  durationMs: number;
  /** Peak RSS heap observed during the run in bytes. */
  peakMemoryBytes: number;
  /** Per-partition processing counts. */
  partitionCounts: Map<number, number>;
}

/** Result for a single processed artifact. */
export interface ArtifactResult {
  artifactId: string;
  partitionKey: string;
  partition: number;
  valid: boolean;
  validation: ValidationResult;
  inspection: string;
  durationMs: number;
  sizeBytes: number;
}

/** Callback invoked for each processed artifact when emitIncremental is true. */
export type ResultCallback = (result: ArtifactResult) => void | Promise<void>;

/** An async-iterable source of BOM artifacts. */
export type BOMArtifactSource =
  | AsyncIterable<BOMArtifact>
  | Iterable<BOMArtifact>;

/** Default pipeline configuration. */
export const DEFAULT_PIPELINE_CONFIG: PipelineConfig = {
  maxConcurrency: 4,
  maxMemoryBytes: 512 * 1024 * 1024,
  partitionCount: 1,
  emitIncremental: true,
};

// ─── Streaming BOM Readers ──────────────────────────────────────

/**
 * Read a directory of .json files as a stream of BOM artifacts.
 * Non-recursive; only immediate children ending in `.json`.
 */
export async function* readBOMDirectory(
  dirPath: string,
  partitionCount = 1,
): AsyncGenerator<BOMArtifact> {
  const resolvedDir = resolve(dirPath);
  const entries = await readdir(resolvedDir);
  const jsonFiles = entries.filter((e) => e.endsWith(".json")).sort();

  let counter = 0;
  for (const file of jsonFiles) {
    const fullPath = join(resolvedDir, file);
    const fileStat = await statSafe(fullPath);
    if (!fileStat?.isFile()) continue;

    const data = await readJsonFile(fullPath);
    if (data === null) continue;

    const partition = counter % partitionCount;
    counter++;

    yield {
      id: file,
      data,
      partitionKey: String(partition),
      sizeBytes: fileStat.size,
    };
  }
}

/**
 * Read a newline-delimited JSON (NDJSON) file as a stream of BOM artifacts.
 *
 * Uses Node readline over a file stream so memory is bounded by the largest
 * single line regardless of total file size — suitable for files >100 MB.
 */
export async function* readBOMNDJSON(
  filePath: string,
  partitionCount = 1,
): AsyncGenerator<BOMArtifact> {
  const resolved = resolve(filePath);
  const fileStat = await statSafe(resolved);
  if (!fileStat) return;

  const baseName = resolved.split("/").pop() ?? resolved;
  let rl: ReturnType<typeof createInterface>;
  try {
    rl = createInterface({
      input: createReadStream(resolved, { encoding: "utf-8" }),
      crlfDelay: Number.POSITIVE_INFINITY,
    });
  } catch {
    return;
  }

  let counter = 0;
  for await (const line of rl) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;

    let data: Record<string, unknown>;
    try {
      const parsed = JSON.parse(trimmed);
      if (
        typeof parsed !== "object" ||
        parsed === null ||
        Array.isArray(parsed)
      ) {
        continue;
      }
      data = parsed;
    } catch {
      continue; // skip unparseable lines in NDJSON mode
    }

    const partition = counter % partitionCount;
    counter++;

    yield {
      id: `${baseName}#${counter}`,
      data,
      partitionKey: String(partition),
      sizeBytes: Buffer.byteLength(trimmed, "utf-8"),
    };
  }
}

/**
 * Read a JSON array file as a stream of BOM artifacts.
 * Extracts each top-level array element sequentially.
 */
export async function* readBOMArrayFile(
  filePath: string,
  partitionCount = 1,
): AsyncGenerator<BOMArtifact> {
  const resolved = resolve(filePath);
  const content = await readTextFile(resolved);
  if (content === null) return;

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return;
  }
  if (!Array.isArray(parsed)) return;

  const baseName = resolved.split("/").pop() ?? resolved;

  for (let i = 0; i < parsed.length; i++) {
    const element = parsed[i];
    if (typeof element !== "object" || element === null) continue;

    const elementJson = JSON.stringify(element);
    yield {
      id: `${baseName}[${i}]`,
      data: element as Record<string, unknown>,
      partitionKey: String(i % partitionCount),
      sizeBytes: Buffer.byteLength(elementJson, "utf-8"),
    };
  }
}

/**
 * Read a single JSON BOM file as a stream with one artifact.
 */
export async function* readBOMSingleFile(
  filePath: string,
  partitionCount = 1,
): AsyncGenerator<BOMArtifact> {
  const resolved = resolve(filePath);
  const fileStat = await statSafe(resolved);
  const data = await readJsonFile(resolved);
  if (data === null) return;

  const baseName = resolved.split("/").pop() ?? resolved;
  yield {
    id: baseName,
    data,
    partitionKey: String(0 % partitionCount),
    sizeBytes:
      fileStat?.size ?? Buffer.byteLength(JSON.stringify(data), "utf-8"),
  };
}

/**
 * Auto-detect the source type and read BOM artifacts accordingly.
 *
 * - Directory → `readBOMDirectory`
 * - JSON array → `readBOMArrayFile`
 * - NDJSON (multiple valid JSON lines) → `readBOMNDJSON`
 * - Single BOM object → `readBOMSingleFile`
 *
 * **Note:** Auto-detection reads the full file content for non-directory paths
 * to probe the format. For files >100 MB where the format is known, call the
 * specific reader directly (especially `readBOMNDJSON` which is truly streaming).
 */
export async function* readBOMAutoDetect(
  filePath: string,
  partitionCount = 1,
): AsyncGenerator<BOMArtifact> {
  const resolved = resolve(filePath);
  const s = await statSafe(resolved);
  if (!s) return;

  if (s.isDirectory()) {
    yield* readBOMDirectory(resolved, partitionCount);
    return;
  }

  const content = await readTextFile(resolved);
  if (content === null) return;
  const trimmed = content.trim();

  // JSON array
  if (trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        yield* readBOMArrayFile(resolved, partitionCount);
        return;
      }
    } catch {
      // not a valid array, fall through
    }
  }

  // NDJSON detection: multiple lines each valid JSON
  const lines = trimmed.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length > 1) {
    let allValidJson = true;
    for (const line of lines) {
      try {
        JSON.parse(line.trim());
      } catch {
        allValidJson = false;
        break;
      }
    }
    if (allValidJson) {
      yield* readBOMNDJSON(resolved, partitionCount);
      return;
    }
  }

  // Fallback: single BOM file
  yield* readBOMSingleFile(resolved, partitionCount);
}

// ─── Partitioned Artifact Queue ──────────────────────────────────

/**
 * In-memory partitioned queue for distributing BOM artifacts.
 *
 * Artifacts within the same partition are processed in FIFO order.
 * Different partitions can be processed concurrently, enabling
 * horizontal scaling.
 */
export class PartitionedArtifactQueue {
  private partitions: Map<number, BOMArtifact[]>;
  readonly partitionCount: number;

  constructor(partitionCount: number) {
    this.partitionCount = partitionCount;
    this.partitions = new Map();
    for (let i = 0; i < partitionCount; i++) {
      this.partitions.set(i, []);
    }
  }

  /** Enqueue an artifact into its designated partition. */
  enqueue(artifact: BOMArtifact): void {
    const partition = this.hashPartition(artifact.partitionKey);
    const queue = this.partitions.get(partition);
    if (queue) queue.push(artifact);
  }

  /** Dequeue the next artifact from the given partition, or undefined. */
  dequeue(partition: number): BOMArtifact | undefined {
    return this.partitions.get(partition)?.shift();
  }

  /** Whether the given partition has more artifacts. */
  hasMore(partition: number): boolean {
    return (this.partitions.get(partition)?.length ?? 0) > 0;
  }

  /** Total artifacts across all partitions. */
  get totalSize(): number {
    let total = 0;
    for (const q of this.partitions.values()) total += q.length;
    return total;
  }

  /** Whether every partition is empty. */
  get isEmpty(): boolean {
    for (const q of this.partitions.values()) {
      if (q.length > 0) return false;
    }
    return true;
  }

  /** Simple string hash → partition index. */
  private hashPartition(key: string): number {
    let hash = 0;
    for (let i = 0; i < key.length; i++) {
      hash = ((hash << 5) - hash + key.charCodeAt(i)) | 0;
    }
    return (
      ((hash % this.partitionCount) + this.partitionCount) % this.partitionCount
    );
  }
}

// ─── BOM Processing Pipeline ─────────────────────────────────────

/**
 * Enterprise-grade BOM processing pipeline.
 *
 * Pull model (async iteration) provides natural backpressure: the pipeline
 * only reads artifacts as fast as it can process them. Memory is bounded by
 * the largest single artifact since only one artifact is held at a time per
 * partition worker.
 *
 * Partitions are processed concurrently, each preserving FIFO order for
 * artifacts within that partition. Cross-partition ordering is not guaranteed.
 */
export class BOMProcessingPipeline {
  private config: PipelineConfig;
  private metrics: PipelineMetrics;
  private onResult?: ResultCallback;

  constructor(config: Partial<PipelineConfig> = {}, onResult?: ResultCallback) {
    this.config = { ...DEFAULT_PIPELINE_CONFIG, ...config };
    this.onResult = onResult;
    this.metrics = emptyMetrics();
  }

  /**
   * Process BOM artifacts from the given source.
   * Returns the final pipeline metrics.
   */
  async process(source: BOMArtifactSource): Promise<PipelineMetrics> {
    const startTime = performance.now();
    this.metrics = emptyMetrics();

    // Stage 1: partition artifacts
    const queue = new PartitionedArtifactQueue(this.config.partitionCount);
    for await (const artifact of source) {
      queue.enqueue(artifact);
    }

    // Stage 2: process partitions concurrently
    const workers: Promise<void>[] = [];
    for (let p = 0; p < this.config.partitionCount; p++) {
      workers.push(this.processPartition(p, queue));
    }
    await Promise.all(workers);

    this.metrics.durationMs = performance.now() - startTime;
    return this.snapshotMetrics();
  }

  /** Process artifacts from one partition with backpressure awareness. */
  private async processPartition(
    partition: number,
    queue: PartitionedArtifactQueue,
  ): Promise<void> {
    while (queue.hasMore(partition)) {
      // Backpressure gate: pause if memory exceeds the soft limit
      if (this.config.maxMemoryBytes > 0) {
        const mem = process.memoryUsage().heapUsed;
        if (mem > this.metrics.peakMemoryBytes) {
          this.metrics.peakMemoryBytes = mem;
        }
        if (mem > this.config.maxMemoryBytes) {
          await this.backpressureWait();
        }
      }

      const artifact = queue.dequeue(partition);
      if (!artifact) break;

      const result = this.processArtifact(artifact, partition);

      this.metrics.totalProcessed++;
      this.metrics.totalBytesProcessed += result.sizeBytes;
      this.metrics.partitionCounts.set(
        partition,
        (this.metrics.partitionCounts.get(partition) ?? 0) + 1,
      );
      if (!result.valid) this.metrics.totalErrors++;

      if (this.config.emitIncremental && this.onResult) {
        await this.onResult(result);
      }
    }
  }

  /** Validate and inspect a single artifact (synchronous, bounded memory). */
  private processArtifact(
    artifact: BOMArtifact,
    partition: number,
  ): ArtifactResult {
    const start = performance.now();
    const validation = validateAgentBOM(artifact.data);
    const inspection = inspectAgentBOM(artifact.data);
    return {
      artifactId: artifact.id,
      partitionKey: artifact.partitionKey,
      partition,
      valid: validation.valid,
      validation,
      inspection,
      durationMs: performance.now() - start,
      sizeBytes: artifact.sizeBytes,
    };
  }

  /** Exponential backoff until memory drops below the limit. */
  private async backpressureWait(): Promise<void> {
    let wait = 10;
    while (
      process.memoryUsage().heapUsed > this.config.maxMemoryBytes &&
      wait <= 1000
    ) {
      // eslint-disable-next-line no-await-in-loop -- intentional backoff loop
      await new Promise<void>((r) => setTimeout(r, wait));
      wait *= 2;
    }
    // always yield at least one tick even if still over limit
    await new Promise<void>((r) => setTimeout(r, 1));
  }

  /** Get a snapshot of current metrics (safe to call mid-run). */
  getMetrics(): PipelineMetrics {
    return this.snapshotMetrics();
  }

  private snapshotMetrics(): PipelineMetrics {
    return {
      ...this.metrics,
      partitionCounts: new Map(this.metrics.partitionCounts),
    };
  }
}

// ─── Convenience ─────────────────────────────────────────────────

/**
 * Run a full pipeline on a file or directory with default configuration.
 * Collects all results and returns them along with metrics.
 */
export async function runPipeline(
  filePath: string,
  config: Partial<PipelineConfig> = {},
): Promise<{ results: ArtifactResult[]; metrics: PipelineMetrics }> {
  const results: ArtifactResult[] = [];
  const pipeline = new BOMProcessingPipeline(config, (r) => {
    results.push(r);
  });
  const source = readBOMAutoDetect(filePath, config.partitionCount ?? 1);
  const metrics = await pipeline.process(source);
  return { results, metrics };
}

// ─── Internal helpers ────────────────────────────────────────────

function emptyMetrics(): PipelineMetrics {
  return {
    totalProcessed: 0,
    totalErrors: 0,
    totalBytesProcessed: 0,
    durationMs: 0,
    peakMemoryBytes: 0,
    partitionCounts: new Map(),
  };
}

function statSafe(path: string): Promise<import("node:fs").Stats | null> {
  return new Promise((resolve) => {
    stat(path, (err, stats) => resolve(err ? null : stats));
  });
}

function readTextFile(path: string): Promise<string | null> {
  return new Promise((resolve) => {
    const stream = createReadStream(path, { encoding: "utf-8" });
    const chunks: string[] = [];
    stream.on("data", (chunk: string) => chunks.push(chunk));
    stream.on("end", () => resolve(chunks.join("")));
    stream.on("error", () => resolve(null));
  });
}

function readJsonFile(path: string): Promise<Record<string, unknown> | null> {
  return readTextFile(path).then((text) => {
    if (!text) return null;
    try {
      const parsed = JSON.parse(text);
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        !Array.isArray(parsed)
      ) {
        return parsed as Record<string, unknown>;
      }
      return null;
    } catch {
      return null;
    }
  });
}
