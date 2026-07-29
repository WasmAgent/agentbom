import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type ArtifactResult,
  type BOMArtifact,
  BOMProcessingPipeline,
  PartitionedArtifactQueue,
  readBOMArrayFile,
  readBOMAutoDetect,
  readBOMDirectory,
  readBOMNDJSON,
  readBOMSingleFile,
  runPipeline,
} from "./pipeline.js";

// ─── Fixtures ───────────────────────────────────────────────────

const VALID_BOM = {
  agentbom_version: "0.1",
  identity: {
    agent_id: "test-agent-001",
    agent_name: "Test Agent",
    deployment_context: "development",
    generated_at: "2026-06-28T00:00:00Z",
  },
  attestation: { generator: "test" },
};

const INVALID_BOM = {
  agentbom_version: "0.1",
  // missing identity and attestation
};

/** Collect all items from an async generator. */
async function collect<T>(gen: AsyncGenerator<T>): Promise<T[]> {
  const results: T[] = [];
  for await (const item of gen) results.push(item);
  return results;
}

// ─── Temp directory lifecycle ───────────────────────────────────

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "bom-pipeline-test-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

// ─── readBOMSingleFile ──────────────────────────────────────────

describe("readBOMSingleFile", () => {
  it("reads a single valid BOM file", async () => {
    const filePath = join(tempDir, "single.json");
    await writeFile(filePath, JSON.stringify(VALID_BOM));

    const artifacts = await collect(readBOMSingleFile(filePath));
    expect(artifacts).toHaveLength(1);
    expect(artifacts[0].id).toBe("single.json");
    expect(artifacts[0].data.agentbom_version).toBe("0.1");
    expect(artifacts[0].partitionKey).toBe("0");
    expect(artifacts[0].sizeBytes).toBeGreaterThan(0);
  });

  it("returns empty for non-existent file", async () => {
    const artifacts = await collect(
      readBOMSingleFile(join(tempDir, "nope.json")),
    );
    expect(artifacts).toHaveLength(0);
  });

  it("returns empty for invalid JSON", async () => {
    const filePath = join(tempDir, "bad.json");
    await writeFile(filePath, "not json at all");

    const artifacts = await collect(readBOMSingleFile(filePath));
    expect(artifacts).toHaveLength(0);
  });

  it("returns empty for JSON array (not a single object)", async () => {
    const filePath = join(tempDir, "array.json");
    await writeFile(filePath, JSON.stringify([VALID_BOM]));

    const artifacts = await collect(readBOMSingleFile(filePath));
    expect(artifacts).toHaveLength(0);
  });

  it("returns empty for JSON primitive", async () => {
    const filePath = join(tempDir, "prim.json");
    await writeFile(filePath, "42");

    const artifacts = await collect(readBOMSingleFile(filePath));
    expect(artifacts).toHaveLength(0);
  });
});

// ─── readBOMNDJSON ─────────────────────────────────────────────

describe("readBOMNDJSON", () => {
  it("reads NDJSON with multiple BOMs", async () => {
    const filePath = join(tempDir, "boms.ndjson");
    const content = [
      JSON.stringify(VALID_BOM),
      JSON.stringify({
        ...VALID_BOM,
        identity: { ...VALID_BOM.identity, agent_id: "agent-002" },
      }),
      JSON.stringify(INVALID_BOM),
    ].join("\n");
    await writeFile(filePath, content);

    const artifacts = await collect(readBOMNDJSON(filePath));
    expect(artifacts).toHaveLength(3);
    expect(artifacts[0].id).toContain("#1");
    expect(artifacts[1].id).toContain("#2");
    expect(artifacts[2].id).toContain("#3");
  });

  it("skips empty lines and invalid JSON", async () => {
    const filePath = join(tempDir, "mixed.ndjson");
    await writeFile(
      filePath,
      `${JSON.stringify(VALID_BOM)}\n\nnot json\n${JSON.stringify(VALID_BOM)}\n`,
    );

    const artifacts = await collect(readBOMNDJSON(filePath));
    expect(artifacts).toHaveLength(2);
  });

  it("skips non-object JSON values", async () => {
    const filePath = join(tempDir, "primitives.ndjson");
    await writeFile(
      filePath,
      `42\n"string"\n${JSON.stringify(VALID_BOM)}\n[1,2]\n`,
    );

    const artifacts = await collect(readBOMNDJSON(filePath));
    expect(artifacts).toHaveLength(1);
  });

  it("distributes artifacts across partitions round-robin", async () => {
    const filePath = join(tempDir, "part.ndjson");
    const lines = Array.from({ length: 6 }, (_, i) =>
      JSON.stringify({
        ...VALID_BOM,
        identity: { ...VALID_BOM.identity, agent_id: `a-${i}` },
      }),
    ).join("\n");
    await writeFile(filePath, lines);

    const artifacts = await collect(readBOMNDJSON(filePath, 3));
    expect(artifacts).toHaveLength(6);
    const keys = artifacts.map((a) => a.partitionKey);
    expect(keys).toEqual(["0", "1", "2", "0", "1", "2"]);
  });

  it("returns empty for non-existent file", async () => {
    const artifacts = await collect(
      readBOMNDJSON(join(tempDir, "nope.ndjson")),
    );
    expect(artifacts).toHaveLength(0);
  });
});

// ─── readBOMArrayFile ──────────────────────────────────────────

describe("readBOMArrayFile", () => {
  it("reads JSON array of BOMs", async () => {
    const filePath = join(tempDir, "array.json");
    await writeFile(
      filePath,
      JSON.stringify([
        VALID_BOM,
        {
          ...VALID_BOM,
          identity: { ...VALID_BOM.identity, agent_id: "agent-002" },
        },
      ]),
    );

    const artifacts = await collect(readBOMArrayFile(filePath));
    expect(artifacts).toHaveLength(2);
    expect(artifacts[0].id).toContain("[0]");
    expect(artifacts[1].id).toContain("[1]");
  });

  it("returns empty for non-array JSON", async () => {
    const filePath = join(tempDir, "object.json");
    await writeFile(filePath, JSON.stringify(VALID_BOM));

    const artifacts = await collect(readBOMArrayFile(filePath));
    expect(artifacts).toHaveLength(0);
  });

  it("skips non-object elements in array", async () => {
    const filePath = join(tempDir, "mixed-array.json");
    await writeFile(
      filePath,
      JSON.stringify([VALID_BOM, 42, null, "string", VALID_BOM]),
    );

    const artifacts = await collect(readBOMArrayFile(filePath));
    expect(artifacts).toHaveLength(2);
  });

  it("returns empty for empty array", async () => {
    const filePath = join(tempDir, "empty-array.json");
    await writeFile(filePath, "[]");

    const artifacts = await collect(readBOMArrayFile(filePath));
    expect(artifacts).toHaveLength(0);
  });

  it("returns empty for invalid JSON", async () => {
    const filePath = join(tempDir, "bad-array.json");
    await writeFile(filePath, "not json");

    const artifacts = await collect(readBOMArrayFile(filePath));
    expect(artifacts).toHaveLength(0);
  });
});

// ─── readBOMDirectory ──────────────────────────────────────────

describe("readBOMDirectory", () => {
  it("reads all JSON files in directory (sorted)", async () => {
    await writeFile(join(tempDir, "z-last.json"), JSON.stringify(VALID_BOM));
    await writeFile(join(tempDir, "a-first.json"), JSON.stringify(VALID_BOM));
    await writeFile(join(tempDir, "c.txt"), "not json");

    const artifacts = await collect(readBOMDirectory(tempDir));
    expect(artifacts).toHaveLength(2);
    expect(artifacts[0].id).toBe("a-first.json");
    expect(artifacts[1].id).toBe("z-last.json");
  });

  it("does not recurse into subdirectories", async () => {
    const subDir = join(tempDir, "sub");
    await mkdir(subDir);
    await writeFile(join(subDir, "nested.json"), JSON.stringify(VALID_BOM));

    const artifacts = await collect(readBOMDirectory(tempDir));
    expect(artifacts.every((a) => !a.id.startsWith("nested"))).toBe(true);
  });

  it("skips invalid JSON files", async () => {
    await writeFile(join(tempDir, "good.json"), JSON.stringify(VALID_BOM));
    await writeFile(join(tempDir, "bad.json"), "not json");

    const artifacts = await collect(readBOMDirectory(tempDir));
    expect(artifacts).toHaveLength(1);
  });

  it("distributes across partitions", async () => {
    // Create a dedicated subdirectory for this test
    const testDir = join(tempDir, "partdir");
    await mkdir(testDir);
    for (let i = 0; i < 4; i++) {
      await writeFile(join(testDir, `bom${i}.json`), JSON.stringify(VALID_BOM));
    }

    const artifacts = await collect(readBOMDirectory(testDir, 2));
    expect(artifacts).toHaveLength(4);
    const keys = artifacts.map((a) => a.partitionKey);
    expect(keys).toEqual(["0", "1", "0", "1"]);
  });
});

// ─── readBOMAutoDetect ─────────────────────────────────────────

describe("readBOMAutoDetect", () => {
  it("detects a directory", async () => {
    const dir = join(tempDir, "auto-dir");
    await mkdir(dir);
    await writeFile(join(dir, "a.json"), JSON.stringify(VALID_BOM));

    const artifacts = await collect(readBOMAutoDetect(dir));
    expect(artifacts).toHaveLength(1);
  });

  it("detects a JSON array file", async () => {
    const filePath = join(tempDir, "auto-array.json");
    await writeFile(filePath, JSON.stringify([VALID_BOM, VALID_BOM]));

    const artifacts = await collect(readBOMAutoDetect(filePath));
    expect(artifacts).toHaveLength(2);
  });

  it("detects an NDJSON file", async () => {
    const filePath = join(tempDir, "auto.ndjson");
    await writeFile(
      filePath,
      `${JSON.stringify(VALID_BOM)}\n${JSON.stringify(VALID_BOM)}`,
    );

    const artifacts = await collect(readBOMAutoDetect(filePath));
    expect(artifacts).toHaveLength(2);
  });

  it("falls back to single file for a plain BOM", async () => {
    const filePath = join(tempDir, "auto-single.json");
    await writeFile(filePath, JSON.stringify(VALID_BOM));

    const artifacts = await collect(readBOMAutoDetect(filePath));
    expect(artifacts).toHaveLength(1);
  });

  it("returns empty for non-existent path", async () => {
    const artifacts = await collect(readBOMAutoDetect(join(tempDir, "nope")));
    expect(artifacts).toHaveLength(0);
  });
});

// ─── PartitionedArtifactQueue ─────────────────────────────────

describe("PartitionedArtifactQueue", () => {
  it("distributes and drains artifacts across partitions", () => {
    const queue = new PartitionedArtifactQueue(3);
    const artifacts: BOMArtifact[] = [
      { id: "a", data: VALID_BOM, partitionKey: "0", sizeBytes: 100 },
      { id: "b", data: VALID_BOM, partitionKey: "1", sizeBytes: 100 },
      { id: "c", data: VALID_BOM, partitionKey: "2", sizeBytes: 100 },
    ];

    for (const a of artifacts) queue.enqueue(a);
    expect(queue.totalSize).toBe(3);
    expect(queue.isEmpty).toBe(false);

    const drained: BOMArtifact[] = [];
    while (!queue.isEmpty) {
      for (let p = 0; p < queue.partitionCount; p++) {
        const item = queue.dequeue(p);
        if (item) drained.push(item);
      }
    }
    expect(drained).toHaveLength(3);
    expect(queue.isEmpty).toBe(true);
  });

  it("handles empty queue gracefully", () => {
    const queue = new PartitionedArtifactQueue(2);
    expect(queue.isEmpty).toBe(true);
    expect(queue.totalSize).toBe(0);
    expect(queue.dequeue(0)).toBeUndefined();
    expect(queue.hasMore(0)).toBe(false);
  });

  it("preserves FIFO order within a partition", () => {
    const queue = new PartitionedArtifactQueue(1);
    queue.enqueue({
      id: "first",
      data: VALID_BOM,
      partitionKey: "0",
      sizeBytes: 10,
    });
    queue.enqueue({
      id: "second",
      data: VALID_BOM,
      partitionKey: "0",
      sizeBytes: 20,
    });
    queue.enqueue({
      id: "third",
      data: VALID_BOM,
      partitionKey: "0",
      sizeBytes: 30,
    });

    expect(queue.dequeue(0)?.id).toBe("first");
    expect(queue.dequeue(0)?.id).toBe("second");
    expect(queue.dequeue(0)?.id).toBe("third");
    expect(queue.dequeue(0)).toBeUndefined();
  });

  it("hashes partitionKey to a stable partition", () => {
    const queue = new PartitionedArtifactQueue(4);
    queue.enqueue({
      id: "a",
      data: VALID_BOM,
      partitionKey: "key-x",
      sizeBytes: 10,
    });
    queue.enqueue({
      id: "b",
      data: VALID_BOM,
      partitionKey: "key-x",
      sizeBytes: 10,
    });

    // Both should land in the same partition
    let firstPartition: number | undefined;
    for (let p = 0; p < 4; p++) {
      if (queue.hasMore(p)) {
        firstPartition = p;
        queue.dequeue(p);
      }
    }
    // The second should be in the same partition
    expect(firstPartition).toBeDefined();
    expect(queue.hasMore(firstPartition as number)).toBe(true);
  });
});

// ─── BOMProcessingPipeline ────────────────────────────────────

describe("BOMProcessingPipeline", () => {
  it("processes a stream of valid BOMs", async () => {
    const results: ArtifactResult[] = [];
    const pipeline = new BOMProcessingPipeline({}, (r) => {
      results.push(r);
    });

    async function* source(): AsyncGenerator<BOMArtifact> {
      yield { id: "a", data: VALID_BOM, partitionKey: "0", sizeBytes: 100 };
      yield { id: "b", data: VALID_BOM, partitionKey: "0", sizeBytes: 100 };
    }

    const metrics = await pipeline.process(source());
    expect(metrics.totalProcessed).toBe(2);
    expect(metrics.totalErrors).toBe(0);
    expect(results).toHaveLength(2);
    expect(results.every((r) => r.valid)).toBe(true);
  });

  it("counts validation errors", async () => {
    const results: ArtifactResult[] = [];
    const pipeline = new BOMProcessingPipeline({}, (r) => {
      results.push(r);
    });

    async function* source(): AsyncGenerator<BOMArtifact> {
      yield { id: "valid", data: VALID_BOM, partitionKey: "0", sizeBytes: 100 };
      yield {
        id: "invalid",
        data: INVALID_BOM,
        partitionKey: "0",
        sizeBytes: 50,
      };
    }

    const metrics = await pipeline.process(source());
    expect(metrics.totalProcessed).toBe(2);
    expect(metrics.totalErrors).toBe(1);
    expect(results[0].valid).toBe(true);
    expect(results[1].valid).toBe(false);
  });

  it("tracks bytes processed", async () => {
    const pipeline = new BOMProcessingPipeline({});

    async function* source(): AsyncGenerator<BOMArtifact> {
      yield { id: "a", data: VALID_BOM, partitionKey: "0", sizeBytes: 500 };
      yield { id: "b", data: VALID_BOM, partitionKey: "0", sizeBytes: 300 };
    }

    const metrics = await pipeline.process(source());
    expect(metrics.totalBytesProcessed).toBe(800);
  });

  it("distributes work across partitions", async () => {
    const results: ArtifactResult[] = [];
    const pipeline = new BOMProcessingPipeline({ partitionCount: 2 }, (r) => {
      results.push(r);
    });

    async function* source(): AsyncGenerator<BOMArtifact> {
      yield { id: "a", data: VALID_BOM, partitionKey: "0", sizeBytes: 100 };
      yield { id: "b", data: VALID_BOM, partitionKey: "1", sizeBytes: 100 };
      yield { id: "c", data: VALID_BOM, partitionKey: "0", sizeBytes: 100 };
    }

    const metrics = await pipeline.process(source());
    expect(metrics.partitionCounts.get(0)).toBe(2);
    expect(metrics.partitionCounts.get(1)).toBe(1);
  });

  it("records positive duration", async () => {
    const pipeline = new BOMProcessingPipeline({});

    async function* source(): AsyncGenerator<BOMArtifact> {
      yield { id: "a", data: VALID_BOM, partitionKey: "0", sizeBytes: 100 };
    }

    const metrics = await pipeline.process(source());
    expect(metrics.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("includes validation error details in results", async () => {
    const results: ArtifactResult[] = [];
    const pipeline = new BOMProcessingPipeline({}, (r) => {
      results.push(r);
    });

    async function* source(): AsyncGenerator<BOMArtifact> {
      yield { id: "bad", data: INVALID_BOM, partitionKey: "0", sizeBytes: 50 };
    }

    await pipeline.process(source());
    expect(results).toHaveLength(1);
    expect(results[0].validation.valid).toBe(false);
    expect(results[0].validation.errorDetails.length).toBeGreaterThan(0);
    expect(results[0].inspection).toContain("AgentBOM");
  });

  it("handles empty source", async () => {
    const pipeline = new BOMProcessingPipeline({});

    async function* source(): AsyncGenerator<BOMArtifact> {
      // yield nothing
    }

    const metrics = await pipeline.process(source());
    expect(metrics.totalProcessed).toBe(0);
    expect(metrics.totalErrors).toBe(0);
  });

  it("works with synchronous iterables", async () => {
    const results: ArtifactResult[] = [];
    const pipeline = new BOMProcessingPipeline({}, (r) => {
      results.push(r);
    });

    const artifacts: BOMArtifact[] = [
      { id: "a", data: VALID_BOM, partitionKey: "0", sizeBytes: 100 },
    ];

    const metrics = await pipeline.process(artifacts);
    expect(metrics.totalProcessed).toBe(1);
    expect(results).toHaveLength(1);
  });
});

// ─── backpressure ──────────────────────────────────────────────

describe("backpressure behavior", () => {
  it("completes processing under a very low memory limit", async () => {
    const results: ArtifactResult[] = [];
    const pipeline = new BOMProcessingPipeline(
      { maxMemoryBytes: 1 }, // 1 byte — triggers backpressure on every artifact
      (r) => {
        results.push(r);
      },
    );

    async function* source(): AsyncGenerator<BOMArtifact> {
      yield { id: "a", data: VALID_BOM, partitionKey: "0", sizeBytes: 100 };
      yield { id: "b", data: VALID_BOM, partitionKey: "0", sizeBytes: 100 };
    }

    const metrics = await pipeline.process(source());
    expect(metrics.totalProcessed).toBe(2);
  });
});

// ─── runPipeline convenience ───────────────────────────────────

describe("runPipeline convenience", () => {
  it("processes a directory of BOM files", async () => {
    const dir = join(tempDir, "run-dir");
    await mkdir(dir);
    await writeFile(join(dir, "v1.json"), JSON.stringify(VALID_BOM));
    await writeFile(join(dir, "v2.json"), JSON.stringify(VALID_BOM));
    await writeFile(join(dir, "bad.json"), JSON.stringify(INVALID_BOM));

    const { results, metrics } = await runPipeline(dir);
    expect(results).toHaveLength(3);
    expect(metrics.totalProcessed).toBe(3);
    expect(metrics.totalErrors).toBe(1);
  });

  it("processes a single BOM file", async () => {
    const filePath = join(tempDir, "run-single.json");
    await writeFile(filePath, JSON.stringify(VALID_BOM));

    const { results, metrics } = await runPipeline(filePath);
    expect(results).toHaveLength(1);
    expect(metrics.totalProcessed).toBe(1);
    expect(metrics.totalErrors).toBe(0);
  });

  it("processes an NDJSON file", async () => {
    const filePath = join(tempDir, "run-stream.ndjson");
    await writeFile(
      filePath,
      [JSON.stringify(VALID_BOM), JSON.stringify(VALID_BOM)].join("\n"),
    );

    const { results, metrics } = await runPipeline(filePath);
    expect(results).toHaveLength(2);
    expect(metrics.totalProcessed).toBe(2);
  });

  it("processes a JSON array file", async () => {
    const filePath = join(tempDir, "run-array.json");
    await writeFile(
      filePath,
      JSON.stringify([VALID_BOM, VALID_BOM, INVALID_BOM]),
    );

    const { results, metrics } = await runPipeline(filePath);
    expect(results).toHaveLength(3);
    expect(metrics.totalErrors).toBe(1);
  });

  it("respects partitionCount configuration", async () => {
    const filePath = join(tempDir, "run-part.ndjson");
    await writeFile(
      filePath,
      Array.from({ length: 10 }, () => JSON.stringify(VALID_BOM)).join("\n"),
    );

    const { metrics } = await runPipeline(filePath, { partitionCount: 4 });
    expect(metrics.totalProcessed).toBe(10);
    expect(metrics.partitionCounts.size).toBeGreaterThan(1);
  });
});
