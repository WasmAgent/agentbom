import { resolve } from 'node:path';
import { type PipelineConfig, runPipeline } from '@wasmagent/agentbom-core/pipeline';

/**
 * `agentbom pipeline <path> [--partitions N] [--no-incremental]`
 *
 * Enterprise-grade BOM processing pipeline command. Reads BOM artifacts from a
 * file or directory (auto-detecting NDJSON, JSON array, or single BOM format),
 * validates each artifact, and reports per-artifact results plus aggregate metrics.
 */
export async function agentbomPipelineCommand(args: string[]): Promise<number> {
  if (args.length < 1) {
    console.error('Error: agentbom pipeline requires a <path> argument');
    console.error('Usage: agentbom pipeline <path> [--partitions N] [--no-incremental]');
    return 1;
  }

  const filePath = resolve(args[0]);
  const config: Partial<PipelineConfig> = {};

  // Parse optional flags
  let i = 1;
  while (i < args.length) {
    const flag = args[i];
    if (flag === '--partitions' && args[i + 1] !== undefined) {
      const n = Number.parseInt(args[i + 1], 10);
      if (Number.isNaN(n) || n < 1) {
        console.error(`Error: --partitions must be a positive integer, got "${args[i + 1]}"`);
        return 1;
      }
      config.partitionCount = n;
      i += 2;
    } else if (flag === '--no-incremental') {
      config.emitIncremental = false;
      i += 1;
    } else {
      console.error(`Error: unknown flag "${flag}"`);
      return 1;
    }
  }

  const partLabel = config.partitionCount
    ? ` (${config.partitionCount} partition${config.partitionCount > 1 ? 's' : ''})`
    : '';
  console.log(`Processing BOM artifacts from: ${filePath}${partLabel}`);

  const wallStart = Date.now();
  const { results, metrics } = await runPipeline(filePath, config);
  const wallMs = Date.now() - wallStart;

  // Per-artifact results
  for (const result of results) {
    const status = result.valid ? '✓' : '✗';
    console.log(
      `  ${status} ${result.artifactId} — ${result.durationMs.toFixed(1)}ms — ${result.sizeBytes} bytes`,
    );
    if (!result.valid) {
      for (const err of result.validation.errors.slice(0, 5)) {
        console.log(`      ${err}`);
      }
      if (result.validation.errors.length > 5) {
        console.log(`      ... and ${result.validation.errors.length - 5} more errors`);
      }
    }
  }

  // Summary
  console.log();
  console.log('Pipeline summary:');
  console.log(`  Artifacts: ${metrics.totalProcessed}`);
  console.log(`  Errors:     ${metrics.totalErrors}`);
  console.log(`  Bytes:      ${metrics.totalBytesProcessed}`);
  console.log(`  Duration:   ${metrics.durationMs.toFixed(1)}ms (wall: ${wallMs}ms)`);
  console.log(`  Peak heap:  ${metrics.peakMemoryBytes} bytes`);

  if (config.partitionCount && config.partitionCount > 1) {
    console.log('  Partition counts:');
    for (const [p, count] of metrics.partitionCounts) {
      console.log(`    Partition ${p}: ${count}`);
    }
  }

  return metrics.totalErrors > 0 ? 1 : 0;
}
