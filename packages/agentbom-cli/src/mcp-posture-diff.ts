import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  diffMCPPosture,
  formatPostureDiff,
  validateMCPPosture,
} from '@wasmagent/mcp-posture';

export function diffMCPPostureCommand(oldFilePath: string, newFilePath: string): number {
  const oldPath = resolve(oldFilePath);
  const newPath = resolve(newFilePath);

  let oldRaw: string;
  try {
    oldRaw = readFileSync(oldPath, 'utf-8');
  } catch {
    console.error(`Error: cannot read file "${oldPath}"`);
    return 1;
  }

  let newRaw: string;
  try {
    newRaw = readFileSync(newPath, 'utf-8');
  } catch {
    console.error(`Error: cannot read file "${newPath}"`);
    return 1;
  }

  let oldData: unknown;
  try {
    oldData = JSON.parse(oldRaw);
  } catch {
    console.error(`Error: "${oldPath}" is not valid JSON`);
    return 1;
  }

  let newData: unknown;
  try {
    newData = JSON.parse(newRaw);
  } catch {
    console.error(`Error: "${newPath}" is not valid JSON`);
    return 1;
  }

  const oldResult = validateMCPPosture(oldData);
  if (!oldResult.valid) {
    console.error(`Validation failed for old file "${oldPath}":`);
    for (const err of oldResult.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  const newResult = validateMCPPosture(newData);
  if (!newResult.valid) {
    console.error(`Validation failed for new file "${newPath}":`);
    for (const err of newResult.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  const diff = diffMCPPosture(
    oldData as Record<string, unknown>,
    newData as Record<string, unknown>,
  );

  console.log('Comparing MCP Posture snapshots:');
  console.log(`  old: ${oldPath}`);
  console.log(`  new: ${newPath}`);
  console.log();

  const output = formatPostureDiff(diff);
  console.log(output);

  if (diff.isEmpty()) {
    return 0;
  }

  return 1;
}
