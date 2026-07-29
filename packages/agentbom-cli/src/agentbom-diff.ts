import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  diffAgentBOM,
  formatAgentBOMDiff,
  validateAgentBOM,
} from '@wasmagent/agentbom-core';

export function diffAgentBOMCommand(oldFilePath: string, newFilePath: string): number {
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

  const oldResult = validateAgentBOM(oldData);
  if (!oldResult.valid) {
    console.error(`Validation failed for old file "${oldPath}":`);
    for (const err of oldResult.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  const newResult = validateAgentBOM(newData);
  if (!newResult.valid) {
    console.error(`Validation failed for new file "${newPath}":`);
    for (const err of newResult.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  const oldBom = oldData as Record<string, unknown>;
  const newBom = newData as Record<string, unknown>;
  const diff = diffAgentBOM(oldBom, newBom);

  console.log('Comparing AgentBOMs:');
  console.log(`  old: ${oldPath}`);
  console.log(`  new: ${newPath}`);
  console.log();

  const output = formatAgentBOMDiff(diff);
  console.log(output);

  if (diff.isEmpty()) {
    return 0;
  }

  return 1;
}
