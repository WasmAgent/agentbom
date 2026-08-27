import { resolve } from "node:path";
import {
  diffMCPPosture,
  formatPostureDiff,
  validateMCPPosture,
} from "@wasmagent/mcp-posture";
import { readArtifactFile } from "./trust-publish.js";

export function diffMCPPostureCommand(
  oldFilePath: string,
  newFilePath: string,
): number {
  const oldPath = resolve(oldFilePath);
  const newPath = resolve(newFilePath);

  const oldFile = readArtifactFile(oldPath);
  if (oldFile.error) return oldFile.error;

  const newFile = readArtifactFile(newPath);
  if (newFile.error) return newFile.error;

  const oldResult = validateMCPPosture(oldFile.data);
  if (!oldResult.valid) {
    console.error(`Validation failed for old file "${oldPath}":`);
    for (const err of oldResult.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  const newResult = validateMCPPosture(newFile.data);
  if (!newResult.valid) {
    console.error(`Validation failed for new file "${newPath}":`);
    for (const err of newResult.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  const diff = diffMCPPosture(oldFile.data, newFile.data);

  console.log("Comparing MCP Posture snapshots:");
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
