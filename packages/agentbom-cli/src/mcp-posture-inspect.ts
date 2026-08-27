import { inspectMCPPosture, validateMCPPosture } from "@wasmagent/mcp-posture";
import { readArtifactFile } from "./trust-publish.js";

export function inspectMCPPostureCommand(filePath: string): number {
  const { data, error } = readArtifactFile(filePath);
  if (error) return error;

  const result = validateMCPPosture(data);
  if (!result.valid) {
    console.error(`Validation failed for "${filePath}":`);
    for (const err of result.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  console.log(inspectMCPPosture(data));

  return 0;
}
