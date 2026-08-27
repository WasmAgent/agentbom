import { validateAgentBOM } from "@wasmagent/agentbom-core";
import { readArtifactFile } from "./trust-publish.js";

export function validateAgentBOMCommand(filePath: string): number {
  const { data, error } = readArtifactFile(filePath);
  if (error) return error;

  const result = validateAgentBOM(data);
  if (!result.valid) {
    console.error(`Validation failed for "${filePath}":`);
    for (const err of result.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  console.log(`Valid AgentBOM v${data.agentbom_version}`);
  return 0;
}
