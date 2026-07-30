import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { inspectAgentBOM, validateAgentBOM } from "@wasmagent/agentbom-core";

export function inspectAgentBOMCommand(filePath: string): number {
  const resolvedPath = resolve(filePath);

  let raw: string;
  try {
    raw = readFileSync(resolvedPath, "utf-8");
  } catch {
    console.error(`Error: cannot read file "${resolvedPath}"`);
    return 1;
  }

  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    console.error(`Error: "${resolvedPath}" is not valid JSON`);
    return 1;
  }

  const result = validateAgentBOM(data);
  if (!result.valid) {
    console.error(`Validation failed for "${resolvedPath}":`);
    for (const err of result.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  const bom = data as Record<string, unknown>;
  console.log(inspectAgentBOM(bom));

  return 0;
}
