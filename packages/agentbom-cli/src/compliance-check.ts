import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type CompatibilityProfileInput,
  type ComplianceProfile,
  checkCompliance,
  checkProfileSchemaCompatibility,
  getLatestVersion,
  upgradeProfileMappings,
  validateAgentBOM,
} from "@wasmagent/agentbom-core";
import { readArtifactFile } from "./trust-publish.js";

function loadProfile(profileId: string): ComplianceProfile | null {
  const profilesDir = resolve(
    dirname(fileURLToPath(import.meta.url)),
    "../profiles",
  );

  const profilePath = resolve(profilesDir, `${profileId}.json`);

  try {
    const raw = readFileSync(profilePath, "utf-8");
    return JSON.parse(raw) as ComplianceProfile;
  } catch {
    return null;
  }
}

/** Map a compliance profile onto the schema-compatibility checker input. */
function toCompatibilityProfileInput(
  profile: ComplianceProfile,
): CompatibilityProfileInput {
  return {
    profile_version: profile.profile_version,
    rules: {
      identity: profile.rules.identity
        ? {
            required_fields: profile.rules.identity.required_fields,
            allowed_contexts: profile.rules.identity.allowed_contexts,
            requires_version: profile.rules.identity.requires_version,
          }
        : undefined,
      tool_layer: profile.rules.tool_layer
        ? {
            max_severity: profile.rules.tool_layer.max_severity,
            requires_tool_inventory:
              profile.rules.tool_layer.requires_tool_inventory,
            blocked_permissions: profile.rules.tool_layer.blocked_permissions,
            blocked_sources: profile.rules.tool_layer.blocked_sources,
          }
        : undefined,
      risk_layer: profile.rules.risk_layer
        ? {
            requires_risk_assessment:
              profile.rules.risk_layer.requires_risk_assessment,
            max_unmitigated_critical:
              profile.rules.risk_layer.max_unmitigated_critical,
            max_unmitigated_high: profile.rules.risk_layer.max_unmitigated_high,
            max_unmitigated_medium:
              profile.rules.risk_layer.max_unmitigated_medium,
            requires_mitigation_for:
              profile.rules.risk_layer.requires_mitigation_for,
          }
        : undefined,
      attestation: profile.rules.attestation
        ? {
            requires_signature: profile.rules.attestation.requires_signature,
            requires_timestamp: profile.rules.attestation.requires_timestamp,
          }
        : undefined,
    },
  };
}

export function complianceCheckCommand(args: string[]): number {
  if (args.length < 3) {
    console.error(
      "Usage: agent-trust compliance-check <bom.json> --profile <name> [--min-score <score>]",
    );
    console.error("");
    console.error("Available profiles:");
    console.error("  soc2-2024       SOC 2 Type II compliance (2024)");
    console.error("  iso27001-2022   ISO/IEC 27001:2022 compliance");
    console.error(
      "  eidas-controlled eIDAS controlled digital identity services",
    );
    return 1;
  }

  const bomPath = args[0];
  const profileArg = args[1];

  if (profileArg !== "--profile") {
    console.error(`Error: expected "--profile" argument, got "${profileArg}"`);
    return 1;
  }

  const profileId = args[2];

  // Parse --min-score if present
  let minScore = 1.0;
  for (let i = 3; i < args.length; i++) {
    if (args[i] === "--min-score" && i + 1 < args.length) {
      const parsed = Number.parseFloat(args[i + 1]);
      if (!Number.isNaN(parsed) && parsed >= 0 && parsed <= 1) {
        minScore = parsed;
      } else {
        console.error(
          `Error: --min-score must be a number between 0 and 1, got "${args[i + 1]}"`,
        );
        return 1;
      }
      break;
    }
  }

  // Load AgentBOM
  const resolvedBomPath = resolve(bomPath);
  const { data: bomData, error } = readArtifactFile(resolvedBomPath);
  if (error) return error;

  // Validate AgentBOM schema
  const bomValidation = validateAgentBOM(bomData);
  if (!bomValidation.valid) {
    console.error(
      `Error: AgentBOM validation failed for "${resolvedBomPath}":`,
    );
    for (const err of bomValidation.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  // Load compliance profile
  const profile = loadProfile(profileId);
  if (!profile) {
    console.error(`Error: cannot load compliance profile "${profileId}"`);
    console.error(`Expected file: profiles/${profileId}.json`);
    return 1;
  }

  // Run compliance checks
  const result = checkCompliance(bomData, profile, minScore);
  const score = result.score;

  // Output results
  console.log(
    `Compliance Check: ${profile.framework.name} ${profile.framework.version}`,
  );
  console.log(`Profile: ${profile.profile_id}`);
  console.log(`AgentBOM: ${resolvedBomPath}`);
  console.log(
    `Score: ${(score * 100).toFixed(1)}% (threshold: ${(minScore * 100).toFixed(0)}%)`,
  );
  console.log("");

  if (result.passed_checks.length > 0) {
    console.log("✓ Passed checks:");
    for (const check of result.passed_checks) {
      console.log(`  ${check}`);
    }
    console.log("");
  }

  if (result.warnings.length > 0) {
    console.log("⚠ Warnings:");
    for (const warning of result.warnings) {
      console.log(`  ${warning}`);
    }
    console.log("");
  }

  if (result.errors.length > 0) {
    console.log("✗ Failed checks:");
    for (const error of result.errors) {
      console.log(`  ${error}`);
    }
    console.log("");
  }

  if (result.compliant) {
    console.log(
      `✓ COMPLIANT (score ${(score * 100).toFixed(1)}% ≥ ${(minScore * 100).toFixed(0)}%)`,
    );
    return 0;
  }
  console.log(
    `✗ NON-COMPLIANT (score ${(score * 100).toFixed(1)}% < ${(minScore * 100).toFixed(0)}%)`,
  );
  return 1;
}

export function verifyProfileCommand(args: string[]): number {
  if (args.length < 1) {
    console.error(
      "Usage: compliance-verify-profile <profile-id> [--schema-version <ver>]",
    );
    console.error("");
    console.error("Available profiles:");
    console.error("  soc2-2024       SOC 2 Type II compliance (2024)");
    console.error("  iso27001-2022   ISO/IEC 27001:2022 compliance");
    console.error(
      "  eidas-controlled eIDAS controlled digital identity services",
    );
    return 1;
  }

  const profileId = args[0];

  // Parse --schema-version if present
  let schemaVersion = getLatestVersion();
  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--schema-version" && i + 1 < args.length) {
      schemaVersion = args[i + 1];
      break;
    }
  }

  // Load compliance profile
  const profile = loadProfile(profileId);
  if (!profile) {
    console.error(`Error: cannot load compliance profile "${profileId}"`);
    console.error(`Expected file: profiles/${profileId}.json`);
    return 1;
  }

  const result = checkProfileSchemaCompatibility(
    toCompatibilityProfileInput(profile),
    schemaVersion,
  );

  console.log(`Profile Compatibility Check: ${profileId}`);
  console.log(`  Profile version:   ${result.profile_version}`);
  console.log(`  AgentBOM schema:   v${result.agentbom_version}`);
  console.log(`  Compatible:        ${result.compatible ? "✓ yes" : "✗ no"}`);
  console.log("");

  if (result.breaking.length > 0) {
    console.log(`✗ Breaking issues (${result.breaking.length}):`);
    for (const issue of result.breaking) {
      console.log(`  [${issue.section}] ${issue.field}: ${issue.message}`);
    }
    console.log("");
  }

  if (result.gaps.length > 0) {
    console.log(`ℹ Coverage gaps (${result.gaps.length}):
  Schema sections not covered by any profile rule:`);
    for (const gap of result.gaps) {
      console.log(`  ${gap.path} — ${gap.description}`);
    }
    console.log("");
  }

  if (result.mapping_updates.length > 0) {
    const optional = result.mapping_updates.filter(
      (u) => u.type === "optional",
    );
    const breaking = result.mapping_updates.filter(
      (u) => u.type === "breaking",
    );
    if (breaking.length > 0) {
      console.log(`Breaking mapping updates (${breaking.length}):`);
      for (const update of breaking) {
        console.log(`  [${update.profile_section}] ${update.description}`);
        console.log(`    Action: ${update.action}`);
      }
      console.log("");
    }
    if (optional.length > 0) {
      console.log(`Optional mapping updates (${optional.length}):`);
      for (const update of optional) {
        console.log(`  [${update.profile_section}] ${update.description}`);
        console.log(`    Action: ${update.action}`);
      }
      console.log("");
    }
  }

  if (result.breaking.length === 0 && result.gaps.length === 0) {
    console.log(
      `✓ Profile is fully compatible with AgentBOM schema v${schemaVersion}`,
    );
  }

  return result.compatible ? 0 : 1;
}

export function upgradeProfileCommand(args: string[]): number {
  if (args.length < 1) {
    console.error(
      "Usage: compliance-upgrade-profile <profile-id> [--schema-version <ver>] [--dry-run]",
    );
    console.error("");
    console.error(
      "Automatically resolve breaking mapping changes in a compliance profile.",
    );
    console.error("");
    console.error("Options:");
    console.error(
      "  --schema-version <ver>  Target AgentBOM schema version (default: latest)",
    );
    console.error(
      "  --dry-run               Show what would change without modifying the profile",
    );
    console.error("");
    console.error("Available profiles:");
    console.error("  soc2-2024       SOC 2 Type II compliance (2024)");
    console.error("  iso27001-2022   ISO/IEC 27001:2022 compliance");
    console.error(
      "  eidas-controlled eIDAS controlled digital identity services",
    );
    return 1;
  }

  const profileId = args[0];

  let schemaVersion = getLatestVersion();
  let dryRun = false;
  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--schema-version" && i + 1 < args.length) {
      schemaVersion = args[i + 1];
      i++;
    } else if (args[i] === "--dry-run") {
      dryRun = true;
    }
  }

  const profile = loadProfile(profileId);
  if (!profile) {
    console.error(`Error: cannot load compliance profile "${profileId}"`);
    console.error(`Expected file: profiles/${profileId}.json`);
    return 1;
  }

  const result = upgradeProfileMappings(
    toCompatibilityProfileInput(profile),
    schemaVersion,
  );

  console.log(`Profile Upgrade: ${profileId}`);
  console.log(`  Profile version:   ${result.compatibility.profile_version}`);
  console.log(`  AgentBOM schema:   v${result.compatibility.agentbom_version}`);
  console.log("");

  if (
    !result.compatibility.compatible &&
    result.compatibility.breaking.length > 0
  ) {
    console.log(
      `Breaking issues detected (${result.compatibility.breaking.length}):`,
    );
    for (const issue of result.compatibility.breaking) {
      console.log(`  [${issue.section}] ${issue.field}: ${issue.message}`);
    }
    console.log("");
  }

  if (!result.changes_applied) {
    console.log("✓ No breaking changes — profile is already compatible.");
    if (result.compatibility.gaps.length > 0) {
      console.log(
        `ℹ ${result.compatibility.gaps.length} coverage gap(s) remain (optional updates).`,
      );
    }
    return 0;
  }

  console.log(`Auto-applied fixes (${result.applied_updates.length}):`);
  for (const update of result.applied_updates) {
    console.log(`  ✓ ${update}`);
  }
  console.log("");

  if (result.unresolved.length > 0) {
    console.log(
      `Unresolved issues (${result.unresolved.length}) — manual review needed:`,
    );
    for (const update of result.unresolved) {
      console.log(`  [${update.profile_section}] ${update.description}`);
      console.log(`    Action: ${update.action}`);
    }
    console.log("");
  }

  if (dryRun) {
    console.log("(dry-run — no output written)");
    return 0;
  }

  console.log(JSON.stringify(result.upgraded_profile, null, 2));
  return 0;
}
