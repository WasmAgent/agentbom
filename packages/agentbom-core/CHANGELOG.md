# @wasmagent/agentbom-core

## 0.4.0

### Minor Changes

- acab71f: feat: complete Milestone 1 & 2 — workflow_layer validation, compliance controls, ISO 27001 & EU AI Act tests

  - validateAgentBOM: full workflow_layer (action_pathway) field validation with schema descriptor entries
  - checkCompliance: adds ControlResult type for per-control pass/fail structured result
  - compliance.test.ts: SOC2, ISO 27001, EU AI Act Annex IV end-to-end profile coverage
  - agentbom-autogen: AutoGen 0.4+ adapter now maps workflows to workflow_layer

## 0.3.4

### Patch Changes

- 006daaf: fix: add ajv-formats dependency to suppress "unknown format uri ignored" warning (#291)

  Registers ajv-formats with the AJV 2020 instance so that the `uri` format keyword
  in the AgentBOM schema is enforced instead of being silently ignored.
  Previously, AJV logged "unknown format \"uri\" ignored" twice per `validateAgentBOM()`
  call, polluting startup logs in production.

## 0.3.3

### Patch Changes

- 36f70f2: feat: migrate agentbom CLI from agent-trust-infra; add pipeline subpath export

  **@wasmagent/agentbom-cli** (new package):
  Full developer CLI for AgentBOM workflows:

  - BOM generation, validation, inspection, and diff
  - MCP Posture validation, inspection, and diff
  - Trust chain end-to-end demo (`chain` command)
  - Compliance checking against SOC2, ISO27001, eIDAS, and EU AI Act Annex IV profiles
  - Regulatory reporting (`report --framework soc2|iso27001|ai-act`)
  - Trust chain verification and drift monitoring
  - Sigstore bundle verification
  - HTML fleet dashboard export
  - Marketplace trust package export
  - Multi-agent team composition validation
  - AgentBOM migration across schema versions

  Includes compliance profile data:

  - `profiles/soc2-2024.json`
  - `profiles/iso27001-2022.json`
  - `profiles/eidas-controlled.json`
  - `profiles/eu-ai-act-annex-iv.json` (new in Milestone 5)

  **@wasmagent/agentbom-core** (patch):

  - Add `./pipeline` subpath export so CLI can import `PipelineConfig` and `runPipeline` directly

## 0.3.2

### Patch Changes

- 8cd15a5: chore: fix release workflow npm authentication

## 0.3.1

### Patch Changes

- a067bb7: chore: retrigger npm publish with updated token

## 0.3.0

### Minor Changes

- b8d3aa8: feat: initial npm publication of @wasmagent/agentbom packages

  Publishes AgentBOM validator, compliance checker, version migrator,
  diff utilities, and framework adapters migrated from agent-trust-infra.

## 0.2.0

### Minor Changes

- 4bd2adf: feat: migrate AgentBOM implementation from agent-trust-infra

  Migrates the full AgentBOM validator, compliance checker, version migrator,
  diff utilities, and framework adapters (AutoGen, LangChain, LlamaIndex) from
  WasmAgent/agent-trust-infra into this dedicated repository.

  Schema loading uses @wasmagent/protocol as the canonical SSOT.
