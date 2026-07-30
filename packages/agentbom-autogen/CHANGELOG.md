# @wasmagent/agentbom-autogen

## 0.3.5

### Patch Changes

- acab71f: feat: complete Milestone 1 & 2 — workflow_layer validation, compliance controls, ISO 27001 & EU AI Act tests

  - validateAgentBOM: full workflow_layer (action_pathway) field validation with schema descriptor entries
  - checkCompliance: adds ControlResult type for per-control pass/fail structured result
  - compliance.test.ts: SOC2, ISO 27001, EU AI Act Annex IV end-to-end profile coverage
  - agentbom-autogen: AutoGen 0.4+ adapter now maps workflows to workflow_layer

- Updated dependencies [acab71f]
  - @wasmagent/agentbom-core@0.4.0

## 0.3.4

### Patch Changes

- Updated dependencies [006daaf]
  - @wasmagent/agentbom-core@0.3.4

## 0.3.3

### Patch Changes

- Updated dependencies [36f70f2]
  - @wasmagent/agentbom-core@0.3.3

## 0.3.2

### Patch Changes

- Updated dependencies [8cd15a5]
  - @wasmagent/agentbom-core@0.3.2

## 0.3.1

### Patch Changes

- Updated dependencies [a067bb7]
  - @wasmagent/agentbom-core@0.3.1

## 0.3.0

### Minor Changes

- b8d3aa8: feat: initial npm publication of @wasmagent/agentbom packages

  Publishes AgentBOM validator, compliance checker, version migrator,
  diff utilities, and framework adapters migrated from agent-trust-infra.

### Patch Changes

- Updated dependencies [b8d3aa8]
  - @wasmagent/agentbom-core@0.3.0

## 0.2.0

### Minor Changes

- 4bd2adf: feat: migrate AgentBOM implementation from agent-trust-infra

  Migrates the full AgentBOM validator, compliance checker, version migrator,
  diff utilities, and framework adapters (AutoGen, LangChain, LlamaIndex) from
  WasmAgent/agent-trust-infra into this dedicated repository.

  Schema loading uses @wasmagent/protocol as the canonical SSOT.

### Patch Changes

- Updated dependencies [4bd2adf]
  - @wasmagent/agentbom-core@0.2.0
