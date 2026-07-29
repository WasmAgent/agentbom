# @wasmagent/agentbom-core

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
