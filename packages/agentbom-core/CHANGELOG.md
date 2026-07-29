# @wasmagent/agentbom-core

## 0.2.0

### Minor Changes

- 4bd2adf: feat: migrate AgentBOM implementation from agent-trust-infra

  Migrates the full AgentBOM validator, compliance checker, version migrator,
  diff utilities, and framework adapters (AutoGen, LangChain, LlamaIndex) from
  WasmAgent/agent-trust-infra into this dedicated repository.

  Schema loading uses @wasmagent/protocol as the canonical SSOT.
