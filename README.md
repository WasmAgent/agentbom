# agentbom

AgentBOM is an open specification and library for describing AI agent inventories: the tools
an agent uses, its permission scopes, model dependencies, compliance posture, and capability
assertions — all in a single, verifiable document. This repository provides the reference
implementation: a pure-function core library and thin framework adapters.

## Install

```bash
npm install @wasmagent/agentbom-core
```

## Usage

### Validate an AgentBOM document

```typescript
import { validateAgentBOM } from "@wasmagent/agentbom-core";

const result = validateAgentBOM(doc);
if (!result.valid) {
  for (const err of result.errors) {
    console.error(err); // "identity.agent_id: must be string"
  }
}
```

### Run a compliance check

```typescript
import { checkCompliance } from "@wasmagent/agentbom-core";

const result = checkCompliance(doc, {
  require_signed: true,
  max_tool_count: 20,
  disallowed_scopes: ["filesystem:write"],
});

console.log(result.score);   // 0–1 weighted score
console.log(result.passed);  // true / false
for (const finding of result.findings) {
  console.log(finding.rule, finding.severity, finding.message);
}
```

### Diff two versions and detect drift

```typescript
import { diffAgentBOM, buildDriftAlert, formatDriftAlert } from "@wasmagent/agentbom-core";

const diff = diffAgentBOM(baseline, current);
const alert = buildDriftAlert("my-agent", diff, baselineTs, currentTs);
console.log(formatDriftAlert(alert));
```

## Packages

| Package | npm name | Description |
|---------|----------|-------------|
| `agentbom-core` | `@wasmagent/agentbom-core` | Validator, compliance checker, BOM diff, drift alert, pipeline |
| `agentbom-langchain` | `@wasmagent/agentbom-langchain` | LangChain adapter |
| `agentbom-llamaindex` | `@wasmagent/agentbom-llamaindex` | LlamaIndex adapter |
| `agentbom-autogen` | `@wasmagent/agentbom-autogen` | AutoGen adapter |

## Related repositories

| Repository | Role |
|------------|------|
| [`wasmagent-protocol`](https://github.com/WasmAgent/wasmagent-protocol) | Canonical AgentBOM JSON schema (SSOT) |
| [`agent-trust-infra`](https://github.com/WasmAgent/agent-trust-infra) | AgentBOM + MCP Posture specifications and CLI (`agentbom validate`) |
| [`open-agent-audit`](https://github.com/WasmAgent/open-agent-audit) | Compliance report generation and audit dashboard |

The schema that drives all validation in `agentbom-core` is defined in `wasmagent-protocol`
and imported via `@wasmagent/protocol`. Never copy or redefine it here.

The CLI (`agentbom validate`, `agentbom inspect`) is in `agent-trust-infra` for the transition
period; it wraps the packages in this repo.

---

*Migrated from [WasmAgent/agent-trust-infra](https://github.com/WasmAgent/agent-trust-infra) — the library packages have a new home here while the specifications and CLI remain in that repo during the transition.*
