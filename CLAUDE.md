# agentbom — CLAUDE.md

## What this repo is (and is not)

**Is:** A library monorepo providing the AgentBOM reference implementation.
Ships a pure-function core (`@wasmagent/agentbom-core`) and thin framework adapters
(LangChain, LlamaIndex, AutoGen) that wrap it.

**Is NOT — do not implement these here:**
- A CLI tool (CLI lives in `agent-trust-infra` during transition; long-term it gets a dedicated tool repo)
- A runtime agent framework, MCP firewall, or AEP emitter (`wasmagent-js` territory)
- A schema definition layer — all schemas come from `@wasmagent/protocol`
- A compliance-report generator or audit dashboard (`open-agent-audit` territory)

---

## Repository Boundaries

### This repo owns
- `@wasmagent/agentbom-core` — validator, compliance checker, BOM diff, drift alert, migration, pipeline
- `@wasmagent/agentbom-langchain` — LangChain adapter (depends on core + LangChain peer dep)
- `@wasmagent/agentbom-llamaindex` — LlamaIndex adapter (depends on core + LlamaIndex peer dep)
- `@wasmagent/agentbom-autogen` — AutoGen adapter (depends on core + AutoGen peer dep)

### Other repositories own — do not duplicate here

| Capability | Owner |
|---|---|
| AgentBOM **schema** JSON (canonical SSOT) | `wasmagent-protocol` (`@wasmagent/protocol`) |
| AgentBOM + MCP Posture **specifications** | `agent-trust-infra` |
| CLI (`agentbom validate`, `agentbom inspect`) | `agent-trust-infra` (`cli/`) — transitional |
| Compliance report generation, audit dashboard | `open-agent-audit` |
| AEP emitter, MCP firewall, runtime protection | `wasmagent-js` |

### Allowed cross-repo patterns
- **Always** consume schema via `getSchema("agentbom")` from `@wasmagent/protocol`. Never inline or copy schema JSON.
- Adapters may only depend on `agentbom-core` plus their framework peer dep — no direct `@wasmagent/protocol` import in adapters.
- If the schema needs to change, open the change against `wasmagent-protocol`, then bump the protocol dep here.

---

## Package Structure

```
packages/
  agentbom-core/        @wasmagent/agentbom-core      — validator, compliance, diff, drift, pipeline
  agentbom-langchain/   @wasmagent/agentbom-langchain  — LangChain adapter
  agentbom-llamaindex/  @wasmagent/agentbom-llamaindex — LlamaIndex adapter
  agentbom-autogen/     @wasmagent/agentbom-autogen    — AutoGen adapter
```

---

## DO list

- **Library-first:** every export must be importable without side effects (no `console.log`, no `process.exit`, no file I/O at import time)
- **Pure functions in core:** `validateAgentBOM`, `checkCompliance`, `diffAgentBOM`, `inspectAgentBOM`, and `buildDriftAlert` must remain pure — no fs access, no network calls, no global state mutation
- **Schema from protocol only:** `getSchema("agentbom")` is the one and only way to load the schema in `agentbom-core`
- **Adapter isolation:** each adapter package depends only on `agentbom-core` + its own framework peer dep; adapters call core functions, they do not re-implement logic
- **Test coverage:** all changes to `agentbom-core` must include tests covering the affected path (validator, compliance, diff, migration, pipeline)
- **Changesets for public API changes:** run `bun changeset` and commit the changeset file with any PR that changes exported types or function signatures
- **Keep `compliance.ts` interface stable:** `checkCompliance(doc, profile)` returns `ComplianceResult` — do not add I/O parameters

## NO-DO list

- **No CLI command handlers here** — argument parsing, `process.exit`, stderr output belong in the CLI package in `agent-trust-infra`
- **No file I/O in library code** — `pipeline.ts` uses `node:fs` internally (that is its job); all other core exports must not touch the filesystem
- **No schema duplication** — never define an AgentBOM schema in this repo; always import from `@wasmagent/protocol`
- **No framework-specific code in `agentbom-core`** — LangChain / LlamaIndex / AutoGen types belong in their respective adapter packages
- **No breaking `compliance.ts` interface** — `checkCompliance` is a pure function; adding `console.log`, `fs` access, or network calls is a violation
- **No `process.exit` in library code** — callers decide how to handle errors
- **No duplicate adapters** — if a new framework integration is needed, add a new `agentbom-<framework>` package; do not add it to `agentbom-core`

---

## Build & Verify

```bash
bun install
bun run typecheck    # tsc --noEmit across all packages
bun run build        # compile to dist/
bun test             # run all package tests
bun run lint         # biome check packages/
bun run lint:fix     # biome check --write packages/
```

All four checks must pass before committing. CI runs the same sequence.

**Test commands per package:**
```bash
bun test packages/agentbom-core/src/
bun test packages/agentbom-langchain/src/
bun test packages/agentbom-llamaindex/src/
bun test packages/agentbom-autogen/src/
```

---

## Changeset Workflow

This repo uses [Changesets](https://github.com/changesets/changesets) for versioning.

```bash
bun changeset          # describe what changed and which package (major/minor/patch)
bun changeset version  # bump versions (CI does this on release)
bun changeset publish  # publish to npm (CI only)
```

- `patch` — bug fix, no API change
- `minor` — new export, backward-compatible change
- `major` — only for breaking changes that require callers to update their code; confirm with repo owner before bumping major

---

## Strategic context

This repo was split out from `agent-trust-infra` to give the AgentBOM library a clean,
framework-neutral home. The `agent-trust-infra` CLI still wraps these packages during the
transition period. Schema authority stays in `wasmagent-protocol`.
