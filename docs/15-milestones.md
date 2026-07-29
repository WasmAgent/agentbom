## Milestone 1 — Core Validator & Schema Stability

- [ ] `bun test packages/agentbom-core` — AgentBOM v0.1 schema validation covers all required fields and rejects invalid documents
- [ ] `packages/agentbom-core/src/index.ts:validateAgentBOM` — add `action_pathway` field validation per schema v0.1.1
- [ ] `packages/agentbom-core/src/index.ts:checkCompliance` — compliance scoring returns structured result with per-control pass/fail
- [ ] Add test: `packages/agentbom-core/src/compliance.test.ts` covers SOC2, ISO27001, and EU AI Act Annex IV profiles end-to-end

## Milestone 2 — Framework Adapters

- [ ] `packages/agentbom-autogen/src/index.ts:generateAgentBOM` — adapter produces valid AgentBOM for AutoGen 0.4+ agent definitions
- [ ] `packages/agentbom-langchain/src/index.ts:generateAgentBOM` — adapter covers LangChain v0.2 AgentExecutor and LCEL chains
- [ ] `packages/agentbom-llamaindex/src/index.ts:generateAgentBOM` — adapter handles LlamaIndex QueryEngine and ReActAgent
- [ ] Add test: each adapter test file covers at least 5 real-world agent definition shapes

## Milestone 3 — CLI Tools (agentbom-cli)

- [ ] `packages/agentbom-cli/src/main.ts` — `agentbom validate <file>` exits 0 on valid, 1 on invalid with human-readable error
- [ ] `packages/agentbom-cli/src/compliance-check.ts` — `agentbom compliance-check --framework eu-ai-act <file>` produces scored report
- [ ] `packages/agentbom-cli/src/regulatory-report.ts` — `agentbom regulatory-report --framework ai-act <file>` generates Annex IV evidence report
- [ ] `packages/agentbom-cli/src/trust-publish.ts` — CAS registry publish/pull roundtrip test passes
- [ ] Add test: `packages/agentbom-cli/src/main.test.ts` covers all CLI commands end-to-end

## Milestone 4 — MCP Posture Integration

- [ ] `packages/agentbom-cli/src/trust-verify-chain.ts` — chain verification follows passport JWT → agentbom_ref → posture_ref at least 2 hops
- [ ] `packages/agentbom-cli/src/sigstore-verify.ts` — Sigstore bundle verification works in air-gapped mode (no network calls)
- [ ] `packages/agentbom-cli/src/trust-subscribe.ts` — drift subscription detects AgentBOM changes and emits DriftAlert events
- [ ] Add test: `packages/agentbom-cli/src/sigstore-verify.test.ts` covers FIPS mode and air-gapped mode paths

## Milestone 5 — Publication & Distribution

- [ ] `packages/agentbom-core/package.json` — all subpath exports declared (`./pipeline`, `./compliance`) and match dist output
- [ ] `packages/agentbom-cli/package.json` — `bin` field set so `npx @wasmagent/agentbom-cli validate` works after install
- [ ] `docs/` — API documentation for all public exports generated from JSDoc comments
- [ ] Add test: install `@wasmagent/agentbom-core` from npm in a clean project and run validateAgentBOM — no missing peer deps
