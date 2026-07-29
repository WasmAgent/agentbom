---
"@wasmagent/agentbom-cli": minor
"@wasmagent/agentbom-core": patch
---

feat: migrate agentbom CLI from agent-trust-infra; add pipeline subpath export

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
