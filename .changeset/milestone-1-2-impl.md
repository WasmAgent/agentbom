---
"@wasmagent/agentbom-core": minor
"@wasmagent/agentbom-autogen": patch
---

feat: complete Milestone 1 & 2 — workflow_layer validation, compliance controls, ISO 27001 & EU AI Act tests

- validateAgentBOM: full workflow_layer (action_pathway) field validation with schema descriptor entries
- checkCompliance: adds ControlResult type for per-control pass/fail structured result
- compliance.test.ts: SOC2, ISO 27001, EU AI Act Annex IV end-to-end profile coverage
- agentbom-autogen: AutoGen 0.4+ adapter now maps workflows to workflow_layer
