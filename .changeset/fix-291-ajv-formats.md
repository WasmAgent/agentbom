---
"@wasmagent/agentbom-core": patch
---

fix: add ajv-formats dependency to suppress "unknown format uri ignored" warning (#291)

Registers ajv-formats with the AJV 2020 instance so that the `uri` format keyword
in the AgentBOM schema is enforced instead of being silently ignored.
Previously, AJV logged "unknown format \"uri\" ignored" twice per `validateAgentBOM()`
call, polluting startup logs in production.
