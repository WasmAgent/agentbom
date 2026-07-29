import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { reportCommand } from './regulatory-report.js';

let tmpDir: string;

beforeEach(() => {
  tmpDir = join(
    tmpdir(),
    `regulatory-report-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(tmpDir, { recursive: true });
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function writeTmpFile(name: string, content: string): string {
  const p = join(tmpDir, name);
  writeFileSync(p, content, 'utf-8');
  return p;
}

/** Minimal valid AgentBOM that passes schema validation */
const MINIMAL_BOM = {
  agentbom_version: '0.1',
  identity: {
    agent_id: 'agent-report-001',
    agent_name: 'Report Test Agent',
    deployment_context: 'production',
    generated_at: '2026-06-28T00:00:00Z',
  },
  attestation: { generator: 'test' },
};

/** Full AgentBOM with all sections populated */
const FULL_BOM = {
  agentbom_version: '0.1',
  identity: {
    agent_id: 'agent-full-001',
    agent_name: 'Full Report Agent',
    agent_version: '1.2.3',
    deployment_context: 'production',
    generated_at: '2026-07-01T00:00:00Z',
  },
  tool_layer: [
    {
      tool_id: 'fs-read',
      tool_name: 'read_file',
      source: 'builtin',
      permissions: ['fs:read'],
    },
    {
      tool_id: 'fs-write',
      tool_name: 'write_file',
      source: 'builtin',
      permissions: ['fs:write'],
    },
  ],
  risk_layer: [
    {
      risk_id: 'risk-001',
      severity: 'medium',
      category: 'data_access',
      description: 'file system write access',
      status: 'mitigated',
    },
  ],
  audit_log: [
    {
      timestamp: '2026-07-01T10:00:00Z',
      event_type: 'tool_invocation',
      actor: 'user',
      resource: 'read_file',
      outcome: 'success',
    },
    {
      timestamp: '2026-07-01T10:01:00Z',
      event_type: 'policy_check',
      actor: 'system',
      outcome: 'failure',
    },
  ],
  evidence_layer: {
    aep_references: ['aep://ref/001'],
    evidence_hashes: [{ type: 'sha256', hash: 'abc123', timestamp: '2026-07-01T00:00:00Z' }],
  },
  attestation: {
    generator: 'trust-cli',
    signature: 'test-sig-001',
    timestamp: '2026-07-01T00:00:00Z',
  },
};

describe('reportCommand', () => {
  describe('argument parsing', () => {
    it('returns 0 with help when --help flag is passed', () => {
      const spy = spyOn(console, 'log');
      expect(reportCommand(['--help'])).toBe(0);
      expect(spy).toHaveBeenCalled();
      const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(output).toContain('Usage: agent-trust report');
      expect(output).toContain('soc2');
      expect(output).toContain('iso27001');
      expect(output).toContain('ai-act');
    });

    it('returns 0 with help when -h flag is passed', () => {
      const spy = spyOn(console, 'log');
      expect(reportCommand(['-h'])).toBe(0);
      expect(spy).toHaveBeenCalled();
    });

    it('returns 1 when no arguments provided', () => {
      expect(reportCommand([])).toBe(1);
    });

    it('returns 1 when bom path missing', () => {
      expect(reportCommand(['--framework', 'soc2'])).toBe(1);
    });

    it('returns 1 when --framework missing', () => {
      const path = writeTmpFile('bom.json', JSON.stringify(MINIMAL_BOM));
      expect(reportCommand([path])).toBe(1);
    });

    it('returns 1 for unsupported framework', () => {
      const path = writeTmpFile('bom.json', JSON.stringify(MINIMAL_BOM));
      expect(reportCommand([path, '--framework', 'gdpr'])).toBe(1);
    });

    it('returns 1 for invalid --format', () => {
      const path = writeTmpFile('bom.json', JSON.stringify(MINIMAL_BOM));
      expect(reportCommand([path, '--framework', 'soc2', '--format', 'pdf'])).toBe(1);
    });

    it('returns 1 for invalid --evidence-level', () => {
      const path = writeTmpFile('bom.json', JSON.stringify(MINIMAL_BOM));
      expect(reportCommand([path, '--framework', 'soc2', '--evidence-level', 'verbose'])).toBe(1);
    });

    it('returns 1 for non-existent file', () => {
      expect(reportCommand(['/nonexistent/bom.json', '--framework', 'soc2'])).toBe(1);
    });

    it('returns 1 for invalid JSON', () => {
      const path = writeTmpFile('bad.json', '{ not valid json');
      expect(reportCommand([path, '--framework', 'soc2'])).toBe(1);
    });
  });

  describe('SOC2 framework', () => {
    it('generates text report with SOC 2 control objectives', () => {
      const path = writeTmpFile('soc2-bom.json', JSON.stringify(FULL_BOM));
      const spy = spyOn(console, 'log');

      expect(reportCommand([path, '--framework', 'soc2'])).toBe(0);

      const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(output).toContain('REGULATORY COMPLIANCE REPORT');
      expect(output).toContain('SOC 2');
      expect(output).toContain('EXECUTIVE SUMMARY');
      expect(output).toContain('CONTROL OBJECTIVES');
      expect(output).toContain('SOC2.CC6.1');
      expect(output).toContain('SOC2.CC6.2');
      expect(output).toContain('SOC2.CC6.3');
      expect(output).toContain('SOC2.CC7.1');
      expect(output).toContain('SOC2.CC7.2');
      expect(output).toContain('SOC2.CC8.1');
      expect(output).toContain('SOC2.A1.2');
      expect(output).toContain('Full Report Agent');
    });

    it('generates JSON report with structured data', () => {
      const path = writeTmpFile('soc2-json.json', JSON.stringify(FULL_BOM));
      const spy = spyOn(console, 'log');

      expect(reportCommand([path, '--framework', 'soc2', '--format', 'json'])).toBe(0);

      // Find the JSON output call (last console.log call with a JSON object string)
      const jsonCalls = spy.mock.calls.map((c) => c.join(' ')).filter((c) => c.startsWith('{'));
      expect(jsonCalls.length).toBeGreaterThan(0);
      const report = JSON.parse(jsonCalls[jsonCalls.length - 1]);
      expect(report.report_metadata.framework).toContain('SOC 2');
      expect(report.executive_summary.controls_assessed).toBeGreaterThan(0);
      expect(report.executive_summary.controls_satisfied).toBeGreaterThan(0);
      expect(report.control_objectives.length).toBeGreaterThan(0);
      expect(report.control_objectives[0]).toHaveProperty('id');
      expect(report.control_objectives[0]).toHaveProperty('title');
      expect(report.control_objectives[0]).toHaveProperty('status');
      expect(report.control_objectives[0]).toHaveProperty('evidence');
      expect(report.control_objectives[0]).toHaveProperty('findings');
    });

    it('includes period in report metadata', () => {
      const path = writeTmpFile('soc2-period.json', JSON.stringify(FULL_BOM));
      const spy = spyOn(console, 'log');

      reportCommand([path, '--framework', 'soc2', '--period', 'Q1-2026', '--format', 'json']);

      const jsonCalls = spy.mock.calls.map((c) => c.join(' ')).filter((c) => c.startsWith('{'));
      const report = JSON.parse(jsonCalls[jsonCalls.length - 1]);
      expect(report.report_metadata.period).toBe('Q1-2026');
    });

    it('detailed evidence level includes more evidence citations', () => {
      const path = writeTmpFile('soc2-detailed.json', JSON.stringify(FULL_BOM));
      const logSpy = spyOn(console, 'log');

      reportCommand([path, '--framework', 'soc2', '--format', 'json']);
      // Find the last call that starts with '{' (JSON output)
      const summaryCalls = logSpy.mock.calls
        .map((c) => c.join(' '))
        .filter((c) => c.startsWith('{'));
      const summaryReport = JSON.parse(summaryCalls[summaryCalls.length - 1]);

      logSpy.mockClear();
      reportCommand([
        path,
        '--framework',
        'soc2',
        '--evidence-level',
        'detailed',
        '--format',
        'json',
      ]);
      const detailedCalls = logSpy.mock.calls
        .map((c) => c.join(' '))
        .filter((c) => c.startsWith('{'));
      const detailedReport = JSON.parse(detailedCalls[detailedCalls.length - 1]);

      // Detailed should have at least as many evidence citations as summary
      expect(detailedReport.executive_summary.evidence_citations).toBeGreaterThanOrEqual(
        summaryReport.executive_summary.evidence_citations,
      );
    });
  });

  describe('ISO 27001 framework', () => {
    it('generates report with ISO 27001 control objectives', () => {
      const path = writeTmpFile('iso-bom.json', JSON.stringify(FULL_BOM));
      const spy = spyOn(console, 'log');

      expect(reportCommand([path, '--framework', 'iso27001'])).toBe(0);

      const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(output).toContain('ISO');
      expect(output).toContain('ISO27001.A.5.15');
      expect(output).toContain('ISO27001.A.5.16');
      expect(output).toContain('ISO27001.A.8.9');
      expect(output).toContain('ISO27001.A.6.1');
    });
  });

  describe('EU AI Act framework', () => {
    it('generates report with AI Act control objectives using inline profile', () => {
      const path = writeTmpFile('aiact-bom.json', JSON.stringify(FULL_BOM));
      const spy = spyOn(console, 'log');

      expect(reportCommand([path, '--framework', 'ai-act'])).toBe(0);

      const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(output).toContain('AI Act');
      expect(output).toContain('AI-ACT.ANNEX-IV.1');
      expect(output).toContain('AI-ACT.ANNEX-IV.2');
      expect(output).toContain('AI-ACT.ANNEX-IV.3');
      expect(output).toContain('AI-ACT.ANNEX-IV.4');
      expect(output).toContain('AI-ACT.ANNEX-IV.5');
      expect(output).toContain('AI-ACT.ANNEX-IV.6');
    });

    it('AI Act JSON report has correct structure', () => {
      const path = writeTmpFile('aiact-json.json', JSON.stringify(FULL_BOM));
      const spy = spyOn(console, 'log');

      reportCommand([path, '--framework', 'ai-act', '--format', 'json']);

      const jsonCalls = spy.mock.calls.map((c) => c.join(' ')).filter((c) => c.startsWith('{'));
      const report = JSON.parse(jsonCalls[jsonCalls.length - 1]);
      expect(report.report_metadata.framework).toContain('AI Act');
      expect(report.control_objectives.length).toBe(6);
    });
  });

  describe('compliance status determination', () => {
    it('returns 0 for fully compliant BOM', () => {
      const path = writeTmpFile('compliant.json', JSON.stringify(FULL_BOM));
      expect(reportCommand([path, '--framework', 'soc2'])).toBe(0);
    });

    it('returns 1 for BOM with missing identity (non-compliant)', () => {
      // Schema-valid BOM but without meaningful identity for SOC2 controls
      const bom = {
        agentbom_version: '0.1',
        identity: {
          agent_id: 'minimal-agent',
          deployment_context: 'development',
          generated_at: '2026-07-01T00:00:00Z',
        },
        attestation: { generator: 'test' },
      };
      const path = writeTmpFile('no-identity.json', JSON.stringify(bom));
      // development context not in SOC2 allowed contexts [staging, production]
      expect(reportCommand([path, '--framework', 'soc2'])).toBe(1);
    });

    it('returns 1 for BOM with missing attestation when required', () => {
      const bom = {
        ...MINIMAL_BOM,
        attestation: { generator: 'test' },
      };
      const path = writeTmpFile('no-attestation.json', JSON.stringify(bom));
      // SOC2 profile requires attestation signature — MINIMAL_BOM has no signature
      const result = reportCommand([path, '--framework', 'soc2']);
      expect(result).toBe(1);
    });
  });

  describe('edge cases', () => {
    it('handles BOM with empty tool_layer', () => {
      const bom = {
        ...FULL_BOM,
        tool_layer: [],
      };
      const path = writeTmpFile('empty-tools.json', JSON.stringify(bom));
      const spy = spyOn(console, 'log');

      const result = reportCommand([path, '--framework', 'soc2']);
      // Should still produce a report (not crash)
      expect(result).toBeGreaterThanOrEqual(0);

      const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(output).toContain('REGULATORY COMPLIANCE REPORT');
    });

    it('handles BOM with empty risk_layer', () => {
      const bom = {
        ...FULL_BOM,
        risk_layer: [],
      };
      const path = writeTmpFile('empty-risks.json', JSON.stringify(bom));
      const spy = spyOn(console, 'log');

      const result = reportCommand([path, '--framework', 'soc2']);
      expect(result).toBeGreaterThanOrEqual(0);

      const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(output).toContain('REGULATORY COMPLIANCE REPORT');
    });

    it('handles BOM with no audit_log', () => {
      const bom = {
        ...FULL_BOM,
        audit_log: undefined,
      };
      const path = writeTmpFile('no-audit.json', JSON.stringify(bom));
      const spy = spyOn(console, 'log');

      const result = reportCommand([path, '--framework', 'soc2']);
      // Missing audit log should affect incident response controls
      expect(result).toBeGreaterThanOrEqual(0);

      const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(output).toContain('REGULATORY COMPLIANCE REPORT');
    });
  });
});
