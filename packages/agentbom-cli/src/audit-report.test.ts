import { describe, expect, it } from 'bun:test';
import { generateAuditReport, generateMultiAgentAuditReport } from './audit-report.js';

// --- Minimal valid AgentBOM fixture ---

const baseBOM = {
  agentbom_version: '0.1',
  identity: {
    agent_id: 'agent-001',
    agent_name: 'Agent Alpha',
    generated_at: '2026-01-15T10:00:00Z',
  },
};

const baseBOMv2 = {
  agentbom_version: '0.1',
  identity: {
    agent_id: 'agent-002',
    agent_name: 'Agent Beta',
    generated_at: '2026-01-15T10:05:00Z',
  },
};

describe('generateAuditReport', () => {
  it('returns a report header for a minimal BOM', () => {
    const report = generateAuditReport(baseBOM as never);
    expect(report).toContain('AGENT TRUST AUDIT REPORT');
    expect(report).toContain('Agent Alpha');
    expect(report).toContain('agent-001');
  });

  it('includes audit summary statistics', () => {
    const bom = {
      ...baseBOM,
      audit_log: [
        {
          timestamp: '2026-01-15T10:00:00Z',
          event_type: 'tool_call',
          actor: 'agent-001',
          outcome: 'success' as const,
        },
        {
          timestamp: '2026-01-15T10:01:00Z',
          event_type: 'tool_call',
          actor: 'agent-001',
          outcome: 'failure' as const,
        },
      ],
    };
    const report = generateAuditReport(bom as never);
    expect(report).toContain('Total Audit Events:       2');
    expect(report).toContain('Successful Events:        1');
    expect(report).toContain('Failed Events:            1');
  });

  it('includes risk summary by severity', () => {
    const bom = {
      ...baseBOM,
      risk_layer: [
        { risk_id: 'r1', severity: 'high', category: 'perm', description: 'test', status: 'open' },
        {
          risk_id: 'r2',
          severity: 'critical',
          category: 'perm',
          description: 'test',
          status: 'open',
        },
        {
          risk_id: 'r3',
          severity: 'low',
          category: 'info',
          description: 'test',
          status: 'mitigated',
        },
      ],
    };
    const report = generateAuditReport(bom as never);
    expect(report).toContain('Critical: 1');
    expect(report).toContain('High:     1');
    expect(report).toContain('Low:      1');
    expect(report).toContain('Open Risk Findings:       2');
  });

  it('includes evidence citations', () => {
    const bom = {
      ...baseBOM,
      evidence_layer: {
        aep_references: ['aep://event/123'],
        evidence_hashes: [{ type: 'sha256', hash: 'abc123', timestamp: '2026-01-15T10:00:00Z' }],
      },
    };
    const report = generateAuditReport(bom as never);
    expect(report).toContain('EVIDENCE CITATIONS');
    expect(report).toContain('aep://event/123');
    expect(report).toContain('sha256: abc123');
  });

  it('shows no audit trail when empty', () => {
    const report = generateAuditReport(baseBOM as never);
    expect(report).toContain('No audit log entries found.');
  });
});

describe('generateMultiAgentAuditReport', () => {
  it('returns multi-agent header with agent count', () => {
    const report = generateMultiAgentAuditReport([baseBOM as never, baseBOMv2 as never]);
    expect(report).toContain('MULTI-AGENT TRUST AUDIT REPORT');
    expect(report).toContain('Agents in Scope:  2');
  });

  it('includes agent roster with peer counts', () => {
    const bom1 = {
      ...baseBOM,
      agent_collaboration: {
        peer_agents: [{ agent_id: 'agent-002', role: 'delegate' }],
        shared_resources: [
          { resource_id: 'db-1', resource_type: 'datastore', access_pattern: 'read_write' },
        ],
      },
    };
    const report = generateMultiAgentAuditReport([bom1 as never, baseBOMv2 as never]);
    expect(report).toContain('Agent Alpha');
    expect(report).toContain('Agent Beta');
    expect(report).toContain('AGENT ROSTER');
    expect(report).toContain('Peers: 1');
    expect(report).toContain('Shared Resources: 1');
  });

  it('includes collaboration topology summary', () => {
    const bom1 = {
      ...baseBOM,
      agent_collaboration: {
        peer_agents: [
          { agent_id: 'agent-002', role: 'delegate' },
          { agent_id: 'agent-003', role: 'peer' },
        ],
        delegation_boundaries: [
          {
            boundary_id: 'bnd-1',
            direction: 'outbound',
            constraint_type: 'tool_delegation',
            target_agents: ['agent-002'],
            max_delegation_depth: 2,
          },
        ],
        shared_resources: [
          {
            resource_id: 'db-1',
            resource_type: 'datastore',
            access_pattern: 'read_write',
            accessing_agents: ['agent-001', 'agent-002'],
          },
        ],
      },
    };
    const report = generateMultiAgentAuditReport([bom1 as never, baseBOMv2 as never]);
    expect(report).toContain('COLLABORATION TOPOLOGY');
    expect(report).toContain('Unique Peer Agents:       2');
    expect(report).toContain('Shared Resources:         1');
    expect(report).toContain('Delegation Boundaries:    1');
    expect(report).toContain('bnd-1');
    expect(report).toContain('outbound');
    expect(report).toContain('tool_delegation');
    expect(report).toContain('Max delegation depth: 2');
    expect(report).toContain('db-1');
    expect(report).toContain('datastore');
  });

  it('reconstructs causal chains from delegation events', () => {
    const bom1 = {
      ...baseBOM,
      audit_log: [
        {
          timestamp: '2026-01-15T10:00:00Z',
          event_type: 'delegation',
          actor: 'agent-001',
          outcome: 'success',
          details: { delegated_to: 'agent-002' },
        },
      ],
      agent_collaboration: {
        peer_agents: [{ agent_id: 'agent-002', role: 'delegate' }],
      },
    };
    const bom2 = {
      ...baseBOMv2,
      audit_log: [
        {
          timestamp: '2026-01-15T10:00:05Z',
          event_type: 'tool_call',
          actor: 'agent-002',
          resource: 'tool-search',
          outcome: 'success',
        },
      ],
    };
    const report = generateMultiAgentAuditReport([bom1 as never, bom2 as never]);
    expect(report).toContain('CAUSAL CHAIN ANALYSIS');
    expect(report).toContain('Reconstructed Causal Chains: 1');
    expect(report).toContain('chain-1');
    expect(report).toContain('Agent Alpha');
    expect(report).toContain('Agent Beta');
  });

  it('detects causal links via shared resource access', () => {
    const bom1 = {
      ...baseBOM,
      audit_log: [
        {
          timestamp: '2026-01-15T10:00:00Z',
          event_type: 'data_read',
          actor: 'agent-001',
          resource: 'shared-db',
          outcome: 'success',
        },
      ],
      agent_collaboration: {
        shared_resources: [
          { resource_id: 'shared-db', resource_type: 'datastore', access_pattern: 'read_write' },
        ],
      },
    };
    const bom2 = {
      ...baseBOMv2,
      audit_log: [
        {
          timestamp: '2026-01-15T10:00:03Z',
          event_type: 'data_write',
          actor: 'agent-002',
          resource: 'shared-db',
          outcome: 'success',
        },
      ],
    };
    const report = generateMultiAgentAuditReport([bom1 as never, bom2 as never]);
    expect(report).toContain('CAUSAL CHAIN ANALYSIS');
    expect(report).toContain('Reconstructed Causal Chains: 1');
  });

  it('detects causal links via actor matching previous agent', () => {
    const bom1 = {
      ...baseBOM,
      audit_log: [
        {
          timestamp: '2026-01-15T10:00:00Z',
          event_type: 'delegation',
          actor: 'agent-001',
          outcome: 'success',
        },
      ],
      agent_collaboration: {
        peer_agents: [{ agent_id: 'agent-002', role: 'delegate' }],
      },
    };
    const bom2 = {
      ...baseBOMv2,
      audit_log: [
        {
          timestamp: '2026-01-15T10:00:02Z',
          event_type: 'tool_call',
          actor: 'agent-001',
          resource: 'tool-calc',
          outcome: 'success',
        },
      ],
    };
    const report = generateMultiAgentAuditReport([bom1 as never, bom2 as never]);
    expect(report).toContain('Reconstructed Causal Chains: 1');
  });

  it('shows no causal chains when agents are independent', () => {
    const bom1 = {
      ...baseBOM,
      audit_log: [
        {
          timestamp: '2026-01-15T10:00:00Z',
          event_type: 'tool_call',
          actor: 'agent-001',
          outcome: 'success',
        },
      ],
    };
    const bom2 = {
      ...baseBOMv2,
      audit_log: [
        {
          timestamp: '2026-01-15T11:00:00Z',
          event_type: 'tool_call',
          actor: 'agent-002',
          outcome: 'success',
        },
      ],
    };
    const report = generateMultiAgentAuditReport([bom1 as never, bom2 as never]);
    expect(report).toContain('No cross-agent causal chains detected.');
  });

  it('combines audit statistics across agents', () => {
    const bom1 = {
      ...baseBOM,
      audit_log: [
        {
          timestamp: '2026-01-15T10:00:00Z',
          event_type: 'tool_call',
          actor: 'agent-001',
          outcome: 'success' as const,
        },
        {
          timestamp: '2026-01-15T10:01:00Z',
          event_type: 'tool_call',
          actor: 'agent-001',
          outcome: 'failure' as const,
        },
      ],
      risk_layer: [
        { risk_id: 'r1', severity: 'high', category: 'perm', description: 'test', status: 'open' },
      ],
    };
    const bom2 = {
      ...baseBOMv2,
      audit_log: [
        {
          timestamp: '2026-01-15T10:05:00Z',
          event_type: 'data_access',
          actor: 'agent-002',
          outcome: 'success' as const,
        },
      ],
      risk_layer: [
        {
          risk_id: 'r2',
          severity: 'critical',
          category: 'data',
          description: 'test',
          status: 'open',
        },
      ],
    };
    const report = generateMultiAgentAuditReport([bom1 as never, bom2 as never]);
    expect(report).toContain('COMBINED AUDIT SUMMARY');
    expect(report).toContain('Total Audit Events:       3');
    expect(report).toContain('Successful Events:        2');
    expect(report).toContain('Failed Events:            1');
    expect(report).toContain('Unique Event Types:       2');
    expect(report).toContain('Events by Type:');
    expect(report).toContain('tool_call: 2');
    expect(report).toContain('data_access: 1');
    expect(report).toContain('Open Risk Findings:       2');
    expect(report).toContain('Risk per Agent:');
    expect(report).toContain('Agent Alpha: 1 total, 1 open, 0 critical');
    expect(report).toContain('Agent Beta: 1 total, 1 open, 1 critical');
  });

  it('works with a single agent (graceful degradation)', () => {
    const report = generateMultiAgentAuditReport([baseBOM as never]);
    expect(report).toContain('MULTI-AGENT TRUST AUDIT REPORT');
    expect(report).toContain('Agents in Scope:  1');
    expect(report).toContain('No cross-agent causal chains detected.');
  });

  it('includes per-event-type breakdown sorted by count', () => {
    const bom = {
      ...baseBOM,
      audit_log: [
        {
          timestamp: '2026-01-15T10:00:00Z',
          event_type: 'tool_call',
          actor: 'agent-001',
          outcome: 'success' as const,
        },
        {
          timestamp: '2026-01-15T10:01:00Z',
          event_type: 'tool_call',
          actor: 'agent-001',
          outcome: 'success' as const,
        },
        {
          timestamp: '2026-01-15T10:02:00Z',
          event_type: 'tool_call',
          actor: 'agent-001',
          outcome: 'success' as const,
        },
        {
          timestamp: '2026-01-15T10:03:00Z',
          event_type: 'data_access',
          actor: 'agent-001',
          outcome: 'success' as const,
        },
      ],
    };
    const report = generateMultiAgentAuditReport([bom as never]);
    // tool_call (3) should appear before data_access (1)
    const toolIdx = report.indexOf('tool_call: 3');
    const dataIdx = report.indexOf('data_access: 1');
    expect(toolIdx).toBeGreaterThan(-1);
    expect(dataIdx).toBeGreaterThan(-1);
    expect(toolIdx).toBeLessThan(dataIdx);
  });
});
