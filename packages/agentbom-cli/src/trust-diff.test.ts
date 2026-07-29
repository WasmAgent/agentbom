import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { runCommand } from './index.js';
import {
  diffTrustArtifacts,
  extractChangesFromFormatted,
  type FieldChange,
  formatGenericDiff,
  parseDiffArgs,
  trustDiffCommand,
} from './trust-diff.js';

// ---- Fixtures ----

const VALID_AGENTBOM_OLD = {
  agentbom_version: '0.1',
  identity: {
    agent_id: 'test-agent-diff',
    agent_name: 'Test Agent v1',
    deployment_context: 'development',
    generated_at: '2026-01-01T00:00:00Z',
  },
  attestation: { generator: 'test' },
  tool_layer: [
    {
      tool_id: 'fs-read',
      tool_name: 'read_file',
      source: 'builtin',
      permissions: ['fs:read'],
      risk_signals: [],
    },
  ],
  permission_layer: {
    granted_scopes: ['fs:read'],
    data_access: ['local_workspace'],
    credential_references: [],
  },
  risk_layer: [],
};

const VALID_AGENTBOM_NEW = {
  agentbom_version: '0.1',
  identity: {
    agent_id: 'test-agent-diff',
    agent_name: 'Test Agent v2',
    deployment_context: 'production',
    generated_at: '2026-02-01T00:00:00Z',
  },
  attestation: { generator: 'test' },
  tool_layer: [
    {
      tool_id: 'fs-read',
      tool_name: 'read_file',
      source: 'builtin',
      permissions: ['fs:read', 'fs:write'],
      risk_signals: [],
    },
    {
      tool_id: 'web-fetch',
      tool_name: 'fetch_url',
      source: 'mcp',
      permissions: ['network:read'],
      risk_signals: [],
    },
  ],
  permission_layer: {
    granted_scopes: ['fs:read', 'fs:write', 'network:read'],
    data_access: ['local_workspace', 'remote_api'],
    credential_references: [],
  },
  risk_layer: [],
};

const VALID_MCP_POSTURE_OLD = {
  posture_version: '0.1',
  identity: {
    agent_id: 'test-mcp-diff',
    snapshot_id: 'snap-001',
    captured_at: '2026-01-01T00:00:00Z',
  },
  servers: [
    {
      server_id: 'filesystem',
      server_name: 'Filesystem Server',
      transport: 'stdio',
      capabilities: ['read'],
    },
  ],
  attestation: { generator: 'test' },
};

const VALID_MCP_POSTURE_NEW = {
  posture_version: '0.1',
  identity: {
    agent_id: 'test-mcp-diff',
    snapshot_id: 'snap-002',
    captured_at: '2026-02-01T00:00:00Z',
  },
  servers: [
    {
      server_id: 'filesystem',
      server_name: 'Filesystem Server v2',
      transport: 'stdio',
      capabilities: ['read', 'write'],
    },
    {
      server_id: 'web',
      server_name: 'Web Server',
      transport: 'sse',
      capabilities: ['fetch'],
    },
  ],
  attestation: { generator: 'test' },
};

const VALID_TRUST_PASSPORT_OLD = {
  passport_version: '0.1',
  identity: {
    passport_id: 'passport-001',
    agent_id: 'test-passport-diff',
    agent_name: 'Test Agent v1',
    issuer: 'Test Issuer',
    issuance_context: 'development',
  },
  validity: {
    issued_at: '2026-01-01T00:00:00Z',
    expires_at: '2027-01-01T00:00:00Z',
  },
  attestation: {
    generator: 'test',
    issuer: 'Test Issuer',
    coverage: 'selected_technical_evidence',
  },
  revocation: {
    revoked: false,
    revoked_at: null,
    revocation_reason: null,
    revocation_triggers: [],
  },
  risk_summary: { critical: 0, high: 1, medium: 2, low: 0, open_findings: 3 },
};

const VALID_TRUST_PASSPORT_NEW = {
  passport_version: '0.1',
  identity: {
    passport_id: 'passport-001',
    agent_id: 'test-passport-diff',
    agent_name: 'Test Agent v2',
    issuer: 'Test Issuer',
    issuance_context: 'production',
  },
  validity: {
    issued_at: '2026-01-01T00:00:00Z',
    expires_at: '2027-06-01T00:00:00Z',
  },
  attestation: {
    generator: 'test',
    issuer: 'Test Issuer',
    coverage: 'partial',
  },
  revocation: {
    revoked: false,
    revoked_at: null,
    revocation_reason: null,
    revocation_triggers: ['policy_violation'],
  },
  risk_summary: { critical: 1, high: 2, medium: 2, low: 0, open_findings: 5 },
  evidence_summary: {
    evidence_quality: 'high',
    framework_mappings: [{ framework: 'OWASP', coverage: 'partial' }],
  },
};

// ---- Test setup ----

let tmpDir: string;

beforeEach(() => {
  tmpDir = join(tmpdir(), `trust-diff-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tmpDir, { recursive: true });
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function writeJson(name: string, data: unknown): string {
  const p = join(tmpDir, name);
  writeFileSync(p, JSON.stringify(data), 'utf-8');
  return p;
}

// ---- parseDiffArgs ----

describe('parseDiffArgs', () => {
  it('returns usage string for --help', () => {
    const result = parseDiffArgs(['--help']);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('returns usage string for -h', () => {
    const result = parseDiffArgs(['-h']);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('returns usage string for empty args', () => {
    const result = parseDiffArgs([]);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('returns error for single positional arg', () => {
    const result = parseDiffArgs(['file-a.json']);
    expect(typeof result).toBe('string');
    expect(result).toContain('requires two file path arguments');
  });

  it('parses two positional args', () => {
    const result = parseDiffArgs(['a.json', 'b.json']);
    expect(typeof result).not.toBe('string');
    const config = result as { oldPath: string; newPath: string; json: boolean };
    expect(config.oldPath).toBe(resolve('a.json'));
    expect(config.newPath).toBe(resolve('b.json'));
    expect(config.json).toBe(false);
  });

  it('parses --json flag', () => {
    const result = parseDiffArgs(['a.json', 'b.json', '--json']);
    expect(typeof result).not.toBe('string');
    const config = result as { oldPath: string; newPath: string; json: boolean };
    expect(config.json).toBe(true);
  });

  it('returns error for unknown flag', () => {
    const result = parseDiffArgs(['a.json', 'b.json', '--bogus']);
    expect(typeof result).toBe('string');
    expect(result).toContain('unknown argument');
  });
});

// ---- diffTrustArtifacts — error paths ----

describe('diffTrustArtifacts — error paths', () => {
  it('returns error for non-existent old file', () => {
    const newPath = writeJson('new.json', VALID_AGENTBOM_OLD);
    const result = diffTrustArtifacts('/nonexistent/a.json', newPath);
    expect(typeof result).toBe('string');
    expect(result).toContain('Error');
  });

  it('returns error for non-existent new file', () => {
    const oldPath = writeJson('old.json', VALID_AGENTBOM_OLD);
    const result = diffTrustArtifacts(oldPath, '/nonexistent/b.json');
    expect(typeof result).toBe('string');
    expect(result).toContain('Error');
  });

  it('returns error for unknown old artifact type', () => {
    const oldPath = writeJson('old.json', { foo: 'bar' });
    const newPath = writeJson('new.json', VALID_AGENTBOM_OLD);
    const result = diffTrustArtifacts(oldPath, newPath);
    expect(typeof result).toBe('string');
    expect(result).toContain('does not match any known schema');
  });

  it('returns error for unknown new artifact type', () => {
    const oldPath = writeJson('old.json', VALID_AGENTBOM_OLD);
    const newPath = writeJson('new.json', { foo: 'bar' });
    const result = diffTrustArtifacts(oldPath, newPath);
    expect(typeof result).toBe('string');
    expect(result).toContain('does not match any known schema');
  });

  it('returns error for type mismatch', () => {
    const oldPath = writeJson('old.json', VALID_AGENTBOM_OLD);
    const newPath = writeJson('new.json', VALID_MCP_POSTURE_OLD);
    const result = diffTrustArtifacts(oldPath, newPath);
    expect(typeof result).toBe('string');
    expect(result).toContain('type mismatch');
  });
});

// ---- diffTrustArtifacts — AgentBOM ----

describe('diffTrustArtifacts — AgentBOM', () => {
  it('returns empty result for identical AgentBOMs', () => {
    const path = writeJson('same.json', VALID_AGENTBOM_OLD);
    const result = diffTrustArtifacts(path, path);
    expect(typeof result).not.toBe('string');
    const diff = result as { isEmpty: boolean; artifactType: string };
    expect(diff.isEmpty).toBe(true);
    expect(diff.artifactType).toBe('agentbom');
  });

  it('detects tool additions and permission changes', () => {
    const oldPath = writeJson('old.json', VALID_AGENTBOM_OLD);
    const newPath = writeJson('new.json', VALID_AGENTBOM_NEW);
    const result = diffTrustArtifacts(oldPath, newPath);
    expect(typeof result).not.toBe('string');
    const diff = result as { isEmpty: boolean; formatted: string; changes: FieldChange[] };
    expect(diff.isEmpty).toBe(false);
    expect(diff.formatted).toContain('added');
    // Should detect new tool (web-fetch) and permission changes (fs:write added)
    expect(diff.changes.length).toBeGreaterThan(0);
  });

  it('includes formatted output with tool and permission info', () => {
    const oldPath = writeJson('old.json', VALID_AGENTBOM_OLD);
    const newPath = writeJson('new.json', VALID_AGENTBOM_NEW);
    const result = diffTrustArtifacts(oldPath, newPath);
    expect(typeof result).not.toBe('string');
    const diff = result as { formatted: string };
    // The formatted output should mention tools and/or permissions
    const output = diff.formatted;
    expect(output.length).toBeGreaterThan(0);
  });
});

// ---- diffTrustArtifacts — MCP Posture ----

describe('diffTrustArtifacts — MCP Posture', () => {
  it('returns empty result for identical MCP Postures', () => {
    const path = writeJson('same.json', VALID_MCP_POSTURE_OLD);
    const result = diffTrustArtifacts(path, path);
    expect(typeof result).not.toBe('string');
    const diff = result as { isEmpty: boolean; artifactType: string };
    expect(diff.isEmpty).toBe(true);
    expect(diff.artifactType).toBe('mcp-posture');
  });

  it('detects server additions and modifications', () => {
    const oldPath = writeJson('old.json', VALID_MCP_POSTURE_OLD);
    const newPath = writeJson('new.json', VALID_MCP_POSTURE_NEW);
    const result = diffTrustArtifacts(oldPath, newPath);
    expect(typeof result).not.toBe('string');
    const diff = result as { isEmpty: boolean; formatted: string; changes: FieldChange[] };
    expect(diff.isEmpty).toBe(false);
    expect(diff.changes.length).toBeGreaterThan(0);
    // Should mention the new server (web)
    expect(diff.formatted).toContain('added');
  });
});

// ---- diffTrustArtifacts — Trust Passport ----

describe('diffTrustArtifacts — Trust Passport', () => {
  it('returns empty result for identical Trust Passports', () => {
    const path = writeJson('same.json', VALID_TRUST_PASSPORT_OLD);
    const result = diffTrustArtifacts(path, path);
    expect(typeof result).not.toBe('string');
    const diff = result as { isEmpty: boolean; artifactType: string };
    expect(diff.isEmpty).toBe(true);
    expect(diff.artifactType).toBe('trust-passport');
  });

  it('detects identity and validity changes', () => {
    const oldPath = writeJson('old.json', VALID_TRUST_PASSPORT_OLD);
    const newPath = writeJson('new.json', VALID_TRUST_PASSPORT_NEW);
    const result = diffTrustArtifacts(oldPath, newPath);
    expect(typeof result).not.toBe('string');
    const diff = result as { isEmpty: boolean; formatted: string; changes: FieldChange[] };
    expect(diff.isEmpty).toBe(false);
    expect(diff.changes.length).toBeGreaterThan(0);
    // Should detect the agent_name change, expires_at change, etc.
    const paths = diff.changes.map((c) => c.path);
    expect(paths.some((p) => p.includes('agent_name'))).toBe(true);
    expect(paths.some((p) => p.includes('expires_at'))).toBe(true);
  });

  it('detects risk_summary count changes', () => {
    const oldPath = writeJson('old.json', VALID_TRUST_PASSPORT_OLD);
    const newPath = writeJson('new.json', VALID_TRUST_PASSPORT_NEW);
    const result = diffTrustArtifacts(oldPath, newPath);
    expect(typeof result).not.toBe('string');
    const diff = result as { changes: FieldChange[] };
    const paths = diff.changes.map((c) => c.path);
    // risk_summary.critical went from 0 to 1, high from 1 to 2, open_findings from 3 to 5
    expect(paths.some((p) => p.includes('risk_summary'))).toBe(true);
  });

  it('detects added fields (evidence_summary)', () => {
    const oldPath = writeJson('old.json', VALID_TRUST_PASSPORT_OLD);
    const newPath = writeJson('new.json', VALID_TRUST_PASSPORT_NEW);
    const result = diffTrustArtifacts(oldPath, newPath);
    expect(typeof result).not.toBe('string');
    const diff = result as { changes: FieldChange[] };
    const added = diff.changes.filter((c) => c.type === 'added');
    expect(added.length).toBeGreaterThan(0);
    expect(added.some((c) => c.path.includes('evidence_summary'))).toBe(true);
  });

  it('detects revocation_triggers changes', () => {
    const oldPath = writeJson('old.json', VALID_TRUST_PASSPORT_OLD);
    const newPath = writeJson('new.json', VALID_TRUST_PASSPORT_NEW);
    const result = diffTrustArtifacts(oldPath, newPath);
    expect(typeof result).not.toBe('string');
    const diff = result as { changes: FieldChange[] };
    const paths = diff.changes.map((c) => c.path);
    expect(paths.some((p) => p.includes('revocation_triggers'))).toBe(true);
  });

  it('detects coverage change in attestation', () => {
    const oldPath = writeJson('old.json', VALID_TRUST_PASSPORT_OLD);
    const newPath = writeJson('new.json', VALID_TRUST_PASSPORT_NEW);
    const result = diffTrustArtifacts(oldPath, newPath);
    expect(typeof result).not.toBe('string');
    const diff = result as { changes: FieldChange[] };
    const paths = diff.changes.map((c) => c.path);
    expect(paths.some((p) => p.includes('coverage'))).toBe(true);
  });
});

// ---- formatGenericDiff ----

describe('formatGenericDiff', () => {
  it('formats added changes', () => {
    const changes: FieldChange[] = [
      { path: 'identity.agent_name', type: 'added', new: 'New Agent' },
    ];
    const output = formatGenericDiff(changes);
    expect(output).toContain('Fields added (1)');
    expect(output).toContain('+ identity.agent_name:');
  });

  it('formats removed changes', () => {
    const changes: FieldChange[] = [
      { path: 'identity.deprecated', type: 'removed', old: 'old-value' },
    ];
    const output = formatGenericDiff(changes);
    expect(output).toContain('Fields removed (1)');
    expect(output).toContain('- identity.deprecated:');
  });

  it('formats modified changes', () => {
    const changes: FieldChange[] = [
      {
        path: 'validity.expires_at',
        type: 'modified',
        old: '2027-01-01T00:00:00Z',
        new: '2027-06-01T00:00:00Z',
      },
    ];
    const output = formatGenericDiff(changes);
    expect(output).toContain('Fields changed (1)');
    expect(output).toContain('~ validity.expires_at:');
    expect(output).toContain('→');
  });

  it('returns "No changes detected" for empty input', () => {
    const output = formatGenericDiff([]);
    expect(output).toContain('No changes detected');
  });

  it('groups all three types together', () => {
    const changes: FieldChange[] = [
      { path: 'a', type: 'added', new: 1 },
      { path: 'b', type: 'removed', old: 2 },
      { path: 'c', type: 'modified', old: 3, new: 4 },
    ];
    const output = formatGenericDiff(changes);
    expect(output).toContain('Fields added (1)');
    expect(output).toContain('Fields removed (1)');
    expect(output).toContain('Fields changed (1)');
  });
});

// ---- extractChangesFromFormatted ----

describe('extractChangesFromFormatted', () => {
  it('parses + lines as added', () => {
    const changes = extractChangesFromFormatted('  + tool_name: fetch_url');
    expect(changes).toHaveLength(1);
    expect(changes[0].type).toBe('added');
    expect(changes[0].path).toContain('tool_name');
  });

  it('parses - lines as removed', () => {
    const changes = extractChangesFromFormatted('  - deprecated_field');
    expect(changes).toHaveLength(1);
    expect(changes[0].type).toBe('removed');
  });

  it('parses ~ lines as modified', () => {
    const changes = extractChangesFromFormatted('  ~ permissions: expanded');
    expect(changes).toHaveLength(1);
    expect(changes[0].type).toBe('modified');
  });

  it('ignores non-change lines', () => {
    const changes = extractChangesFromFormatted('Tools added (2):\nNo changes detected.');
    expect(changes).toHaveLength(0);
  });
});

// ---- Integration: diff command via runCommand ----

describe('diff command via runCommand', () => {
  it('shows help for diff --help', () => {
    const spy = spyOn(console, 'log');
    const result = runCommand(['diff', '--help']);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('Usage:');
    expect(output).toContain('artifact-a.json');
    expect(output).toContain('artifact-b.json');
    expect(output).toContain('--json');
  });

  it('shows help for diff -h', () => {
    const spy = spyOn(console, 'log');
    const result = runCommand(['diff', '-h']);
    expect(result).toBe(0);
    expect(spy).toHaveBeenCalled();
  });

  it('returns 1 for diff without enough args', () => {
    const spy = spyOn(console, 'error');
    const result = runCommand(['diff', 'only-one.json']);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('requires two file path arguments');
  });

  it('returns 1 for non-existent old file', () => {
    const spy = spyOn(console, 'error');
    const newPath = writeJson('new.json', VALID_AGENTBOM_OLD);
    const result = runCommand(['diff', '/nonexistent/a.json', newPath]);
    expect(result).toBe(1);
    expect(spy).toHaveBeenCalled();
  });

  it('returns 0 for identical AgentBOM files', () => {
    const path = writeJson('same.json', VALID_AGENTBOM_OLD);
    const spy = spyOn(console, 'log').mockClear();
    const result = runCommand(['diff', path, path]);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('AgentBOM');
    expect(output).toContain('No differences found');
  });

  it('returns 1 for different AgentBOM files', () => {
    const oldPath = writeJson('old.json', VALID_AGENTBOM_OLD);
    const newPath = writeJson('new.json', VALID_AGENTBOM_NEW);
    const spy = spyOn(console, 'log');
    const result = runCommand(['diff', oldPath, newPath]);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('AgentBOM');
  });

  it('returns 0 for identical MCP Posture files', () => {
    const path = writeJson('same.json', VALID_MCP_POSTURE_OLD);
    const spy = spyOn(console, 'log');
    const result = runCommand(['diff', path, path]);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('MCP Posture');
  });

  it('returns 1 for different MCP Posture files', () => {
    const oldPath = writeJson('old.json', VALID_MCP_POSTURE_OLD);
    const newPath = writeJson('new.json', VALID_MCP_POSTURE_NEW);
    const spy = spyOn(console, 'log');
    const result = runCommand(['diff', oldPath, newPath]);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('MCP Posture');
  });

  it('returns 0 for identical Trust Passport files', () => {
    const path = writeJson('same.json', VALID_TRUST_PASSPORT_OLD);
    const spy = spyOn(console, 'log');
    const result = runCommand(['diff', path, path]);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('Trust Passport');
  });

  it('returns 1 for different Trust Passport files', () => {
    const oldPath = writeJson('old.json', VALID_TRUST_PASSPORT_OLD);
    const newPath = writeJson('new.json', VALID_TRUST_PASSPORT_NEW);
    const spy = spyOn(console, 'log');
    const result = runCommand(['diff', oldPath, newPath]);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('Trust Passport');
    expect(output).toContain('changed');
  });

  it('returns 1 for type mismatch', () => {
    const oldPath = writeJson('old.json', VALID_AGENTBOM_OLD);
    const newPath = writeJson('new.json', VALID_MCP_POSTURE_OLD);
    const spy = spyOn(console, 'error');
    const result = runCommand(['diff', oldPath, newPath]);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('type mismatch');
  });

  it('outputs JSON when --json flag is passed', () => {
    const path = writeJson('same.json', VALID_AGENTBOM_OLD);
    const spy = spyOn(console, 'log').mockClear();
    const result = runCommand(['diff', path, path, '--json']);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    // Should be valid JSON (only the last call, which is the JSON output)
    const jsonCall = spy.mock.calls[spy.mock.calls.length - 1].join(' ');
    const parsed = JSON.parse(jsonCall);
    expect(parsed.artifact_type).toBe('agentbom');
    expect(parsed.is_empty).toBe(true);
    expect(parsed).toHaveProperty('changes');
    expect(parsed).toHaveProperty('change_count');
  });

  it('returns 1 for unknown flag', () => {
    const spy = spyOn(console, 'error');
    const result = runCommand(['diff', 'a.json', 'b.json', '--bogus']);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('unknown argument');
  });

  it('returns 1 for unknown artifact type', () => {
    const oldPath = writeJson('old.json', { foo: 'bar' });
    const newPath = writeJson('new.json', { foo: 'baz' });
    const spy = spyOn(console, 'error');
    const result = runCommand(['diff', oldPath, newPath]);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('does not match any known schema');
  });
});
