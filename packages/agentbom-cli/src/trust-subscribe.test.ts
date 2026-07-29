import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  findAgentBOMFiles,
  notifyCallback,
  parseSubscribeArgs,
  runDriftCheck,
  type SubscribeConfig,
} from './trust-subscribe.js';

// ---- Fixtures ----

const BASELINE_BOM = {
  agentbom_version: '0.1',
  identity: {
    agent_id: 'test-agent-sub',
    agent_name: 'Test Subscribe Agent',
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

const DRIFTED_BOM = {
  ...BASELINE_BOM,
  identity: {
    ...BASELINE_BOM.identity,
    generated_at: '2026-01-02T00:00:00Z',
  },
  tool_layer: [
    ...BASELINE_BOM.tool_layer,
    {
      tool_id: 'fs-write',
      tool_name: 'write_file',
      source: 'builtin',
      permissions: ['fs:write'],
      risk_signals: [],
    },
  ],
  permission_layer: {
    granted_scopes: ['fs:read', 'fs:write'],
    data_access: ['local_workspace'],
    credential_references: [],
  },
};

// ---- Test setup ----

let tmpDir: string;

beforeEach(() => {
  tmpDir = join(
    tmpdir(),
    `trust-subscribe-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
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

// ---- parseSubscribeArgs ----

describe('parseSubscribeArgs', () => {
  it('returns usage string for --help', () => {
    const result = parseSubscribeArgs(['--help']);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('returns usage string for -h', () => {
    const result = parseSubscribeArgs(['-h']);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('returns error for empty args', () => {
    const result = parseSubscribeArgs([]);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('returns error when --baseline is missing', () => {
    const result = parseSubscribeArgs(['my-agent']);
    expect(typeof result).toBe('string');
    expect(result).toContain('--baseline');
  });

  it('returns error for unknown flag', () => {
    const result = parseSubscribeArgs(['my-agent', '--baseline', '/tmp/b.json', '--bogus']);
    expect(typeof result).toBe('string');
    expect(result).toContain('unknown argument');
  });

  it('parses required args and returns config', () => {
    const result = parseSubscribeArgs(['my-agent', '--baseline', '/tmp/b.json']);
    expect(typeof result).not.toBe('string');
    const config = result as SubscribeConfig;
    expect(config.agentIdentity).toBe('my-agent');
    expect(config.baselinePath).toBe('/tmp/b.json');
    expect(config.watchDir).toBe('/tmp');
    expect(config.intervalSeconds).toBe(30);
    expect(config.once).toBe(false);
    expect(config.callbackUrl).toBeUndefined();
  });

  it('parses all optional flags', () => {
    const result = parseSubscribeArgs([
      'agent-x',
      '--baseline',
      '/b.json',
      '--watch',
      '/artifacts',
      '--callback',
      'https://hooks.example.com/drift',
      '--interval',
      '60',
      '--once',
    ]);
    expect(typeof result).not.toBe('string');
    const config = result as SubscribeConfig;
    expect(config.agentIdentity).toBe('agent-x');
    expect(config.baselinePath).toBe('/b.json');
    expect(config.watchDir).toBe('/artifacts');
    expect(config.callbackUrl).toBe('https://hooks.example.com/drift');
    expect(config.intervalSeconds).toBe(60);
    expect(config.once).toBe(true);
  });

  it('rejects --interval below minimum of 5', () => {
    const result = parseSubscribeArgs(['a', '--baseline', '/b.json', '--interval', '3']);
    expect(typeof result).toBe('string');
    expect(result).toContain('≥ 5');
  });

  it('rejects non-numeric --interval', () => {
    const result = parseSubscribeArgs(['a', '--baseline', '/b.json', '--interval', 'abc']);
    expect(typeof result).toBe('string');
    expect(result).toContain('integer');
  });

  it('resolves --watch relative to CWD', () => {
    const result = parseSubscribeArgs(['a', '--baseline', '/b.json', '--watch', 'artifacts']);
    expect(typeof result).not.toBe('string');
    const config = result as SubscribeConfig;
    expect(config.watchDir).toBe(resolve('artifacts'));
  });
});

// ---- findAgentBOMFiles ----

describe('findAgentBOMFiles', () => {
  it('finds matching AgentBOM files in a directory', () => {
    writeJson('baseline.json', BASELINE_BOM);
    writeJson('current.json', DRIFTED_BOM);
    // Non-matching agent
    writeJson('other-agent.json', {
      ...BASELINE_BOM,
      identity: { ...BASELINE_BOM.identity, agent_id: 'other-agent' },
    });

    const files = findAgentBOMFiles(tmpDir, 'test-agent-sub');
    expect(files.length).toBe(2);
    expect(files).toContainEqual(join(tmpDir, 'baseline.json'));
    expect(files).toContainEqual(join(tmpDir, 'current.json'));
  });

  it('returns empty for non-existent directory', () => {
    const files = findAgentBOMFiles('/nonexistent/path/xyz', 'agent');
    expect(files).toEqual([]);
  });

  it('skips non-JSON files', () => {
    writeJson('valid.json', BASELINE_BOM);
    writeFileSync(join(tmpDir, 'readme.txt'), 'not json', 'utf-8');

    const files = findAgentBOMFiles(tmpDir, 'test-agent-sub');
    expect(files.length).toBe(1);
  });

  it('skips invalid JSON files', () => {
    writeJson('valid.json', BASELINE_BOM);
    writeFileSync(join(tmpDir, 'bad.json'), '{ not valid json', 'utf-8');

    const files = findAgentBOMFiles(tmpDir, 'test-agent-sub');
    expect(files.length).toBe(1);
  });

  it('skips files that are not valid AgentBOM schema', () => {
    writeJson('valid.json', BASELINE_BOM);
    writeJson('invalid.json', { foo: 'bar' });

    const files = findAgentBOMFiles(tmpDir, 'test-agent-sub');
    expect(files.length).toBe(1);
  });

  it('returns empty when no files match agent identity', () => {
    writeJson('other.json', BASELINE_BOM);

    const files = findAgentBOMFiles(tmpDir, 'different-agent');
    expect(files).toEqual([]);
  });
});

// ---- runDriftCheck ----

describe('runDriftCheck', () => {
  it('detects no drift when baseline is the only file', () => {
    const baselinePath = writeJson('baseline.json', BASELINE_BOM);

    const config: SubscribeConfig = {
      agentIdentity: 'test-agent-sub',
      baselinePath,
      watchDir: tmpDir,
      once: true,
    };

    const result = runDriftCheck(config);
    expect(result.hasDrift).toBe(false);
    expect(result.alert.isEmpty()).toBe(true);
  });

  it('detects drift when a modified AgentBOM is present', () => {
    const baselinePath = writeJson('baseline.json', BASELINE_BOM);
    writeJson('current.json', DRIFTED_BOM);

    const config: SubscribeConfig = {
      agentIdentity: 'test-agent-sub',
      baselinePath,
      watchDir: tmpDir,
      once: true,
    };

    const result = runDriftCheck(config);
    expect(result.hasDrift).toBe(true);
    expect(result.alert.isEmpty()).toBe(false);
    expect(result.scannedFiles).toContainEqual(join(tmpDir, 'current.json'));
    // Should have tool_added and scope_expanded events
    const categories = result.alert.events.map((e) => e.category);
    expect(categories).toContain('tool_added');
    expect(categories).toContain('scope_expanded');
  });

  it('detects no drift when current matches baseline exactly', () => {
    const baselinePath = writeJson('baseline.json', BASELINE_BOM);
    // Write an identical copy with a different name
    writeJson('copy.json', { ...BASELINE_BOM });

    const config: SubscribeConfig = {
      agentIdentity: 'test-agent-sub',
      baselinePath,
      watchDir: tmpDir,
      once: true,
    };

    const result = runDriftCheck(config);
    expect(result.hasDrift).toBe(false);
    expect(result.alert.isEmpty()).toBe(true);
  });

  it('returns error message when baseline cannot be read', () => {
    const config: SubscribeConfig = {
      agentIdentity: 'test-agent-sub',
      baselinePath: '/nonexistent/baseline.json',
      watchDir: tmpDir,
      once: true,
    };

    const result = runDriftCheck(config);
    expect(result.hasDrift).toBe(false);
    expect(result.formatted).toContain('Error');
  });

  it('ignores files that do not match the agent identity', () => {
    const baselinePath = writeJson('baseline.json', BASELINE_BOM);
    writeJson('other.json', {
      ...DRIFTED_BOM,
      identity: { ...DRIFTED_BOM.identity, agent_id: 'other-agent' },
    });

    const config: SubscribeConfig = {
      agentIdentity: 'test-agent-sub',
      baselinePath,
      watchDir: tmpDir,
      once: true,
    };

    const result = runDriftCheck(config);
    expect(result.hasDrift).toBe(false);
  });

  it('formats alert output with agent_id and timestamps', () => {
    const baselinePath = writeJson('baseline.json', BASELINE_BOM);
    writeJson('current.json', DRIFTED_BOM);

    const config: SubscribeConfig = {
      agentIdentity: 'test-agent-sub',
      baselinePath,
      watchDir: tmpDir,
      once: true,
    };

    const result = runDriftCheck(config);
    expect(result.formatted).toContain('test-agent-sub');
    expect(result.formatted).toContain('2026-01-01T00:00:00Z');
    expect(result.formatted).toContain('2026-01-02T00:00:00Z');
  });
});

// ---- notifyCallback ----

describe('notifyCallback', () => {
  it('returns false for an unreachable URL', async () => {
    const result = await notifyCallback('http://localhost:1/impossible', {
      hasDrift: true,
      alert: {
        agent_id: 'a',
        baseline_at: '2026-01-01T00:00:00Z',
        current_at: '2026-01-02T00:00:00Z',
        events: [],
        hasHighSeverity: () => false,
        isEmpty: () => true,
      },
      formatted: 'test',
      scannedFiles: [],
    });
    expect(result).toBe(false);
  });
});

// ---- Integration: subscribe command via runCommand ----

import { runCommand } from './index.js';

describe('subscribe command via runCommand', () => {
  it('shows help for subscribe --help', async () => {
    const spy = spyOn(console, 'log');
    // runCommand returns Promise<number> for subscribe
    const result = await (runCommand(['subscribe', '--help']) as Promise<number>);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('Usage:');
    expect(output).toContain('--baseline');
    expect(output).toContain('--once');
    expect(output).toContain('--callback');
  });

  it('returns 1 for subscribe without --baseline', async () => {
    const spy = spyOn(console, 'error');
    const result = await (runCommand(['subscribe', 'my-agent']) as Promise<number>);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('--baseline');
  });

  it('returns 1 for subscribe with non-existent baseline', async () => {
    const spy = spyOn(console, 'error');
    const result = await (runCommand([
      'subscribe',
      'my-agent',
      '--baseline',
      '/nonexistent/baseline.json',
      '--once',
    ]) as Promise<number>);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('cannot read baseline');
  });

  it('returns 0 for subscribe --once with no drift', async () => {
    const baselinePath = writeJson('baseline.json', BASELINE_BOM);
    const spyLog = spyOn(console, 'log');

    const result = await (runCommand([
      'subscribe',
      'test-agent-sub',
      '--baseline',
      baselinePath,
      '--once',
    ]) as Promise<number>);
    expect(result).toBe(0);
    const output = spyLog.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('monitoring agent');
    expect(output).toContain('single-check');
  });

  it('returns 1 for subscribe --once when drift is detected', async () => {
    const baselinePath = writeJson('baseline.json', BASELINE_BOM);
    writeJson('current.json', DRIFTED_BOM);
    const spyLog = spyOn(console, 'log');

    const result = await (runCommand([
      'subscribe',
      'test-agent-sub',
      '--baseline',
      baselinePath,
      '--once',
    ]) as Promise<number>);
    expect(result).toBe(1);
    const output = spyLog.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('DRIFT DETECTED');
  });

  it('rejects unknown subscribe flags', async () => {
    const spy = spyOn(console, 'error');
    const result = await (runCommand([
      'subscribe',
      'a',
      '--baseline',
      '/b.json',
      '--unknown-flag',
    ]) as Promise<number>);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('unknown argument');
  });

  it('rejects --interval below 5', async () => {
    const spy = spyOn(console, 'error');
    const result = await (runCommand([
      'subscribe',
      'a',
      '--baseline',
      '/b.json',
      '--interval',
      '2',
    ]) as Promise<number>);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('≥ 5');
  });
});
