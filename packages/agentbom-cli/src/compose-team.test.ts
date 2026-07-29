import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { composeTeamCommand } from './compose-team.js';

describe('composeTeamCommand', () => {
  let tmpDir: string;
  let logOutput: string[];
  let errorOutput: string[];
  let logSpy: ReturnType<typeof spyOn>;
  let errorSpy: ReturnType<typeof spyOn>;

  beforeEach(() => {
    tmpDir = join(
      tmpdir(),
      `compose-team-test-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    mkdirSync(tmpDir, { recursive: true });
    logOutput = [];
    errorOutput = [];
    logSpy = spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      logOutput.push(args.map(String).join(' '));
    });
    errorSpy = spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      errorOutput.push(args.map(String).join(' '));
    });
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  // --- Argument validation ---

  it('returns 1 and prints error when no args provided', () => {
    const result = composeTeamCommand([]);
    expect(result).toBe(1);
    expect(errorOutput).toEqual(['Error: compose-team requires at least 2 agent BOM files']);
    expect(logOutput).toEqual([]);
  });

  it('returns 1 when only 1 BOM path provided', () => {
    const result = composeTeamCommand(['single.bom']);
    expect(result).toBe(1);
    expect(errorOutput).toEqual(['Error: compose-team requires at least 2 agent BOM files']);
  });

  // --- File I/O errors ---

  it('returns 1 and prints error when BOM file cannot be read', () => {
    const result = composeTeamCommand(['/nonexistent/a.bom', '/nonexistent/b.bom']);
    expect(result).toBe(1);
    expect(errorOutput[0]).toContain('Error: Cannot read BOM file:');
    expect(errorOutput[0]).toContain('/nonexistent/a.bom');
  });

  it('returns 1 and prints error for invalid JSON content', () => {
    const badPath = join(tmpDir, 'bad.json');
    writeFileSync(badPath, 'not valid json{{{');

    const result = composeTeamCommand([badPath, '/nonexistent/other.bom']);
    expect(result).toBe(1);
    expect(errorOutput[0]).toContain('Error: Invalid BOM format in file:');
    expect(errorOutput[0]).toContain('not valid JSON');
  });

  it('returns 1 and prints first validation error for invalid BOM schema', () => {
    const badPath = join(tmpDir, 'invalid-bom.json');
    writeFileSync(badPath, JSON.stringify({ foo: 'bar' }));

    const result = composeTeamCommand([badPath, '/nonexistent/other.bom']);
    expect(result).toBe(1);
    expect(errorOutput[0]).toContain('Error: Invalid BOM format in file:');
    // First error should reference the missing required fields
    expect(errorOutput[0]).toMatch(/required|must/i);
  });

  // --- Happy path: 2 valid BOMs ---

  it('returns 0 and prints composite manifest JSON for 2 valid BOMs', () => {
    const bom1 = JSON.stringify({
      agentbom_version: '0.1',
      identity: {
        agent_id: 'agent-001',
        agent_name: 'Alpha',
        generated_at: '2026-01-15T10:00:00Z',
      },
      attestation: { generator: 'test' },
    });
    const bom2 = JSON.stringify({
      agentbom_version: '0.1',
      identity: {
        agent_id: 'agent-002',
        agent_name: 'Beta',
        generated_at: '2026-01-15T10:05:00Z',
      },
      attestation: { generator: 'test' },
    });

    const path1 = join(tmpDir, 'agent1.json');
    const path2 = join(tmpDir, 'agent2.json');
    writeFileSync(path1, bom1);
    writeFileSync(path2, bom2);

    const result = composeTeamCommand([path1, path2]);
    expect(result).toBe(0);

    const output = logOutput.join('\n');
    const manifest = JSON.parse(output);

    expect(manifest.schema).toBe('composite-trust-manifest/v1');
    expect(manifest.agent_count).toBe(2);
    expect(manifest.agents).toHaveLength(2);
    expect(manifest.generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(manifest.aggregated_capabilities).toEqual([]);
    expect(manifest.trust_relationships).toEqual([]);
  });

  it('includes correct agent entries with bom_path', () => {
    const bom1 = JSON.stringify({
      agentbom_version: '0.1',
      identity: {
        agent_id: 'agent-001',
        agent_name: 'Alpha',
        generated_at: '2026-01-15T10:00:00Z',
      },
      attestation: { generator: 'test' },
    });
    const bom2 = JSON.stringify({
      agentbom_version: '0.1',
      identity: {
        agent_id: 'agent-002',
        agent_name: 'Beta',
        generated_at: '2026-01-15T10:05:00Z',
      },
      attestation: { generator: 'test' },
    });

    const path1 = join(tmpDir, 'alpha.json');
    const path2 = join(tmpDir, 'beta.json');
    writeFileSync(path1, bom1);
    writeFileSync(path2, bom2);

    const result = composeTeamCommand([path1, path2]);
    expect(result).toBe(0);

    const manifest = JSON.parse(logOutput.join('\n'));

    expect(manifest.agents[0]).toEqual({
      agent_id: 'agent-001',
      agent_name: 'Alpha',
      bom_path: path1,
    });
    expect(manifest.agents[1]).toEqual({
      agent_id: 'agent-002',
      agent_name: 'Beta',
      bom_path: path2,
    });
  });

  // --- Capabilities aggregation ---

  it('aggregates capabilities as sorted union from model_layer.capabilities', () => {
    const bom1 = JSON.stringify({
      agentbom_version: '0.1',
      identity: {
        agent_id: 'agent-001',
        agent_name: 'Alpha',
        generated_at: '2026-01-15T10:00:00Z',
      },
      model_layer: {
        provider: 'openai',
        model_id: 'gpt-4',
        capabilities: ['code-generation', 'analysis'],
      },
      attestation: { generator: 'test' },
    });
    const bom2 = JSON.stringify({
      agentbom_version: '0.1',
      identity: {
        agent_id: 'agent-002',
        agent_name: 'Beta',
        generated_at: '2026-01-15T10:05:00Z',
      },
      model_layer: {
        provider: 'anthropic',
        model_id: 'claude-3',
        capabilities: ['analysis', 'planning'],
      },
      attestation: { generator: 'test' },
    });

    const path1 = join(tmpDir, 'a.json');
    const path2 = join(tmpDir, 'b.json');
    writeFileSync(path1, bom1);
    writeFileSync(path2, bom2);

    const result = composeTeamCommand([path1, path2]);
    expect(result).toBe(0);

    const manifest = JSON.parse(logOutput.join('\n'));

    // Union of capabilities, sorted
    expect(manifest.aggregated_capabilities).toEqual(['analysis', 'code-generation', 'planning']);
  });

  // --- Trust relationships from peer_agents ---

  it('collects trust relationships from agent_collaboration.peer_agents', () => {
    const bom1 = JSON.stringify({
      agentbom_version: '0.1',
      identity: {
        agent_id: 'agent-001',
        agent_name: 'Alpha',
        generated_at: '2026-01-15T10:00:00Z',
      },
      agent_collaboration: {
        peer_agents: [{ agent_id: 'agent-002', role: 'delegate' }],
      },
      attestation: { generator: 'test' },
    });
    const bom2 = JSON.stringify({
      agentbom_version: '0.1',
      identity: {
        agent_id: 'agent-002',
        agent_name: 'Beta',
        generated_at: '2026-01-15T10:05:00Z',
      },
      agent_collaboration: {
        peer_agents: [{ agent_id: 'agent-001', role: 'supervisor' }],
      },
      attestation: { generator: 'test' },
    });

    const path1 = join(tmpDir, 'a.json');
    const path2 = join(tmpDir, 'b.json');
    writeFileSync(path1, bom1);
    writeFileSync(path2, bom2);

    const result = composeTeamCommand([path1, path2]);
    expect(result).toBe(0);

    const manifest = JSON.parse(logOutput.join('\n'));

    expect(manifest.trust_relationships).toHaveLength(2);
    expect(manifest.trust_relationships).toContainEqual({
      from: 'agent-001',
      to: 'agent-002',
      type: 'delegate',
    });
    expect(manifest.trust_relationships).toContainEqual({
      from: 'agent-002',
      to: 'agent-001',
      type: 'supervisor',
    });
  });

  // --- JSON output quality ---

  it('prints valid JSON via JSON.stringify(manifest, null, 2) that can be re-parsed', () => {
    const bom1 = JSON.stringify({
      agentbom_version: '0.1',
      identity: {
        agent_id: 'agent-001',
        agent_name: 'Alpha',
        generated_at: '2026-01-15T10:00:00Z',
      },
      attestation: { generator: 'test' },
    });
    const bom2 = JSON.stringify({
      agentbom_version: '0.1',
      identity: {
        agent_id: 'agent-002',
        agent_name: 'Beta',
        generated_at: '2026-01-15T10:05:00Z',
      },
      attestation: { generator: 'test' },
    });

    const path1 = join(tmpDir, 'a.json');
    const path2 = join(tmpDir, 'b.json');
    writeFileSync(path1, bom1);
    writeFileSync(path2, bom2);

    const result = composeTeamCommand([path1, path2]);
    expect(result).toBe(0);

    const raw = logOutput.join('\n');
    expect(() => JSON.parse(raw)).not.toThrow();
    const manifest = JSON.parse(raw);
    expect(manifest).toHaveProperty('schema', 'composite-trust-manifest/v1');
  });

  // --- 3+ BOMs ---

  it('handles 3 or more BOMs', () => {
    const paths: string[] = [];
    for (let i = 1; i <= 3; i++) {
      const path = join(tmpDir, `agent${i}.json`);
      writeFileSync(
        path,
        JSON.stringify({
          agentbom_version: '0.1',
          identity: {
            agent_id: `agent-${String(i).padStart(3, '0')}`,
            agent_name: `Agent ${i}`,
            generated_at: '2026-01-15T10:00:00Z',
          },
          attestation: { generator: 'test' },
        }),
      );
      paths.push(path);
    }

    const result = composeTeamCommand(paths);
    expect(result).toBe(0);

    const manifest = JSON.parse(logOutput.join('\n'));
    expect(manifest.agent_count).toBe(3);
    expect(manifest.agents).toHaveLength(3);
    expect(manifest.agents.map((a: { agent_id: string }) => a.agent_id)).toEqual([
      'agent-001',
      'agent-002',
      'agent-003',
    ]);
  });
});
