import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { publishArtifact } from './trust-publish.js';
import {
  extractDependencyIds,
  isCasId,
  objectPathForCasId,
  type PullConfig,
  parsePullArgs,
  pullArtifact,
  type ResolvedDependency,
  resolveArtifactId,
  resolveDependencies,
  resolveTagToCasId,
  verifyIntegrity,
} from './trust-pull.js';

// ---- Fixtures ----

const VALID_AGENTBOM = {
  agentbom_version: '0.1',
  identity: {
    agent_id: 'test-agent-pull',
    agent_name: 'Test Pull Agent',
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

const VALID_MCP_POSTURE = {
  posture_version: '0.1',
  identity: {
    agent_id: 'test-mcp-agent',
    snapshot_id: 'snap-001',
    captured_at: '2026-01-01T00:00:00Z',
  },
  servers: [
    {
      server_id: 'filesystem',
      server_name: 'Filesystem Server',
      transport: 'stdio',
      capabilities: ['read', 'write'],
    },
  ],
  attestation: { generator: 'test' },
};

const VALID_TRUST_PASSPORT = {
  passport_version: '0.1',
  identity: {
    passport_id: 'passport-001',
    agent_id: 'test-passport-agent',
    agent_name: 'Test Passport Agent',
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
};

// ---- Test setup ----

let tmpDir: string;
let registryDir: string;

beforeEach(() => {
  tmpDir = join(tmpdir(), `trust-pull-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tmpDir, { recursive: true });
  registryDir = join(tmpDir, 'registry');
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function writeJson(name: string, data: unknown): string {
  const p = join(tmpDir, name);
  writeFileSync(p, JSON.stringify(data), 'utf-8');
  return p;
}

/** Publish a fixture and return its CAS id (fails the test if publishing errored). */
function publish(data: unknown, tag?: string): string {
  const path = writeJson(`artifact-${Math.random().toString(36).slice(2)}.json`, data);
  const result = publishArtifact(path, registryDir, tag);
  if (typeof result === 'string') {
    throw new Error(`setup publish failed: ${result}`);
  }
  return result.casId;
}

/** Recursively collect every error string in a resolved-dependency tree. */
function collectTreeErrors(nodes: ResolvedDependency[], errors: string[] = []): string[] {
  for (const node of nodes) {
    if (node.error) errors.push(node.error);
    if (node.dependencies) collectTreeErrors(node.dependencies, errors);
  }
  return errors;
}

// ---- objectPathForCasId ----

describe('objectPathForCasId', () => {
  it('shards the hex digest into <hex[0:2]>/<hex[2:4]>/<full>.json', () => {
    const casId = 'sha256:abcdef0123456789';
    const p = objectPathForCasId(casId, registryDir);
    expect(p).toBe(join(registryDir, 'objects', 'ab', 'cd', 'abcdef0123456789.json'));
  });

  it('ignores a missing sha256: prefix gracefully', () => {
    const p = objectPathForCasId('sha256:abcdef', registryDir);
    expect(p).toContain('objects');
    expect(p.endsWith('abcdef.json')).toBe(true);
  });
});

// ---- isCasId ----

describe('isCasId', () => {
  it('accepts a well-formed sha256:<64-hex> id', () => {
    expect(isCasId(`sha256:${'a'.repeat(64)}`)).toBe(true);
  });

  it('rejects a tag label', () => {
    expect(isCasId('latest')).toBe(false);
  });

  it('rejects a truncated digest', () => {
    expect(isCasId('sha256:abc')).toBe(false);
  });

  it('rejects uppercase hex', () => {
    expect(isCasId(`sha256:${'A'.repeat(64)}`)).toBe(false);
  });

  it('rejects missing prefix', () => {
    expect(isCasId('a'.repeat(64))).toBe(false);
  });
});

// ---- resolveTagToCasId ----

describe('resolveTagToCasId', () => {
  it('returns the cas_id for a known tag', () => {
    publish(VALID_AGENTBOM, 'latest');
    const casId = resolveTagToCasId(registryDir, 'latest');
    expect(casId).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('returns null for an unknown tag', () => {
    expect(resolveTagToCasId(registryDir, 'nope')).toBeNull();
  });

  it('returns null for a corrupted tag pointer', () => {
    mkdirSync(join(registryDir, 'tags'), { recursive: true });
    writeFileSync(join(registryDir, 'tags', 'broken.json'), 'not json', 'utf-8');
    expect(resolveTagToCasId(registryDir, 'broken')).toBeNull();
  });

  it('returns null when the pointer cas_id is malformed', () => {
    mkdirSync(join(registryDir, 'tags'), { recursive: true });
    writeFileSync(
      join(registryDir, 'tags', 'bad.json'),
      JSON.stringify({ cas_id: 'not-a-cas-id' }),
      'utf-8',
    );
    expect(resolveTagToCasId(registryDir, 'bad')).toBeNull();
  });
});

// ---- resolveArtifactId ----

describe('resolveArtifactId', () => {
  it('passes a CAS id through unchanged', () => {
    const casId = `sha256:${'a'.repeat(64)}`;
    const resolved = resolveArtifactId(casId, registryDir);
    expect(resolved).not.toBeNull();
    expect(resolved?.casId).toBe(casId);
    expect(resolved?.viaTag).toBeUndefined();
  });

  it('resolves a tag label via the tag pointer', () => {
    publish(VALID_AGENTBOM, 'stable');
    const resolved = resolveArtifactId('stable', registryDir);
    expect(resolved).not.toBeNull();
    expect(resolved?.casId).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(resolved?.viaTag).toBe('stable');
  });

  it('returns null for an unresolvable id', () => {
    expect(resolveArtifactId('unknown-tag', registryDir)).toBeNull();
  });
});

// ---- verifyIntegrity ----

describe('verifyIntegrity', () => {
  it('verifies matching content', () => {
    const content = JSON.stringify(VALID_AGENTBOM);
    const casId = verifyIntegrity(content, '').computedCasId;
    const result = verifyIntegrity(content, casId);
    expect(result.ok).toBe(true);
    expect(result.computedCasId).toBe(casId);
  });

  it('detects tampered content', () => {
    const original = JSON.stringify(VALID_AGENTBOM);
    const casId = verifyIntegrity(original, '').computedCasId;
    const tampered = JSON.stringify({ ...VALID_AGENTBOM, tampered: true });
    const result = verifyIntegrity(tampered, casId);
    expect(result.ok).toBe(false);
    expect(result.computedCasId).not.toBe(casId);
  });
});

// ---- extractDependencyIds ----

describe('extractDependencyIds', () => {
  it('reads distribution.supersedes', () => {
    const ids = extractDependencyIds({
      distribution: { supersedes: ['sha256:aaa', 'sha256:bbb'] },
    });
    expect(ids).toEqual(['sha256:aaa', 'sha256:bbb']);
  });

  it('reads a string-form dependencies array', () => {
    const ids = extractDependencyIds({ dependencies: ['sha256:ccc'] });
    expect(ids).toEqual(['sha256:ccc']);
  });

  it('reads an object-form dependencies array ({ id })', () => {
    const ids = extractDependencyIds({ dependencies: [{ id: 'sha256:ddd' }, { name: 'x' }] });
    expect(ids).toEqual(['sha256:ddd']);
  });

  it('merges supersedes and dependencies preserving first-seen order', () => {
    const ids = extractDependencyIds({
      distribution: { supersedes: ['a', 'b'] },
      dependencies: ['b', 'c'],
    });
    expect(ids).toEqual(['a', 'b', 'c']);
  });

  it('deduplicates repeated ids', () => {
    const ids = extractDependencyIds({
      distribution: { supersedes: ['a', 'a'] },
      dependencies: ['a'],
    });
    expect(ids).toEqual(['a']);
  });

  it('returns empty when no dependency fields are present', () => {
    expect(extractDependencyIds({ foo: 'bar' })).toEqual([]);
  });

  it('ignores non-string and empty-string entries', () => {
    const ids = extractDependencyIds({
      distribution: { supersedes: ['', 42, 'keep'] },
      dependencies: [null, ''],
    });
    expect(ids).toEqual(['keep']);
  });
});

// ---- pullArtifact (core) ----

describe('pullArtifact', () => {
  it('pulls a published AgentBOM by CAS id and verifies integrity', () => {
    const casId = publish(VALID_AGENTBOM);
    const result = pullArtifact(casId, registryDir);

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.casId).toBe(casId);
    expect(result.resolvedVia).toBe('cas-id');
    expect(result.artifactType).toBe('agentbom');
    expect(result.integrityVerified).toBe(true);
    expect(result.computedCasId).toBe(casId);
    expect(result.version).toBe(1);
    expect(result.sizeBytes).toBeGreaterThan(0);
    expect(result.registryPath).toContain(registryDir);
    expect(result.dependencyIds).toEqual([]);
    expect(result.artifact).toEqual(VALID_AGENTBOM);
  });

  it('pulls a published MCP Posture artifact', () => {
    const casId = publish(VALID_MCP_POSTURE);
    const result = pullArtifact(casId, registryDir);
    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;
    expect(result.artifactType).toBe('mcp-posture');
    expect(result.integrityVerified).toBe(true);
  });

  it('pulls a published Trust Passport artifact', () => {
    const casId = publish(VALID_TRUST_PASSPORT);
    const result = pullArtifact(casId, registryDir);
    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;
    expect(result.artifactType).toBe('trust-passport');
    expect(result.integrityVerified).toBe(true);
  });

  it('pulls by tag label and reports resolvedVia tag', () => {
    const casId = publish(VALID_AGENTBOM, 'latest');
    const result = pullArtifact('latest', registryDir);

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.casId).toBe(casId);
    expect(result.resolvedVia).toBe('tag');
    expect(result.viaTag).toBe('latest');
    expect(result.integrityVerified).toBe(true);
  });

  it('returns an error string for an unresolvable artifact id', () => {
    const result = pullArtifact('unknown-tag', registryDir);
    expect(typeof result).toBe('string');
    expect(result).toContain('could not be resolved');
  });

  it('returns an error string when the CAS id is absent from the registry', () => {
    const result = pullArtifact(`sha256:${'0'.repeat(64)}`, registryDir);
    expect(typeof result).toBe('string');
    expect(result).toContain('not present in registry');
  });

  it('reports integrity failure (but still returns a result) when content is tampered', () => {
    const casId = publish(VALID_AGENTBOM);
    const objectPath = objectPathForCasId(casId, registryDir);
    writeFileSync(objectPath, JSON.stringify({ ...VALID_AGENTBOM, tampered: true }), 'utf-8');

    const result = pullArtifact(casId, registryDir);
    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.integrityVerified).toBe(false);
    expect(result.computedCasId).not.toBe(casId);
    expect(result.casId).toBe(casId);
  });

  it('returns an error string when the stored object is corrupt JSON', () => {
    const casId = publish(VALID_AGENTBOM);
    writeFileSync(objectPathForCasId(casId, registryDir), '{ not valid json', 'utf-8');
    const result = pullArtifact(casId, registryDir);
    expect(typeof result).toBe('string');
    expect(result).toContain('not valid JSON');
  });

  it('extracts distribution.supersedes as dependency ids', () => {
    const dep = { ...VALID_AGENTBOM, distribution: { supersedes: ['sha256:predecessor'] } };
    const casId = publish(dep);
    const result = pullArtifact(casId, registryDir);
    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;
    expect(result.dependencyIds).toEqual(['sha256:predecessor']);
    expect(result.resolvedDependencies).toEqual([]);
  });

  it('resolves dependencies transitively when withDeps is set', () => {
    const predecessorCasId = publish(VALID_AGENTBOM);
    const successor = {
      ...VALID_MCP_POSTURE,
      distribution: { supersedes: [predecessorCasId] },
    };
    const successorCasId = publish(successor);

    const result = pullArtifact(successorCasId, registryDir, true);
    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.dependencyIds).toEqual([predecessorCasId]);
    expect(result.resolvedDependencies).toHaveLength(1);
    const dep = result.resolvedDependencies[0];
    expect(dep.resolved).toBe(true);
    expect(dep.casId).toBe(predecessorCasId);
    expect(dep.integrityVerified).toBe(true);
    expect(dep.artifactType).toBe('agentbom');
    expect(dep.version).toBe(1);
  });

  it('reports unresolved dependencies without throwing', () => {
    // An unknown tag label cannot be resolved to a CAS id at all.
    const successor = {
      ...VALID_AGENTBOM,
      distribution: { supersedes: ['unknown-tag-dep'] },
    };
    const successorCasId = publish(successor);

    const result = pullArtifact(successorCasId, registryDir, true);
    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    const dep = result.resolvedDependencies[0];
    expect(dep.resolved).toBe(false);
    expect(dep.casId).toBeUndefined();
    expect(dep.error).toContain('not found');
  });

  it('reports a dependency given as a CAS id that is absent from the registry', () => {
    // A well-formed CAS id that simply has no stored object: we know the id,
    // but the object is missing, so resolved=false with a "not present" error.
    const absentCasId = `sha256:${'9'.repeat(64)}`;
    const successor = {
      ...VALID_AGENTBOM,
      distribution: { supersedes: [absentCasId] },
    };
    const successorCasId = publish(successor);

    const result = pullArtifact(successorCasId, registryDir, true);
    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    const dep = result.resolvedDependencies[0];
    expect(dep.resolved).toBe(false);
    expect(dep.casId).toBe(absentCasId);
    expect(dep.error).toContain('not present');
  });

  it('is cycle-safe — mutual supersession does not loop forever', () => {
    // Publish B (plain) to learn its CAS id, publish A referencing B, then
    // rewrite B's stored object so B also references A. This yields a
    // dependency cycle A <-> B without a content-hashing fixed point.
    const aBase = {
      ...VALID_AGENTBOM,
      identity: { ...VALID_AGENTBOM.identity, agent_id: 'agent-a' },
    };
    const bBase = {
      ...VALID_AGENTBOM,
      identity: { ...VALID_AGENTBOM.identity, agent_id: 'agent-b' },
    };

    const bCasId = publish(bBase);
    const aData = { ...aBase, distribution: { supersedes: [bCasId] } };
    const aCasId = publish(aData);
    const bData = { ...bBase, distribution: { supersedes: [aCasId] } };
    writeFileSync(objectPathForCasId(bCasId, registryDir), JSON.stringify(bData), 'utf-8');

    // Pulling A with deps must terminate (this assertion itself proves no
    // infinite loop) and surface a cycle marker somewhere in the tree.
    const result = pullArtifact(aCasId, registryDir, true);
    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.resolvedDependencies[0].casId).toBe(bCasId);

    const errors = collectTreeErrors(result.resolvedDependencies);
    expect(errors.some((e) => e.includes('cycle'))).toBe(true);
  }, 10000);
});

// ---- resolveDependencies ----

describe('resolveDependencies', () => {
  it('returns empty for no dependencies', () => {
    expect(resolveDependencies([], registryDir, true)).toEqual([]);
  });

  it('does not recurse when recurse is false', () => {
    const predecessorCasId = publish(VALID_AGENTBOM);
    const successor = {
      ...VALID_AGENTBOM,
      identity: { ...VALID_AGENTBOM.identity, agent_id: 'succ' },
      distribution: { supersedes: [predecessorCasId] },
    };
    const successorCasId = publish(successor);

    const deps = resolveDependencies([successorCasId], registryDir, false);
    expect(deps).toHaveLength(1);
    expect(deps[0].resolved).toBe(true);
    // Without recursion, the child's own dependencies are not expanded.
    expect(deps[0].dependencies).toBeUndefined();
  });
});

// ---- parsePullArgs ----

describe('parsePullArgs', () => {
  it('returns usage string for --help', () => {
    const result = parsePullArgs(['--help']);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('returns usage string for -h', () => {
    const result = parsePullArgs(['-h']);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('returns usage string for empty args', () => {
    const result = parsePullArgs([]);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('parses required positional artifact id', () => {
    const result = parsePullArgs(['sha256:abc']);
    expect(typeof result).not.toBe('string');
    const config = result as PullConfig;
    expect(config.artifactId).toBe('sha256:abc');
    expect(config.registryDir).toContain('.trust-registry');
    expect(config.withDeps).toBe(false);
    expect(config.outputPath).toBeUndefined();
  });

  it('parses --registry flag', () => {
    const result = parsePullArgs(['latest', '--registry', '/my-registry']);
    expect(typeof result).not.toBe('string');
    const config = result as PullConfig;
    expect(config.registryDir).toBe('/my-registry');
  });

  it('parses --output flag', () => {
    const result = parsePullArgs(['latest', '--output', './out.json']);
    expect(typeof result).not.toBe('string');
    const config = result as PullConfig;
    expect(config.outputPath).toContain('out.json');
  });

  it('parses --with-deps flag', () => {
    const result = parsePullArgs(['latest', '--with-deps']);
    expect(typeof result).not.toBe('string');
    const config = result as PullConfig;
    expect(config.withDeps).toBe(true);
  });

  it('parses all flags together', () => {
    const result = parsePullArgs([
      'latest',
      '--registry',
      './reg',
      '--output',
      './out.json',
      '--with-deps',
    ]);
    expect(typeof result).not.toBe('string');
    const config = result as PullConfig;
    expect(config.artifactId).toBe('latest');
    expect(config.registryDir).toContain('reg');
    expect(config.outputPath).toContain('out.json');
    expect(config.withDeps).toBe(true);
  });

  it('returns error for unknown flag', () => {
    const result = parsePullArgs(['latest', '--bogus']);
    expect(typeof result).toBe('string');
    expect(result).toContain('unknown argument');
  });

  it('returns error for --registry without value', () => {
    const result = parsePullArgs(['latest', '--registry']);
    expect(typeof result).toBe('string');
    expect(result).toContain('unknown argument');
  });

  it('returns error for --output without value', () => {
    const result = parsePullArgs(['latest', '--output']);
    expect(typeof result).toBe('string');
    expect(result).toContain('unknown argument');
  });
});

// ---- Integration: pull command via runCommand ----

import { runCommand } from './index.js';

describe('pull command via runCommand', () => {
  it('shows help for pull --help', () => {
    const spy = spyOn(console, 'log');
    const result = runCommand(['pull', '--help']);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('Usage:');
    expect(output).toContain('<artifact-id>');
    expect(output).toContain('--registry');
    expect(output).toContain('--with-deps');
    expect(output).toContain('--output');
  });

  it('returns 1 for pull with unknown flag', () => {
    const spy = spyOn(console, 'error');
    const result = runCommand(['pull', 'latest', '--bogus']);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('unknown argument');
  });

  it('returns 1 for an unresolvable artifact id', () => {
    const spy = spyOn(console, 'error');
    const result = runCommand(['pull', 'unknown-tag', '--registry', registryDir]);
    expect(result).toBe(1);
    expect(spy).toHaveBeenCalled();
  });

  it('returns 1 when the CAS id is missing from the registry', () => {
    const spy = spyOn(console, 'error');
    const result = runCommand(['pull', `sha256:${'0'.repeat(64)}`, '--registry', registryDir]);
    expect(result).toBe(1);
    expect(spy).toHaveBeenCalled();
  });

  it('returns 0 and prints JSON for a valid pull by CAS id', () => {
    const casId = publish(VALID_AGENTBOM);
    const spy = spyOn(console, 'log');
    const result = runCommand(['pull', casId, '--registry', registryDir]);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain(casId);
    expect(output).toContain('"integrityVerified": true');
    expect(output).toContain('agentbom');
  });

  it('returns 0 for a valid pull by tag', () => {
    publish(VALID_MCP_POSTURE, 'stable');
    const spy = spyOn(console, 'log');
    const result = runCommand(['pull', 'stable', '--registry', registryDir]);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('mcp-posture');
    expect(output).toContain('"resolvedVia": "tag"');
  });

  it('exits non-zero when integrity verification fails', () => {
    const casId = publish(VALID_AGENTBOM);
    writeFileSync(
      objectPathForCasId(casId, registryDir),
      JSON.stringify({ tampered: true }),
      'utf-8',
    );
    const errSpy = spyOn(console, 'error');
    const result = runCommand(['pull', casId, '--registry', registryDir]);
    expect(result).toBe(1);
    const output = errSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('integrity verification failed');
  });

  it('writes the artifact to --output and still reports metadata', () => {
    const casId = publish(VALID_AGENTBOM);
    const outPath = join(tmpDir, 'pulled.json');
    const spy = spyOn(console, 'log');
    const result = runCommand(['pull', casId, '--registry', registryDir, '--output', outPath]);
    expect(result).toBe(0);
    expect(existsSync(outPath)).toBe(true);
    const written = JSON.parse(readFileSync(outPath, 'utf-8'));
    expect(written).toEqual(VALID_AGENTBOM);
    expect(spy).toHaveBeenCalled();
  });

  it('resolves dependencies via --with-deps', () => {
    const predecessorCasId = publish(VALID_AGENTBOM);
    const successor = {
      ...VALID_AGENTBOM,
      identity: { ...VALID_AGENTBOM.identity, agent_id: 'succ-cli' },
      distribution: { supersedes: [predecessorCasId] },
    };
    const successorCasId = publish(successor);

    const spy = spyOn(console, 'log');
    const result = runCommand(['pull', successorCasId, '--registry', registryDir, '--with-deps']);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain(predecessorCasId);
    expect(output).toContain('"resolvedDependencies"');
  });
});
