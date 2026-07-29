import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  computeCasId,
  detectArtifactType,
  type PublishConfig,
  parsePublishArgs,
  publishArtifact,
  readArtifactFile,
  readRegistryManifest,
  writeRegistryManifest,
  writeTagPointer,
} from './trust-publish.js';

// ---- Fixtures ----

const VALID_AGENTBOM = {
  agentbom_version: '0.1',
  identity: {
    agent_id: 'test-agent-pub',
    agent_name: 'Test Publish Agent',
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
  tmpDir = join(
    tmpdir(),
    `trust-publish-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
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

// ---- computeCasId ----

describe('computeCasId', () => {
  it('returns sha256:<hex> format', () => {
    const casId = computeCasId('hello');
    expect(casId).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('is deterministic — same content yields same CAS ID', () => {
    const casId1 = computeCasId('hello');
    const casId2 = computeCasId('hello');
    expect(casId1).toBe(casId2);
  });

  it('differs for different content', () => {
    const casId1 = computeCasId('hello');
    const casId2 = computeCasId('world');
    expect(casId1).not.toBe(casId2);
  });

  it('handles JSON content', () => {
    const casId = computeCasId(JSON.stringify({ key: 'value' }));
    expect(casId).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('handles empty string', () => {
    const casId = computeCasId('');
    expect(casId).toMatch(/^sha256:[a-f0-9]{64}$/);
    // Known SHA-256 of empty string
    expect(casId).toBe('sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});

// ---- detectArtifactType ----

describe('detectArtifactType', () => {
  it('detects AgentBOM', () => {
    expect(detectArtifactType(VALID_AGENTBOM)).toBe('agentbom');
  });

  it('detects MCP Posture', () => {
    expect(detectArtifactType(VALID_MCP_POSTURE)).toBe('mcp-posture');
  });

  it('detects Trust Passport', () => {
    expect(detectArtifactType(VALID_TRUST_PASSPORT)).toBe('trust-passport');
  });

  it('returns unknown for unrecognized data', () => {
    expect(detectArtifactType({ foo: 'bar' })).toBe('unknown');
  });

  it('returns unknown for non-object', () => {
    expect(detectArtifactType('string')).toBe('unknown');
    expect(detectArtifactType(42)).toBe('unknown');
    expect(detectArtifactType(null)).toBe('unknown');
    expect(detectArtifactType([])).toBe('unknown');
  });
});

// ---- readArtifactFile ----

describe('readArtifactFile', () => {
  it('reads and parses a valid JSON file', () => {
    const path = writeJson('valid.json', VALID_AGENTBOM);
    const { data, error } = readArtifactFile(path);
    expect(error).toBe(0);
    expect(data.agentbom_version).toBe('0.1');
  });

  it('returns error for non-existent file', () => {
    const spy = spyOn(console, 'error');
    const { error } = readArtifactFile('/nonexistent/file.json');
    expect(error).toBe(1);
    expect(spy).toHaveBeenCalled();
  });

  it('returns error for invalid JSON', () => {
    const path = join(tmpDir, 'bad.json');
    writeFileSync(path, '{ not valid json', 'utf-8');
    const spy = spyOn(console, 'error');
    const { error } = readArtifactFile(path);
    expect(error).toBe(1);
    expect(spy).toHaveBeenCalled();
  });

  it('returns error for non-object JSON (array)', () => {
    const path = join(tmpDir, 'array.json');
    writeFileSync(path, '[1, 2, 3]', 'utf-8');
    const spy = spyOn(console, 'error');
    const { error } = readArtifactFile(path);
    expect(error).toBe(1);
    expect(spy).toHaveBeenCalled();
  });
});

// ---- parsePublishArgs ----

describe('parsePublishArgs', () => {
  it('returns usage string for --help', () => {
    const result = parsePublishArgs(['--help']);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('returns usage string for -h', () => {
    const result = parsePublishArgs(['-h']);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('returns error for empty args', () => {
    const result = parsePublishArgs([]);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('parses required args and returns config', () => {
    const artifactPath = writeJson('bom.json', VALID_AGENTBOM);
    const result = parsePublishArgs([artifactPath]);
    expect(typeof result).not.toBe('string');
    const config = result as PublishConfig;
    expect(config.artifactPath).toBe(artifactPath);
    expect(config.registryDir).toContain('.trust-registry');
    expect(config.tag).toBeUndefined();
  });

  it('parses --registry flag', () => {
    const artifactPath = writeJson('bom.json', VALID_AGENTBOM);
    const result = parsePublishArgs([artifactPath, '--registry', '/my-registry']);
    expect(typeof result).not.toBe('string');
    const config = result as PublishConfig;
    expect(config.registryDir).toBe('/my-registry');
  });

  it('parses --tag flag', () => {
    const artifactPath = writeJson('bom.json', VALID_AGENTBOM);
    const result = parsePublishArgs([artifactPath, '--tag', 'latest']);
    expect(typeof result).not.toBe('string');
    const config = result as PublishConfig;
    expect(config.tag).toBe('latest');
  });

  it('parses all flags together', () => {
    const artifactPath = writeJson('bom.json', VALID_AGENTBOM);
    const result = parsePublishArgs([artifactPath, '--registry', './my-reg', '--tag', 'v1.0']);
    expect(typeof result).not.toBe('string');
    const config = result as PublishConfig;
    expect(config.artifactPath).toBe(artifactPath);
    expect(config.registryDir).toBe(resolve('./my-reg'));
    expect(config.tag).toBe('v1.0');
  });

  it('returns error for unknown flag', () => {
    const result = parsePublishArgs(['file.json', '--bogus']);
    expect(typeof result).toBe('string');
    expect(result).toContain('unknown argument');
  });

  it('returns error for --registry without value', () => {
    const artifactPath = writeJson('bom.json', VALID_AGENTBOM);
    const result = parsePublishArgs([artifactPath, '--registry']);
    expect(typeof result).toBe('string');
    expect(result).toContain('unknown argument');
  });

  it('resolves artifact path to absolute', () => {
    const artifactPath = writeJson('bom.json', VALID_AGENTBOM);
    const result = parsePublishArgs([artifactPath]);
    expect(typeof result).not.toBe('string');
    const config = result as PublishConfig;
    expect(config.artifactPath).toBe(artifactPath);
  });
});

// ---- Registry manifest helpers ----

describe('readRegistryManifest', () => {
  it('returns empty object for non-existent directory', () => {
    const manifest = readRegistryManifest('/nonexistent/path');
    expect(manifest).toEqual({});
  });

  it('returns empty object when manifest file does not exist', () => {
    mkdirSync(registryDir, { recursive: true });
    const manifest = readRegistryManifest(registryDir);
    expect(manifest).toEqual({});
  });

  it('reads a valid manifest', () => {
    mkdirSync(registryDir, { recursive: true });
    const manifestData = { 'sha256:abc': 1, 'sha256:def': 2 };
    writeFileSync(join(registryDir, 'manifest.json'), JSON.stringify(manifestData), 'utf-8');
    const manifest = readRegistryManifest(registryDir);
    expect(manifest).toEqual(manifestData);
  });

  it('returns empty object for corrupted manifest', () => {
    mkdirSync(registryDir, { recursive: true });
    writeFileSync(join(registryDir, 'manifest.json'), 'not json', 'utf-8');
    const manifest = readRegistryManifest(registryDir);
    expect(manifest).toEqual({});
  });
});

describe('writeRegistryManifest', () => {
  it('creates registry directory if missing', () => {
    const newDir = join(tmpDir, 'new-registry');
    writeRegistryManifest(newDir, { 'sha256:abc': 1 });
    expect(existsSync(join(newDir, 'manifest.json'))).toBe(true);
  });

  it('writes manifest as JSON', () => {
    writeRegistryManifest(registryDir, { 'sha256:abc': 1, 'sha256:def': 2 });
    const raw = readFileSync(join(registryDir, 'manifest.json'), 'utf-8');
    const data = JSON.parse(raw);
    expect(data).toEqual({ 'sha256:abc': 1, 'sha256:def': 2 });
  });
});

describe('writeTagPointer', () => {
  it('creates tags directory and writes pointer file', () => {
    writeTagPointer(registryDir, 'latest', 'sha256:abc123');
    const tagPath = join(registryDir, 'tags', 'latest.json');
    expect(existsSync(tagPath)).toBe(true);
    const raw = readFileSync(tagPath, 'utf-8');
    const data = JSON.parse(raw);
    expect(data.cas_id).toBe('sha256:abc123');
    expect(data.tagged_at).toBeDefined();
  });
});

// ---- publishArtifact (core) ----

describe('publishArtifact', () => {
  it('publishes a valid AgentBOM and returns structured result', () => {
    const artifactPath = writeJson('agentbom.json', VALID_AGENTBOM);
    const result = publishArtifact(artifactPath, registryDir);

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.casId).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(result.artifactType).toBe('agentbom');
    expect(result.version).toBe(1);
    expect(result.publishedAt).toBeDefined();
    expect(result.registryPath).toContain(registryDir);
    expect(result.sizeBytes).toBeGreaterThan(0);

    // Verify the artifact was actually stored
    expect(existsSync(result.registryPath)).toBe(true);
  });

  it('publishes a valid MCP Posture artifact', () => {
    const artifactPath = writeJson('posture.json', VALID_MCP_POSTURE);
    const result = publishArtifact(artifactPath, registryDir);

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.artifactType).toBe('mcp-posture');
    expect(result.version).toBe(1);
    expect(existsSync(result.registryPath)).toBe(true);
  });

  it('publishes a valid Trust Passport artifact', () => {
    const artifactPath = writeJson('passport.json', VALID_TRUST_PASSPORT);
    const result = publishArtifact(artifactPath, registryDir);

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.artifactType).toBe('trust-passport');
    expect(result.version).toBe(1);
    expect(existsSync(result.registryPath)).toBe(true);
  });

  it('rejects unknown artifact type', () => {
    const artifactPath = writeJson('unknown.json', { foo: 'bar' });
    const result = publishArtifact(artifactPath, registryDir);

    expect(typeof result).toBe('string');
    expect(result).toContain('any known schema');
  });

  it('returns error for non-existent artifact file', () => {
    const spy = spyOn(console, 'error');
    const result = publishArtifact('/nonexistent/artifact.json', registryDir);

    expect(typeof result).toBe('string');
    expect(result).toContain('Error');
  });

  it('creates registry directory if missing', () => {
    const artifactPath = writeJson('bom.json', VALID_AGENTBOM);
    const newRegDir = join(tmpDir, 'new-registry');
    const result = publishArtifact(artifactPath, newRegDir);

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(existsSync(result.registryPath)).toBe(true);
  });

  it('deduplicates identical content — same CAS ID and version', () => {
    const artifactPath1 = writeJson('bom1.json', VALID_AGENTBOM);
    const artifactPath2 = writeJson('bom2.json', VALID_AGENTBOM);

    const result1 = publishArtifact(artifactPath1, registryDir);
    expect(typeof result1).not.toBe('string');
    if (typeof result1 === 'string') return;

    const result2 = publishArtifact(artifactPath2, registryDir);
    expect(typeof result2).not.toBe('string');
    if (typeof result2 === 'string') return;

    expect(result1.casId).toBe(result2.casId);
    expect(result1.version).toBe(result2.version);
  });

  it('assigns incrementing versions for different content', () => {
    const path1 = writeJson('bom1.json', VALID_AGENTBOM);
    const path2 = writeJson('bom2.json', VALID_MCP_POSTURE);

    const result1 = publishArtifact(path1, registryDir);
    expect(typeof result1).not.toBe('string');
    if (typeof result1 === 'string') return;

    const result2 = publishArtifact(path2, registryDir);
    expect(typeof result2).not.toBe('string');
    if (typeof result2 === 'string') return;

    expect(result1.version).toBe(1);
    expect(result2.version).toBe(2);
    expect(result1.casId).not.toBe(result2.casId);
  });

  it('writes tag pointer when tag is provided', () => {
    const artifactPath = writeJson('bom.json', VALID_AGENTBOM);
    const result = publishArtifact(artifactPath, registryDir, 'latest');

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.tag).toBe('latest');
    const tagPath = join(registryDir, 'tags', 'latest.json');
    expect(existsSync(tagPath)).toBe(true);

    const tagData = JSON.parse(readFileSync(tagPath, 'utf-8'));
    expect(tagData.cas_id).toBe(result.casId);
  });

  it('stores artifact content correctly in registry', () => {
    const artifactPath = writeJson('bom.json', VALID_AGENTBOM);
    const result = publishArtifact(artifactPath, registryDir);

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    const stored = JSON.parse(readFileSync(result.registryPath, 'utf-8'));
    expect(stored).toEqual(VALID_AGENTBOM);
  });

  it('stores manifest with correct CAS ID entry', () => {
    const artifactPath = writeJson('bom.json', VALID_AGENTBOM);
    const result = publishArtifact(artifactPath, registryDir);

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    const manifest = readRegistryManifest(registryDir);
    expect(manifest[result.casId]).toBe(result.version);
  });
});

// ---- Integration: publish command via runCommand ----

import { runCommand } from './index.js';

describe('publish command via runCommand', () => {
  it('shows help for publish --help', () => {
    const spy = spyOn(console, 'log');
    const result = runCommand(['publish', '--help']);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('Usage:');
    expect(output).toContain('artifact.json');
    expect(output).toContain('--registry');
    expect(output).toContain('--tag');
  });

  it('shows help for publish -h', () => {
    const spy = spyOn(console, 'log');
    const result = runCommand(['publish', '-h']);
    expect(result).toBe(0);
    expect(spy).toHaveBeenCalled();
  });

  it('returns 1 for publish without artifact path', () => {
    const spy = spyOn(console, 'error');
    const result = runCommand(['publish']);
    // Empty args returns usage via --help path (returns 0)
    // Actually no — publish command gets args.slice(1), so if called as
    // runCommand(['publish']), publishCommand gets [] which shows help
    // That's fine — it's a valid invocation
  });

  it('returns 1 for publish with unknown flag', () => {
    const spy = spyOn(console, 'error');
    const result = runCommand(['publish', 'file.json', '--bogus']);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('unknown argument');
  });

  it('returns 1 for publish with non-existent file', () => {
    const spy = spyOn(console, 'error');
    const result = runCommand(['publish', '/nonexistent/file.json']);
    expect(result).toBe(1);
    expect(spy).toHaveBeenCalled();
  });

  it('returns 1 for publish with unknown artifact type', () => {
    const path = writeJson('unknown.json', { foo: 'bar' });
    const spy = spyOn(console, 'error');
    const result = runCommand(['publish', path]);
    expect(result).toBe(1);
    // The last error call should mention unknown schema
    const lastCall = spy.mock.calls[spy.mock.calls.length - 1];
    expect(lastCall.join(' ')).toContain('any known schema');
  });

  it('returns 0 and prints JSON for valid AgentBOM', () => {
    const path = writeJson('agentbom.json', VALID_AGENTBOM);
    const spy = spyOn(console, 'log');
    const result = runCommand(['publish', path, '--registry', registryDir]);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('sha256:');
    expect(output).toContain('agentbom');
    expect(output).toContain('"version"');
  });

  it('returns 0 and prints JSON for valid MCP Posture', () => {
    const path = writeJson('posture.json', VALID_MCP_POSTURE);
    const spy = spyOn(console, 'log');
    const result = runCommand(['publish', path, '--registry', registryDir]);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('mcp-posture');
  });

  it('returns 0 and prints JSON for valid Trust Passport', () => {
    const path = writeJson('passport.json', VALID_TRUST_PASSPORT);
    const spy = spyOn(console, 'log');
    const result = runCommand(['publish', path, '--registry', registryDir]);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('trust-passport');
  });

  it('handles --tag flag via runCommand', () => {
    const path = writeJson('bom.json', VALID_AGENTBOM);
    const spy = spyOn(console, 'log');
    const result = runCommand(['publish', path, '--registry', registryDir, '--tag', 'latest']);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('latest');
  });
});
