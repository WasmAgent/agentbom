/**
 * Tests for `trust-cli verify-chain <passport.jwt> --depth N` — recursive trust
 * chain verification with configurable depth and caching.
 */
import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCommand } from './index.js';
import { publishArtifact } from './trust-publish.js';
import { objectPathForCasId } from './trust-pull.js';
import {
  parseVerifyChainArgs,
  type VerifyChainConfig,
  verifyChain,
  verifyChainCommand,
} from './trust-verify-chain.js';

// ---- Fixtures ----

const VALID_AGENTBOM = {
  agentbom_version: '0.1',
  identity: {
    agent_id: 'test-agent-chain',
    agent_name: 'Test Chain Agent',
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
    snapshot_id: 'snap-chain-001',
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
    passport_id: 'passport-chain-001',
    agent_id: 'test-passport-agent',
    agent_name: 'Test Passport Agent',
    issuer: 'Test Issuer',
    issuance_context: 'development',
  },
  validity: {
    issued_at: '2026-01-01T00:00:00Z',
    expires_at: '2030-01-01T00:00:00Z',
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
    `trust-verify-chain-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
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

/** Publish a fixture and return its CAS id (fails the test if publishing errored). */
function publish(data: unknown, tag?: string): string {
  const path = writeJson(`artifact-${Math.random().toString(36).slice(2)}.json`, data);
  const result = publishArtifact(path, registryDir, tag);
  if (typeof result === 'string') {
    throw new Error(`setup publish failed: ${result}`);
  }
  return result.casId;
}

/** Create a minimal JWT file (unsigned, three base64url parts). */
function writeMinimalJwt(payload: Record<string, unknown>): string {
  const headerB64 = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signatureB64 = Buffer.from('dummy-signature').toString('base64url');
  const jwt = `${headerB64}.${payloadB64}.${signatureB64}`;
  const jwtPath = join(tmpDir, `passport-${Math.random().toString(36).slice(2)}.jwt`);
  writeFileSync(jwtPath, jwt, 'utf-8');
  return jwtPath;
}

// ---- parseVerifyChainArgs ----

describe('parseVerifyChainArgs', () => {
  it('returns usage string for --help', () => {
    const result = parseVerifyChainArgs(['--help']);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('returns usage string for -h', () => {
    const result = parseVerifyChainArgs(['-h']);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('returns usage string for empty args', () => {
    const result = parseVerifyChainArgs([]);
    expect(typeof result).toBe('string');
    expect(result).toContain('Usage:');
  });

  it('parses required positional jwt path', () => {
    const result = parseVerifyChainArgs(['passport.jwt']);
    expect(typeof result).not.toBe('string');
    const config = result as VerifyChainConfig;
    expect(config.jwtPath).toContain('passport.jwt');
    expect(config.maxDepth).toBe(3);
    expect(config.publicKeyPath).toBeUndefined();
  });

  it('parses --depth flag', () => {
    const result = parseVerifyChainArgs(['passport.jwt', '--depth', '5']);
    expect(typeof result).not.toBe('string');
    const config = result as VerifyChainConfig;
    expect(config.maxDepth).toBe(5);
  });

  it('parses --depth 0', () => {
    const result = parseVerifyChainArgs(['passport.jwt', '--depth', '0']);
    expect(typeof result).not.toBe('string');
    const config = result as VerifyChainConfig;
    expect(config.maxDepth).toBe(0);
  });

  it('rejects negative --depth', () => {
    const result = parseVerifyChainArgs(['passport.jwt', '--depth', '-1']);
    expect(typeof result).toBe('string');
    expect(result).toContain('non-negative integer');
  });

  it('rejects non-integer --depth', () => {
    const result = parseVerifyChainArgs(['passport.jwt', '--depth', 'abc']);
    expect(typeof result).toBe('string');
    expect(result).toContain('non-negative integer');
  });

  it('parses --key flag', () => {
    const result = parseVerifyChainArgs(['passport.jwt', '--key', 'pubkey.pem']);
    expect(typeof result).not.toBe('string');
    const config = result as VerifyChainConfig;
    expect(config.publicKeyPath).toContain('pubkey.pem');
  });

  it('parses --registry flag', () => {
    const result = parseVerifyChainArgs(['passport.jwt', '--registry', '/my-registry']);
    expect(typeof result).not.toBe('string');
    const config = result as VerifyChainConfig;
    expect(config.registryDir).toBe('/my-registry');
  });

  it('parses all flags together', () => {
    const result = parseVerifyChainArgs([
      'passport.jwt',
      '--depth',
      '10',
      '--key',
      'key.pem',
      '--registry',
      './reg',
    ]);
    expect(typeof result).not.toBe('string');
    const config = result as VerifyChainConfig;
    expect(config.maxDepth).toBe(10);
    expect(config.publicKeyPath).toContain('key.pem');
    expect(config.registryDir).toContain('reg');
  });

  it('returns error for unknown flag', () => {
    const result = parseVerifyChainArgs(['passport.jwt', '--bogus']);
    expect(typeof result).toBe('string');
    expect(result).toContain('unknown argument');
  });

  it('returns error for --depth without value', () => {
    const result = parseVerifyChainArgs(['passport.jwt', '--depth']);
    expect(typeof result).toBe('string');
    expect(result).toContain('unknown argument');
  });

  it('returns error for --key without value', () => {
    const result = parseVerifyChainArgs(['passport.jwt', '--key']);
    expect(typeof result).toBe('string');
    expect(result).toContain('unknown argument');
  });

  it('returns error for --registry without value', () => {
    const result = parseVerifyChainArgs(['passport.jwt', '--registry']);
    expect(typeof result).toBe('string');
    expect(result).toContain('unknown argument');
  });
});

// ---- verifyChain (core) ----

describe('verifyChain', () => {
  it('returns error string for nonexistent JWT file', () => {
    const result = verifyChain({
      jwtPath: '/nonexistent/passport.jwt',
      maxDepth: 3,
      registryDir,
    });
    expect(typeof result).toBe('string');
    expect(result).toContain('failed to read JWT');
  });

  it('returns error string for malformed JWT (not three parts)', () => {
    const jwtPath = join(tmpDir, 'bad.jwt');
    writeFileSync(jwtPath, 'not-a-jwt', 'utf-8');
    const result = verifyChain({
      jwtPath,
      maxDepth: 3,
      registryDir,
    });
    expect(typeof result).toBe('string');
    expect(result).toContain('JWT');
  });

  it('returns error string for invalid JSON payload in JWT', () => {
    const headerB64 = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString(
      'base64url',
    );
    const payloadB64 = Buffer.from('not-valid-json').toString('base64url');
    const sigB64 = Buffer.from('x').toString('base64url');
    const jwtPath = join(tmpDir, 'bad-payload.jwt');
    writeFileSync(jwtPath, `${headerB64}.${payloadB64}.${sigB64}`, 'utf-8');

    const result = verifyChain({
      jwtPath,
      maxDepth: 3,
      registryDir,
    });
    expect(typeof result).toBe('string');
    expect(result).toContain('payload');
  });

  it('verifies a valid passport JWT with no references (depth 0)', () => {
    const jwtPath = writeMinimalJwt(VALID_TRUST_PASSPORT);

    const result = verifyChain({
      jwtPath,
      maxDepth: 0,
      registryDir,
    });

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    // Root should have structure valid (even without key, structure check passes)
    expect(result.root.structureValid).toBe(true);
    expect(result.root.payload).toBeTruthy();
    expect(result.valid).toBe(false); // signature not verified without key
    expect(result.totalNodes).toBe(0);
    expect(result.depthReached).toBe(0);
  });

  it('reports signature errors when no key is provided', () => {
    const jwtPath = writeMinimalJwt(VALID_TRUST_PASSPORT);

    const result = verifyChain({
      jwtPath,
      maxDepth: 3,
      registryDir,
    });

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.root.signatureValid).toBe(false);
    expect(result.root.errors).toContain('No public key provided; signature not verified');
    expect(result.valid).toBe(false);
  });

  it('follows agentbom_ref and posture_ref when artifacts exist in registry', () => {
    const bomCasId = publish(VALID_AGENTBOM);
    const postureCasId = publish(VALID_MCP_POSTURE);

    const passportWithRefs = {
      ...VALID_TRUST_PASSPORT,
      agentbom_ref: { agentbom_id: bomCasId },
      posture_ref: { snapshot_id: postureCasId },
    };
    const jwtPath = writeMinimalJwt(passportWithRefs);

    const result = verifyChain({
      jwtPath,
      maxDepth: 3,
      registryDir,
    });

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.totalNodes).toBe(2);
    expect(result.nodes[0].reference).toBe(bomCasId);
    expect(result.nodes[0].nodeType).toBe('agentbom');
    expect(result.nodes[0].integrityVerified).toBe(true);
    expect(result.nodes[1].reference).toBe(postureCasId);
    expect(result.nodes[1].nodeType).toBe('mcp-posture');
    expect(result.nodes[1].integrityVerified).toBe(true);
    expect(result.depthReached).toBe(1);
    expect(result.cacheMisses).toBe(2);
    expect(result.cacheHits).toBe(0);
  });

  it('respects --depth 0 and does not follow references', () => {
    const bomCasId = publish(VALID_AGENTBOM);
    const passportWithRefs = {
      ...VALID_TRUST_PASSPORT,
      agentbom_ref: { agentbom_id: bomCasId },
    };
    const jwtPath = writeMinimalJwt(passportWithRefs);

    const result = verifyChain({
      jwtPath,
      maxDepth: 0,
      registryDir,
    });

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.totalNodes).toBe(0);
    expect(result.depthReached).toBe(0);
  });

  it('reports errors for unresolvable artifact references', () => {
    const passportWithRefs = {
      ...VALID_TRUST_PASSPORT,
      agentbom_ref: { agentbom_id: 'sha256:nonexistent' },
    };
    const jwtPath = writeMinimalJwt(passportWithRefs);

    const result = verifyChain({
      jwtPath,
      maxDepth: 3,
      registryDir,
    });

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.totalNodes).toBe(1);
    expect(result.nodes[0].valid).toBe(false);
    expect(result.nodes[0].errors[0]).toContain('could not be resolved');
    expect(result.valid).toBe(false);
  });

  it('reports integrity failure for tampered registry artifacts', () => {
    const bomCasId = publish(VALID_AGENTBOM);
    // Tamper the stored artifact
    const objPath = objectPathForCasId(bomCasId, registryDir);
    writeFileSync(objPath, JSON.stringify({ tampered: true }), 'utf-8');

    const passportWithRefs = {
      ...VALID_TRUST_PASSPORT,
      agentbom_ref: { agentbom_id: bomCasId },
    };
    const jwtPath = writeMinimalJwt(passportWithRefs);

    const result = verifyChain({
      jwtPath,
      maxDepth: 3,
      registryDir,
    });

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    expect(result.totalNodes).toBe(1);
    expect(result.nodes[0].integrityVerified).toBe(false);
    expect(result.nodes[0].errors.some((e) => e.includes('integrity'))).toBe(true);
    expect(result.valid).toBe(false);
  });

  it('detects and prevents cycles', () => {
    // Create two AgentBOM artifacts that reference each other via dependencies.
    // Publish clean AgentBOMs first (dependencies would break validation),
    // then mutate the stored objects to add cross-references.
    const aBase = {
      ...VALID_AGENTBOM,
      identity: { ...VALID_AGENTBOM.identity, agent_id: 'agent-a' },
    };
    const bBase = {
      ...VALID_AGENTBOM,
      identity: { ...VALID_AGENTBOM.identity, agent_id: 'agent-b' },
    };

    const bCasId = publish(bBase);
    const aCasId = publish(aBase);

    // Mutate A to reference B
    const aPath = objectPathForCasId(aCasId, registryDir);
    writeFileSync(aPath, JSON.stringify({ ...aBase, dependencies: [{ id: bCasId }] }), 'utf-8');
    // Mutate B to reference A (creating a cycle)
    const bPath = objectPathForCasId(bCasId, registryDir);
    writeFileSync(bPath, JSON.stringify({ ...bBase, dependencies: [{ id: aCasId }] }), 'utf-8');

    const passportWithRefs = {
      ...VALID_TRUST_PASSPORT,
      agentbom_ref: { agentbom_id: aCasId },
    };
    const jwtPath = writeMinimalJwt(passportWithRefs);

    // This should terminate (not infinite loop) — the assertion itself proves termination
    const result = verifyChain({
      jwtPath,
      maxDepth: 10,
      registryDir,
    });

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    // Cycle should be detected and reported
    const cycleErrors = result.nodes.flatMap((n) => n.errors);
    expect(cycleErrors.some((e) => e.includes('cycle'))).toBe(true);
  }, 10000);

  it('caches repeated artifact references across the chain', () => {
    const sharedCasId = publish(VALID_AGENTBOM);

    // Passport references the same artifact twice via different paths
    const passportWithRefs = {
      ...VALID_TRUST_PASSPORT,
      agentbom_ref: { agentbom_id: sharedCasId },
      dependencies: [sharedCasId],
    };
    const jwtPath = writeMinimalJwt(passportWithRefs);

    const result = verifyChain({
      jwtPath,
      maxDepth: 3,
      registryDir,
    });

    expect(typeof result).not.toBe('string');
    if (typeof result === 'string') return;

    // Second reference should be a cache hit
    expect(result.cacheHits).toBeGreaterThan(0);
    expect(result.cacheMisses).toBe(1);
  });
});

// ---- Integration: verify-chain command via runCommand ----

describe('verify-chain command via runCommand', () => {
  it('shows help for verify-chain --help', () => {
    const spy = spyOn(console, 'log');
    const result = runCommand(['verify-chain', '--help']);
    expect(result).toBe(0);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('Usage:');
    expect(output).toContain('<passport.jwt>');
    expect(output).toContain('--depth');
    expect(output).toContain('--key');
    expect(output).toContain('--registry');
  });

  it('returns 1 for verify-chain with no args', () => {
    const spy = spyOn(console, 'log');
    const result = runCommand(['verify-chain']);
    expect(result).toBe(0); // --help for empty args
  });

  it('returns 1 for verify-chain with unknown flag', () => {
    const spy = spyOn(console, 'error');
    const result = runCommand(['verify-chain', 'passport.jwt', '--bogus']);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('unknown argument');
  });

  it('returns 1 for nonexistent JWT file', () => {
    const spy = spyOn(console, 'error');
    const result = runCommand([
      'verify-chain',
      '/nonexistent/passport.jwt',
      '--registry',
      registryDir,
    ]);
    expect(result).toBe(1);
    expect(spy).toHaveBeenCalled();
  });

  it('returns 1 for invalid --depth value', () => {
    const spy = spyOn(console, 'error');
    const result = runCommand(['verify-chain', 'p.jwt', '--depth', 'abc']);
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('non-negative integer');
  });

  it('prints JSON output for a valid chain verification', () => {
    const jwtPath = writeMinimalJwt(VALID_TRUST_PASSPORT);
    const spy = spyOn(console, 'log');
    const result = runCommand(['verify-chain', jwtPath, '--depth', '3', '--registry', registryDir]);
    // Result should be non-zero because no key provided (signature not verified)
    expect(result).toBe(1);
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('"root"');
    expect(output).toContain('"signatureValid"');
    expect(output).toContain('"structureValid"');
    expect(output).toContain('"totalNodes"');
    expect(output).toContain('"depthReached"');
    expect(output).toContain('"cacheHits"');
    expect(output).toContain('"cacheMisses"');
  });

  it('prints JSON output with chain nodes when artifacts are in registry', () => {
    const bomCasId = publish(VALID_AGENTBOM);
    const passportWithRefs = {
      ...VALID_TRUST_PASSPORT,
      agentbom_ref: { agentbom_id: bomCasId },
    };
    const jwtPath = writeMinimalJwt(passportWithRefs);
    const spy = spyOn(console, 'log');
    const result = runCommand(['verify-chain', jwtPath, '--depth', '3', '--registry', registryDir]);

    expect(result).toBe(1); // signature not verified
    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('"nodes"');
    expect(output).toContain(bomCasId);
    expect(output).toContain('"agentbom"');
    expect(output).toContain('"integrityVerified": true');
  });
});
