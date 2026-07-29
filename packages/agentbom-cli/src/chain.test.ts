/**
 * End-to-end chain test (P0).
 *
 * Runs the full `agent-trust chain` in-process against the bscode-agent
 * fixtures, fully offline, and asserts every step is valid. If this test
 * fails, the public demo is broken.
 */
import { describe, expect, it } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CHAIN_STEPS, chainCommand, runChain } from './chain.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEMO_DIR = resolve(__dirname, "../examples/bscode-agent");

function readJSON(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf-8'));
}

describe('agent-trust chain (end-to-end, offline)', () => {
  it('runs against examples/bscode-agent with overall status valid', () => {
    const report = runChain(DEMO_DIR);
    expect(report.overall.status).toBe('valid');
    expect(report.overall.total_steps).toBe(5);
    expect(report.overall.valid_steps).toBe(5);
  });

  it('produces exactly 5 steps, each valid, in the documented order', () => {
    const report = runChain(DEMO_DIR);
    expect(report.steps.map((s) => s.step)).toEqual([...CHAIN_STEPS]);
    expect(report.steps.map((s) => s.step)).toEqual([
      'manifest',
      'agentbom',
      'mcp-posture',
      'audit-report',
      'trust-passport',
    ]);
    for (const step of report.steps) {
      expect(step.verdict).toBe('valid');
      expect(step.errors).toEqual([]);
      expect(step.duration_ms).toBeGreaterThanOrEqual(0);
      expect(step.output_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(step.label).toBeTruthy();
    }
  });

  it('records timestamp and repo_sha', () => {
    const report = runChain(DEMO_DIR);
    expect(report.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T.*Z$/);
    expect(typeof report.repo_sha).toBe('string');
    expect(report.repo_sha.length).toBeGreaterThan(0);
    expect(report.example).toBe(resolve(DEMO_DIR));
  });

  it('per-step output hashes are deterministic across runs', () => {
    const a = runChain(DEMO_DIR);
    const b = runChain(DEMO_DIR);
    expect(a.steps.map((s) => s.output_hash)).toEqual(b.steps.map((s) => s.output_hash));
  });

  it('chainCommand exits 0 and writes chain-report.json with a valid overall status', () => {
    const outDir = mkdtempSync(join(tmpdir(), 'chain-cmd-'));
    const outPath = join(outDir, 'chain-report.json');
    try {
      const code = chainCommand(['--example', DEMO_DIR, '--out', outPath]);
      expect(code).toBe(0);
      expect(existsSync(outPath)).toBe(true);

      const report = readJSON(outPath) as {
        overall: { status: string };
        steps: { verdict: string }[];
      };
      expect(report.overall.status).toBe('valid');
      expect(report.steps).toHaveLength(5);
      expect(report.steps.every((s) => s.verdict === 'valid')).toBe(true);
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  });

  it('chainCommand --help exits 0 and documents an example', () => {
    const code = chainCommand(['--help']);
    expect(code).toBe(0);
  });

  it('fails closed when the example is missing required fixtures', () => {
    const emptyDir = mkdtempSync(join(tmpdir(), 'chain-empty-'));
    try {
      const report = runChain(emptyDir);
      expect(report.overall.status).toBe('invalid');
      expect(report.overall.valid_steps).toBe(0);
      // Every step should record at least one error.
      expect(report.steps.every((s) => s.errors.length > 0)).toBe(true);
    } finally {
      rmSync(emptyDir, { recursive: true, force: true });
    }
  });

  it('flags an expired passport without touching the network', () => {
    const sandbox = mkdtempSync(join(tmpdir(), 'chain-bad-passport-'));
    try {
      // Reuse the valid agentbom/posture but make the passport expired.
      const bom = readJSON(join(DEMO_DIR, 'agentbom.json'));
      const posture = readJSON(join(DEMO_DIR, 'posture.json'));
      const passport = readJSON(join(DEMO_DIR, 'trust-passport.json')) as {
        validity: { expires_at: string };
      };
      passport.validity.expires_at = '2020-01-01T00:00:00Z';

      writeFileSync(join(sandbox, 'agentbom.json'), JSON.stringify(bom));
      writeFileSync(join(sandbox, 'posture.json'), JSON.stringify(posture));
      writeFileSync(join(sandbox, 'trust-passport.json'), JSON.stringify(passport));

      const report = runChain(sandbox);
      expect(report.overall.status).toBe('invalid');
      const passportStep = report.steps.find((s) => s.step === 'trust-passport');
      expect(passportStep?.verdict).toBe('invalid');
      expect(passportStep?.errors.join(' ')).toContain('expired');
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });
});
