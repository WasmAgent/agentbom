import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { validateTrustPassport } from '@openagentaudit/passport';
/**
 * passport sign — Sign a Trust Passport JSON as a JWT using Ed25519 (EdDSA).
 *
 * Uses @wasmagent/aep's LocalEd25519Signer (backed by @noble/ed25519) to align
 * with the signing implementation used across the WasmAgent ecosystem.
 * Previously used node:crypto with manual PKCS#8 DER construction.
 */
import { createLocalSignerFromSeed, LocalEd25519Signer } from '@wasmagent/aep';

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Base64url encode a Buffer or Uint8Array or string. */
function base64url(input: Buffer | Uint8Array | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf-8') : Buffer.from(input);
  return buf.toString('base64url');
}

/** Read an Ed25519 private key seed (32 bytes) from PEM or raw hex format. */
export function readKeySeed(keyPath: string): Uint8Array {
  const raw = readFileSync(keyPath, 'utf-8').trim();

  if (raw.startsWith('-----BEGIN')) {
    // PEM format — extract raw seed bytes from PKCS#8 DER
    // PKCS#8 Ed25519 DER: 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32-byte seed>
    const b64 = raw.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const der = Buffer.from(b64, 'base64');
    // Seed starts at offset 16 in standard PKCS#8 Ed25519 DER
    if (der.length >= 48) {
      return new Uint8Array(der.slice(16, 48));
    }
    throw new Error(
      `Cannot extract seed from PEM in "${keyPath}" — unexpected DER length ${der.length}`,
    );
  }

  // Raw hex format: 64 hex chars = 32 bytes seed
  const hexClean = raw.replace(/\s+/g, '');
  if (/^[0-9a-fA-F]{64}$/.test(hexClean)) {
    return new Uint8Array(Buffer.from(hexClean, 'hex'));
  }

  throw new Error(
    `Unsupported key format in "${keyPath}". Expected PEM (-----BEGIN PRIVATE KEY-----) or 64-char hex seed.`,
  );
}

/** Parse a duration string like "1y", "90d", "6m" into milliseconds. */
function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)\s*(y|m|d|h)$/i);
  if (!match) throw new Error(`Invalid duration format: "${duration}". Use e.g. 1y, 90d, 6m, 24h`);
  const value = Number.parseInt(match[1], 10);
  const unit = match[2].toLowerCase();
  switch (unit) {
    case 'y':
      return value * 365 * 24 * 60 * 60 * 1000;
    case 'm':
      return value * 30 * 24 * 60 * 60 * 1000;
    case 'd':
      return value * 24 * 60 * 60 * 1000;
    case 'h':
      return value * 60 * 60 * 1000;
    default:
      throw new Error(`Unknown duration unit: ${unit}`);
  }
}

export interface SignOptions {
  artifactPath: string;
  keyPath: string;
  expires?: string; // duration like "1y", "90d"
}

/**
 * Sign a Trust Passport JSON and return the JWT string.
 * Uses LocalEd25519Signer from @wasmagent/aep for signing.
 */
export async function signPassport(options: SignOptions): Promise<string> {
  const { artifactPath, keyPath, expires } = options;

  const passportRaw = readFileSync(resolve(artifactPath), 'utf-8');
  const parsedPassport = JSON.parse(passportRaw) as unknown;
  if (!isRecord(parsedPassport)) {
    throw new Error('Invalid passport format: root must be an object');
  }

  // Pre-fill expires_at before validation so signPassport can accept passports
  // without an explicit expiry and add a default (the test contract: "sign adds
  // default expiry when not present").
  const passport = parsedPassport;
  const existingValidity = passport.validity;
  if (existingValidity !== undefined && !isRecord(existingValidity)) {
    throw new Error('Invalid passport format: validity must be an object');
  }
  const validity = existingValidity ?? {};
  if (!('expires_at' in validity)) {
    const expiryMs = expires ? parseDuration(expires) : 365 * 24 * 60 * 60 * 1000;
    validity.expires_at = new Date(Date.now() + expiryMs).toISOString();
    passport.validity = validity;
  }

  // Validate structure after default expiry is applied
  const structureResult = validateTrustPassport(passport);
  if (!structureResult.valid) {
    throw new Error(`Invalid passport format: ${structureResult.errors.join('; ')}`);
  }

  const seed = readKeySeed(resolve(keyPath));
  // Use createLocalSignerFromSeed for hex seeds (v1.21.1 convenience API),
  // fall back to LocalEd25519Signer for raw Uint8Array seeds from PEM.
  const hexSeed = Buffer.from(seed).toString('hex');
  const signer = createLocalSignerFromSeed(hexSeed, 'trust-passport-key');

  const header = { alg: 'EdDSA', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const expiresAtStr = typeof validity.expires_at === 'string' ? validity.expires_at : undefined;
  const exp = expiresAtStr
    ? Math.floor(new Date(expiresAtStr).getTime() / 1000)
    : now + 365 * 24 * 60 * 60;

  const payload = { ...passport, iat: now, exp };

  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  // AEPSigner.sign() returns base64 — we need base64url for JWT
  const sigBase64 = await signer.sign(Buffer.from(signingInput, 'utf-8'));
  const signatureB64url = sigBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return `${signingInput}.${signatureB64url}`;
}

/** CLI entry point for `passport sign`. */
export async function signPassportCommand(args: string[]): Promise<number> {
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(
      [
        'Usage: agent-trust passport sign <artifact.json> --key <key-path> [--expires <duration>]',
        '',
        'Signs a Trust Passport JSON as a JWT using Ed25519 (EdDSA).',
        'Signing uses @wasmagent/aep LocalEd25519Signer (@noble/ed25519).',
        '',
        'Options:',
        '  --key <path>       Path to Ed25519 private key (PEM or 64-char hex seed)',
        '  --expires <dur>    Expiry duration if not set in passport (default: 1y)',
        '                     Formats: 1y, 90d, 6m, 24h',
        '',
        'Output: signed JWT printed to stdout.',
      ].join('\n'),
    );
    return 0;
  }

  let artifactPath = '';
  let keyPath = '';
  let expires: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];
    if (arg === '--key' && next) {
      keyPath = next;
      i++;
    } else if (arg === '--expires' && next) {
      expires = next;
      i++;
    } else if (!arg.startsWith('--') && !artifactPath) {
      artifactPath = arg;
    } else if (!arg.startsWith('--')) {
      console.error(`Error: unexpected argument "${arg}"`);
      return 1;
    }
  }

  if (!artifactPath) {
    console.error('Error: passport sign requires an <artifact.json> argument');
    return 1;
  }
  if (!keyPath) {
    console.error('Error: passport sign requires --key <key-path>');
    return 1;
  }

  try {
    const jwt = await signPassport({ artifactPath, keyPath, expires });
    console.log(jwt);
    return 0;
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}
