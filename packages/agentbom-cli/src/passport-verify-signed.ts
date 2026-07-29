/**
 * passport verify-signed — Verify a signed Trust Passport JWT.
 *
 * Reads a signed JWT, verifies the EdDSA signature, checks expiry,
 * validates passport structure, and prints a verification report.
 */
import { createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { isExpired, validateTrustPassport } from '@openagentaudit/passport';

// isRecord is a private utility not exported by @openagentaudit/passport
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Decode a base64url string to a Buffer. */
function base64urlDecode(input: string): Buffer {
  // Add padding if needed
  const padded = input + '='.repeat((4 - (input.length % 4)) % 4);
  return Buffer.from(padded, 'base64url');
}

/** Read an Ed25519 public key from PEM or raw hex format. */
export function readPublicKey(keyPath: string): ReturnType<typeof createPublicKey> {
  const raw = readFileSync(keyPath, 'utf-8').trim();

  if (raw.startsWith('-----BEGIN')) {
    // PEM format
    return createPublicKey(raw);
  }

  // Raw hex format: 64 hex chars = 32 bytes public key
  const hexClean = raw.replace(/\s+/g, '');
  if (/^[0-9a-fA-F]{64}$/.test(hexClean)) {
    const pubBytes = Buffer.from(hexClean, 'hex');
    // Wrap raw public key in SubjectPublicKeyInfo DER for Ed25519
    // Ed25519 SPKI prefix: 302a300506032b6570032100
    const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
    const der = Buffer.concat([spkiPrefix, pubBytes]);
    return createPublicKey({ key: der, format: 'der', type: 'spki' });
  }

  throw new Error(
    `Unsupported key format in "${keyPath}". Expected PEM (-----BEGIN PUBLIC KEY-----) or 64-char hex.`,
  );
}

export interface VerifyResult {
  valid: boolean;
  signatureValid: boolean;
  expired: boolean;
  structureValid: boolean;
  structureErrors: string[];
  payload: Record<string, unknown> | null;
  errors: string[];
}

export interface VerifyOptions {
  jwtPath?: string;
  jwtString?: string;
  publicKeyPath?: string;
}

/**
 * Verify a signed Trust Passport JWT.
 * Returns a detailed verification result.
 */
export function verifySignedPassport(options: VerifyOptions): VerifyResult {
  const errors: string[] = [];
  let jwtString: string;

  if (options.jwtString) {
    jwtString = options.jwtString.trim();
  } else if (options.jwtPath) {
    jwtString = readFileSync(resolve(options.jwtPath), 'utf-8').trim();
  } else {
    return {
      valid: false,
      signatureValid: false,
      expired: false,
      structureValid: false,
      structureErrors: [],
      payload: null,
      errors: ['No JWT input provided (path or string)'],
    };
  }

  // Parse JWT parts
  const parts = jwtString.split('.');
  if (parts.length !== 3) {
    return {
      valid: false,
      signatureValid: false,
      expired: false,
      structureValid: false,
      structureErrors: [],
      payload: null,
      errors: ['Invalid JWT format: expected 3 dot-separated parts'],
    };
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  // Decode header
  let header: Record<string, unknown>;
  try {
    const decodedHeader = JSON.parse(base64urlDecode(headerB64).toString('utf-8')) as unknown;
    if (!isRecord(decodedHeader)) {
      throw new Error('header root is not an object');
    }
    header = decodedHeader;
  } catch {
    return {
      valid: false,
      signatureValid: false,
      expired: false,
      structureValid: false,
      structureErrors: [],
      payload: null,
      errors: ['Failed to decode JWT header'],
    };
  }

  if (header.alg !== 'EdDSA') {
    errors.push(`Unexpected algorithm: "${header.alg}" (expected "EdDSA")`);
  }

  // Decode payload
  let payload: Record<string, unknown>;
  try {
    const decodedPayload = JSON.parse(base64urlDecode(payloadB64).toString('utf-8')) as unknown;
    if (!isRecord(decodedPayload)) {
      throw new Error('payload root is not an object');
    }
    payload = decodedPayload;
  } catch {
    return {
      valid: false,
      signatureValid: false,
      expired: false,
      structureValid: false,
      structureErrors: [],
      payload: null,
      errors: ['Failed to decode JWT payload'],
    };
  }

  // Verify signature
  let signatureValid = false;
  if (options.publicKeyPath) {
    try {
      const publicKey = readPublicKey(resolve(options.publicKeyPath));
      const signingInput = `${headerB64}.${payloadB64}`;
      const signature = base64urlDecode(signatureB64);
      signatureValid = verify(null, Buffer.from(signingInput, 'utf-8'), publicKey, signature);
      if (!signatureValid) {
        errors.push('Signature verification failed');
      }
    } catch (err) {
      errors.push(
        `Signature verification error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  } else {
    // No public key provided — cannot verify signature
    errors.push('No public key provided; signature not verified');
  }

  // Check expiry via JWT exp claim
  let expired = false;
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && payload.exp < now) {
    expired = true;
    errors.push(`JWT has expired (exp: ${new Date(payload.exp * 1000).toISOString()})`);
  }

  // Also check passport validity.expires_at
  if (isExpired(payload as { validity?: { expires_at?: string } })) {
    expired = true;
    const expiresAt = (payload.validity as Record<string, unknown>)?.expires_at;
    if (expiresAt && !errors.some((e) => e.includes('expired'))) {
      errors.push(`Passport validity has expired (expires_at: ${expiresAt})`);
    }
  }

  // Validate passport structure (excluding JWT-specific fields)
  const passportPayload = { ...payload };
  passportPayload.iat = undefined;
  passportPayload.exp = undefined;

  const structureResult = validateTrustPassport(passportPayload);
  const structureValid = structureResult.valid;
  if (!structureValid) {
    errors.push(...structureResult.errors.map((e) => `Structure: ${e}`));
  }

  const valid = signatureValid && !expired && structureValid && errors.length === 0;

  return {
    valid,
    signatureValid,
    expired,
    structureValid,
    structureErrors: structureResult.errors,
    payload,
    errors,
  };
}

/** CLI entry point for `passport verify-signed`. */
export function verifySignedPassportCommand(args: string[]): number {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(
      [
        'Usage: agent-trust passport verify-signed <jwt-path> [--key <pubkey-path>]',
        '',
        'Verifies a signed Trust Passport JWT (EdDSA/Ed25519).',
        '',
        'Options:',
        '  --key <path>   Path to Ed25519 public key (PEM or 64-char hex)',
        '',
        'Exit codes:',
        '  0  Verification passed',
        '  1  Verification failed',
      ].join('\n'),
    );
    return 0;
  }

  let jwtPath = '';
  let publicKeyPath: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];
    if (arg === '--key' && next) {
      publicKeyPath = next;
      i++;
    } else if (!arg.startsWith('--') && !jwtPath) {
      jwtPath = arg;
    } else if (!arg.startsWith('--')) {
      console.error(`Error: unexpected argument "${arg}"`);
      return 1;
    }
  }

  if (!jwtPath) {
    console.error('Error: passport verify-signed requires a <jwt-path> argument');
    return 1;
  }

  try {
    const result = verifySignedPassport({ jwtPath, publicKeyPath });

    // Print structured result
    console.log(
      JSON.stringify(
        {
          valid: result.valid,
          signature: result.signatureValid ? 'valid' : 'invalid',
          expired: result.expired,
          structure: result.structureValid ? 'valid' : 'invalid',
          errors: result.errors,
        },
        null,
        2,
      ),
    );

    return result.valid ? 0 : 1;
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}
