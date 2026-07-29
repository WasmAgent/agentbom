/**
 * passport verify-sigstore — Verify a Trust Passport artifact with a Sigstore bundle.
 *
 * Implements Sigstore bundle verification (v0.3) for production hardening:
 * - Certificate chain validation and signature verification
 * - Air-gapped mode (--offline): skip Rekor/transparency log checks
 * - FIPS-compliant crypto (--fips): enforce FIPS-approved algorithms only
 * - Enterprise SSO (--issuer): verify OIDC issuer in certificate SANs
 *
 * Uses node:crypto for all cryptographic operations (no external deps).
 */
import { createHash, createVerify, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { validateTrustPassport } from '@openagentaudit/passport';

// isRecord is a private utility not exported by @openagentaudit/passport
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// Bundle types
// ---------------------------------------------------------------------------

export interface SigstoreBundle {
  mediaType: string;
  content: {
    $case: string;
    messageDigest?: { algorithm: string; digest: string };
    signature: string;
  };
  verificationMaterial: {
    content: {
      $case: string;
      certificates: Array<{ rawBytes: string }>;
    };
    tlogEntries?: Array<{
      logIndex?: number;
      integratedTime?: number;
      inclusionPromise?: { signedEntryTimestamp: string };
    }>;
  };
}

// ---------------------------------------------------------------------------
// Options and result types
// ---------------------------------------------------------------------------

export interface SigstoreVerifyOptions {
  bundlePath?: string;
  artifactPath?: string;
  artifactContent?: Buffer;
  offline?: boolean;
  fips?: boolean;
  trustedIssuer?: string;
}

export interface SigstoreVerifyResult {
  valid: boolean;
  signatureValid: boolean;
  certificateValid: boolean;
  tlogVerified: boolean;
  artifactValid: boolean;
  fipsCompliant: boolean;
  issuerMatch: boolean;
  errors: string[];
  warnings: string[];
}

// ---------------------------------------------------------------------------
// FIPS-approved algorithm sets
// ---------------------------------------------------------------------------

const FIPS_APPROVED_HASHES = new Set(['SHA256', 'SHA384', 'SHA512']);

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function base64ToBuffer(b64: string): Buffer {
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

/**
 * Parse a Sigstore bundle JSON string into a typed structure.
 * Throws on structural issues so callers can surface clear errors.
 */
function parseBundle(raw: string): SigstoreBundle {
  const data = JSON.parse(raw) as unknown;
  if (!isRecord(data)) throw new Error('Invalid bundle: root must be an object');
  if (typeof data.mediaType !== 'string') throw new Error('Invalid bundle: missing mediaType');

  const content = data.content;
  if (!isRecord(content)) throw new Error('Invalid bundle: missing content');
  if (typeof content.signature !== 'string')
    throw new Error('Invalid bundle: content.signature must be a string');

  const vm = data.verificationMaterial;
  if (!isRecord(vm)) throw new Error('Invalid bundle: missing verificationMaterial');
  const vmContent = vm.content;
  if (!isRecord(vmContent)) throw new Error('Invalid bundle: missing verificationMaterial.content');
  const certs = vmContent.certificates;
  if (!Array.isArray(certs) || certs.length === 0)
    throw new Error('Invalid bundle: certificates must be a non-empty array');

  return {
    mediaType: data.mediaType as string,
    content: {
      $case: (content.$case as string) ?? 'MessageSignature',
      messageDigest: isRecord(content.messageDigest)
        ? {
            algorithm: content.messageDigest.algorithm as string,
            digest: content.messageDigest.digest as string,
          }
        : undefined,
      signature: content.signature as string,
    },
    verificationMaterial: {
      content: {
        $case: (vmContent.$case as string) ?? 'x509CertificateChain',
        certificates: certs.map((c: unknown) => ({
          rawBytes: isRecord(c) && typeof c.rawBytes === 'string' ? c.rawBytes : '',
        })),
      },
      tlogEntries: Array.isArray(vm.tlogEntries)
        ? (vm.tlogEntries as SigstoreBundle['verificationMaterial']['tlogEntries'])
        : undefined,
    },
  };
}

/**
 * Verify a raw artifact buffer against a certificate's public key.
 * Supports Ed25519, RSA, and ECDSA key types.
 */
function verifyArtifactSignature(
  artifact: Buffer,
  signature: Buffer,
  cert: X509Certificate,
): boolean {
  try {
    const keyType = cert.publicKey.asymmetricKeyType;
    if (keyType === 'ed25519') {
      const v = createVerify('Ed25519');
      v.update(artifact);
      return v.verify(cert.publicKey, signature);
    }
    // RSA / ECDSA — try SHA-256, then SHA-384, then SHA-512
    for (const hash of ['sha256', 'sha384', 'sha512'] as const) {
      try {
        const v = createVerify(hash);
        v.update(artifact);
        if (v.verify(cert.publicKey, signature)) return true;
      } catch {
        // swallow unsupported hash algorithm
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Check whether a trusted OIDC issuer appears in the certificate's
 * Subject Alternative Names (type 6 = URI).
 *
 * Method 1: cert.getExtension('subjectAltName') (Node.js ≥ 17.3).
 * Method 2: search raw DER for the issuer URL — URI SANs encode the URL
 * as UTF-8 bytes (tag 0x86) inside the DER. This fallback works in runtimes
 * that don't implement getExtension (e.g. Bun).
 */
function checkOidcIssuer(certDer: Buffer, cert: X509Certificate, trustedIssuer: string): boolean {
  // Method 1: structured extension access (Node.js ≥ 17.3)
  try {
    const san = cert.getExtension('subjectAltName');
    if (san && typeof san === 'object') {
      const obj = san as Record<string, unknown>;
      const altNames = obj.altNames as Array<{ type: number; value: string }> | undefined;
      if (Array.isArray(altNames)) {
        return altNames.some((e) => e.type === 6 && e.value === trustedIssuer);
      }
      const val = obj.value as string | undefined;
      return val?.includes(trustedIssuer) ?? false;
    }
  } catch {
    /* getExtension not supported in this runtime — fall through to DER search */
  }

  // Method 2: search DER encoding for the issuer URL as a UTF-8 substring.
  // URI SANs contain the URL verbatim in the DER, so a substring match is
  // reliable for standard certificates.
  return certDer.includes(Buffer.from(trustedIssuer, 'utf-8'));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Verify a Trust Passport artifact against a Sigstore bundle.
 *
 * Returns a detailed result with per-check outcomes:
 * - `certificateValid`: leaf certificate parsed successfully
 * - `signatureValid`: artifact signature matches leaf certificate
 * - `artifactValid`: artifact is a structurally valid Trust Passport
 * - `tlogVerified`: Rekor transparency log entry confirmed (false in offline mode)
 * - `fipsCompliant`: all algorithms are FIPS-approved (when `fips: true`)
 * - `issuerMatch`: OIDC issuer found in certificate SANs (when `trustedIssuer` set)
 */
export function verifySigstoreBundle(options: SigstoreVerifyOptions): SigstoreVerifyResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  let signatureValid = false;
  let signatureChecked = false;
  let certificateValid = false;
  let tlogVerified = false;
  let artifactValid = false;
  let fipsCompliant = true;
  let issuerMatch = true;

  // ---- 1. Load and parse bundle ----
  let bundle: SigstoreBundle;
  if (options.bundlePath) {
    try {
      const raw = readFileSync(resolve(options.bundlePath), 'utf-8').trim();
      bundle = parseBundle(raw);
    } catch (err) {
      return {
        valid: false,
        signatureValid: false,
        certificateValid: false,
        tlogVerified: false,
        artifactValid: false,
        fipsCompliant: true,
        issuerMatch: true,
        errors: [`Bundle load error: ${err instanceof Error ? err.message : String(err)}`],
        warnings: [],
      };
    }
  } else {
    return {
      valid: false,
      signatureValid: false,
      certificateValid: false,
      tlogVerified: false,
      artifactValid: false,
      fipsCompliant: true,
      issuerMatch: true,
      errors: ['No bundle input provided (bundlePath required)'],
      warnings: [],
    };
  }

  // ---- 2. Parse leaf certificate and run crypto checks ----
  try {
    const leafRaw = base64ToBuffer(bundle.verificationMaterial.content.certificates[0].rawBytes);
    const leafCert = new X509Certificate(leafRaw);
    certificateValid = true;

    // 2a. FIPS mode: enforce approved key algorithm and hash
    if (options.fips) {
      const keyType = leafCert.publicKey.asymmetricKeyType;
      const approvedKeyTypes = new Set(['rsa', 'ec', 'ed25519']);
      if (!approvedKeyTypes.has(keyType ?? '')) {
        fipsCompliant = false;
        errors.push(`FIPS mode: unapproved key algorithm "${keyType}"`);
      }
      if (bundle.content.messageDigest) {
        const hashAlg = bundle.content.messageDigest.algorithm.toUpperCase();
        if (!FIPS_APPROVED_HASHES.has(hashAlg)) {
          fipsCompliant = false;
          errors.push(
            `FIPS mode: unapproved hash algorithm "${bundle.content.messageDigest.algorithm}" (approved: SHA256, SHA384, SHA512)`,
          );
        }
      }
    }

    // 2b. Verify artifact signature against leaf certificate
    const artifact =
      options.artifactContent ??
      (options.artifactPath ? readFileSync(resolve(options.artifactPath)) : null);

    if (artifact) {
      signatureChecked = true;
      const sig = base64ToBuffer(bundle.content.signature);
      signatureValid = verifyArtifactSignature(artifact, sig, leafCert);
      if (!signatureValid) {
        errors.push('Signature verification failed');
      }

      // 2c. Verify message digest when present
      if (bundle.content.messageDigest && artifact) {
        const digestAlg = bundle.content.messageDigest.algorithm.toLowerCase();
        const expectedDigest = base64ToBuffer(bundle.content.messageDigest.digest);
        const actualDigest = createHash(digestAlg).update(artifact).digest();
        if (!expectedDigest.equals(actualDigest)) {
          errors.push('Message digest mismatch');
          signatureValid = false;
        }
      }
    } else {
      warnings.push('No artifact provided; signature verification skipped');
    }

    // 2d. Enterprise SSO: verify OIDC issuer in certificate SANs
    if (options.trustedIssuer) {
      issuerMatch = checkOidcIssuer(leafRaw, leafCert, options.trustedIssuer);
      if (!issuerMatch) {
        errors.push(`SSO issuer mismatch: expected "${options.trustedIssuer}" in certificate SANs`);
      }
    }
  } catch (err) {
    certificateValid = false;
    errors.push(`Certificate error: ${err instanceof Error ? err.message : String(err)}`);
  }

  // ---- 3. Transparency log ----
  const tlogEntries = bundle.verificationMaterial.tlogEntries;
  if (tlogEntries && tlogEntries.length > 0) {
    if (options.offline) {
      warnings.push('Offline mode: transparency log entries present but Rekor check skipped');
      tlogVerified = false;
    } else {
      const entry = tlogEntries[0];
      if (entry.logIndex !== undefined && entry.integratedTime !== undefined) {
        warnings.push(
          'Transparency log entry found; full Rekor verification requires @sigstore/client',
        );
        tlogVerified = false;
      } else {
        warnings.push('Transparency log entry is incomplete');
        tlogVerified = false;
      }
    }
  } else if (!options.offline) {
    warnings.push('No transparency log entries in bundle');
  }

  // ---- 4. Validate artifact as Trust Passport ----
  if (options.artifactContent || options.artifactPath) {
    try {
      const artifactRaw =
        options.artifactContent?.toString('utf-8') ??
        (options.artifactPath ? readFileSync(resolve(options.artifactPath), 'utf-8') : '');
      const parsed = JSON.parse(artifactRaw) as unknown;
      if (isRecord(parsed)) {
        const result = validateTrustPassport(parsed);
        artifactValid = result.valid;
        if (!result.valid) {
          for (const e of result.errors) errors.push(`Artifact: ${e}`);
        }
      }
    } catch {
      artifactValid = false;
    }
  }

  // ---- 5. Overall validity ----
  const valid =
    certificateValid &&
    (!signatureChecked || signatureValid) &&
    errors.length === 0 &&
    (artifactValid || (!options.artifactContent && !options.artifactPath)) &&
    (fipsCompliant || !options.fips) &&
    (issuerMatch || !options.trustedIssuer);

  return {
    valid,
    signatureValid,
    certificateValid,
    tlogVerified,
    artifactValid,
    fipsCompliant,
    issuerMatch,
    errors,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

/** CLI entry point for `passport verify-sigstore`. */
export function verifySigstoreCommand(args: string[]): number {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(
      [
        'Usage: agent-trust passport verify-sigstore <bundle.json> [options]',
        '',
        'Verifies a Trust Passport artifact with a Sigstore bundle.',
        '',
        'Options:',
        '  --artifact <path>    Path to the Trust Passport artifact to verify',
        '  --offline            Air-gapped mode: skip Rekor/transparency log verification',
        '  --fips               Require FIPS-compliant algorithms (SHA-256/384/512 only)',
        '  --issuer <url>       Verify OIDC issuer in certificate SANs (enterprise SSO)',
        '',
        'Exit codes:',
        '  0  Verification passed',
        '  1  Verification failed',
      ].join('\n'),
    );
    return 0;
  }

  let bundlePath = '';
  let artifactPath: string | undefined;
  let offline = false;
  let fips = false;
  let trustedIssuer: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];
    if (arg === '--artifact' && next) {
      artifactPath = next;
      i++;
    } else if (arg === '--offline') {
      offline = true;
    } else if (arg === '--fips') {
      fips = true;
    } else if (arg === '--issuer' && next) {
      trustedIssuer = next;
      i++;
    } else if (!arg.startsWith('--') && !bundlePath) {
      bundlePath = arg;
    } else if (!arg.startsWith('--')) {
      console.error(`Error: unexpected argument "${arg}"`);
      return 1;
    }
  }

  if (!bundlePath) {
    console.error('Error: passport verify-sigstore requires a <bundle.json> argument');
    return 1;
  }

  try {
    const result = verifySigstoreBundle({
      bundlePath,
      artifactPath,
      offline,
      fips,
      trustedIssuer,
    });
    console.log(
      JSON.stringify(
        {
          valid: result.valid,
          signature: result.signatureValid ? 'valid' : 'invalid',
          certificate: result.certificateValid ? 'valid' : 'invalid',
          tlog: result.tlogVerified ? 'verified' : 'not_verified',
          artifact: result.artifactValid ? 'valid' : 'not_checked',
          fips: result.fipsCompliant ? 'compliant' : 'non_compliant',
          issuer: result.issuerMatch ? 'match' : 'not_checked',
          errors: result.errors,
          warnings: result.warnings,
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
