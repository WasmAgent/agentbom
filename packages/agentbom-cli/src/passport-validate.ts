import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { inspectTrustPassport, isExpired, validateTrustPassport } from '@openagentaudit/passport';

const WARN_EXPIRY_DAYS = 14;

function expiresWithinDays(
  passport: { validity?: { expires_at?: string } },
  days: number,
): boolean {
  const expiresAt = passport.validity?.expires_at;
  if (!expiresAt) return false;
  const expiry = new Date(expiresAt).getTime();
  const now = Date.now();
  const diffMs = expiry - now;
  return diffMs > 0 && diffMs <= days * 24 * 60 * 60 * 1000;
}

export function validatePassportCommand(filePath: string): number {
  const resolvedPath = resolve(filePath);

  let raw: string;
  try {
    raw = readFileSync(resolvedPath, 'utf-8');
  } catch {
    console.error(`Error: cannot read file "${resolvedPath}"`);
    return 1;
  }

  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    console.error(`Error: "${resolvedPath}" is not valid JSON`);
    return 1;
  }

  const result = validateTrustPassport(data);
  if (!result.valid) {
    console.error(`Validation failed for "${resolvedPath}":`);
    for (const err of result.errors) {
      console.error(`  - ${err}`);
    }
    return 1;
  }

  const passport = data as Record<string, unknown>;
  console.log(inspectTrustPassport(passport));

  if (isExpired(passport)) {
    console.error('\nPassport has EXPIRED.');
    return 1;
  }

  if (expiresWithinDays(passport, WARN_EXPIRY_DAYS)) {
    const expiresAt = (passport.validity as Record<string, string>)?.expires_at ?? '';
    const daysLeft = Math.ceil(
      (new Date(expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24),
    );
    console.warn(
      `\nWarning: passport expires within ${WARN_EXPIRY_DAYS} days (${daysLeft} days remaining).`,
    );
  }

  console.log('\nPassport is valid.');
  return 0;
}
