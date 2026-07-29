import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { inspectTrustPassport, isExpired } from '@openagentaudit/passport';

export function inspectPassportCommand(filePath: string): number {
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

  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    console.error(`Error: "${resolvedPath}" does not contain a valid passport object`);
    return 1;
  }

  const passport = data as Record<string, unknown>;
  const identity = passport.identity as Record<string, string> | undefined;

  console.log(inspectTrustPassport(passport));
  console.log(`  Issuer:   ${identity?.issuer ?? '?'}`);
  console.log(`  Status:   ${isExpired(passport) ? 'EXPIRED' : 'Active'}`);

  return 0;
}
