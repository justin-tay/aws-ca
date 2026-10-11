import type { ConfigIssue } from './errors';

export type Rec = Record<string, unknown>;

export class Collector {
  readonly issues: ConfigIssue[] = [];
  add(path: string, message: string): void {
    this.issues.push({ path, message });
  }
}

export const child = (path: string, key: string): string => (path === '' ? key : `${path}.${key}`);

export function isRecord(value: unknown): value is Rec {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** An optional section: `undefined` is fine, anything but an object is reported. */
export function section(c: Collector, value: unknown, path: string, allowed: readonly string[]): Rec {
  if (value === undefined) {
    return {};
  }
  if (!isRecord(value)) {
    c.add(path, 'Must be an object.');
    return {};
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      c.add(child(path, key), `Unknown option. Allowed: ${allowed.join(', ')}.`);
    }
  }
  return value;
}

export function pick<T extends string | number>(
  c: Collector,
  value: unknown,
  allowed: readonly T[],
  path: string,
  fallback: T,
): T {
  if (value === undefined) {
    return fallback;
  }
  const found = allowed.find((option) => option === value);
  if (found === undefined) {
    c.add(path, `Must be one of ${allowed.map((option) => JSON.stringify(option)).join(', ')}.`);
    return fallback;
  }
  return found;
}

export function integer(
  c: Collector,
  value: unknown,
  path: string,
  min: number,
  max: number,
  fallback: number,
): number {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    c.add(path, `Must be a whole number from ${min} to ${max}.`);
    return fallback;
  }
  return value;
}

export function flag(c: Collector, value: unknown, path: string, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'boolean') {
    c.add(path, 'Must be true or false.');
    return fallback;
  }
  return value;
}

export function text(
  c: Collector,
  value: unknown,
  path: string,
  pattern: RegExp,
  what: string,
  fallback: string,
): string {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'string' || !pattern.test(value)) {
    c.add(path, `Must be ${what}.`);
    return fallback;
  }
  return value;
}
