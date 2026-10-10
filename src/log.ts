/**
 * A logger that writes one JSON object per line and removes anything that could be a credential
 * or key material before it is written. Redaction is by field name, applied at any depth, so a
 * careless `logger.info('x', { request })` cannot leak an `Authorization` header or a CSR.
 */
export type LogFields = Record<string, unknown>;

export interface Logger {
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
}

const SENSITIVE = /authorization|password|secret|token|key|cookie|credential|body|csr|pem|signature/i;
const REDACTED = '[redacted]';
const MAX_DEPTH = 6;

export function redact(value: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) {
    return REDACTED;
  }
  if (value instanceof Error) {
    return { name: value.name, message: value.message };
  }
  if (Array.isArray(value)) {
    return value.map((item) => redact(item, depth + 1));
  }
  if (value !== null && typeof value === 'object') {
    const result: Record<string, unknown> = {};
    for (const [name, inner] of Object.entries(value)) {
      result[name] = SENSITIVE.test(name) ? REDACTED : redact(inner, depth + 1);
    }
    return result;
  }
  return value;
}

export function createLogger(write: (line: string) => void = console.log): Logger {
  const emit = (level: string, message: string, fields: LogFields = {}): void => {
    write(JSON.stringify({ level, message, ...(redact(fields) as LogFields) }));
  };
  return {
    info: (message, fields) => emit('info', message, fields),
    warn: (message, fields) => emit('warn', message, fields),
    error: (message, fields) => emit('error', message, fields),
  };
}

export const silentLogger: Logger = { info: () => undefined, warn: () => undefined, error: () => undefined };
