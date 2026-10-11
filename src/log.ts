import { AsyncLocalStorage } from 'node:async_hooks';

/** The ECS version the records follow; see docs/logging.md. */
export const ECS_VERSION = '8.11.0';

/**
 * The closed catalogue of events. Add an entry (and a row in docs/logging.md) before logging a new
 * kind of event; never log an ad hoc message. `type` is the ECS `event.type` of a success; a refusal
 * adds `denied` and a failure of this side adds `error`.
 */
const EVENTS = {
  login: { category: ['authentication'], type: ['info'] },
  issue_certificate: { category: ['iam'], type: ['creation'] },
  revoke_certificate: { category: ['iam'], type: ['change'] },
  issue_scep_challenge: { category: ['iam'], type: ['creation'] },
  refresh_crl: { category: ['file'], type: ['change'] },
  rotate_operational_key: { category: ['configuration'], type: ['change'] },
  ensure_operational_keys: { category: ['configuration'], type: ['info'] },
  provision_cas: { category: ['configuration'], type: ['info'] },
  remove_ca_keys: { category: ['configuration'], type: ['deletion'] },
  keep_ca_keys: { category: ['configuration'], type: ['info'] },
  wait_for_permissions: { category: ['configuration'], type: ['info'] },
  rotate_origin_secret: { category: ['configuration'], type: ['change'] },
  ensure_origin_secret: { category: ['configuration'], type: ['info'] },
  serve_request: { category: ['web'], type: ['access'] },
  process_request: { category: ['web'], type: ['error'] },
} as const;

export type EventAction = keyof typeof EVENTS;

/**
 * How an event went. `success`: it happened. `denied`: this side refused it, because of the
 * request (ECS outcome `failure`, `denied`, level `warn`). `error`: this side failed (ECS outcome
 * `failure`, `error`, level `error`).
 */
export type EventResult = 'success' | 'denied' | 'error';

/** Controlled values of `event.reason`. */
export type EventReason =
  | 'invalid_request'
  | 'unauthenticated'
  | 'not_allowed'
  | 'not_found'
  | 'already_revoked'
  | 'policy_refused'
  | 'user_not_allowed'
  | 'challenge_missing'
  | 'challenge_mismatch'
  | 'challenge_unknown'
  | 'challenge_expired'
  | 'challenge_bound'
  | 'limit_reached'
  | 'rate_limited'
  | 'unavailable'
  | 'not_ready'
  | 'crl_pending';

/**
 * Every field a record may carry. ECS names where ECS has one (see the conformance table in
 * docs/logging.md); `aws_ca.*` for what it does not. A key outside this list is dropped, so a
 * careless call cannot put a header, a body or a key in a record.
 */
const FIELD_NAMES = [
  'event.duration',
  'event.reason',
  'http.request.id',
  'http.request.method',
  'http.response.status_code',
  'http.response.body.bytes',
  'url.path',
  'source.ip',
  'user_agent.original',
  'user.name',
  'user.target.name',
  'x509.serial_number',
  'x509.subject.distinguished_name',
  'error.type',
  'error.message',
  'aws_ca.ca',
  'aws_ca.protocol',
  'aws_ca.profile',
  'aws_ca.renewal',
  'aws_ca.revocation.reason',
  'aws_ca.crl.number',
  'aws_ca.crl.entries',
  'aws_ca.crl.published',
  'aws_ca.operational_key.purpose',
  'aws_ca.operational_key.sequence',
  'aws_ca.operational_key.rotated',
  'aws_ca.operational_key.count',
  'aws_ca.scep.fail_info',
  'aws_ca.challenge.via',
  'aws_ca.challenge.bound',
  'aws_ca.provisioned.cas',
  'aws_ca.provisioned.created',
  'aws_ca.root_key.exported',
  'aws_ca.removed.keys',
  'aws_ca.removed.delegated_keys',
] as const;

type FieldName = (typeof FIELD_NAMES)[number];
type FieldValue = string | number | boolean | undefined;

/** The fields of an event, by their dotted names. `undefined` values are left out. */
export type LogFields = Partial<Record<Exclude<FieldName, 'event.reason'>, FieldValue>> & {
  'event.reason'?: EventReason;
};

const ALLOWED = new Set<string>(FIELD_NAMES);
const MAX_VALUE_LENGTH = 256;

export interface Logger {
  event(action: EventAction, result: EventResult, message: string, fields?: LogFields): void;
}

const context = new AsyncLocalStorage<LogFields>();

/** Runs `run` with fields that every record written inside it carries (a request's id, for one). */
export function withLogContext<T>(fields: LogFields, run: () => T): T {
  return context.run({ ...context.getStore(), ...fields }, run);
}

const TRACE_HEADER_ENV = '_X_AMZN_TRACE_ID';

/** The trace ID Lambda sets in `_X_AMZN_TRACE_ID` for an invocation with trace context. */
function xrayTraceId(): string | undefined {
  return /(?:^|;)Root=([^;]+)/.exec(process.env[TRACE_HEADER_ENV] ?? '')?.[1];
}

const LEVELS: Record<EventResult, 'info' | 'warn' | 'error'> = {
  success: 'info',
  denied: 'warn',
  error: 'error',
};

function typesOf(base: readonly string[], result: EventResult): string[] {
  if (result === 'success') {
    return [...base];
  }
  const extra = result === 'denied' ? 'denied' : 'error';
  return base.includes(extra) ? [...base] : [...base, extra];
}

function clean(fields: LogFields): Record<string, unknown> {
  const kept: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(fields)) {
    if (value === undefined || !ALLOWED.has(name)) {
      continue;
    }
    kept[name] = typeof value === 'string' ? value.slice(0, MAX_VALUE_LENGTH) : value;
  }
  return kept;
}

/**
 * Writes one ECS JSON object per event, with flat dotted keys. It writes with `process.stdout`
 * rather than `console.log`, which Lambda's text log format prefixes with a timestamp, request ID
 * and level. A failure to log never fails a request.
 */
export function createLogger(
  write: (line: string) => void = (line) => {
    process.stdout.write(`${line}\n`);
  },
): Logger {
  return {
    event(action, result, message, fields = {}) {
      try {
        const base = EVENTS[action];
        const record = {
          '@timestamp': new Date().toISOString(),
          'log.level': LEVELS[result],
          message,
          'ecs.version': ECS_VERSION,
          'service.name': process.env.AWS_LAMBDA_FUNCTION_NAME,
          'cloud.provider': 'aws',
          'cloud.region': process.env.AWS_REGION,
          'event.category': base.category,
          'event.type': typesOf(base.type, result),
          'event.action': action,
          'event.outcome': result === 'success' ? 'success' : 'failure',
          'trace.id': xrayTraceId(),
          ...clean({ ...context.getStore(), ...fields }),
        };
        write(JSON.stringify(record));
      } catch {
        // Deliberately ignored: logging must never fail a request.
      }
    },
  };
}

export const silentLogger: Logger = { event: () => undefined };

/**
 * `error.type`, plus `error.message` when `safe`: only for errors whose messages this code wrote
 * (a policy refusal, a protocol error), never for a library's, which might echo its input. No stack
 * trace is logged.
 */
export function errorFields(error: unknown, safe = false): LogFields {
  return {
    'error.type': error instanceof Error ? error.name : typeof error,
    ...(safe && error instanceof Error ? { 'error.message': error.message } : {}),
  };
}
