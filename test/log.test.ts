import { createLogger, errorFields, withLogContext, ECS_VERSION } from '../src/log';

const capture = () => {
  const lines: string[] = [];
  return {
    lines,
    logger: createLogger((line) => lines.push(line)),
    last: () => JSON.parse(lines.at(-1) ?? '{}'),
  };
};

describe('the ECS logger', () => {
  it('writes one flat ECS record with the base, event and cloud fields', () => {
    const { logger, last, lines } = capture();
    logger.event('issue_certificate', 'success', 'Certificate issued.', {
      'aws_ca.ca': 'issuing',
      'x509.serial_number': 'ab',
    });
    expect(lines).toHaveLength(1);
    expect(last()).toMatchObject({
      'log.level': 'info',
      message: 'Certificate issued.',
      'ecs.version': ECS_VERSION,
      'cloud.provider': 'aws',
      'event.category': ['iam'],
      'event.type': ['creation'],
      'event.action': 'issue_certificate',
      'event.outcome': 'success',
      'aws_ca.ca': 'issuing',
      'x509.serial_number': 'ab',
    });
    expect(Date.parse(last()['@timestamp'])).not.toBeNaN();
  });

  it('keeps the action free of the outcome, and marks a refusal and a failure', () => {
    const { logger, last } = capture();
    logger.event('revoke_certificate', 'denied', 'Refused.');
    expect(last()).toMatchObject({
      'log.level': 'warn',
      'event.action': 'revoke_certificate',
      'event.type': ['change', 'denied'],
      'event.outcome': 'failure',
    });
    logger.event('refresh_crl', 'error', 'Failed.');
    expect(last()).toMatchObject({
      'log.level': 'error',
      'event.type': ['change', 'error'],
      'event.outcome': 'failure',
    });
    logger.event('process_request', 'error', 'Failed.');
    expect(last()['event.type']).toEqual(['error']);
  });

  it('drops a field that is not in the schema, and leaves out undefined ones', () => {
    const { logger, last } = capture();
    logger.event('serve_request', 'success', 'Served.', {
      'http.request.method': 'GET',
      authorization: 'Basic c2VjcmV0',
      'user.name': undefined,
    } as never);
    const record = last();
    expect(record['http.request.method']).toBe('GET');
    expect(record).not.toHaveProperty('authorization');
    expect(record).not.toHaveProperty('user.name');
    expect(JSON.stringify(record)).not.toContain('c2VjcmV0');
  });

  it('cuts long values and cannot be split by a line break in one', () => {
    const { logger, last, lines } = capture();
    logger.event('serve_request', 'success', 'Served.', { 'url.path': `/a\n{"x":1}${'b'.repeat(400)}` });
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain('\n');
    expect(last()['url.path'].length).toBe(256);
  });

  it('adds the context of the request it runs in, and not outside it', () => {
    const { logger, last } = capture();
    withLogContext({ 'http.request.id': 'req-1' }, () => {
      logger.event('serve_request', 'success', 'Served.');
    });
    expect(last()['http.request.id']).toBe('req-1');
    logger.event('serve_request', 'success', 'Served.');
    expect(last()).not.toHaveProperty('http.request.id');
  });

  it('never throws, whatever the sink does', () => {
    const logger = createLogger(() => {
      throw new Error('sink is full');
    });
    expect(() => logger.event('serve_request', 'success', 'Served.')).not.toThrow();
  });

  it('logs an error as its type, and its message only when told it is safe', () => {
    expect(errorFields(new TypeError('secret value'))).toEqual({ 'error.type': 'TypeError' });
    expect(errorFields(new TypeError('ours'), true)).toEqual({
      'error.type': 'TypeError',
      'error.message': 'ours',
    });
    expect(errorFields('boom')).toEqual({ 'error.type': 'string' });
  });
});
