import { BODY_LIMITS, binary, json, mediaType, readJsonBody, safeEqual } from '../../src/http';
import type { HttpRequest } from '../../src/http';
import { commonNameProblem } from '../../src/policy';

const request = (headers: Record<string, string>, body: string): HttpRequest => ({
  method: 'POST',
  path: '/x',
  headers,
  body: new TextEncoder().encode(body),
});

describe('mediaType', () => {
  it('is the lowercase type without parameters, or empty', () => {
    expect(mediaType({ headers: { 'content-type': 'Application/JSON; charset=utf-8' } })).toBe(
      'application/json',
    );
    expect(mediaType({ headers: {} })).toBe('');
  });
});

describe('safeEqual', () => {
  it('compares equal and unequal secrets, of any length', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'abcd')).toBe(false);
    expect(safeEqual('', '')).toBe(true);
  });
});

describe('json and binary', () => {
  it('build responses; binary is base64 and marked so', () => {
    expect(json(201, { a: 1 }, { 'cache-control': 'no-store' })).toEqual({
      status: 201,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
      body: '{"a":1}',
    });
    expect(binary(new Uint8Array([1, 2, 3]), 'application/x-test')).toEqual({
      status: 200,
      headers: { 'content-type': 'application/x-test' },
      body: 'AQID',
      isBase64Encoded: true,
    });
  });
});

const status = (r: HttpRequest, required = true): number | undefined => {
  const result = readJsonBody(r, { required });
  return 'response' in result ? result.response.status : undefined;
};

describe('readJsonBody', () => {
  const type = { 'content-type': 'application/json' };

  it('returns the object', () => {
    expect(readJsonBody(request(type, '{"a":1}'), { required: true })).toEqual({ value: { a: 1 } });
  });

  it('refuses a wrong type, an empty or large body, bad JSON and a non-object', () => {
    expect(status(request({ 'content-type': 'text/plain' }, '{}'))).toBe(415);
    expect(status(request(type, ''))).toBe(400);
    expect(status(request(type, 'x'.repeat(BODY_LIMITS.json + 1)))).toBe(400);
    expect(status(request(type, '{not json'))).toBe(400);
    expect(status(request(type, '[1]'))).toBe(400);
    expect(status(request(type, 'null'))).toBe(400);
  });

  it('accepts no body at all when it is optional', () => {
    expect(readJsonBody(request({}, ''), { required: false })).toEqual({ value: undefined });
  });
});

describe('commonNameProblem', () => {
  it('accepts 1 to 64 characters and refuses empty, long and control characters', () => {
    expect(commonNameProblem('device-1')).toBeUndefined();
    expect(commonNameProblem('x'.repeat(64))).toBeUndefined();
    expect(commonNameProblem('')).toContain('1 to 64');
    expect(commonNameProblem('x'.repeat(65))).toContain('1 to 64');
    expect(commonNameProblem('a\u0007b')).toContain('control characters');
    expect(commonNameProblem('a\u007Fb')).toContain('control characters');
  });
});
