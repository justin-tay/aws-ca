import { join } from 'node:path';
import { loadConfigInput, resolveConfig } from '../../src/config';

const fixture = join(__dirname, 'fixtures', 'example.config.ts');

describe('loadConfigInput', () => {
  it('reads the default export of a TypeScript config file', () => {
    const config = resolveConfig(loadConfigInput(fixture));
    expect(config.policy.allowedDomainSuffixes).toEqual(['fixture.internal']);
    expect(config.frontDoor.type).toBe('function-url');
  });

  it('treats a missing default file as empty configuration', () => {
    expect(loadConfigInput(join(__dirname, 'fixtures', 'absent.config.ts'))).toEqual({});
  });

  it('fails when an explicitly requested file is missing', () => {
    expect(() => loadConfigInput(join(__dirname, 'fixtures', 'absent.config.ts'), true)).toThrow(/not found/);
  });
});
