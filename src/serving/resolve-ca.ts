import type { Profile, ResolvedConfig } from '../config';
import type { CaRecord, CaRepository } from '../repo';

export interface ResolveCaDependencies {
  config: Pick<ResolvedConfig, 'subordinateCas'>;
  repository: Pick<CaRepository, 'getCa'>;
}

/**
 * The addressable CA for a request: a configured issuing CA that has a record and, when `profile`
 * is given, issues that profile. Without a label it is the first such CA. A label that names the
 * root, or a CA that was removed from the configuration, resolves to nothing even if a record
 * remains. The caller turns `undefined` into the answer its protocol uses.
 */
export async function resolveCa(
  deps: ResolveCaDependencies,
  label: string | undefined,
  options: { profile?: Profile } = {},
): Promise<CaRecord | undefined> {
  const { profile } = options;
  const configured = deps.config.subordinateCas.find(
    (ca) =>
      (label === undefined || ca.label === label) && (profile === undefined || ca.profiles.includes(profile)),
  );
  return configured === undefined ? undefined : deps.repository.getCa(configured.label);
}
