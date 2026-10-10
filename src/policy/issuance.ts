import { Name } from '@peculiar/x509';
import type { SubjectAltName } from '../ca';
import type { ParsedCsr } from '../ca/csr';
import type { Profile, ResolvedConfig } from '../config';

/** A request that the issuance policy refuses. The message is safe to show the requester. */
export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyError';
  }
}

export interface IssuanceRequest {
  csr: ParsedCsr;
  /** The authenticated user. */
  username: string;
  groups: string[];
  /** The issuing CA that will sign. */
  caLabel: string;
  config: Pick<ResolvedConfig, 'subordinateCas' | 'groups' | 'policy' | 'lifetimes'>;
}

export interface IssuanceDecision {
  profile: Profile;
  /** The subject to put in the certificate, as an RFC 4514 string. Never the CSR's subject as is. */
  subject: string;
  subjectAltNames: SubjectAltName[];
  validityDays: number;
}

const HOSTNAME_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const MAX_NAME_LENGTH = 253;

const SPECIAL = new Set([',', '+', '"', '\\', '<', '>', ';', '=']);

/** RFC 4514 escaping of an attribute value. */
export function escapeDnValue(value: string): string {
  const characters = Array.from(value, (character) => {
    if (character === '\0') {
      return '\\00';
    }
    return SPECIAL.has(character) ? `\\${character}` : character;
  });
  // A leading space or '#' and a trailing space also need escaping.
  if (characters[0] === '#' || characters[0] === ' ') {
    characters[0] = `\\${characters[0]}`;
  }
  const last = characters.length - 1;
  if (last > 0 && characters[last] === ' ') {
    characters[last] = '\\ ';
  }
  return characters.join('');
}

function commonNamesOf(subject: string): string[] {
  const names: string[] = [];
  for (const entry of new Name(subject).toJSON()) {
    for (const value of entry.CN ?? []) {
      names.push(value);
    }
  }
  return names;
}

function isHostname(value: string): boolean {
  return (
    value.length <= MAX_NAME_LENGTH &&
    value.includes('.') &&
    value.split('.').every((label) => HOSTNAME_LABEL.test(label))
  );
}

const withinSuffix = (host: string, suffix: string): boolean =>
  host === suffix || host.endsWith(`.${suffix}`);

/**
 * Decides what, if anything, the user may be issued for this request. A request that has DNS or IP
 * names is a `server` request, anything else is a `client` request. What the certificate says comes
 * from here, never from the CSR's subject: for a client the configured template with the
 * authenticated user name, for a server the first requested DNS name.
 */
export function decideIssuance(request: IssuanceRequest): IssuanceDecision {
  const { csr, username, groups, config } = request;
  const ca = config.subordinateCas.find((candidate) => candidate.label === request.caLabel);
  if (!ca) {
    throw new PolicyError(`There is no CA "${request.caLabel}".`);
  }
  const wantsServer = csr.requestedNames.some((name) => name.type === 'dns' || name.type === 'ip');
  const profile: Profile = wantsServer ? 'server' : 'client';

  if (!groups.includes(config.groups[profile])) {
    throw new PolicyError(`User "${username}" is not allowed to enroll ${profile} certificates.`);
  }
  if (!ca.profiles.includes(profile)) {
    throw new PolicyError(`CA "${ca.label}" does not issue ${profile} certificates.`);
  }
  const commonNames = commonNamesOf(csr.subject);

  if (profile === 'client') {
    const mismatched = commonNames.find((name) => name !== username);
    if (mismatched !== undefined) {
      throw new PolicyError('The request subject CN must be the authenticated user name.');
    }
    return {
      profile,
      subject: config.policy.subjectTemplate.replaceAll('{username}', escapeDnValue(username)),
      subjectAltNames: [],
      validityDays: config.lifetimes.clientDays,
    };
  }

  const suffixes = config.policy.allowedDomainSuffixes.map((suffix) => suffix.replace(/^\./, ''));
  if (suffixes.length === 0) {
    throw new PolicyError('Server certificates are disabled: no allowed domain suffixes are configured.');
  }
  const hosts: string[] = [];
  for (const name of csr.requestedNames) {
    if (name.type !== 'dns') {
      throw new PolicyError(`Only DNS names are allowed in server certificates (got ${name.type}).`);
    }
    const host = name.value.toLowerCase();
    if (!isHostname(host)) {
      throw new PolicyError(`"${name.value}" is not a valid host name.`);
    }
    if (!suffixes.some((suffix) => withinSuffix(host, suffix))) {
      throw new PolicyError(`"${name.value}" is outside the allowed domains.`);
    }
    if (!hosts.includes(host)) {
      hosts.push(host);
    }
  }
  for (const commonName of commonNames) {
    if (!hosts.includes(commonName.toLowerCase())) {
      throw new PolicyError('The request subject CN must be one of the requested DNS names.');
    }
  }
  return {
    profile,
    subject: `CN=${escapeDnValue(hosts[0])}`,
    subjectAltNames: hosts.map((value) => ({ type: 'dns', value })),
    validityDays: config.lifetimes.serverDays,
  };
}
