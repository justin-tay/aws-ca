import { ConfigError, type ConfigIssue } from './errors';
import type {
  AwsCaConfigInput,
  CognitoTier,
  DomainInput,
  EndpointType,
  KeyAlgorithm,
  KeyBackend,
  KeyProtection,
  OcspSigning,
  Profile,
  ResolvedCa,
  ResolvedConfig,
  ResolvedFrontDoor,
  ResolvedKeyStore,
  ResolvedOperationalKey,
  ResolvedRootCa,
  ResolvedSubordinateCa,
  RootKeyHandling,
  RsaModulusLength,
} from './types';

type Rec = Record<string, unknown>;

const BACKENDS = ['parameter', 'secret', 'kms'] as const satisfies readonly KeyBackend[];
const PROTECTIONS = [
  'aws-managed-key',
  'app-encrypted',
  'customer-managed-key',
] as const satisfies readonly KeyProtection[];
const CURVES = ['P-256', 'P-384', 'P-521'] as const;
const MODULUS_LENGTHS = [2048, 3072, 4096] as const satisfies readonly RsaModulusLength[];
const PROFILES = ['client', 'server'] as const satisfies readonly Profile[];
const ROOT_KEY_HANDLING = ['retain', 'offline'] as const satisfies readonly RootKeyHandling[];
const OCSP_SIGNING = ['operational', 'kms', 'ca'] as const satisfies readonly OcspSigning[];
const COGNITO_TIERS = ['lite', 'essentials'] as const satisfies readonly CognitoTier[];
const ENDPOINT_TYPES = ['regional', 'private'] as const satisfies readonly EndpointType[];
const REMOVAL_POLICIES = ['retain', 'destroy'] as const;
const FRONT_DOORS = ['function-url', 'cloudfront', 'http-api', 'rest-api'] as const;

const DAYS_PER_YEAR = 365;
const DN = /^[A-Za-z][A-Za-z0-9.]*=[^,=]+(,\s*[A-Za-z][A-Za-z0-9.]*=[^,=]+)*$/;
const LABEL = /^[a-z0-9][a-z0-9-]{0,31}$/;
const HOST_LABEL = '[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?';
const HOSTNAME = new RegExp(`^${HOST_LABEL}(\\.${HOST_LABEL})*$`);
const DOMAIN_SUFFIX = new RegExp(`^\\.?${HOST_LABEL}(\\.${HOST_LABEL})*$`);
const NAME_PREFIX = /^\/[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)*$/;
/** SSM rejects parameter names beginning with "aws" or "ssm", with or without the leading slash. */
const RESERVED_PARAMETER_PREFIX = /^\/?(aws|ssm)/i;
const KMS_KEY_ARN = /^arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:(key|alias)\/.+$/;
const ACM_ARN = /^arn:aws[a-z-]*:acm:([a-z0-9-]+):\d{12}:certificate\/.+$/;
const GROUP_NAME = /^\S{1,128}$/;
const VPC_ENDPOINT_ID = /^vpce-[0-9a-f]+$/;
const VPC_ID = /^vpc-[0-9a-f]+$/;
const SUBNET_ID = /^subnet-[0-9a-f]+$/;

const KMS_OPERATIONAL_KEY =
  'The operational key cannot be stored in KMS: SCEP clients encrypt to it with RSA PKCS#1 v1.5, ' +
  'which KMS asymmetric Decrypt does not support. Use "parameter" or "secret".';

class Collector {
  readonly issues: ConfigIssue[] = [];
  add(path: string, message: string): void {
    this.issues.push({ path, message });
  }
}

const child = (path: string, key: string): string => (path === '' ? key : `${path}.${key}`);

function isRecord(value: unknown): value is Rec {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** An optional section: `undefined` is fine, anything but an object is reported. */
function section(c: Collector, value: unknown, path: string, allowed: readonly string[]): Rec {
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

function pick<T extends string | number>(
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

function integer(
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

function flag(c: Collector, value: unknown, path: string, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'boolean') {
    c.add(path, 'Must be true or false.');
    return fallback;
  }
  return value;
}

function text(
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

// ---- building blocks ----------------------------------------------------

function resolveAlgorithm(c: Collector, value: unknown, path: string): KeyAlgorithm {
  const fallback: KeyAlgorithm = { type: 'ecdsa', curve: 'P-256' };
  if (value === undefined) {
    return fallback;
  }
  if (!isRecord(value)) {
    c.add(path, 'Must be an object such as { type: "ecdsa", curve: "P-256" }.');
    return fallback;
  }
  if (value.type === 'ecdsa') {
    const rec = section(c, value, path, ['type', 'curve']);
    return { type: 'ecdsa', curve: pick(c, rec.curve, CURVES, child(path, 'curve'), 'P-256') };
  }
  if (value.type === 'rsa') {
    const rec = section(c, value, path, ['type', 'modulusLength']);
    return {
      type: 'rsa',
      modulusLength: pick(c, rec.modulusLength, MODULUS_LENGTHS, child(path, 'modulusLength'), 2048),
    };
  }
  c.add(child(path, 'type'), 'Must be "ecdsa" or "rsa".');
  return fallback;
}

interface KeyStoreRules {
  /** The message to report when `kms` is chosen but not allowed. */
  kmsNotAllowed?: string;
}

function resolveKeyStore(
  c: Collector,
  value: unknown,
  path: string,
  rules: KeyStoreRules = {},
): ResolvedKeyStore {
  const rec = section(c, value, path, ['backend', 'protection', 'kmsKeyArn']);
  const backendPath = child(path, 'backend');
  let backend = pick(c, rec.backend, BACKENDS, backendPath, 'parameter');
  if (backend === 'kms' && rules.kmsNotAllowed !== undefined) {
    c.add(backendPath, rules.kmsNotAllowed);
    backend = 'parameter';
  }
  if (backend === 'kms') {
    if (rec.protection !== undefined) {
      c.add(child(path, 'protection'), 'Not applicable to the "kms" backend: the key never leaves KMS.');
    }
    if (rec.kmsKeyArn !== undefined) {
      c.add(child(path, 'kmsKeyArn'), 'Not applicable to the "kms" backend.');
    }
    return { backend: 'kms' };
  }
  const protection = pick(c, rec.protection, PROTECTIONS, child(path, 'protection'), 'app-encrypted');
  const resolved: ResolvedKeyStore = { backend, protection };
  if (rec.kmsKeyArn !== undefined) {
    if (protection === 'customer-managed-key') {
      resolved.kmsKeyArn = text(
        c,
        rec.kmsKeyArn,
        child(path, 'kmsKeyArn'),
        KMS_KEY_ARN,
        'a KMS key or alias ARN',
        '',
      );
    } else {
      c.add(child(path, 'kmsKeyArn'), 'Only valid with protection "customer-managed-key".');
    }
  }
  return resolved;
}

function resolveSubject(c: Collector, value: unknown, path: string, fallback: string): string {
  return text(c, value, path, DN, 'a distinguished name such as CN=Example CA,O=Example', fallback);
}

function resolveCa(c: Collector, rec: Rec, path: string, subject: string, validityYears: number): ResolvedCa {
  return {
    subject: resolveSubject(c, rec.subject, child(path, 'subject'), subject),
    algorithm: resolveAlgorithm(c, rec.algorithm, child(path, 'algorithm')),
    keyStore: resolveKeyStore(c, rec.keyStore, child(path, 'keyStore')),
    validityYears: integer(c, rec.validityYears, child(path, 'validityYears'), 1, 50, validityYears),
  };
}

// ---- sections -------------------------------------------------------------

function resolveRootCa(c: Collector, value: unknown): ResolvedRootCa {
  const rec = section(c, value, 'rootCa', [
    'subject',
    'algorithm',
    'keyStore',
    'validityYears',
    'keyHandling',
  ]);
  const ca = resolveCa(c, rec, 'rootCa', 'CN=aws-ca Root CA', 20);
  const keyHandling = pick(c, rec.keyHandling, ROOT_KEY_HANDLING, 'rootCa.keyHandling', 'retain');
  if (keyHandling === 'offline' && ca.keyStore.backend === 'kms') {
    c.add(
      'rootCa.keyHandling',
      'An offline root key has to be exported, and a KMS key cannot be exported. ' +
        'Use "parameter" or "secret" for the root, or keep it ("retain").',
    );
  }
  return { ...ca, keyHandling };
}

function resolveProfiles(c: Collector, value: unknown, path: string): Profile[] {
  if (value === undefined) {
    return [...PROFILES];
  }
  if (!Array.isArray(value) || value.length === 0) {
    c.add(path, 'Must be a non-empty list of "client" and "server".');
    return [...PROFILES];
  }
  const profiles = new Set<Profile>();
  for (const [index, item] of value.entries()) {
    profiles.add(pick(c, item, PROFILES, `${path}[${index}]`, 'client'));
  }
  return [...profiles];
}

function resolveSubordinateCas(c: Collector, value: unknown, root: ResolvedRootCa): ResolvedSubordinateCa[] {
  const defaultYears = Math.min(10, root.validityYears - 1);
  const fallback = (): ResolvedSubordinateCa[] => [
    {
      ...resolveCa(c, {}, 'subordinateCas[0]', 'CN=aws-ca issuing CA', defaultYears),
      label: 'issuing',
      profiles: [...PROFILES],
    },
  ];
  if (value === undefined) {
    return fallback();
  }
  if (!Array.isArray(value)) {
    c.add('subordinateCas', 'Must be a list.');
    return fallback();
  }
  if (value.length === 0) {
    c.add('subordinateCas', 'At least one subordinate CA is required.');
    return fallback();
  }
  const labels = new Set<string>();
  return value.map((item: unknown, index): ResolvedSubordinateCa => {
    const path = `subordinateCas[${index}]`;
    const rec = section(c, item, path, [
      'label',
      'subject',
      'algorithm',
      'keyStore',
      'validityYears',
      'profiles',
    ]);
    const label = text(
      c,
      rec.label,
      child(path, 'label'),
      LABEL,
      'lowercase letters, digits and "-", at most 32 characters',
      '',
    );
    if (rec.label === undefined) {
      c.add(child(path, 'label'), 'Required.');
    } else if (label === 'root') {
      c.add(child(path, 'label'), '"root" is reserved for the root CA.');
    } else if (labels.has(label)) {
      c.add(child(path, 'label'), `Duplicate label "${label}".`);
    }
    labels.add(label);
    const ca = resolveCa(c, rec, path, `CN=aws-ca ${label || 'subordinate'} CA`, defaultYears);
    if (rec.validityYears !== undefined && ca.validityYears >= root.validityYears) {
      c.add(
        child(path, 'validityYears'),
        `Must be shorter than the root CA's validity (${root.validityYears} years).`,
      );
    }
    return { ...ca, label, profiles: resolveProfiles(c, rec.profiles, child(path, 'profiles')) };
  });
}

function resolveOperationalKey(
  c: Collector,
  value: unknown,
  needed: boolean,
  cas: ResolvedSubordinateCa[],
): ResolvedOperationalKey | undefined {
  if (!needed) {
    if (value !== undefined) {
      c.add(
        'operationalKey',
        'Configured but not used: SCEP is disabled and OCSP does not use the operational key.',
      );
    }
    return undefined;
  }
  const rec = section(c, value, 'operationalKey', [
    'backend',
    'protection',
    'kmsKeyArn',
    'modulusLength',
    'validityDays',
  ]);
  // The key store options sit directly in the operational key section, next to its own settings.
  const storeOptions = { backend: rec.backend, protection: rec.protection, kmsKeyArn: rec.kmsKeyArn };
  const keyStore = resolveKeyStore(c, storeOptions, 'operationalKey', { kmsNotAllowed: KMS_OPERATIONAL_KEY });
  const validityDays = integer(c, rec.validityDays, 'operationalKey.validityDays', 1, 3650, 365);
  const shortest = Math.min(...cas.map((ca) => ca.validityYears)) * DAYS_PER_YEAR;
  if (validityDays > shortest) {
    c.add('operationalKey.validityDays', `Must fit inside the shortest subordinate CA (${shortest} days).`);
  }
  return {
    keyStore: keyStore as ResolvedOperationalKey['keyStore'],
    modulusLength: pick(c, rec.modulusLength, MODULUS_LENGTHS, 'operationalKey.modulusLength', 2048),
    validityDays,
  };
}

function resolveDomain(c: Collector, value: unknown, path: string, region?: string): DomainInput | undefined {
  if (value === undefined) {
    return undefined;
  }
  const rec = section(c, value, path, ['name', 'certificateArn']);
  if (rec.name === undefined || rec.certificateArn === undefined) {
    c.add(path, 'Both name and certificateArn are required.');
    return undefined;
  }
  const name = text(c, rec.name, child(path, 'name'), HOSTNAME, 'a lowercase host name', '');
  const arnPath = child(path, 'certificateArn');
  const certificateArn = text(c, rec.certificateArn, arnPath, ACM_ARN, 'an ACM certificate ARN', '');
  const arnRegion = ACM_ARN.exec(certificateArn)?.[1];
  if (region !== undefined && arnRegion !== undefined && arnRegion !== region) {
    c.add(arnPath, `The certificate must be in ${region} (it is in ${arnRegion}).`);
  }
  return { name, certificateArn };
}

function resolveRestApi(c: Collector, raw: Rec, mtls: boolean, domain?: DomainInput): ResolvedFrontDoor {
  const endpointType = pick(c, raw.endpointType, ENDPOINT_TYPES, 'frontDoor.endpointType', 'regional');
  const result: ResolvedFrontDoor = { type: 'rest-api', endpointType, mtls };
  if (domain) {
    result.domain = domain;
  }
  if (endpointType === 'regional') {
    for (const key of ['vpcEndpointId', 'vpcId', 'subnetIds']) {
      if (raw[key] !== undefined) {
        c.add(`frontDoor.${key}`, 'Only valid when endpointType is "private".');
      }
    }
    if (mtls && !domain) {
      c.add('frontDoor.domain', 'mTLS needs a custom domain.');
    }
    return result;
  }
  if (mtls) {
    c.add('frontDoor.mtls', 'mTLS is not available on a private API.');
  }
  if (raw.vpcEndpointId !== undefined) {
    result.vpcEndpointId = text(
      c,
      raw.vpcEndpointId,
      'frontDoor.vpcEndpointId',
      VPC_ENDPOINT_ID,
      'a VPC endpoint id such as vpce-0abc123',
      '',
    );
    return result;
  }
  if (raw.vpcId === undefined) {
    c.add(
      'frontDoor.vpcEndpointId',
      'A private API needs vpcEndpointId, or vpcId and subnetIds to create one.',
    );
    return result;
  }
  result.vpcId = text(c, raw.vpcId, 'frontDoor.vpcId', VPC_ID, 'a VPC id such as vpc-0abc123', '');
  const subnets = raw.subnetIds;
  if (!Array.isArray(subnets) || subnets.length === 0) {
    c.add('frontDoor.subnetIds', 'At least one subnet is required with vpcId.');
  } else {
    result.subnetIds = subnets.map((subnet: unknown, index) =>
      text(c, subnet, `frontDoor.subnetIds[${index}]`, SUBNET_ID, 'a subnet id such as subnet-0abc123', ''),
    );
  }
  return result;
}

function resolveFrontDoor(c: Collector, value: unknown, cas: ResolvedCa[]): ResolvedFrontDoor {
  const fallback: ResolvedFrontDoor = { type: 'cloudfront', mtls: false };
  const raw = section(c, value, 'frontDoor', [
    'type',
    'mtls',
    'domain',
    'endpointType',
    'vpcEndpointId',
    'vpcId',
    'subnetIds',
  ]);
  const type = pick(c, raw.type, FRONT_DOORS, 'frontDoor.type', 'cloudfront');
  if (raw.type !== undefined && type !== raw.type) {
    return fallback;
  }
  const allowedByType: Record<(typeof FRONT_DOORS)[number], readonly string[]> = {
    'function-url': ['type'],
    cloudfront: ['type', 'mtls', 'domain'],
    'http-api': ['type', 'mtls', 'domain'],
    'rest-api': ['type', 'mtls', 'domain', 'endpointType', 'vpcEndpointId', 'vpcId', 'subnetIds'],
  };
  for (const key of Object.keys(raw)) {
    if (key === 'mtls' && type === 'function-url') {
      c.add('frontDoor.mtls', 'Not supported by a Function URL: it cannot request client certificates.');
    } else if (!allowedByType[type].includes(key)) {
      c.add(`frontDoor.${key}`, `Not valid for a "${type}" front door.`);
    }
  }
  if (type === 'function-url') {
    return { type };
  }
  const mtls = flag(c, raw.mtls, 'frontDoor.mtls', false);
  const domain = resolveDomain(
    c,
    raw.domain,
    'frontDoor.domain',
    type === 'cloudfront' ? 'us-east-1' : undefined,
  );
  if (type === 'cloudfront') {
    const p521 = cas.some((ca) => ca.algorithm.type === 'ecdsa' && ca.algorithm.curve === 'P-521');
    if (mtls && p521) {
      c.add(
        'frontDoor.mtls',
        'CloudFront trust stores support ECDSA P-256 and P-384 only, and at least one CA uses P-521.',
      );
    }
    return domain ? { type, mtls, domain } : { type, mtls };
  }
  if (type === 'http-api') {
    if (mtls && !domain) {
      c.add('frontDoor.domain', 'mTLS needs a custom domain.');
    }
    return domain ? { type, mtls, domain } : { type, mtls };
  }
  return resolveRestApi(c, raw, mtls, domain);
}

function resolveSuffixes(c: Collector, value: unknown, required: boolean): string[] {
  const path = 'policy.allowedDomainSuffixes';
  const needed =
    'Required because a subordinate CA issues the "server" profile: list the domains it may certify.';
  if (value === undefined) {
    if (required) {
      c.add(path, needed);
    }
    return [];
  }
  if (!Array.isArray(value)) {
    c.add(path, 'Must be a list of domain suffixes such as "example.internal".');
    return [];
  }
  if (required && value.length === 0) {
    c.add(path, needed);
  }
  return value.map((suffix: unknown, index) =>
    text(
      c,
      suffix,
      `${path}[${index}]`,
      DOMAIN_SUFFIX,
      'a lowercase domain suffix, optionally with a leading dot',
      '',
    ),
  );
}

function resolveSubjectTemplate(c: Collector, value: unknown): string {
  const path = 'policy.subjectTemplate';
  const fallback = 'CN={username}';
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'string' || !value.includes('{username}')) {
    c.add(path, 'Must contain {username} so the certificate is bound to the authenticated user.');
    return fallback;
  }
  if (!DN.test(value.replaceAll('{username}', 'user'))) {
    c.add(path, 'Must be a distinguished name template such as CN={username},O=Example.');
    return fallback;
  }
  return value;
}

function resolveGroups(c: Collector, value: unknown): ResolvedConfig['groups'] {
  const rec = section(c, value, 'groups', ['client', 'server', 'admin']);
  const what = 'a group name without whitespace';
  const names = {
    client: text(c, rec.client, 'groups.client', GROUP_NAME, what, 'est-client'),
    server: text(c, rec.server, 'groups.server', GROUP_NAME, what, 'est-server'),
    admin: text(c, rec.admin, 'groups.admin', GROUP_NAME, what, 'est-admin'),
  };
  const seen = new Map<string, string>();
  for (const key of ['client', 'server', 'admin'] as const) {
    const first = seen.get(names[key]);
    if (first === undefined) {
      seen.set(names[key], key);
    } else {
      c.add(`groups.${key}`, `Must differ from groups.${first}.`);
    }
  }
  return names;
}

// ---- entry point ----------------------------------------------------------

/**
 * Validates the deployer's configuration and fills in the defaults.
 * Throws a {@link ConfigError} listing every problem found.
 */
export function resolveConfig(input: AwsCaConfigInput = {}): ResolvedConfig {
  const c = new Collector();
  const top = section(c, input, '', [
    'namePrefix',
    'rootCa',
    'subordinateCas',
    'operationalKey',
    'scep',
    'ocsp',
    'crl',
    'lifetimes',
    'policy',
    'groups',
    'auth',
    'frontDoor',
    'removalPolicy',
  ]);

  const removalPolicy = pick(c, top.removalPolicy, REMOVAL_POLICIES, 'removalPolicy', 'retain');
  const namePrefix = text(
    c,
    top.namePrefix,
    'namePrefix',
    NAME_PREFIX,
    'an absolute parameter path such as /private-ca',
    '/private-ca',
  );
  if (RESERVED_PARAMETER_PREFIX.test(namePrefix)) {
    c.add(
      'namePrefix',
      'Systems Manager reserves parameter names that start with "aws" or "ssm" (in any case); ' +
        'choose a prefix such as /private-ca.',
    );
  }
  const rootCa = resolveRootCa(c, top.rootCa);
  const subordinateCas = resolveSubordinateCas(c, top.subordinateCas, rootCa);
  const issuing = (profile: Profile): ResolvedSubordinateCa[] =>
    subordinateCas.filter((ca) => ca.profiles.includes(profile));

  const scepRec = section(c, top.scep, 'scep', ['enabled']);
  const scepEnabled = flag(c, scepRec.enabled, 'scep.enabled', true);
  if (scepEnabled && issuing('client').length === 0) {
    c.add('scep.enabled', 'SCEP issues the "client" profile, but no subordinate CA issues it.');
  }

  const ocspRec = section(c, top.ocsp, 'ocsp', ['enabled', 'signing', 'maxAgeSeconds', 'nextUpdateHours']);
  const ocspEnabled = flag(c, ocspRec.enabled, 'ocsp.enabled', true);
  const ocspSigning = pick(c, ocspRec.signing, OCSP_SIGNING, 'ocsp.signing', 'operational');
  const nextUpdateHours = integer(c, ocspRec.nextUpdateHours, 'ocsp.nextUpdateHours', 1, 168, 4);
  const maxAgeSeconds = integer(c, ocspRec.maxAgeSeconds, 'ocsp.maxAgeSeconds', 0, 7 * 24 * 3600, 3600);
  if (maxAgeSeconds > nextUpdateHours * 3600) {
    c.add('ocsp.maxAgeSeconds', `Must not exceed nextUpdateHours (${nextUpdateHours * 3600} seconds).`);
  }
  if (ocspSigning === 'kms' && !ocspEnabled) {
    c.add('ocsp.signing', 'A dedicated KMS signing key needs OCSP to be enabled.');
  }
  if (ocspSigning === 'ca' && subordinateCas.some((ca) => ca.keyStore.backend !== 'kms')) {
    c.add(
      'ocsp.signing',
      'Signing OCSP responses with the CA key needs every subordinate CA to use the "kms" backend; ' +
        'otherwise use "operational".',
    );
  }

  const operationalKeyNeeded = scepEnabled || (ocspEnabled && ocspSigning === 'operational');
  const operationalKey = resolveOperationalKey(c, top.operationalKey, operationalKeyNeeded, subordinateCas);

  const crlRec = section(c, top.crl, 'crl', ['nextUpdateDays']);
  const crl = { nextUpdateDays: integer(c, crlRec.nextUpdateDays, 'crl.nextUpdateDays', 1, 90, 7) };

  const lifetimeRec = section(c, top.lifetimes, 'lifetimes', ['clientDays', 'serverDays']);
  const lifetimes = {
    clientDays: integer(c, lifetimeRec.clientDays, 'lifetimes.clientDays', 1, 3650, 365),
    serverDays: integer(c, lifetimeRec.serverDays, 'lifetimes.serverDays', 1, 3650, 90),
  };
  for (const profile of PROFILES) {
    const days = lifetimes[`${profile}Days`];
    const tooShort = issuing(profile).find((ca) => ca.validityYears * DAYS_PER_YEAR < days);
    if (tooShort) {
      c.add(
        `lifetimes.${profile}Days`,
        `Must fit inside the subordinate CA "${tooShort.label}" (${tooShort.validityYears * DAYS_PER_YEAR} days).`,
      );
    }
  }

  const policyRec = section(c, top.policy, 'policy', ['allowedDomainSuffixes', 'subjectTemplate']);
  const allowedDomainSuffixes = resolveSuffixes(
    c,
    policyRec.allowedDomainSuffixes,
    issuing('server').length > 0,
  );
  const subjectTemplate = resolveSubjectTemplate(c, policyRec.subjectTemplate);

  const groups = resolveGroups(c, top.groups);
  const authRec = section(c, top.auth, 'auth', ['cognitoTier']);
  const auth = { cognitoTier: pick(c, authRec.cognitoTier, COGNITO_TIERS, 'auth.cognitoTier', 'lite') };
  const frontDoor = resolveFrontDoor(c, top.frontDoor, [rootCa, ...subordinateCas]);

  if (c.issues.length > 0) {
    throw new ConfigError(c.issues);
  }

  const warnings: string[] = [];
  if (ocspEnabled && frontDoor.type !== 'cloudfront') {
    warnings.push(
      `OCSP will be served over HTTPS only with the "${frontDoor.type}" front door; clients that need an ` +
        'http:// responder URL cannot use it. The "cloudfront" front door can serve OCSP over HTTP.',
    );
  }

  return {
    namePrefix,
    rootCa,
    subordinateCas,
    ...(operationalKey ? { operationalKey } : {}),
    scep: { enabled: scepEnabled },
    ocsp: { enabled: ocspEnabled, signing: ocspSigning, maxAgeSeconds, nextUpdateHours },
    crl,
    lifetimes,
    policy: { allowedDomainSuffixes, subjectTemplate },
    groups,
    auth,
    frontDoor,
    removalPolicy,
    warnings,
  };
}
