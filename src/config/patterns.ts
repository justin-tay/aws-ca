// The allowed values and the patterns the configuration is checked against.

import type {
  CognitoTier,
  EndpointType,
  KeyBackend,
  KeyProtection,
  OcspSigning,
  Profile,
  RootKeyHandling,
  RsaModulusLength,
  ScepChallengeMode,
} from './types';

export const BACKENDS = ['parameter', 'secret', 'kms'] as const satisfies readonly KeyBackend[];
export const PROTECTIONS = [
  'aws-managed-key',
  'app-encrypted',
  'customer-managed-key',
] as const satisfies readonly KeyProtection[];
export const CURVES = ['P-256', 'P-384', 'P-521'] as const;
export const MODULUS_LENGTHS = [2048, 3072, 4096] as const satisfies readonly RsaModulusLength[];
export const PROFILES = ['client', 'server'] as const satisfies readonly Profile[];
export const ROOT_KEY_HANDLING = ['retain', 'offline'] as const satisfies readonly RootKeyHandling[];
export const OCSP_SIGNING = ['operational', 'kms', 'ca'] as const satisfies readonly OcspSigning[];
export const COGNITO_TIERS = ['lite', 'essentials'] as const satisfies readonly CognitoTier[];
export const SCEP_CHALLENGES = ['static', 'dynamic', 'both'] as const satisfies readonly ScepChallengeMode[];
export const ENDPOINT_TYPES = ['regional', 'private'] as const satisfies readonly EndpointType[];
export const REMOVAL_POLICIES = ['retain', 'destroy'] as const;
export const FRONT_DOORS = ['function-url', 'cloudfront', 'http-api', 'rest-api'] as const;

export const DAYS_PER_YEAR = 365;
export const DN = /^[A-Za-z][A-Za-z0-9.]*=[^,=]+(,\s*[A-Za-z][A-Za-z0-9.]*=[^,=]+)*$/;
export const HOST_LABEL = '[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?';
export const HOSTNAME = new RegExp(`^${HOST_LABEL}(\\.${HOST_LABEL})*$`);
export const DOMAIN_SUFFIX = new RegExp(`^\\.?${HOST_LABEL}(\\.${HOST_LABEL})*$`);
export const NAME_PREFIX = /^\/[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)*$/;
/** SSM rejects parameter names beginning with "aws" or "ssm", with or without the leading slash. */
export const RESERVED_PARAMETER_PREFIX = /^\/?(aws|ssm)/i;
export const KMS_KEY_ARN = /^arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:(key|alias)\/.+$/;
export const ACM_ARN = /^arn:aws[a-z-]*:acm:([a-z0-9-]+):\d{12}:certificate\/.+$/;
export const GROUP_NAME = /^\S{1,128}$/;
export const VPC_ENDPOINT_ID = /^vpce-[0-9a-f]+$/;
export const VPC_ID = /^vpc-[0-9a-f]+$/;
export const SUBNET_ID = /^subnet-[0-9a-f]+$/;

export const KMS_OPERATIONAL_KEY =
  'The operational key cannot be stored in KMS: SCEP clients encrypt to it with RSA PKCS#1 v1.5, ' +
  'which KMS asymmetric Decrypt does not support. Use "parameter" or "secret".';
