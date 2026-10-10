// Input types: what a deployer writes. Every field is optional and has a default.
// Resolved types: what the rest of the app reads. Nothing is optional unless it
// is genuinely absent (for example the operational key when nothing uses it).

export type KeyBackend = 'parameter' | 'secret' | 'kms';
/** How a key held in a parameter or secret is protected at rest. Not applicable to `kms`. */
export type KeyProtection = 'aws-managed-key' | 'app-encrypted' | 'customer-managed-key';
export type EcCurve = 'P-256' | 'P-384' | 'P-521';
export type RsaModulusLength = 2048 | 3072 | 4096;
export type KeyAlgorithm =
  | { type: 'ecdsa'; curve: EcCurve }
  | { type: 'rsa'; modulusLength: RsaModulusLength };
export type Profile = 'client' | 'server';
export type RootKeyHandling = 'retain' | 'offline';
export type OcspSigning = 'operational' | 'kms' | 'ca';
export type CognitoTier = 'lite' | 'essentials';
export type EndpointType = 'regional' | 'private';

export interface KeyStoreInput {
  backend?: KeyBackend;
  protection?: KeyProtection;
  /** An existing KMS key or alias to use when `protection` is `customer-managed-key`. Created by the stack if omitted. */
  kmsKeyArn?: string;
}

export interface CaInput {
  /** Distinguished name, for example `CN=Example Root CA,O=Example`. */
  subject?: string;
  algorithm?: KeyAlgorithm;
  keyStore?: KeyStoreInput;
  validityYears?: number;
}

export interface RootCaInput extends CaInput {
  keyHandling?: RootKeyHandling;
}

export interface SubordinateCaInput extends CaInput {
  /** Stable identifier used in endpoint paths and storage keys. Lowercase letters, digits and `-`. */
  label: string;
  profiles?: Profile[];
}

export interface OperationalKeyInput {
  backend?: Exclude<KeyBackend, 'kms'>;
  protection?: KeyProtection;
  kmsKeyArn?: string;
  modulusLength?: RsaModulusLength;
  validityDays?: number;
}

export interface DomainInput {
  name: string;
  /** ACM certificate. For `cloudfront` it must be in us-east-1. */
  certificateArn: string;
}

export type FrontDoorInput =
  | { type: 'function-url' }
  | { type: 'cloudfront'; mtls?: boolean; domain?: DomainInput }
  | { type: 'http-api'; mtls?: boolean; domain?: DomainInput }
  | {
      type: 'rest-api';
      endpointType?: EndpointType;
      mtls?: boolean;
      domain?: DomainInput;
      vpcEndpointId?: string;
      vpcId?: string;
      subnetIds?: string[];
    };

export interface AwsCaConfigInput {
  /** Prefix for parameter names. Default `/private-ca`. */
  namePrefix?: string;
  rootCa?: RootCaInput;
  /** Default: one `issuing` CA that issues both profiles. */
  subordinateCas?: SubordinateCaInput[];
  operationalKey?: OperationalKeyInput;
  scep?: { enabled?: boolean };
  ocsp?: { enabled?: boolean; signing?: OcspSigning; maxAgeSeconds?: number; nextUpdateHours?: number };
  crl?: { nextUpdateDays?: number };
  lifetimes?: { clientDays?: number; serverDays?: number };
  policy?: { allowedDomainSuffixes?: string[]; subjectTemplate?: string };
  groups?: { client?: string; server?: string; admin?: string };
  auth?: { cognitoTier?: CognitoTier };
  frontDoor?: FrontDoorInput;
}

// ---- resolved ----------------------------------------------------------

export type ResolvedKeyStore =
  | { backend: 'kms' }
  | { backend: 'parameter' | 'secret'; protection: KeyProtection; kmsKeyArn?: string };

export interface ResolvedCa {
  subject: string;
  algorithm: KeyAlgorithm;
  keyStore: ResolvedKeyStore;
  validityYears: number;
}

export interface ResolvedRootCa extends ResolvedCa {
  keyHandling: RootKeyHandling;
}

export interface ResolvedSubordinateCa extends ResolvedCa {
  label: string;
  profiles: Profile[];
}

export interface ResolvedOperationalKey {
  keyStore: Extract<ResolvedKeyStore, { backend: 'parameter' | 'secret' }>;
  modulusLength: RsaModulusLength;
  validityDays: number;
}

export type ResolvedFrontDoor =
  | { type: 'function-url' }
  | { type: 'cloudfront'; mtls: boolean; domain?: DomainInput }
  | { type: 'http-api'; mtls: boolean; domain?: DomainInput }
  | {
      type: 'rest-api';
      endpointType: EndpointType;
      mtls: boolean;
      domain?: DomainInput;
      vpcEndpointId?: string;
      vpcId?: string;
      subnetIds?: string[];
    };

export interface ResolvedConfig {
  namePrefix: string;
  rootCa: ResolvedRootCa;
  subordinateCas: ResolvedSubordinateCa[];
  /** Absent when neither SCEP nor OCSP-with-operational-key needs it. */
  operationalKey?: ResolvedOperationalKey;
  scep: { enabled: boolean };
  ocsp: { enabled: boolean; signing: OcspSigning; maxAgeSeconds: number; nextUpdateHours: number };
  crl: { nextUpdateDays: number };
  lifetimes: { clientDays: number; serverDays: number };
  policy: { allowedDomainSuffixes: string[]; subjectTemplate: string };
  groups: { client: string; server: string; admin: string };
  auth: { cognitoTier: CognitoTier };
  frontDoor: ResolvedFrontDoor;
  /** Non-fatal findings. The app prints them as synth warnings. */
  warnings: string[];
}
