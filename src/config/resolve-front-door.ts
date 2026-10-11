import type { DomainInput, ResolvedCa, ResolvedFrontDoor } from './types';
import {
  ENDPOINT_TYPES,
  FRONT_DOORS,
  HOSTNAME,
  ACM_ARN,
  VPC_ENDPOINT_ID,
  VPC_ID,
  SUBNET_ID,
} from './patterns';
import { Collector, child, section, pick, integer, flag, text, type Rec } from './validate';

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

export function resolveFrontDoor(c: Collector, value: unknown, cas: ResolvedCa[]): ResolvedFrontDoor {
  const fallback: ResolvedFrontDoor = { type: 'cloudfront', mtls: false, originSecretVersion: 1 };
  const raw = section(c, value, 'frontDoor', [
    'type',
    'mtls',
    'domain',
    'endpointType',
    'vpcEndpointId',
    'vpcId',
    'subnetIds',
    'originSecretVersion',
  ]);
  const type = pick(c, raw.type, FRONT_DOORS, 'frontDoor.type', 'cloudfront');
  if (raw.type !== undefined && type !== raw.type) {
    return fallback;
  }
  const allowedByType: Record<(typeof FRONT_DOORS)[number], readonly string[]> = {
    'function-url': ['type'],
    cloudfront: ['type', 'mtls', 'domain', 'originSecretVersion'],
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
    const originSecretVersion = integer(
      c,
      raw.originSecretVersion,
      'frontDoor.originSecretVersion',
      1,
      1_000_000,
      1,
    );
    return domain ? { type, mtls, originSecretVersion, domain } : { type, mtls, originSecretVersion };
  }
  if (type === 'http-api') {
    if (mtls && !domain) {
      c.add('frontDoor.domain', 'mTLS needs a custom domain.');
    }
    return domain ? { type, mtls, domain } : { type, mtls };
  }
  return resolveRestApi(c, raw, mtls, domain);
}
