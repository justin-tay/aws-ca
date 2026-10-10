import { App } from 'aws-cdk-lib/core';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { AwsCaStack } from '../lib/aws-ca-stack';
import { resolveConfig, type AwsCaConfigInput } from '../src/config';

function templateFor(input: AwsCaConfigInput): Template {
  // Bundling is covered elsewhere; these tests only need the template.
  const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
  const stack = new AwsCaStack(app, 'FrontDoor', {
    config: resolveConfig({ policy: { allowedDomainSuffixes: ['example.internal'] }, ...input }),
  });
  return Template.fromStack(stack);
}

type Resources = Record<string, { Properties: Record<string, unknown> }>;

const distributions = (template: Template): Resources =>
  template.findResources('AWS::CloudFront::Distribution') as Resources;

const behaviorsOf = (distribution: {
  Properties: Record<string, unknown>;
}): { default: Record<string, unknown>; byPath: Record<string, Record<string, unknown>> } => {
  const config = distribution.Properties.DistributionConfig as {
    DefaultCacheBehavior: Record<string, unknown>;
    CacheBehaviors?: Record<string, unknown>[];
  };
  return {
    default: config.DefaultCacheBehavior,
    byPath: Object.fromEntries(
      (config.CacheBehaviors ?? []).map((behavior) => [behavior.PathPattern as string, behavior]),
    ),
  };
};

describe('the function-url front door', () => {
  const template = templateFor({ frontDoor: { type: 'function-url' } });

  it('has no CloudFront at all, and a public Function URL', () => {
    expect(Object.keys(distributions(template))).toHaveLength(0);
    template.hasResourceProperties('AWS::Lambda::Url', { AuthType: 'NONE' });
  });

  it('does not ask the Lambda to check an origin secret', () => {
    const json = JSON.stringify(template.toJSON());
    expect(json).not.toContain('ORIGIN_VERIFY_PARAMETER');
    expect(json).not.toContain('x-origin-verify');
  });
});

describe('the cloudfront front door without mTLS', () => {
  const template = templateFor({ frontDoor: { type: 'cloudfront' } });

  it('is one distribution: enrollment HTTPS only, CRL and OCSP also HTTP', () => {
    const all = Object.values(distributions(template));
    expect(all).toHaveLength(1);
    const { default: main, byPath } = behaviorsOf(all[0]);
    expect(main.ViewerProtocolPolicy).toBe('https-only');
    expect(byPath['/crl/*'].ViewerProtocolPolicy).toBe('allow-all');
    expect(byPath['/ocsp/*'].ViewerProtocolPolicy).toBe('allow-all');
  });

  it('has no viewer mTLS and no trust store', () => {
    expect(JSON.stringify(template.toJSON())).not.toContain('ViewerMtlsConfig');
    expect(Object.keys(template.findResources('AWS::CloudFront::TrustStore'))).toHaveLength(0);
  });

  it('reaches the Function URL with a secret header, and not with origin access control', () => {
    expect(Object.keys(template.findResources('AWS::CloudFront::OriginAccessControl'))).toHaveLength(0);
    const origins = (
      Object.values(distributions(template))[0].Properties.DistributionConfig as {
        Origins: { OriginCustomHeaders?: { HeaderName: string }[]; OriginAccessControlId?: string }[];
      }
    ).Origins;
    expect(origins).toHaveLength(1);
    expect(origins[0].OriginCustomHeaders?.map((header) => header.HeaderName)).toEqual(['x-origin-verify']);
    expect(origins[0].OriginAccessControlId).toBeUndefined();
  });

  it('forwards Authorization through the cache key, because an origin request policy cannot', () => {
    const policies = Object.values(
      template.findResources('AWS::CloudFront::OriginRequestPolicy') as Resources,
    ).map((policy) => JSON.stringify(policy.Properties));
    expect(policies.some((policy) => policy.includes('Authorization'))).toBe(false);
    const caches = Object.values(template.findResources('AWS::CloudFront::CachePolicy') as Resources).map(
      (policy) => JSON.stringify(policy.Properties),
    );
    expect(caches.some((policy) => policy.includes('Authorization'))).toBe(true);
  });

  it('never whitelists Host, which a Function URL answers with 403', () => {
    const policies = JSON.stringify(template.findResources('AWS::CloudFront::OriginRequestPolicy'));
    expect(policies).not.toContain('"Host"');
    expect(policies).not.toContain('allViewer');
  });

  it('makes the Lambda check the secret and know where it is published', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: {
        Variables: {
          ORIGIN_VERIFY_PARAMETER: '/private-ca/internal/origin-verify',
          PUBLIC_URLS_PARAMETER: '/private-ca/internal/public-urls',
        },
      },
    });
  });

  it('publishes the addresses once the distribution exists', () => {
    template.hasResourceProperties('AWS::CloudFormation::CustomResource', { Kind: 'public-urls' });
  });
});

describe('the cloudfront front door with mTLS', () => {
  const template = templateFor({ frontDoor: { type: 'cloudfront', mtls: true } });
  const all = Object.values(distributions(template));
  const mtls = all.filter((d) => JSON.stringify(d.Properties).includes('ViewerMtlsConfig'));
  const plain = all.filter((d) => !JSON.stringify(d.Properties).includes('ViewerMtlsConfig'));

  it('is two distributions: HTTP and mTLS are never on the same one', () => {
    expect(all).toHaveLength(2);
    expect(mtls).toHaveLength(1);
    expect(plain).toHaveLength(1);
    for (const behavior of Object.values(behaviorsOf(mtls[0]).byPath)) {
      expect(behavior.ViewerProtocolPolicy).not.toBe('allow-all');
    }
    expect(behaviorsOf(mtls[0]).default.ViewerProtocolPolicy).toBe('https-only');
  });

  it('asks for a client certificate from the trust store without insisting, over HTTP/2', () => {
    const config = mtls[0].Properties.DistributionConfig as Record<string, unknown>;
    // Optional, so a first enrollment by password is possible; a presented certificate is validated.
    expect(config.ViewerMtlsConfig).toMatchObject({ Mode: 'optional' });
    expect(config.HttpVersion).toBe('http2');
    expect(Object.keys(template.findResources('AWS::CloudFront::TrustStore'))).toHaveLength(1);
  });

  it('serves only CRL and OCSP on the plain distribution, and 404 for everything else', () => {
    const { default: main, byPath } = behaviorsOf(plain[0]);
    expect(Object.keys(byPath).toSorted()).toEqual(['/crl/*', '/ocsp/*']);
    expect(JSON.stringify(main)).toContain('FunctionAssociations');
  });

  it('forwards the viewer certificate headers to the Lambda, which trusts them after the secret check', () => {
    const policies = JSON.stringify(template.findResources('AWS::CloudFront::OriginRequestPolicy'));
    expect(policies).toContain('CloudFront-Viewer-Cert-Pem');
    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: { Variables: { MTLS_VIEWER_CERT: '1' } },
    });
  });

  it('gives the bootstrap the bucket permissions it needs for the trust bundle', () => {
    const json = JSON.stringify(template.findResources('AWS::IAM::Policy'));
    expect(json).toContain('trust/*');
    expect(json).toContain('s3:ListBucket');
  });
});

describe('a custom domain', () => {
  const template = templateFor({
    frontDoor: {
      type: 'cloudfront',
      domain: {
        name: 'pki.example.internal',
        certificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000',
      },
    },
  });

  it('puts the name and certificate on the distribution, with TLS 1.2 or later', () => {
    const config = Object.values(distributions(template))[0].Properties.DistributionConfig as {
      Aliases: string[];
      ViewerCertificate: { MinimumProtocolVersion: string };
    };
    expect(config.Aliases).toEqual(['pki.example.internal']);
    expect(config.ViewerCertificate.MinimumProtocolVersion).toMatch(/TLSv1\.2/);
  });
});

describe('the http-api front door', () => {
  const domain = {
    name: 'pki.example.internal',
    certificateArn:
      'arn:aws:acm:ap-southeast-1:123456789012:certificate/00000000-0000-0000-0000-000000000000',
  };

  it('is an HTTP API proxying to the Lambda, with no Function URL to go around it', () => {
    const template = templateFor({ frontDoor: { type: 'http-api' } });
    template.resourceCountIs('AWS::ApiGatewayV2::Api', 1);
    template.hasResourceProperties('AWS::ApiGatewayV2::Route', { RouteKey: 'ANY /{proxy+}' });
    expect(Object.keys(template.findResources('AWS::Lambda::Url'))).toHaveLength(0);
    expect(Object.keys(distributions(template))).toHaveLength(0);
  });

  it('keeps the default endpoint without mTLS', () => {
    const template = templateFor({ frontDoor: { type: 'http-api' } });
    const apis = Object.values(template.findResources('AWS::ApiGatewayV2::Api'));
    expect(apis[0].Properties.DisableExecuteApiEndpoint).toBeFalsy();
  });

  it('with mTLS: a custom domain with the CA bundle as trust store, and no default endpoint', () => {
    const template = templateFor({ frontDoor: { type: 'http-api', mtls: true, domain } });
    const apis = Object.values(template.findResources('AWS::ApiGatewayV2::Api'));
    expect(apis[0].Properties.DisableExecuteApiEndpoint).toBe(true);
    template.hasResourceProperties('AWS::ApiGatewayV2::DomainName', {
      DomainName: 'pki.example.internal',
      MutualTlsAuthentication: Match.objectLike({ TruststoreUri: Match.anyValue() }),
    });
    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: { Variables: { MTLS_APIGW: '1' } },
    });
  });

  it('never makes the Lambda look for an origin secret', () => {
    const template = templateFor({ frontDoor: { type: 'http-api' } });
    expect(JSON.stringify(template.toJSON())).not.toContain('ORIGIN_VERIFY_PARAMETER');
  });
});

describe('the rest-api front door', () => {
  it('regional: a REST API proxy that passes binary bodies', () => {
    const template = templateFor({ frontDoor: { type: 'rest-api' } });
    template.hasResourceProperties('AWS::ApiGateway::RestApi', {
      EndpointConfiguration: { Types: ['REGIONAL'] },
      BinaryMediaTypes: ['*/*'],
    });
    expect(Object.keys(template.findResources('AWS::Lambda::Url'))).toHaveLength(0);
  });

  it('private with an existing VPC endpoint: reachable only from it', () => {
    const template = templateFor({
      frontDoor: { type: 'rest-api', endpointType: 'private', vpcEndpointId: 'vpce-0123456789abcdef0' },
    });
    template.hasResourceProperties('AWS::ApiGateway::RestApi', {
      EndpointConfiguration: { Types: ['PRIVATE'], VpcEndpointIds: ['vpce-0123456789abcdef0'] },
    });
    const policy = JSON.stringify(
      Object.values(template.findResources('AWS::ApiGateway::RestApi'))[0].Properties.Policy,
    );
    expect(policy).toContain('aws:SourceVpce');
    expect(policy).toContain('vpce-0123456789abcdef0');
    expect(policy).toContain('Deny');
  });

  it('private from a VPC and subnets: creates the endpoint, with private DNS and a closed group', () => {
    const template = templateFor({
      frontDoor: {
        type: 'rest-api',
        endpointType: 'private',
        vpcId: 'vpc-0123456789abcdef0',
        subnetIds: ['subnet-0123456789abcdef0', 'subnet-0123456789abcdef1'],
      },
    });
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', {
      VpcId: 'vpc-0123456789abcdef0',
      VpcEndpointType: 'Interface',
      PrivateDnsEnabled: true,
      SubnetIds: ['subnet-0123456789abcdef0', 'subnet-0123456789abcdef1'],
    });
    const groups = JSON.stringify(template.findResources('AWS::EC2::SecurityGroup'));
    expect(groups).toContain('10.0.0.0/8');
    expect(groups).not.toContain('0.0.0.0/0');
  });

  it('with mTLS on a regional domain: no default endpoint', () => {
    const template = templateFor({
      frontDoor: {
        type: 'rest-api',
        mtls: true,
        domain: {
          name: 'pki.example.internal',
          certificateArn:
            'arn:aws:acm:ap-southeast-1:123456789012:certificate/00000000-0000-0000-0000-000000000000',
        },
      },
    });
    template.hasResourceProperties('AWS::ApiGateway::RestApi', { DisableExecuteApiEndpoint: true });
    template.hasResourceProperties('AWS::ApiGateway::DomainName', {
      MutualTlsAuthentication: Match.objectLike({ TruststoreUri: Match.anyValue() }),
    });
  });
});
