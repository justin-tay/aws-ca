import { Duration, Stack } from 'aws-cdk-lib/core';
import { Certificate } from 'aws-cdk-lib/aws-certificatemanager';
import {
  AllowedMethods,
  CacheCookieBehavior,
  CacheHeaderBehavior,
  CachePolicy,
  CacheQueryStringBehavior,
  CfnDistribution,
  CfnTrustStore,
  Distribution,
  Function as CloudFrontFunction,
  FunctionCode,
  FunctionEventType,
  HttpVersion,
  OriginRequestCookieBehavior,
  OriginRequestHeaderBehavior,
  OriginRequestPolicy,
  OriginRequestQueryStringBehavior,
  PriceClass,
  SecurityPolicyProtocol,
  ViewerProtocolPolicy,
  type BehaviorOptions,
} from 'aws-cdk-lib/aws-cloudfront';
import { FunctionUrlOrigin } from 'aws-cdk-lib/aws-cloudfront-origins';
import type { IFunctionUrl } from 'aws-cdk-lib/aws-lambda';
import type { Bucket } from 'aws-cdk-lib/aws-s3';
import type { Construct } from 'constructs';
import type { ResolvedConfig } from '../src/config';

export interface CloudFrontFrontDoorProps {
  config: ResolvedConfig & { frontDoor: { type: 'cloudfront' } };
  functionUrl: IFunctionUrl;
  /** Holds the CA bundle that the mTLS trust store reads. */
  bucket: Bucket;
  /** The value of the `x-origin-verify` header, from the bootstrap. */
  originSecret: string;
  /** The object key of the CA bundle, from the bootstrap. Present when mTLS is on. */
  trustBundleKey?: string;
}

/** The headers CloudFront adds for a viewer certificate, which the Lambda reads after the secret check. */
const VIEWER_CERT_HEADERS = [
  'CloudFront-Viewer-Cert-Pem',
  'CloudFront-Viewer-Cert-Subject',
  'CloudFront-Viewer-Cert-Issuer',
  'CloudFront-Viewer-Cert-Serial-Number',
  'CloudFront-Viewer-Cert-Present',
  'CloudFront-Viewer-Cert-Validity',
];

/**
 * The `cloudfront` front door (design.md section 7).
 *
 * - The origin is the public Function URL plus a secret header, **not** OAC: OAC needs the client
 *   to send `x-amz-content-sha256` on POSTs and overwrites `Authorization`.
 * - Viewer mTLS cannot share a distribution with HTTP behaviours, so with mTLS there are two: an
 *   HTTPS-only one for EST, SCEP and revocation, and a plain one that serves only CRL and OCSP.
 * - The origin request policy lists headers by name: the `allViewer*` policies forward `Host`,
 *   which a Function URL answers with 403.
 */
export class CloudFrontFrontDoor {
  /** The distribution that serves enrollment (and revocation). */
  readonly main: Distribution;
  /** The plain HTTP distribution for CRL and OCSP, when mTLS forces a second one. */
  readonly plain?: Distribution;
  readonly trustStore?: CfnTrustStore;
  /** The host name clients use for EST, SCEP and revocation. */
  readonly mainHost: string;
  /** The host name of the plain HTTP distribution, or the same as `mainHost`. */
  readonly revocationHost: string;

  constructor(scope: Construct, props: CloudFrontFrontDoorProps) {
    const { config, functionUrl } = props;
    const frontDoor = config.frontDoor;
    const stack = Stack.of(scope);
    const domain = frontDoor.domain;
    const certificate = domain
      ? Certificate.fromCertificateArn(scope, 'DomainCertificate', domain.certificateArn)
      : undefined;
    const origin = new FunctionUrlOrigin(functionUrl, {
      customHeaders: { 'x-origin-verify': props.originSecret },
    });

    // Authorization cannot be in an origin request policy; it is forwarded because it is in the
    // cache key (see dynamicCache).
    const dynamicHeaders = ['Content-Type', 'Accept', ...(frontDoor.mtls ? VIEWER_CERT_HEADERS : [])];
    const dynamicRequests = new OriginRequestPolicy(scope, 'DynamicOriginRequest', {
      comment: 'Whitelisted headers, all query strings (SCEP), no cookies',
      headerBehavior: OriginRequestHeaderBehavior.allowList(...dynamicHeaders),
      queryStringBehavior: OriginRequestQueryStringBehavior.all(),
      cookieBehavior: OriginRequestCookieBehavior.none(),
    });
    // Nothing is cached for enrollment: the TTLs are zero. A one second ceiling keeps the policy valid
    // while allowing the one header in the key that carries the credentials.
    const dynamicCache = new CachePolicy(scope, 'DynamicCache', {
      comment: 'No caching; Authorization is in the key so that it is forwarded',
      minTtl: Duration.seconds(0),
      defaultTtl: Duration.seconds(0),
      maxTtl: Duration.seconds(1),
      headerBehavior: CacheHeaderBehavior.allowList('Authorization'),
      queryStringBehavior: CacheQueryStringBehavior.all(),
      cookieBehavior: CacheCookieBehavior.none(),
    });
    const bodyRequests = new OriginRequestPolicy(scope, 'RevocationOriginRequest', {
      comment: 'OCSP POST needs its content type; nothing else',
      headerBehavior: OriginRequestHeaderBehavior.allowList('Content-Type'),
      queryStringBehavior: OriginRequestQueryStringBehavior.none(),
      cookieBehavior: OriginRequestCookieBehavior.none(),
    });
    const ocspSeconds = config.ocsp.maxAgeSeconds;
    const ocspCache =
      ocspSeconds > 0
        ? new CachePolicy(scope, 'OcspCache', {
            comment:
              'OCSP GET, keyed on the URL (which carries the request); lifetime from ocsp.maxAgeSeconds',
            minTtl: Duration.seconds(0),
            defaultTtl: Duration.seconds(ocspSeconds),
            maxTtl: Duration.seconds(ocspSeconds),
            headerBehavior: CacheHeaderBehavior.none(),
            queryStringBehavior: CacheQueryStringBehavior.none(),
            cookieBehavior: CacheCookieBehavior.none(),
          })
        : CachePolicy.CACHING_DISABLED;
    const crlCache = new CachePolicy(scope, 'CrlCache', {
      comment: 'CRLs: keyed on the URL, lifetime from the origin Cache-Control',
      minTtl: Duration.seconds(0),
      defaultTtl: Duration.hours(1),
      maxTtl: Duration.days(config.crl.nextUpdateDays),
      headerBehavior: CacheHeaderBehavior.none(),
      queryStringBehavior: CacheQueryStringBehavior.none(),
      cookieBehavior: CacheCookieBehavior.none(),
    });

    const revocationBehaviors: Record<string, BehaviorOptions> = {
      '/crl/*': {
        origin,
        viewerProtocolPolicy: ViewerProtocolPolicy.ALLOW_ALL,
        allowedMethods: AllowedMethods.ALLOW_GET_HEAD,
        cachePolicy: crlCache,
      },
      ...(config.ocsp.enabled
        ? {
            '/ocsp/*': {
              origin,
              viewerProtocolPolicy: ViewerProtocolPolicy.ALLOW_ALL,
              allowedMethods: AllowedMethods.ALLOW_ALL,
              cachePolicy: ocspCache,
              originRequestPolicy: bodyRequests,
            },
          }
        : {}),
    };
    const dynamicBehavior: BehaviorOptions = {
      origin,
      viewerProtocolPolicy: ViewerProtocolPolicy.HTTPS_ONLY,
      allowedMethods: AllowedMethods.ALLOW_ALL,
      cachePolicy: dynamicCache,
      originRequestPolicy: dynamicRequests,
    };

    if (!frontDoor.mtls) {
      // One distribution: enrollment is HTTPS only, CRL and OCSP also allow HTTP.
      this.main = new Distribution(scope, 'Distribution', {
        comment: 'aws-ca',
        defaultBehavior: dynamicBehavior,
        additionalBehaviors: revocationBehaviors,
        priceClass: PriceClass.PRICE_CLASS_ALL,
        ...(domain && certificate
          ? {
              domainNames: [domain.name],
              certificate,
              minimumProtocolVersion: SecurityPolicyProtocol.TLS_V1_2_2021,
            }
          : {}),
      });
      this.mainHost = domain?.name ?? this.main.distributionDomainName;
      this.revocationHost = this.mainHost;
      return;
    }

    // mTLS: the trust store is a snapshot of the CA bundle written by the bootstrap. Its key changes
    // with the bundle, so a changed CA set is an update here rather than a silent no-op.
    this.trustStore = new CfnTrustStore(scope, 'TrustStore', {
      name: `${stack.stackName}-ca-bundle`.slice(0, 64),
      caCertificatesBundleSource: {
        caCertificatesBundleS3Location: {
          bucket: props.bucket.bucketName,
          key: props.trustBundleKey ?? '',
          region: stack.region,
        },
      },
    });
    this.main = new Distribution(scope, 'Distribution', {
      comment: 'aws-ca enrollment (viewer mTLS)',
      defaultBehavior: dynamicBehavior,
      // Viewer mTLS is refused on a distribution that allows HTTP, and needs HTTP/3 off.
      httpVersion: HttpVersion.HTTP2,
      priceClass: PriceClass.PRICE_CLASS_ALL,
      ...(domain && certificate
        ? {
            domainNames: [domain.name],
            certificate,
            minimumProtocolVersion: SecurityPolicyProtocol.TLS_V1_2_2021,
          }
        : {}),
    });
    (this.main.node.defaultChild as CfnDistribution).addPropertyOverride(
      'DistributionConfig.ViewerMtlsConfig',
      {
        // Optional: a device with no certificate yet must be able to make its first (password)
        // enrollment. A certificate that is presented is still validated against the trust store.
        Mode: 'optional',
        TrustStoreConfig: { TrustStoreId: this.trustStore.attrId },
      },
    );

    // The plain distribution answers CRL and OCSP and nothing else.
    const notFound = new CloudFrontFunction(scope, 'NotFound', {
      comment: 'Only /crl and /ocsp are served here',
      code: FunctionCode.fromInline(
        "function handler(event) { return { statusCode: 404, statusDescription: 'Not Found' }; }",
      ),
    });
    this.plain = new Distribution(scope, 'RevocationDistribution', {
      comment: 'aws-ca CRL and OCSP over HTTP',
      defaultBehavior: {
        origin,
        viewerProtocolPolicy: ViewerProtocolPolicy.HTTPS_ONLY,
        allowedMethods: AllowedMethods.ALLOW_GET_HEAD,
        cachePolicy: CachePolicy.CACHING_DISABLED,
        functionAssociations: [{ function: notFound, eventType: FunctionEventType.VIEWER_REQUEST }],
      },
      additionalBehaviors: revocationBehaviors,
      priceClass: PriceClass.PRICE_CLASS_ALL,
    });
    this.mainHost = domain?.name ?? this.main.distributionDomainName;
    this.revocationHost = this.plain.distributionDomainName;
  }
}
