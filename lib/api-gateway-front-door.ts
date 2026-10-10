import { Stack } from 'aws-cdk-lib/core';
import { DomainName as HttpDomainName, HttpApi, HttpMethod, HttpStage } from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import {
  DomainName as RestDomainName,
  EndpointType,
  LambdaIntegration,
  RestApi,
  SecurityPolicy,
} from 'aws-cdk-lib/aws-apigateway';
import { Certificate } from 'aws-cdk-lib/aws-certificatemanager';
import { CfnSecurityGroup, CfnVPCEndpoint, InterfaceVpcEndpoint } from 'aws-cdk-lib/aws-ec2';
import { AnyPrincipal, Effect, PolicyDocument, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import type { IFunction } from 'aws-cdk-lib/aws-lambda';
import type { Bucket } from 'aws-cdk-lib/aws-s3';
import type { Construct } from 'constructs';
import type { ResolvedConfig } from '../src/config';

type ApiConfig = ResolvedConfig & { frontDoor: { type: 'http-api' | 'rest-api' } };

export interface ApiGatewayFrontDoorProps {
  config: ApiConfig;
  handler: IFunction;
  /** Holds the CA bundle API Gateway reads as its mTLS trust store. */
  bucket: Bucket;
  /** The object key of the CA bundle, from the bootstrap. Present when mTLS is on. */
  trustBundleKey?: string;
}

/** The ports and ranges of an interface endpoint's security group: private address space only. */
const PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

/**
 * The `http-api` and `rest-api` front doors (design.md section 7). Both send everything to the one
 * Lambda, as a proxy.
 *
 * - There is no origin secret: API Gateway puts the client certificate in the request context, which
 *   a caller cannot set. What matters instead is that **the default `execute-api` endpoint is
 *   disabled when mTLS is on**, or the certificate requirement could be bypassed through it.
 * - mTLS needs a custom domain; the trust store is the CA bundle the bootstrap wrote to S3.
 * - A private REST API is reachable only through an `execute-api` interface VPC endpoint, and a
 *   resource policy refuses every other source.
 */
export class ApiGatewayFrontDoor {
  /** The address clients use, when it is known at synthesis (a custom domain). */
  readonly publicBase?: string;
  readonly httpApi?: HttpApi;
  readonly restApi?: RestApi;
  readonly vpcEndpoint?: CfnVPCEndpoint;

  constructor(scope: Construct, props: ApiGatewayFrontDoorProps) {
    const { config, handler } = props;
    const frontDoor = config.frontDoor;
    const domain = frontDoor.domain;
    const mtls = frontDoor.mtls;
    const certificate = domain
      ? Certificate.fromCertificateArn(scope, 'DomainCertificate', domain.certificateArn)
      : undefined;
    const trust =
      mtls && props.trustBundleKey ? { bucket: props.bucket, key: props.trustBundleKey } : undefined;
    this.publicBase = domain ? `https://${domain.name}` : undefined;

    if (frontDoor.type === 'http-api') {
      const domainName =
        domain && certificate
          ? new HttpDomainName(scope, 'HttpDomain', {
              domainName: domain.name,
              certificate,
              ...(trust ? { mtls: trust } : {}),
            })
          : undefined;
      const api = new HttpApi(scope, 'HttpApi', {
        apiName: `${Stack.of(scope).stackName}-ca`,
        createDefaultStage: false,
        // With mTLS the default endpoint would let a caller skip the certificate requirement.
        disableExecuteApiEndpoint: mtls,
      });
      api.addRoutes({
        path: '/{proxy+}',
        methods: [HttpMethod.ANY],
        integration: new HttpLambdaIntegration('Proxy', handler),
      });
      new HttpStage(scope, 'DefaultStage', {
        httpApi: api,
        autoDeploy: true,
        ...(domainName ? { domainMapping: { domainName } } : {}),
      });
      this.httpApi = api;
      return;
    }

    const isPrivate = frontDoor.endpointType === 'private';
    let vpcEndpointIds: string[] = [];
    let importedEndpoint;
    if (isPrivate) {
      if (frontDoor.vpcEndpointId) {
        vpcEndpointIds = [frontDoor.vpcEndpointId];
        importedEndpoint = InterfaceVpcEndpoint.fromInterfaceVpcEndpointAttributes(
          scope,
          'ExistingEndpoint',
          {
            vpcEndpointId: frontDoor.vpcEndpointId,
            port: 443,
          },
        );
      } else if (frontDoor.vpcId && frontDoor.subnetIds) {
        const group = new CfnSecurityGroup(scope, 'EndpointSecurityGroup', {
          groupDescription: 'HTTPS to the aws-ca private API endpoint',
          vpcId: frontDoor.vpcId,
          securityGroupIngress: PRIVATE_RANGES.map((range) => ({
            ipProtocol: 'tcp',
            fromPort: 443,
            toPort: 443,
            cidrIp: range,
          })),
        });
        this.vpcEndpoint = new CfnVPCEndpoint(scope, 'ExecuteApiEndpoint', {
          vpcId: frontDoor.vpcId,
          serviceName: `com.amazonaws.${Stack.of(scope).region}.execute-api`,
          vpcEndpointType: 'Interface',
          subnetIds: frontDoor.subnetIds,
          securityGroupIds: [group.attrGroupId],
          privateDnsEnabled: true,
        });
        vpcEndpointIds = [this.vpcEndpoint.ref];
        importedEndpoint = InterfaceVpcEndpoint.fromInterfaceVpcEndpointAttributes(scope, 'CreatedEndpoint', {
          vpcEndpointId: this.vpcEndpoint.ref,
          port: 443,
        });
      }
    }

    const api = new RestApi(scope, 'RestApi', {
      restApiName: `${Stack.of(scope).stackName}-ca`,
      description: 'aws-ca',
      endpointConfiguration: {
        types: [isPrivate ? EndpointType.PRIVATE : EndpointType.REGIONAL],
        ...(importedEndpoint ? { vpcEndpoints: [importedEndpoint] } : {}),
      },
      // The responses are binary (CRLs, OCSP, SCEP): without this API Gateway would not decode them.
      binaryMediaTypes: ['*/*'],
      disableExecuteApiEndpoint: mtls,
      deployOptions: { stageName: 'prod' },
      // The account-wide CloudWatch role is not this stack's to create or change.
      cloudWatchRole: false,
      ...(isPrivate
        ? {
            policy: new PolicyDocument({
              statements: [
                new PolicyStatement({
                  effect: Effect.DENY,
                  principals: [new AnyPrincipal()],
                  actions: ['execute-api:Invoke'],
                  resources: ['execute-api:/*'],
                  conditions: { StringNotEquals: { 'aws:SourceVpce': vpcEndpointIds } },
                }),
                new PolicyStatement({
                  effect: Effect.ALLOW,
                  principals: [new AnyPrincipal()],
                  actions: ['execute-api:Invoke'],
                  resources: ['execute-api:/*'],
                }),
              ],
            }),
          }
        : {}),
    });
    const integration = new LambdaIntegration(handler, { proxy: true });
    api.root.addMethod('ANY', integration);
    api.root.addProxy({ defaultIntegration: integration, anyMethod: true });
    if (domain && certificate && !isPrivate) {
      const name = new RestDomainName(scope, 'RestDomain', {
        domainName: domain.name,
        certificate,
        endpointType: EndpointType.REGIONAL,
        securityPolicy: SecurityPolicy.TLS_1_2,
        ...(trust ? { mtls: trust } : {}),
      });
      name.addBasePathMapping(api, { stage: api.deploymentStage });
    }
    this.restApi = api;
  }
}
