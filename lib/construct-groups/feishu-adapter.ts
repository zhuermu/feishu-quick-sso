import { Duration, Stack } from 'aws-cdk-lib';
import { Function as LambdaFunction, Runtime, Code } from 'aws-cdk-lib/aws-lambda';
import { RestApi, LambdaIntegration, Cors } from 'aws-cdk-lib/aws-apigateway';
import { Key, KeySpec, KeyUsage } from 'aws-cdk-lib/aws-kms';
import { Secret } from 'aws-cdk-lib/aws-secretsmanager';
import {
  PolicyDocument,
  PolicyStatement,
  Effect,
  AnyPrincipal,
} from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { join } from 'path';
import {
  FeishuEndpoints,
  FeishuSubjectClaim,
  ProjectName,
  ResourceName,
  createConstructId,
  createResourceName,
} from '../common/config';

/** Non-secret client id the Cognito OIDC IdP presents to the adapter's /token. */
export const ADAPTER_CLIENT_ID = 'cognito-federation-client';

export interface FeishuAdapterProps {
  readonly projectName: ProjectName;
  readonly feishuAppId: string;
  readonly feishuSubjectClaim: FeishuSubjectClaim;
  readonly endpoints: FeishuEndpoints;
  /** Cognito hosted-UI domain; the adapter strip-proxies Desktop's OAuth to it. */
  readonly cognitoDomain: string;
  readonly allowedCidrs?: string[];
}

/**
 * The stateless Feishu -> OIDC translation layer: an RSA signing key in KMS, a
 * secret holding the app credentials, a Lambda, and a public REST API. This is
 * the serverless equivalent of the Keycloak Feishu SPI plugin, with no database.
 */
export class FeishuAdapter extends Construct {
  public readonly api: RestApi;
  public readonly issuer: string;
  /** Secret that also carries the Cognito-facing client credentials (filled by stack). */
  public readonly credentialsSecret: Secret;

  private readonly fn: LambdaFunction;

  constructor(scope: Construct, id: string, props: FeishuAdapterProps) {
    super(scope, id);

    const { projectName, feishuAppId, feishuSubjectClaim, endpoints, cognitoDomain, allowedCidrs } =
      props;
    const { region } = Stack.of(this);

    // Asymmetric key: private half signs id_tokens, public half feeds the JWKS.
    const signingKey = new Key(this, createConstructId('SigningKey'), {
      alias: createResourceName(projectName, ResourceName.FEISHU_SIGNING_KEY),
      keySpec: KeySpec.RSA_2048,
      keyUsage: KeyUsage.SIGN_VERIFY,
      description: 'Feishu OIDC adapter id_token signing key',
    });

    // Holds { appSecret, cognitoClientId, cognitoClientSecret }. cognitoClientSecret
    // is generated here; appSecret is a placeholder filled post-deploy by the admin.
    // cognitoClientId is a non-secret constant that both the adapter and the Cognito
    // OIDC IdP config agree on.
    this.credentialsSecret = new Secret(this, createConstructId('Credentials'), {
      secretName: createResourceName(projectName, ResourceName.FEISHU_ADAPTER_FUNCTION) + 'Secret',
      description: 'Feishu app secret + Cognito adapter client credentials',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          cognitoClientId: ADAPTER_CLIENT_ID,
          appSecret: 'REPLACE_WITH_FEISHU_APP_SECRET',
        }),
        generateStringKey: 'cognitoClientSecret',
        excludePunctuation: true,
        passwordLength: 48,
      },
    });

    this.fn = new LambdaFunction(this, createConstructId('Function'), {
      functionName: createResourceName(projectName, ResourceName.FEISHU_ADAPTER_FUNCTION),
      runtime: Runtime.PYTHON_3_12,
      handler: 'handler.handler',
      code: Code.fromAsset(join(__dirname, '..', '..', 'lambda', 'feishu_oidc_adapter')),
      timeout: Duration.seconds(15),
      environment: {
        FEISHU_APP_ID: feishuAppId,
        FEISHU_AUTHORIZE_URL: endpoints.authorize,
        FEISHU_TOKEN_URL: endpoints.token,
        FEISHU_USERINFO_URL: endpoints.userInfo,
        FEISHU_SCOPES: 'contact:user.email:readonly',
        SUBJECT_CLAIM: feishuSubjectClaim,
        SIGNING_KEY_ID: signingKey.keyArn,
        SECRET_ARN: this.credentialsSecret.secretArn,
        COGNITO_DOMAIN: cognitoDomain,
        // Issuer is derived from restApiId below, so it is known at synth time.
      },
    });

    signingKey.grantSignVerify(this.fn);
    // grantSignVerify covers Sign/Verify but not GetPublicKey, which the JWKS
    // endpoint needs to export the public key.
    signingKey.grant(this.fn, 'kms:GetPublicKey');
    this.credentialsSecret.grantRead(this.fn);

    const policy = allowedCidrs ? this.createResourcePolicy(allowedCidrs) : undefined;

    this.api = new RestApi(this, createConstructId('Api'), {
      restApiName: createResourceName(projectName, ResourceName.FEISHU_ADAPTER_API),
      deployOptions: { stageName: 'prod' },
      defaultCorsPreflightOptions: { allowOrigins: Cors.ALL_ORIGINS },
      ...(policy && { policy }),
    });

    // Build the issuer from restApiId (a RestApi attribute) rather than api.url,
    // which pulls in the deployment stage and would create a Client->Stage->
    // Method->Lambda->Client dependency cycle when the Lambda reads its own ISSUER.
    this.issuer = `https://${this.api.restApiId}.execute-api.${region}.amazonaws.com/prod`;
    this.fn.addEnvironment('ISSUER', this.issuer);

    const integration = new LambdaIntegration(this.fn);
    this.addRoute(['.well-known', 'openid-configuration'], 'GET', integration);
    this.addRoute(['.well-known', 'jwks.json'], 'GET', integration);
    this.api.root.addResource('authorize').addMethod('GET', integration);
    this.api.root.addResource('callback').addMethod('GET', integration);
    this.api.root.addResource('token').addMethod('POST', integration);
    this.api.root.addResource('userinfo').addMethod('GET', integration);
    // Cognito strip-proxy for Quick Desktop (removes offline_access before Cognito).
    this.addRoute(['cognito', 'authorize'], 'GET', integration);
    this.addRoute(['cognito', 'token'], 'POST', integration);

    // Fold the full route list into the deployment's logical id, so adding or
    // changing a route forces a new deployment that the stage is repointed to.
    // Without this, nested addResource routes can leave the stage on a stale
    // snapshot and return 403 "Missing Authentication Token".
    this.api.latestDeployment?.addToLogicalId([
      'openid-configuration',
      'jwks.json',
      'authorize',
      'callback',
      'token',
      'userinfo',
      'cognito/authorize',
      'cognito/token',
    ]);
  }

  /** Desktop Auth endpoint — Cognito authorize via the offline_access strip-proxy. */
  public get desktopAuthEndpoint(): string {
    return `${this.issuer}/cognito/authorize`;
  }

  /** Desktop Token endpoint — Cognito token via the offline_access strip-proxy. */
  public get desktopTokenEndpoint(): string {
    return `${this.issuer}/cognito/token`;
  }

  private addRoute(
    path: string[],
    method: string,
    integration: LambdaIntegration,
  ): void {
    let resource = this.api.root;
    for (const segment of path) {
      resource = resource.getResource(segment) ?? resource.addResource(segment);
    }
    resource.addMethod(method, integration);
  }

  private createResourcePolicy(allowedCidrs: string[]): PolicyDocument {
    return new PolicyDocument({
      statements: [
        new PolicyStatement({
          effect: Effect.ALLOW,
          principals: [new AnyPrincipal()],
          actions: ['execute-api:Invoke'],
          resources: ['execute-api:/*/*/*'],
        }),
        new PolicyStatement({
          effect: Effect.DENY,
          principals: [new AnyPrincipal()],
          actions: ['execute-api:Invoke'],
          resources: ['execute-api:/*/*/*'],
          conditions: { NotIpAddress: { 'aws:SourceIp': allowedCidrs } },
        }),
      ],
    });
  }
}
