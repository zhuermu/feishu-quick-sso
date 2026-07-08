import { Duration, Stack } from 'aws-cdk-lib';
import { Function as LambdaFunction, Runtime, Code } from 'aws-cdk-lib/aws-lambda';
import { RestApi, LambdaIntegration } from 'aws-cdk-lib/aws-apigateway';
import { IUserPool } from 'aws-cdk-lib/aws-cognito';
import { Role, PolicyStatement, Effect } from 'aws-cdk-lib/aws-iam';
import {
  PolicyDocument,
  PolicyStatement as ResourcePolicyStatement,
  AnyPrincipal,
} from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { join } from 'path';
import {
  ProjectName,
  ResourceName,
  createConstructId,
  createResourceName,
} from '../common/config';

export interface WebPortalProps {
  readonly projectName: ProjectName;
  /** Deterministic Cognito hosted-UI domain (account+region derived, no token). */
  readonly cognitoDomain: string;
  readonly federationRole: Role;
  readonly quickRegion: string;
  readonly allowedCidrs?: string[];
}

/**
 * The Web sign-in portal: an API Gateway + Lambda that runs the OIDC code flow
 * against the shared Cognito pool, then trades the id_token's email for a Quick
 * Web console session via sts:AssumeRole + the AWS federation endpoint.
 */
export class WebPortal extends Construct {
  public readonly api: RestApi;
  public readonly portalUrl: string;
  /** The portal Lambda's execution role ARN — the only principal that may assume the Quick role. */
  public readonly lambdaRoleArn: string;

  private readonly fn: LambdaFunction;

  constructor(scope: Construct, id: string, props: WebPortalProps) {
    super(scope, id);

    const { projectName, cognitoDomain, federationRole, quickRegion, allowedCidrs } = props;
    const { region } = Stack.of(this);

    const policy = allowedCidrs ? this.createResourcePolicy(allowedCidrs) : undefined;

    this.api = new RestApi(this, createConstructId('Api'), {
      restApiName: createResourceName(projectName, ResourceName.WEB_PORTAL_API),
      deployOptions: { stageName: 'prod' },
      ...(policy && { policy }),
    });

    // Derive from restApiId to avoid the self-referential deployment-stage cycle.
    this.portalUrl = `https://${this.api.restApiId}.execute-api.${region}.amazonaws.com/prod`;

    this.fn = new LambdaFunction(this, createConstructId('Function'), {
      functionName: createResourceName(projectName, ResourceName.WEB_PORTAL_FUNCTION),
      runtime: Runtime.PYTHON_3_12,
      handler: 'handler.handler',
      code: Code.fromAsset(join(__dirname, '..', '..', 'lambda', 'web_portal')),
      timeout: Duration.seconds(15),
      environment: {
        COGNITO_DOMAIN: cognitoDomain,
        FEDERATION_ROLE_ARN: federationRole.roleArn,
        QUICK_REGION: quickRegion,
        PORTAL_URL: this.portalUrl,
        // COGNITO_CLIENT_ID + COGNITO_USER_POOL_ID injected via setWebClient once
        // the pool/client exist (breaks the portal<->pool construction cycle).
      },
    });
    this.lambdaRoleArn = this.fn.role!.roleArn;

    // The portal Lambda must be allowed to assume (and tag) the Quick role.
    this.fn.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['sts:AssumeRole', 'sts:TagSession'],
        resources: [federationRole.roleArn],
      }),
    );

    const integration = new LambdaIntegration(this.fn);
    this.api.root.addResource('login').addMethod('GET', integration);
    this.api.root.addResource('callback').addMethod('GET', integration);

    // Fold routes into the deployment logical id so route changes repoint the
    // stage (avoids stale-snapshot 403s). See FeishuAdapter for the full rationale.
    this.api.latestDeployment?.addToLogicalId(['login', 'callback']);
  }

  public get loginUrl(): string {
    return `${this.portalUrl}/login`;
  }

  public get callbackUrl(): string {
    return `${this.portalUrl}/callback`;
  }

  /**
   * Inject the Cognito Web client id + pool after they exist (breaks the cycle), and
   * grant the Lambda permission to read the confidential client's secret at runtime.
   */
  public setWebClient(clientId: string, userPool: IUserPool): void {
    this.fn.addEnvironment('COGNITO_CLIENT_ID', clientId);
    this.fn.addEnvironment('COGNITO_USER_POOL_ID', userPool.userPoolId);
    this.fn.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['cognito-idp:DescribeUserPoolClient'],
        resources: [userPool.userPoolArn],
      }),
    );
  }

  private createResourcePolicy(allowedCidrs: string[]): PolicyDocument {
    return new PolicyDocument({
      statements: [
        new ResourcePolicyStatement({
          effect: Effect.ALLOW,
          principals: [new AnyPrincipal()],
          actions: ['execute-api:Invoke'],
          resources: ['execute-api:/*/*/*'],
        }),
        new ResourcePolicyStatement({
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
