import { CfnOutput, Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  CognitoDomainPrefix,
  FeishuQuickSsoConfig,
  createConstructId,
  createDomainPrefix,
  getRemovalPolicy,
} from '../common/config';
import { FeishuAdapter, ADAPTER_CLIENT_ID } from '../construct-groups/feishu-adapter';
import { IdentityProvider } from '../construct-groups/identity-provider';
import { WebPortal } from '../construct-groups/web-portal';
import { FederationRole } from '../construct-groups/federation-role';

export interface FeishuQuickSsoStackProps extends StackProps {
  readonly config: FeishuQuickSsoConfig;
}

/**
 * One stack, one Cognito pool, four cooperating pieces:
 *
 *   Feishu OIDC adapter  -- upstream IdP that Cognito federates to
 *   Web portal           -- OIDC code flow -> IAM federation -> Quick Web
 *   Federation role      -- the role Quick Web users are admitted as
 *   Identity provider    -- shared Cognito pool + Desktop (PKCE) & Web clients
 *
 * The tricky cross-references (each a distinct CFN resource, so no true cycle):
 *   - Cognito Web client callbackUrl needs the portal API's URL  -> build portal first
 *   - portal Lambda needs the Web client id                       -> inject post-hoc
 *   - federation role trust needs the portal Lambda role ARN      -> narrow post-hoc
 * All URLs are derived from restApiId / account+region so they resolve at synth time.
 */
export class FeishuQuickSsoStack extends Stack {
  constructor(scope: Construct, id: string, props: FeishuQuickSsoStackProps) {
    super(scope, id, props);

    const { config } = props;
    const { projectName, retainResources, allowedCidrs, quickRegion } = config;
    const { account, region } = this;
    const removalPolicy = getRemovalPolicy(retainResources);

    // Deterministic Cognito hosted-UI domain (no token) — usable before the pool exists.
    const domainPrefix = createDomainPrefix(CognitoDomainPrefix.DEFAULT, account, region);
    const cognitoDomain = `https://${domainPrefix}.auth.${region}.amazoncognito.com`;

    // 1. Feishu -> OIDC adapter. Issuer is derived from its own restApiId.
    const adapter = new FeishuAdapter(this, createConstructId('FeishuAdapter'), {
      projectName,
      feishuAppId: config.feishuAppId,
      feishuSubjectClaim: config.feishuSubjectClaim,
      endpoints: config.endpoints,
      cognitoDomain,
      ...(allowedCidrs && { allowedCidrs }),
    });

    // 2. Federation role (trust narrowed to the portal Lambda below).
    const federation = new FederationRole(this, createConstructId('Federation'), {
      projectName,
    });

    // 3. Web sign-in portal. Built before the Cognito clients so its callback URL
    // is known when the Web client is created.
    const portal = new WebPortal(this, createConstructId('WebPortal'), {
      projectName,
      cognitoDomain,
      federationRole: federation.role,
      quickRegion,
      ...(allowedCidrs && { allowedCidrs }),
    });
    federation.trustPortal(portal.lambdaRoleArn);

    // 4. Shared Cognito pool, federating to the adapter, with both clients.
    const identity = new IdentityProvider(this, createConstructId('Identity'), {
      projectName,
      removalPolicy,
      domainPrefix,
      feishuAdapterIssuer: adapter.issuer,
      adapterClientId: ADAPTER_CLIENT_ID,
      adapterClientSecret: adapter.credentialsSecret
        .secretValueFromJson('cognitoClientSecret')
        .unsafeUnwrap(),
      webPortalCallbackUrl: portal.callbackUrl,
    });

    // Cognito fetches the adapter's /.well-known/openid-configuration at IdP-creation
    // time. Force the whole adapter (API stage + Lambda) to be ready first, otherwise
    // the discovery endpoint 404s and IdP creation fails with "Unable to contact".
    identity.node.addDependency(adapter);

    // Close the loop: portal Lambda learns the Web client id + pool (to read the secret).
    portal.setWebClient(identity.webClient.userPoolClientId, identity.pool);

    this.emitOutputs(adapter, identity, portal, federation);
  }

  private emitOutputs(
    adapter: FeishuAdapter,
    identity: IdentityProvider,
    portal: WebPortal,
    federation: FederationRole,
  ): void {
    // Feishu-side config (paste into the Feishu developer console).
    new CfnOutput(this, 'FeishuRedirectUri', { value: `${adapter.issuer}/callback` });
    new CfnOutput(this, 'AdapterCredentialsSecretArn', {
      value: adapter.credentialsSecret.secretArn,
    });

    // Quick Desktop OIDC settings.
    new CfnOutput(this, 'DesktopIssuerUrl', { value: identity.issuerUrl });
    new CfnOutput(this, 'DesktopClientId', {
      value: identity.desktopClient.userPoolClientId,
    });
    // Desktop points at the adapter's strip-proxy, not Cognito directly, because
    // Quick Desktop always sends offline_access, which Cognito rejects.
    new CfnOutput(this, 'DesktopAuthEndpoint', { value: adapter.desktopAuthEndpoint });
    new CfnOutput(this, 'DesktopTokenEndpoint', { value: adapter.desktopTokenEndpoint });
    new CfnOutput(this, 'DesktopJwksUri', {
      value: `${identity.issuerUrl}/.well-known/jwks.json`,
    });

    // Quick Web entry point + IAM federation.
    new CfnOutput(this, 'WebPortalLoginUrl', { value: portal.loginUrl });
    new CfnOutput(this, 'FederationRoleArn', { value: federation.role.roleArn });
    new CfnOutput(this, 'UserPoolId', { value: identity.pool.userPoolId });
  }
}
