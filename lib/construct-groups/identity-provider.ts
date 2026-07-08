import { RemovalPolicy, Stack } from 'aws-cdk-lib';
import {
  UserPool,
  UserPoolClient,
  UserPoolIdentityProviderOidc,
  OidcAttributeRequestMethod,
  ProviderAttribute,
  UserPoolClientIdentityProvider,
  OAuthScope,
} from 'aws-cdk-lib/aws-cognito';
import { Construct } from 'constructs';
import {
  ProjectName,
  ResourceName,
  createConstructId,
  createResourceName,
} from '../common/config';

export interface IdentityProviderProps {
  readonly projectName: ProjectName;
  readonly removalPolicy: RemovalPolicy;
  /** Cognito hosted-UI domain prefix, computed once by the stack. */
  readonly domainPrefix: string;
  /** Public base URL of the Feishu OIDC adapter API (issuer). */
  readonly feishuAdapterIssuer: string;
  /** Client id/secret the User Pool uses when calling the adapter's /token. */
  readonly adapterClientId: string;
  readonly adapterClientSecret: string;
  /** Desktop uses localhost loopback; Web portal callback is added at deploy time. */
  readonly webPortalCallbackUrl: string;
}

/**
 * A single Cognito User Pool that federates to Feishu and is consumed by BOTH
 * Quick Desktop (public client, PKCE) and the Web sign-in portal (confidential
 * client). Sharing one pool is what makes the browser's Cognito session reusable
 * across both entry points — the heart of the single sign-on experience.
 */
export class IdentityProvider extends Construct {
  public readonly pool: UserPool;
  public readonly desktopClient: UserPoolClient;
  public readonly webClient: UserPoolClient;
  public readonly issuerUrl: string;
  public readonly cognitoDomain: string;

  constructor(scope: Construct, id: string, props: IdentityProviderProps) {
    super(scope, id);

    const {
      projectName,
      removalPolicy,
      domainPrefix,
      feishuAdapterIssuer,
      adapterClientId,
      adapterClientSecret,
      webPortalCallbackUrl,
    } = props;
    const { region } = Stack.of(this);

    this.pool = new UserPool(this, createConstructId('Pool'), {
      userPoolName: createResourceName(projectName, ResourceName.USER_POOL),
      selfSignUpEnabled: false,
      // Federated usernames are provider-prefixed (not email-format), so email
      // alias sign-in is safe and lets local admins coexist with Feishu users.
      signInAliases: { username: true, email: true },
      autoVerify: { email: true },
      standardAttributes: { email: { required: true, mutable: true } },
      removalPolicy,
    });

    // The Feishu OIDC adapter registered as an upstream identity provider.
    const feishuIdp = new UserPoolIdentityProviderOidc(this, createConstructId('FeishuIdp'), {
      name: 'Feishu',
      userPool: this.pool,
      clientId: adapterClientId,
      clientSecret: adapterClientSecret,
      issuerUrl: feishuAdapterIssuer,
      scopes: ['openid', 'email', 'profile'],
      attributeRequestMethod: OidcAttributeRequestMethod.GET,
      attributeMapping: {
        email: ProviderAttribute.other('email'),
        fullname: ProviderAttribute.other('name'),
      },
    });

    this.pool.addDomain('Domain', { cognitoDomain: { domainPrefix } });

    // Desktop: public client, authorization code + PKCE, loopback callback.
    this.desktopClient = this.pool.addClient('DesktopClient', {
      userPoolClientName: createResourceName(projectName, ResourceName.DESKTOP_CLIENT),
      generateSecret: false,
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [OAuthScope.OPENID, OAuthScope.EMAIL, OAuthScope.PROFILE],
        callbackUrls: ['http://localhost:18080'],
      },
      supportedIdentityProviders: [UserPoolClientIdentityProvider.custom('Feishu')],
    });

    // Web portal: confidential client, authorization code, portal callback.
    this.webClient = this.pool.addClient('WebClient', {
      userPoolClientName: createResourceName(projectName, ResourceName.WEB_CLIENT),
      generateSecret: true,
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [OAuthScope.OPENID, OAuthScope.EMAIL, OAuthScope.PROFILE],
        callbackUrls: [webPortalCallbackUrl],
      },
      supportedIdentityProviders: [UserPoolClientIdentityProvider.custom('Feishu')],
    });

    // Clients must not be created before the IdP exists.
    this.desktopClient.node.addDependency(feishuIdp);
    this.webClient.node.addDependency(feishuIdp);

    this.issuerUrl = `https://cognito-idp.${region}.amazonaws.com/${this.pool.userPoolId}`;
    this.cognitoDomain = `https://${domainPrefix}.auth.${region}.amazoncognito.com`;
  }
}
