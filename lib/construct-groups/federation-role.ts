import { Duration, Stack } from 'aws-cdk-lib';
import {
  Role,
  CfnRole,
  PolicyStatement,
  Effect,
  ArnPrincipal,
  PolicyDocument,
} from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import {
  ProjectName,
  ResourceName,
  createConstructId,
  createResourceName,
} from '../common/config';

export interface FederationRoleProps {
  readonly projectName: ProjectName;
}

/**
 * The IAM role Quick Web federated users assume. The Web portal's Lambda role is
 * the only principal allowed to assume it, and it may pass an `Email` principal
 * tag (sts:TagSession) — Quick keys the federated user on that tag.
 *
 * The role's permissions policy grants the QuickSight/Quick console reader action
 * so the federation sign-in lands the user in Quick.
 */
export class FederationRole extends Construct {
  public readonly role: Role;

  constructor(scope: Construct, id: string, props: FederationRoleProps) {
    super(scope, id);

    const { projectName } = props;
    const { account } = Stack.of(this);

    this.role = new Role(this, createConstructId('Role'), {
      roleName: createResourceName(projectName, ResourceName.FEDERATION_ROLE),
      // Assumed by the portal Lambda's execution role (added by the stack via
      // grantAssume once that role exists — see stack). Placeholder self-account
      // principal keeps the trust valid until then.
      assumedBy: new ArnPrincipal(`arn:aws:iam::${account}:root`),
      description: 'Assumed by the Web portal to federate Feishu users into Quick',
      // The portal Lambda assumes this via role chaining, which STS hard-caps at
      // 1h regardless of this value. Kept at 1h so the setting matches reality.
      maxSessionDuration: Duration.hours(1),
      inlinePolicies: {
        QuickAccess: new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['quicksight:*'],
              resources: ['*'],
            }),
          ],
        }),
      },
    });
  }

  /**
   * Restrict the trust policy to exactly the portal Lambda role and allow it to
   * tag the session with Email. Called by the stack once the Lambda role exists.
   */
  public trustPortal(portalRoleArn: string): void {
    const cfnRole = this.role.node.defaultChild as CfnRole;
    cfnRole.assumeRolePolicyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: portalRoleArn },
          Action: 'sts:AssumeRole',
        },
        {
          Effect: 'Allow',
          Principal: { AWS: portalRoleArn },
          Action: 'sts:TagSession',
          Condition: { StringLike: { 'aws:RequestTag/Email': '*' } },
        },
      ],
    };
  }
}
