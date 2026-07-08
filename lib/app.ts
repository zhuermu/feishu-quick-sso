#!/usr/bin/env node
import 'source-map-support/register';
import { App } from 'aws-cdk-lib';
import { FeishuQuickSsoStack } from './stacks/feishu-quick-sso-stack';
import {
  FEISHU_CN_ENDPOINTS,
  LARK_ENDPOINTS,
  FeishuQuickSsoConfig,
  FeishuSubjectClaim,
  ProjectName,
  createStackName,
} from './common/config';

const region = process.env.CDK_DEFAULT_REGION || 'us-east-1';

const app = new App();

// Required context: -c feishuAppId=cli_xxxx
const feishuAppId = app.node.tryGetContext('feishuAppId') as string | undefined;
if (!feishuAppId) {
  throw new Error('Missing required context: -c feishuAppId=<your Feishu App ID>');
}

const retainResources = app.node.tryGetContext('retain') === 'true';
const allowedCidrs = app.node.tryGetContext('allowedCidrs') as string[] | undefined;
const quickRegion = (app.node.tryGetContext('quickRegion') as string | undefined) || region;
const useLark = app.node.tryGetContext('lark') === 'true';
const subjectClaim =
  (app.node.tryGetContext('subjectClaim') as FeishuSubjectClaim | undefined) ||
  FeishuSubjectClaim.UNION_ID;

const config: FeishuQuickSsoConfig = {
  projectName: ProjectName.FEISHU_QUICK_SSO,
  retainResources,
  feishuAppId,
  feishuSubjectClaim: subjectClaim,
  endpoints: useLark ? LARK_ENDPOINTS : FEISHU_CN_ENDPOINTS,
  quickRegion,
  ...(allowedCidrs && { allowedCidrs }),
};

new FeishuQuickSsoStack(app, createStackName(config.projectName, 'Main'), {
  config,
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region,
  },
});

app.synth();
