#!/usr/bin/env python3
"""Writes the Feishu App Secret into the adapter's Secrets Manager secret.

After `cdk deploy`, the secret holds a placeholder appSecret. Run this once with
the App Secret from the Feishu developer console (凭证与基础信息 page). It preserves
the auto-generated Cognito client credentials already in the secret.

Usage:
    python3 set_feishu_secret.py --app-secret <FEISHU_APP_SECRET>
    python3 set_feishu_secret.py --app-secret <SECRET> --stack FeishuQuickSsoMainStack
"""

import argparse
import json
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError

DEFAULT_STACK = "FeishuQuickSsoMainStack"
SECRET_OUTPUT_KEY = "AdapterCredentialsSecretArn"


def resolve_secret_arn(stack_name: str) -> str:
    cfn = boto3.client("cloudformation")
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    for output in outputs:
        if output["OutputKey"] == SECRET_OUTPUT_KEY:
            return output["OutputValue"]
    raise SystemExit(f"Output {SECRET_OUTPUT_KEY} not found on stack {stack_name}")


def update_app_secret(secret_arn: str, app_secret: str) -> None:
    sm = boto3.client("secretsmanager")
    current = json.loads(sm.get_secret_value(SecretId=secret_arn)["SecretString"])
    current["appSecret"] = app_secret
    sm.put_secret_value(SecretId=secret_arn, SecretString=json.dumps(current))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-secret", required=True, help="Feishu App Secret")
    parser.add_argument("--stack", default=DEFAULT_STACK, help="CloudFormation stack name")
    args = parser.parse_args()

    try:
        secret_arn = resolve_secret_arn(args.stack)
        update_app_secret(secret_arn, args.app_secret)
    except (BotoCoreError, ClientError) as e:
        print(f"AWS error: {e}", file=sys.stderr)
        return 1

    print(f"Feishu App Secret written to {secret_arn}")
    print("The adapter reads it on the next invocation (cached per warm container).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
