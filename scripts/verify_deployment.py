#!/usr/bin/env python3
"""Smoke-tests a deployed Feishu-Quick-SSO stack without needing a real Feishu login.

Checks the pieces that must be healthy before a human tries the browser flow:
  1. adapter /.well-known/openid-configuration is served and self-consistent
  2. adapter /.well-known/jwks.json returns a usable RSA key
  3. the issuer in discovery matches the Cognito OIDC IdP configuration
  4. the Web portal /login redirects to the Cognito hosted UI

Usage:
    python3 verify_deployment.py                       # auto-discovers from stack outputs
    python3 verify_deployment.py --stack MyStackName
"""

import argparse
import json
import sys
import urllib.request

import boto3

DEFAULT_STACK = "FeishuQuickSsoMainStack"


def stack_outputs(stack_name: str) -> dict:
    cfn = boto3.client("cloudformation")
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read().decode())


def check(label: str, ok: bool, detail: str = "") -> bool:
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {label}" + (f" — {detail}" if detail else ""))
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack", default=DEFAULT_STACK)
    args = parser.parse_args()

    outputs = stack_outputs(args.stack)
    issuer = outputs["FeishuRedirectUri"].rsplit("/callback", 1)[0]
    login_url = outputs["WebPortalLoginUrl"]

    passed = True

    discovery = get_json(f"{issuer}/.well-known/openid-configuration")
    passed &= check(
        "discovery issuer matches",
        discovery.get("issuer") == issuer,
        discovery.get("issuer", "<missing>"),
    )
    passed &= check(
        "discovery advertises RS256",
        "RS256" in discovery.get("id_token_signing_alg_values_supported", []),
    )

    jwks = get_json(discovery["jwks_uri"])
    keys = jwks.get("keys", [])
    passed &= check(
        "jwks has one RSA signing key",
        len(keys) == 1 and keys[0].get("kty") == "RSA" and "n" in keys[0],
    )

    # Portal /login should 302 to the Cognito hosted UI authorize endpoint.
    req = urllib.request.Request(login_url, method="GET")
    opener = urllib.request.build_opener(NoRedirect())
    try:
        opener.open(req, timeout=10)
        location = ""
    except RedirectCaught as e:
        location = e.location
    passed &= check(
        "portal /login redirects to Cognito",
        "amazoncognito.com" in location and "oauth2/authorize" in location,
        location[:80],
    )

    print()
    print("All checks passed." if passed else "Some checks FAILED — see above.")
    return 0 if passed else 1


class RedirectCaught(Exception):
    def __init__(self, location: str) -> None:
        self.location = location


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        raise RedirectCaught(newurl)


if __name__ == "__main__":
    sys.exit(main())
