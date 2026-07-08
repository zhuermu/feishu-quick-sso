"""Web sign-in portal that turns a Cognito session into an Amazon Quick Web login.

Quick Web authenticates through IAM federation: a user is admitted when they arrive
carrying an AWS console session for an IAM role, tagged with their email. This portal
runs the OIDC authorization-code flow against the SAME Cognito User Pool that Quick
Desktop uses, so the browser's existing Cognito cookie logs the user in silently. It
then:

    1. exchanges the code for a Cognito id_token (TLS to the token endpoint),
    2. reads the verified email claim,
    3. sts:AssumeRole into the Quick federation role, tagging the session Email=<email>,
    4. calls the AWS federation getSigninToken endpoint,
    5. 302-redirects the browser into Quick Web, already signed in.

Two routes:
    GET /login    -> 302 to Cognito /authorize (starts or silently resumes the session)
    GET /callback -> the steps above

The id_token here comes straight from the token endpoint over TLS in a flow we
initiated, so we trust it without re-verifying the signature (standard for
confidential code-flow clients). The email claim is what Quick keys users on.
"""

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from enum import Enum, StrEnum

import boto3

sts = boto3.client("sts")
cognito = boto3.client("cognito-idp")


class Route(StrEnum):
    LOGIN = "/login"
    CALLBACK = "/callback"


class StatusCode(int, Enum):
    REDIRECT = 302
    BAD_REQUEST = 400
    FORBIDDEN = 403
    NOT_FOUND = 404
    INTERNAL_ERROR = 500
    BAD_GATEWAY = 502


# --- Environment (set by CDK) ---------------------------------------------------------

COGNITO_DOMAIN = os.environ["COGNITO_DOMAIN"]  # https://<prefix>.auth.<region>.amazoncognito.com
COGNITO_CLIENT_ID = os.environ["COGNITO_CLIENT_ID"]
COGNITO_USER_POOL_ID = os.environ["COGNITO_USER_POOL_ID"]
FEDERATION_ROLE_ARN = os.environ["FEDERATION_ROLE_ARN"]
PORTAL_URL = os.environ["PORTAL_URL"]  # public base URL of this API, e.g. https://xxx/prod
QUICK_REGION = os.environ["QUICK_REGION"]
# Role chaining (a Lambda role assuming another role) is hard-capped at 1h by STS,
# regardless of the target role's MaxSessionDuration. Quick re-federates silently
# after expiry as long as the Cognito/Feishu browser session is alive.
SESSION_DURATION_SECONDS = int(os.environ.get("SESSION_DURATION_SECONDS", "3600"))

QUICK_CONSOLE_URL = f"https://{QUICK_REGION}.quicksight.aws.amazon.com"
SIGNIN_FEDERATION_URL = "https://signin.aws.amazon.com/federation"


class ClientSecret:
    """The Web client is confidential; fetch its secret once and cache it warm."""

    _value: str | None = None

    @classmethod
    def get(cls) -> str:
        if cls._value is None:
            resp = cognito.describe_user_pool_client(
                UserPoolId=COGNITO_USER_POOL_ID, ClientId=COGNITO_CLIENT_ID
            )
            cls._value = resp["UserPoolClient"]["ClientSecret"]
        return cls._value


@dataclass
class Response:
    statusCode: int
    body: str = ""
    headers: dict | None = None

    def to_dict(self) -> dict:
        result = asdict(self)
        if self.headers is None:
            del result["headers"]
        return result


def _redirect(location: str) -> Response:
    return Response(statusCode=StatusCode.REDIRECT, headers={"Location": location})


def _error(status: int, message: str) -> Response:
    return Response(
        statusCode=status,
        headers={"Content-Type": "text/html; charset=utf-8"},
        body=f"<html><body><h3>Sign-in error</h3><p>{message}</p></body></html>",
    )


# --- OIDC code flow against Cognito ---------------------------------------------------


def handle_login() -> Response:
    params = {
        "response_type": "code",
        "client_id": COGNITO_CLIENT_ID,
        "redirect_uri": f"{PORTAL_URL}{Route.CALLBACK.value}",
        "scope": "openid email profile",
    }
    return _redirect(f"{COGNITO_DOMAIN}/oauth2/authorize?{urllib.parse.urlencode(params)}")


def _exchange_code_for_id_token(code: str) -> dict:
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": COGNITO_CLIENT_ID,
            "code": code,
            "redirect_uri": f"{PORTAL_URL}{Route.CALLBACK.value}",
        }
    ).encode()
    # The Web client is confidential, so authenticate with HTTP Basic (client_id:secret).
    basic = base64.b64encode(
        f"{COGNITO_CLIENT_ID}:{ClientSecret.get()}".encode()
    ).decode()
    req = urllib.request.Request(
        f"{COGNITO_DOMAIN}/oauth2/token",
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {basic}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        tokens = json.loads(resp.read().decode())
    return _decode_jwt_payload(tokens["id_token"])


def _decode_jwt_payload(jwt: str) -> dict:
    payload_b64 = jwt.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


# --- IAM federation -> Quick Web ------------------------------------------------------


def _assume_role_for(email: str) -> dict:
    resp = sts.assume_role(
        RoleArn=FEDERATION_ROLE_ARN,
        RoleSessionName=email[:64],
        DurationSeconds=SESSION_DURATION_SECONDS,
        Tags=[{"Key": "Email", "Value": email}],
    )
    return resp["Credentials"]


def _get_signin_token(creds: dict) -> str:
    session = json.dumps(
        {
            "sessionId": creds["AccessKeyId"],
            "sessionKey": creds["SecretAccessKey"],
            "sessionToken": creds["SessionToken"],
        }
    )
    params = urllib.parse.urlencode({"Action": "getSigninToken", "Session": session})
    with urllib.request.urlopen(f"{SIGNIN_FEDERATION_URL}?{params}") as resp:
        return json.loads(resp.read().decode())["SigninToken"]


def _build_login_url(signin_token: str) -> str:
    params = urllib.parse.urlencode(
        {
            "Action": "login",
            "Issuer": PORTAL_URL,
            "Destination": QUICK_CONSOLE_URL,
            "SigninToken": signin_token,
        }
    )
    return f"{SIGNIN_FEDERATION_URL}?{params}"


def handle_callback(event: dict) -> Response:
    params = event.get("queryStringParameters") or {}
    code = params.get("code")
    if not code:
        return _error(StatusCode.BAD_REQUEST, "Missing authorization code.")

    claims = _exchange_code_for_id_token(code)
    email = claims.get("email")
    if not email:
        return _error(StatusCode.FORBIDDEN, "No email claim in token.")

    creds = _assume_role_for(email)
    signin_token = _get_signin_token(creds)
    return _redirect(_build_login_url(signin_token))


# --- Dispatch -------------------------------------------------------------------------


def handler(event: dict, _context: object) -> dict:
    path = event.get("path", "")
    method = event.get("httpMethod", "")
    print(f"REQUEST: {method} {path}")

    try:
        match path:
            case Route.LOGIN:
                response = handle_login()
            case Route.CALLBACK:
                response = handle_callback(event)
            case _:
                response = Response(statusCode=StatusCode.NOT_FOUND, body="Not found")
    except urllib.error.HTTPError as e:
        print(f"UPSTREAM ERROR: {e.code} {e.read().decode()}")
        response = _error(StatusCode.BAD_GATEWAY, "Upstream error during sign-in.")
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {type(e).__name__}: {e}")
        response = _error(StatusCode.INTERNAL_ERROR, "Unexpected error during sign-in.")

    print(f"RESPONSE: {response.statusCode}")
    return response.to_dict()
