"""Stateless OIDC adapter that lets Amazon Cognito federate to a Feishu (Lark) self-built app.

Feishu speaks a non-standard OAuth 2.0: its /token endpoint returns only a
``user_access_token`` and never an ``id_token``, and it exposes no JWKS. Cognito's
OIDC federation, on the other hand, requires a signed ``id_token`` verifiable against
a JWKS. This adapter is the translation layer between the two, and it holds no state:

    Cognito --GET  /authorize--> adapter --302--> Feishu authorize
    Feishu  --GET  /callback --> adapter --302--> Cognito redirect_uri (?code&state)
    Cognito --POST /token    --> adapter --exchange code w/ Feishu, sign id_token--> Cognito

The Cognito redirect_uri and state survive the Feishu round-trip by being packed into
the ``state`` we hand Feishu. The ``code`` we return to Cognito IS the Feishu code, so
/token can exchange it for a ``user_access_token``, read /user_info, and mint a signed
JWT. Signing uses an asymmetric KMS key (RS256); the matching JWKS is derived from
``kms:GetPublicKey`` so no private key material ever leaves KMS.
"""

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from enum import Enum, StrEnum

import boto3

kms = boto3.client("kms")


class Route(StrEnum):
    DISCOVERY = "/.well-known/openid-configuration"
    JWKS = "/.well-known/jwks.json"
    AUTHORIZE = "/authorize"
    CALLBACK = "/callback"
    TOKEN = "/token"
    USERINFO = "/userinfo"
    # Cognito strip-proxy for Quick Desktop: Desktop always sends offline_access,
    # which Cognito rejects with invalid_scope. These endpoints strip it and forward.
    COGNITO_AUTHORIZE = "/cognito/authorize"
    COGNITO_TOKEN = "/cognito/token"


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"


class StatusCode(int, Enum):
    OK = 200
    REDIRECT = 302
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    NOT_FOUND = 404
    INTERNAL_ERROR = 500
    BAD_GATEWAY = 502


class ContentType(StrEnum):
    JSON = "application/json"
    FORM = "application/x-www-form-urlencoded"


# --- Environment (set by CDK) ---------------------------------------------------------

ISSUER = os.environ["ISSUER"]  # public base URL of this API, e.g. https://xxx/prod
FEISHU_APP_ID = os.environ["FEISHU_APP_ID"]
FEISHU_AUTHORIZE_URL = os.environ["FEISHU_AUTHORIZE_URL"]
FEISHU_TOKEN_URL = os.environ["FEISHU_TOKEN_URL"]
FEISHU_USERINFO_URL = os.environ["FEISHU_USERINFO_URL"]
FEISHU_SCOPES = os.environ["FEISHU_SCOPES"]  # space-separated
SUBJECT_CLAIM = os.environ["SUBJECT_CLAIM"]  # "union_id" | "open_id"
SIGNING_KEY_ID = os.environ["SIGNING_KEY_ID"]  # KMS key id/arn
SECRET_ARN = os.environ["SECRET_ARN"]  # Secrets Manager secret ARN
COGNITO_DOMAIN = os.environ["COGNITO_DOMAIN"]  # https://<prefix>.auth.<region>.amazoncognito.com

ID_TOKEN_TTL_SECONDS = 3600


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


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_json(obj: dict) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode())


def _redirect(location: str) -> Response:
    return Response(statusCode=StatusCode.REDIRECT, headers={"Location": location})


def _json(status: int, obj: dict) -> Response:
    return Response(
        statusCode=status,
        headers={"Content-Type": ContentType.JSON.value},
        body=json.dumps(obj),
    )


# --- Secrets: Cognito-facing client credentials + Feishu app secret -------------------


class Secrets:
    """Lazily loads and caches the JSON secret across warm invocations."""

    _cache: dict | None = None

    @classmethod
    def _load(cls) -> dict:
        if cls._cache is None:
            sm = boto3.client("secretsmanager")
            raw = sm.get_secret_value(SecretId=SECRET_ARN)["SecretString"]
            cls._cache = json.loads(raw)
        return cls._cache

    @classmethod
    def feishu_app_secret(cls) -> str:
        return cls._load()["appSecret"]

    @classmethod
    def cognito_client_id(cls) -> str:
        return cls._load()["cognitoClientId"]

    @classmethod
    def cognito_client_secret(cls) -> str:
        return cls._load()["cognitoClientSecret"]


# --- KMS-backed RS256 signing + JWKS --------------------------------------------------


class Signer:
    _kid: str | None = None
    _jwk: dict | None = None

    @classmethod
    def kid(cls) -> str:
        # Deterministic key id derived from the KMS key ARN, stable across invocations.
        if cls._kid is None:
            cls._kid = _b64url(SIGNING_KEY_ID.encode())[:16]
        return cls._kid

    @classmethod
    def sign_jwt(cls, claims: dict) -> str:
        header = {"alg": "RS256", "typ": "JWT", "kid": cls.kid()}
        signing_input = f"{_b64url_json(header)}.{_b64url_json(claims)}"
        signature = kms.sign(
            KeyId=SIGNING_KEY_ID,
            Message=signing_input.encode(),
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )["Signature"]
        return f"{signing_input}.{_b64url(signature)}"

    @classmethod
    def jwks(cls) -> dict:
        if cls._jwk is None:
            der = kms.get_public_key(KeyId=SIGNING_KEY_ID)["PublicKey"]
            n, e = _rsa_public_numbers(der)
            cls._jwk = {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": cls.kid(),
                "n": _b64url(_int_to_bytes(n)),
                "e": _b64url(_int_to_bytes(e)),
            }
        return {"keys": [cls._jwk]}


def _int_to_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _rsa_public_numbers(der: bytes) -> tuple[int, int]:
    """Extract (modulus, exponent) from a DER SubjectPublicKeyInfo without third-party libs.

    SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
    where the BIT STRING wraps RSAPublicKey ::= SEQUENCE { INTEGER n, INTEGER e }.
    """

    def read_len(buf: bytes, i: int) -> tuple[int, int]:
        first = buf[i]
        i += 1
        if first < 0x80:
            return first, i
        num_bytes = first & 0x7F
        return int.from_bytes(buf[i : i + num_bytes], "big"), i + num_bytes

    def expect(buf: bytes, i: int, tag: int) -> tuple[int, int]:
        assert buf[i] == tag, f"expected tag {tag:#x}, got {buf[i]:#x}"
        length, i = read_len(buf, i + 1)
        return length, i

    i = 0
    _, i = expect(der, i, 0x30)  # outer SEQUENCE
    alg_len, i = expect(der, i, 0x30)  # AlgorithmIdentifier SEQUENCE
    i += alg_len  # skip algorithm
    bit_len, i = expect(der, i, 0x03)  # BIT STRING
    i += 1  # skip the leading "unused bits" byte
    _, i = expect(der, i, 0x30)  # RSAPublicKey SEQUENCE
    n_len, i = expect(der, i, 0x02)  # INTEGER modulus
    n = int.from_bytes(der[i : i + n_len], "big")
    i += n_len
    e_len, i = expect(der, i, 0x02)  # INTEGER exponent
    e = int.from_bytes(der[i : i + e_len], "big")
    return n, e


# --- Feishu HTTP calls ----------------------------------------------------------------


def _http_post_json(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": f"{ContentType.JSON.value}; charset=utf-8"},
        method=HttpMethod.POST.value,
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def _http_get_json(url: str, bearer: str) -> dict:
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {bearer}"}, method=HttpMethod.GET.value
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def _exchange_code(code: str) -> str:
    data = _http_post_json(
        FEISHU_TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": FEISHU_APP_ID,
            "client_secret": Secrets.feishu_app_secret(),
            "code": code,
            "redirect_uri": f"{ISSUER}{Route.CALLBACK.value}",
        },
    )
    token = data.get("access_token")
    if not token:
        raise ValueError(f"feishu token exchange failed: {data}")
    return token


def _fetch_user(user_access_token: str) -> dict:
    body = _http_get_json(FEISHU_USERINFO_URL, user_access_token)
    user = body.get("data") or {}
    # Feishu may return the address in either field; the adapter accepts both.
    if not user.get("email") and not user.get("enterprise_email"):
        raise ValueError("feishu user has no email; grant contact:user.email:readonly")
    return user


# --- Route handlers -------------------------------------------------------------------


def handle_discovery() -> Response:
    return _json(
        StatusCode.OK,
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}{Route.AUTHORIZE.value}",
            "token_endpoint": f"{ISSUER}{Route.TOKEN.value}",
            "userinfo_endpoint": f"{ISSUER}{Route.USERINFO.value}",
            "jwks_uri": f"{ISSUER}{Route.JWKS.value}",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "email", "profile"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "claims_supported": ["sub", "email", "email_verified", "name"],
        },
    )


def handle_jwks() -> Response:
    return _json(StatusCode.OK, Signer.jwks())


def handle_authorize(event: dict) -> Response:
    params = event.get("queryStringParameters") or {}
    cognito_redirect = params.get("redirect_uri")
    if not cognito_redirect:
        return _json(StatusCode.BAD_REQUEST, {"error": "invalid_request"})

    # Pack Cognito's redirect_uri + state so they survive the Feishu round-trip.
    packed = _b64url_json(
        {"rd": cognito_redirect, "st": params.get("state", "")}
    )
    feishu_params = {
        "client_id": FEISHU_APP_ID,
        "response_type": "code",
        "redirect_uri": f"{ISSUER}{Route.CALLBACK.value}",
        "scope": FEISHU_SCOPES,
        "state": packed,
    }
    qs = urllib.parse.urlencode(feishu_params)
    return _redirect(f"{FEISHU_AUTHORIZE_URL}?{qs}")


def handle_callback(event: dict) -> Response:
    params = event.get("queryStringParameters") or {}
    code = params.get("code")
    packed = params.get("state", "")
    if not code:
        return _json(StatusCode.BAD_REQUEST, {"error": "access_denied"})

    padded = packed + "=" * (-len(packed) % 4)
    unpacked = json.loads(base64.urlsafe_b64decode(padded))
    cognito_redirect, cognito_state = unpacked["rd"], unpacked["st"]

    # Hand Feishu's code straight back to Cognito; /token will exchange it.
    forward = {"code": code}
    if cognito_state:
        forward["state"] = cognito_state
    return _redirect(f"{cognito_redirect}?{urllib.parse.urlencode(forward)}")


def _authenticate_client(event: dict, body: dict) -> bool:
    expected_id = Secrets.cognito_client_id()
    expected_secret = Secrets.cognito_client_secret()

    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    auth = headers.get("authorization", "")
    if auth.startswith("Basic "):
        decoded = base64.b64decode(auth[6:]).decode()
        client_id, _, client_secret = decoded.partition(":")
        client_id = urllib.parse.unquote(client_id)
        client_secret = urllib.parse.unquote(client_secret)
    else:
        client_id = body.get("client_id", "")
        client_secret = body.get("client_secret", "")

    return client_id == expected_id and client_secret == expected_secret


def _claims_for(user: dict, audience: str) -> dict:
    subject = user.get(SUBJECT_CLAIM) or user["open_id"]
    email = user.get("enterprise_email") or user["email"]
    now = int(time.time())
    return {
        "iss": ISSUER,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": now + ID_TOKEN_TTL_SECONDS,
        "email": email,
        "email_verified": True,
        "name": user.get("name", email),
    }


def handle_token(event: dict) -> Response:
    body = _parse_form(event)
    if not _authenticate_client(event, body):
        return _json(StatusCode.UNAUTHORIZED, {"error": "invalid_client"})

    code = body.get("code")
    if not code:
        return _json(StatusCode.BAD_REQUEST, {"error": "invalid_grant"})

    user_access_token = _exchange_code(code)
    user = _fetch_user(user_access_token)
    claims = _claims_for(user, Secrets.cognito_client_id())

    id_token = Signer.sign_jwt(claims)
    access_token = Signer.sign_jwt({**claims, "token_use": "access"})
    return _json(
        StatusCode.OK,
        {
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": ID_TOKEN_TTL_SECONDS,
        },
    )


def handle_userinfo(event: dict) -> Response:
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    auth = headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return _json(StatusCode.UNAUTHORIZED, {"error": "invalid_token"})

    # We minted this access_token as a JWT; the claims we need are in its payload.
    payload_b64 = auth[7:].split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload_b64))
    return _json(
        StatusCode.OK,
        {
            "sub": claims["sub"],
            "email": claims["email"],
            "email_verified": claims["email_verified"],
            "name": claims["name"],
        },
    )


def _parse_form(event: dict) -> dict:
    raw = event.get("body", "") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode()
    return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}


# --- Cognito strip-proxy for Quick Desktop --------------------------------------------


def _strip_offline_access(scope_str: str) -> str:
    return " ".join(s for s in scope_str.split() if s != "offline_access")


def handle_cognito_authorize(event: dict) -> Response:
    params = event.get("queryStringParameters") or {}
    if "scope" in params:
        params["scope"] = _strip_offline_access(params["scope"])
    qs = urllib.parse.urlencode(params)
    return _redirect(f"{COGNITO_DOMAIN}/oauth2/authorize?{qs}")


def handle_cognito_token(event: dict) -> Response:
    raw = event.get("body", "") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode()
    # Strip offline_access from the token request body too, if present.
    parsed = urllib.parse.parse_qs(raw)
    if "scope" in parsed:
        parsed["scope"] = [_strip_offline_access(parsed["scope"][0])]
    body = urllib.parse.urlencode({k: v[0] for k, v in parsed.items()}).encode()

    headers = {"Content-Type": ContentType.FORM.value}
    req_headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    if "authorization" in req_headers:
        headers["Authorization"] = req_headers["authorization"]

    req = urllib.request.Request(
        f"{COGNITO_DOMAIN}/oauth2/token", data=body, headers=headers, method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        return Response(
            statusCode=resp.status,
            headers={"Content-Type": ContentType.JSON.value},
            body=resp.read().decode(),
        )


# --- Dispatch -------------------------------------------------------------------------


def handler(event: dict, _context: object) -> dict:
    path = event.get("path", "")
    method = event.get("httpMethod", "")
    print(f"REQUEST: {method} {path}")

    try:
        match (path, method):
            case (Route.DISCOVERY, HttpMethod.GET):
                response = handle_discovery()
            case (Route.JWKS, HttpMethod.GET):
                response = handle_jwks()
            case (Route.AUTHORIZE, HttpMethod.GET):
                response = handle_authorize(event)
            case (Route.CALLBACK, HttpMethod.GET):
                response = handle_callback(event)
            case (Route.TOKEN, HttpMethod.POST):
                response = handle_token(event)
            case (Route.USERINFO, HttpMethod.GET):
                response = handle_userinfo(event)
            case (Route.COGNITO_AUTHORIZE, HttpMethod.GET):
                response = handle_cognito_authorize(event)
            case (Route.COGNITO_TOKEN, HttpMethod.POST):
                response = handle_cognito_token(event)
            case _:
                response = Response(statusCode=StatusCode.NOT_FOUND, body="Not found")
    except urllib.error.HTTPError as e:
        print(f"UPSTREAM ERROR: {e.code} {e.read().decode()}")
        response = _json(StatusCode.BAD_GATEWAY, {"error": "upstream_error"})
    except Exception as e:  # noqa: BLE001 - surface a generic error, log the detail
        print(f"ERROR: {type(e).__name__}: {e}")
        response = _json(StatusCode.INTERNAL_ERROR, {"error": "internal_error"})

    print(f"RESPONSE: {response.statusCode}")
    return response.to_dict()
