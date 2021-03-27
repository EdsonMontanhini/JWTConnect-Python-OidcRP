import os
import sys

from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_bundle import KeyBundle
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oauth2 import ResponseMessage
from oidcservice.exception import OidcServiceError
from oidcservice.exception import ParseError
import pytest
import responses

from oidcrp.oauth2 import Client

sys.path.insert(0, '.')

_dirname = os.path.dirname(os.path.abspath(__file__))
BASE_PATH = os.path.join(_dirname, "data", "keys")

_key = import_private_rsa_key_from_file(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"priv_key": _key, "kty": "RSA", "use": "sig"})

CLIENT_ID = "client_1"

HTTPC_PARAMS = {
    "verify": False
}

KEYDEFS = [
    {
        "type": "RSA",
        "key": '',
        "use": ["sig"],
    },
    {
        "type": "EC",
        "crv": "P-256",
        "use": ["sig"]
    }
]

RP_KEYS = {
    'private_path': 'private/jwks.json',
    'key_defs': KEYDEFS,
    'public_path': 'static/jwks.json',
    # this will create the jwks files if they are absent
    'read_only': False
}

CLIENT_PREFERENCES = {
    "application_name": "rphandler",
    "application_type": "web",
    "contacts": ["ops@example.com"],
    "response_type": "code",
    "scope": ["profile", "email", "address", "phone"],
    "token_endpoint_auth_method": "client_secret_basic"
}

SERVICES = {
    "authorization": {
        "class": "oidcservice.oauth2.authorization.Authorization",
        "kwargs": {}
    },
    "accesstoken": {
        "class": "oidcservice.oauth2.access_token.AccessToken",
        "kwargs": {}
    }
}

BASE_URL = "https://rp.example.org"

# default services
STATIC_CLIENT = {
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'client_id': 'client_1',
    'client_secret': 'abcdefghijklmnop',
    "behaviour": CLIENT_PREFERENCES,
    "keys": RP_KEYS,
    "provider_info": {
        "issuer": "https://op.example.com/",
        "authorization_endpoint": "https://op.example.com/auth",
        "token_endpoint": "https://op.example.com/token",
        "userinfo_endpoint": "https://op.example.com/user",
        "jwks_uri": "https://op.example.com/jwks",
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"]
    },
    "add_ons": {
        "pkce": {
            "function": "oidcservice.oidc.add_on.pkce.add_pkce_support",
            "kwargs": {
                "code_challenge_length": 64,
                "code_challenge_method": "S256"
            }
        }
    }
}


class MockResponse():
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = ''


class TestClient(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        # self.redirect_uri = "http://example.com/redirect"
        self.client = Client(config=STATIC_CLIENT, httpc_params=HTTPC_PARAMS, base_url=BASE_URL)

    def test_sequence(self):
        # client1 does the request
        req_args = {
            'redirect_uri': 'https://example.com/auth_cb',
            'response_type': "code"
        }

        req_info = self.client.init_authorization(req_args)
        _state = req_info["request"]["state"]

        auth_response = AuthorizationResponse(code='access_code', state=_state)

        self.client.finalize_auth(auth_response.to_dict(), "https://op.example.com/")

        url = self.client.service_context.provider_info["token_endpoint"]

        # Access token
        token_response = AccessTokenResponse(refresh_token="refresh_with_me",
                                             access_token="access_token",
                                             token_type="Bearer")

        with responses.RequestsMock() as rsps:
            rsps.add("POST", url,
                     body=token_response.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            token_resp = self.client.get_access_token(_state)

        assert token_resp["access_token"] == "access_token"
        resp = self.client.service_context.state.get_item(AccessTokenResponse, "token_response",
                                                          _state)
        assert resp["access_token"] == "access_token"

        # Refresh token
        req_args = {}
        # Access token
        refresh_token_response = AccessTokenResponse(refresh_token="refresh_with_me_2",
                                                     access_token="access_token_2",
                                                     token_type="Bearer")

        with responses.RequestsMock() as rsps:
            rsps.add("POST", url,
                     body=refresh_token_response.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            msg = self.client.refresh_access_token(state=_state)

        assert msg["refresh_token"] == "refresh_with_me_2"

    def test_error_response(self):
        err = ResponseMessage(error='Illegal')
        http_resp = MockResponse(400, err.to_urlencoded())
        resp = self.client.parse_request_response(
            self.client.service['authorization'], http_resp)

        assert resp['error'] == 'Illegal'
        assert resp['status_code'] == 400

    def test_error_response_500(self):
        err = ResponseMessage(error='Illegal')
        http_resp = MockResponse(500, err.to_urlencoded())
        with pytest.raises(ParseError):
            self.client.parse_request_response(
                self.client.service['authorization'], http_resp)

    def test_error_response_2(self):
        err = ResponseMessage(error='Illegal')
        http_resp = MockResponse(
            400, err.to_json(),
            headers={'content-type': 'application/x-www-form-urlencoded'})

        with pytest.raises(OidcServiceError):
            self.client.parse_request_response(
                self.client.service['authorization'], http_resp)
