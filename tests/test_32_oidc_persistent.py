import json
import os
import sys
import time

from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_bundle import KeyBundle
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oidc import IdToken
from oidcmsg.oidc import OpenIDSchema
from oidcmsg.time_util import utc_time_sans_frac
import pytest
import responses

from oidcrp.oauth2 import Client
from oidcrp.oidc import RP

sys.path.insert(0, '.')

_dirname = os.path.dirname(os.path.abspath(__file__))
BASE_PATH = os.path.join(_dirname, "data", "keys")

_key = import_private_rsa_key_from_file(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"priv_key": _key, "kty": "RSA", "use": "sig"})

CLIENT_ID = "client_1"
IDTOKEN = IdToken(iss="http://oidc.example.org/", sub="sub",
                  aud=CLIENT_ID, exp=utc_time_sans_frac() + 86400,
                  nonce="N0nce",
                  iat=time.time())

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
        "class": "oidcservice.oidc.authorization.Authorization",
        "kwargs": {}
    },
    "accesstoken": {
        "class": "oidcservice.oidc.access_token.AccessToken",
        "kwargs": {}
    },
    "userinfo": {
        "class": "oidcservice.oidc.user_info.UserInfo",
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
        self.client1 = RP(config=STATIC_CLIENT, httpc_params=HTTPC_PARAMS, base_url=BASE_URL)
        self.client2 = RP(config=STATIC_CLIENT, httpc_params=HTTPC_PARAMS, base_url=BASE_URL)

    def test_sequence(self):
        # client1 does the request
        req_args = {
            'redirect_uri': 'https://example.com/auth_cb',
            'response_type': "code"
        }

        req_info = self.client1.init_authorization(req_args)
        _state = req_info["request"]["state"]

        _service_context_state = self.client1.service_context.dump()
        self.client2.service_context.load(_service_context_state)

        auth_response = AuthorizationResponse(code='access_code', state=_state)

        self.client2.finalize_auth(auth_response.to_dict(), "https://op.example.com/")

        # synchronize the two instances
        _service_context_state = self.client2.service_context.dump()
        self.client1.service_context.load(_service_context_state)

        session_state_I = self.client1.service_context.state.get_state(_state)
        assert set(session_state_I.keys()) == {"iss", "pkce", "auth_request", "auth_response"}

        session_state_II = self.client2.service_context.state.get_state(_state)
        assert set(session_state_II.keys()) == {"iss", "pkce", "auth_request", "auth_response"}

        url = self.client1.service_context.provider_info["token_endpoint"]

        # Access token
        token_response = AccessTokenResponse(refresh_token="refresh_with_me",
                                             access_token="access_token",
                                             token_type="Bearer")

        with responses.RequestsMock() as rsps:
            rsps.add("POST", url,
                     body=token_response.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            self.client1.get_access_token(_state)

        # Update the 2nd client
        _service_context_state = self.client1.service_context.dump()
        self.client2.service_context.load(_service_context_state)

        session_state_II = self.client2.service_context.state.get_state(_state)
        assert set(session_state_II.keys()) == {"iss", "pkce", "auth_request", "auth_response",
                                                'token_response'}

        resp = self.client2.service_context.state.get_item(AccessTokenResponse, "token_response",
                                                           _state)
        assert resp["access_token"] == "access_token"

        url = self.client1.service_context.provider_info["userinfo_endpoint"]
        _url = "https://example.com/claims.json"
        userinfo_response = OpenIDSchema(**{
            "sub": 'jane_doe',
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe",
            "email": "janedoe@example.com",
            "birthdate": "0000-03-22",
            "eye_color": "blue",
            "_claim_names": {
                "payment_info": "src1",
                "shipping_address": "src1",
            },
            "_claim_sources": {
                "src1": {
                    "endpoint": _url
                }
            }
        })

        with responses.RequestsMock() as rsps:
            rsps.add("GET", url,
                     body=userinfo_response.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            user = self.client2.get_user_info(_state)

        assert user
        assert user["name"] == "Jane Doe"

        # synchronize the two instances 2 -> 1
        _service_context_state = self.client2.service_context.dump()
        self.client1.service_context.load(_service_context_state)

        # Wrong set of claims. Actually extra claim
        _info = {
            "shipping_address": {
                "street_address": "1234 Hollywood Blvd.",
                "locality": "Los Angeles",
                "region": "CA",
                "postal_code": "90210",
                "country": "US"
            },
            "payment_info": "Some_Card 1234 5678 9012 3456",
            "phone_number": "+1 (310) 123-4567"
        }

        with responses.RequestsMock() as rsps:
            rsps.add("GET", _url, body=json.dumps(_info),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            res = self.client1.fetch_distributed_claims(user)

        assert 'payment_info' in res
        assert 'shipping_address' in res
        assert 'phone_number' not in res

