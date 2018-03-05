import os
import pytest
import sys
import time

from cryptojwt.jwk import rsa_load

from oidcmsg.key_bundle import KeyBundle
from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import RefreshAccessTokenRequest
from oidcmsg.oidc import IdToken
from oidcmsg.time_util import utc_time_sans_frac

from oidcservice.client_auth import CLIENT_AUTHN_METHOD

from oidcrp.oauth2 import Client

sys.path.insert(0, '.')

_dirname = os.path.dirname(os.path.abspath(__file__))
BASE_PATH = os.path.join(_dirname, "data", "keys")

_key = rsa_load(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"key": _key, "kty": "RSA", "use": "sig"})

CLIENT_ID = "client_1"
IDTOKEN = IdToken(iss="http://oidc.example.org/", sub="sub",
                  aud=CLIENT_ID, exp=utc_time_sans_frac() + 86400,
                  nonce="N0nce",
                  iat=time.time())


class TestClient(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        self.redirect_uri = "http://example.com/redirect"
        conf = {
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'client_id': 'client_1',
            'client_secret': 'abcdefghijklmnop'
        }
        self.client = Client(client_authn_method=CLIENT_AUTHN_METHOD,
                             config=conf)

    def test_construct_authorization_request(self):
        req_args = {'state': 'ABCDE',
                    'redirect_uri': 'https://example.com/auth_cb',
                    'response_type': ['code']}
        msg = self.client.service['authorization'].construct(
            self.client.client_info, request_args=req_args)
        assert isinstance(msg, AuthorizationRequest)
        assert msg['client_id'] == 'client_1'
        assert msg['redirect_uri'] == 'https://example.com/auth_cb'

    def test_construct_accesstoken_request(self):
        # Bind access code to state
        req_args = {}
        self.client.client_info.state_db['ABCDE'] = {'code': 'access_code'}
        msg = self.client.service['accesstoken'].construct(
            self.client.client_info, request_args=req_args, state='ABCDE')
        assert isinstance(msg, AccessTokenRequest)
        assert msg.to_dict() == {'client_id': 'client_1',
                                 'code': 'access_code',
                                 'client_secret': 'abcdefghijklmnop',
                                 'grant_type': 'authorization_code'}

    def test_construct_refresh_token_request(self):
        # Bind access code to state
        self.client.client_info.state_db['ABCDE'] = {'code': 'access_code'}
        # Bind token to state
        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access")
        self.client.client_info.state_db.add_response(resp, "ABCDE")

        req_args = {}
        msg = self.client.service['refresh_token'].construct(
            self.client.client_info, request_args=req_args, state='ABCDE')
        assert isinstance(msg, RefreshAccessTokenRequest)
        assert msg.to_dict() == {'client_id': 'client_1',
                                 'client_secret': 'abcdefghijklmnop',
                                 'grant_type': 'refresh_token',
                                 'refresh_token': 'refresh_with_me'}
