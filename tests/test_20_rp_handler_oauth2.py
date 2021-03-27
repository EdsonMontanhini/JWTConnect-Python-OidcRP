import os
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from cryptojwt.key_jar import init_key_jar
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oauth2 import ASConfigurationResponse
import pytest
import responses

from oidcrp.oauth2 import Client
from oidcrp.rp_handler import RPHandler

BASE_URL = 'https://example.com/rp'

CLIENT_PREFS = {
    "application_type": "web",
    "application_name": "rphandler",
    "contacts": ["ops@example.com"],
    "response_types": ["code"],
    "scope": ["profile", "email", "address", "phone"],
    "token_endpoint_auth_method": "client_secret_basic",
    "verify_args": {"allow_mismatching_uris": True}
}

CLIENT_BEHAVIOUR = {
    "application_type": "web",
    "application_name": "rphandler",
    "contacts": ["ops@example.com"],
    "response_type": "code",
    "scope": ["profile", "email", "address", "phone"],
    "token_endpoint_auth_method": "client_secret_basic",
    "verify_args": {"allow_mismatching_uris": True}
}

CLIENT_CONFIG = {
    "": {
        "client_preferences": CLIENT_PREFS,
        "redirect_uris": None,
        "services": {
            "discovery": {
                'class': 'oidcservice.oauth2.provider_info_discovery.ProviderInfoDiscovery'
            },
            'authorization': {
                'class': 'oidcservice.oauth2.authorization.Authorization'
            },
            'access_token': {
                'class': 'oidcservice.oauth2.access_token.AccessToken'
            },
            'refresh_access_token': {
                'class': 'oidcservice.oauth2.refresh_access_token'
                         '.RefreshAccessToken'
            }
        }
    },
    'foobar': {
        "issuer": "https://foobar.com/login/oauth/authorize",
        'client_id': 'eeeeeeeee',
        'client_secret': 'aaaaaaaaaaaaaaaaaaaa',
        "redirect_uris": ["{}/authz_cb/foobar".format(BASE_URL)],
        "behaviour": {
            "response_type": "code",
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": "client_secret_basic"
        },
        "provider_info": {
            "authorization_endpoint":
                "https://foobar.com/login/oauth/authorize",
            "token_endpoint":
                "https://foobar.com/login/oauth/access_token"
        },
        'services': {
            'authorization': {
                'class': 'oidcservice.oauth2.authorization.Authorization'
            },
            'access_token': {
                'class': 'oidcservice.oauth2.access_token.AccessToken'
            },
            'refresh_access_token': {
                'class': 'oidcservice.oauth2.refresh_access_token.RefreshAccessToken'
            }
        }
    },
    'foo': {
        "issuer": "https://foobar.com/login/oauth/authorize",
        'client_id': 'eeeeeeeee',
        'client_secret': 'aaaaaaaaaaaaaaaaaaaa',
        "redirect_uris": ["{}/authz_cb/foobar".format(BASE_URL)],
        "behaviour": {
            "response_type": "code",
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": "client_secret_basic"
        },
        'services': {
            'authorization': {
                'class': 'oidcservice.oauth2.authorization.Authorization'
            },
            'access_token': {
                'class': 'oidcservice.oauth2.access_token.AccessToken'
            },
            "discovery": {
                'class': 'oidcservice.oauth2.provider_info_discovery.ProviderInfoDiscovery'
            }
        }
    }
}

KEYDEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

_dirname = os.path.dirname(os.path.abspath(__file__))

ISS = 'https://example.com'

CLI_KEY = init_key_jar(public_path='{}/pub_client.jwks'.format(_dirname),
                       private_path='{}/priv_client.jwks'.format(_dirname),
                       key_defs=KEYDEFS, issuer_id='')

FOOBAR_KEY = init_key_jar(
    public_path='{}/pub_foobar.jwks'.format(_dirname),
    private_path='{}/priv_foobar.jwks'.format(_dirname),
    key_defs=KEYDEFS,
    issuer_id=CLIENT_CONFIG['foobar']['issuer']
)

DYNAMIC_OP_BASEURL = "https://op.example.com"


def iss_id(iss):
    return CLIENT_CONFIG[iss]['issuer']


class TestRPHandler(object):
    @pytest.fixture(autouse=True)
    def rphandler_setup(self):
        self.rph = RPHandler(BASE_URL, client_configs=CLIENT_CONFIG,
                             client_cls=Client, keyjar=CLI_KEY, module_dirs=['oauth2'])

    def test_pick_config(self):
        cnf = self.rph.pick_config('foobar')
        assert cnf['issuer'] == "https://foobar.com/login/oauth/authorize"

        cnf = self.rph.pick_config('')
        assert 'issuer' not in cnf

    def test_setup_static_client(self):
        client = self.rph.client_setup('foobar')
        assert set(client.service.keys()) == {'authorization', 'accesstoken', 'refresh_token',
                                              'provider_info'}

        _context = client.service_context

        assert _context.get('client_id') == 'eeeeeeeee'
        assert _context.get('client_secret') == 'aaaaaaaaaaaaaaaaaaaa'
        assert _context.get('issuer') == "https://foobar.com/login/oauth/authorize"

        assert _context.get('provider_info') is not None
        assert set(_context.get('provider_info').keys()) == {
            'authorization_endpoint', 'token_endpoint', 'issuer'
        }

        assert _context.get('behaviour') == {
            "response_type": "code",
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": 'client_secret_basic'
        }

        for service_type in ['authorization', 'accesstoken']:
            _srv = client.service[service_type]
            _endp = client.service_context.get('provider_info')[_srv.endpoint_name]
            assert _srv.endpoint == _endp

    def test_setup_client_dynamic(self):
        _base_url = CLIENT_CONFIG["foo"]["issuer"]
        resp = {
            "openid-configuration": {
                "url": "{}/.well-known/openid-configuration".format(_base_url),
                "response": ASConfigurationResponse(**{
                    "version": "3.0",
                    "token_endpoint_auth_methods_supported": [
                        "client_secret_post", "client_secret_basic",
                        "client_secret_jwt", "private_key_jwt"],
                    "claims_parameter_supported": True,
                    "request_parameter_supported": True,
                    "request_uri_parameter_supported": True,
                    "require_request_uri_registration": True,
                    "grant_types_supported": ["authorization_code",
                                              "implicit",
                                              "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                              "refresh_token"],
                    "response_types_supported": ["code"],
                    "response_modes_supported": ["query", "fragment",
                                                 "form_post"],
                    "subject_types_supported": ["public", "pairwise"],
                    "claim_types_supported": ["normal", "aggregated",
                                              "distributed"],
                    "claims_supported": ["birthdate", "address",
                                         "nickname", "picture", "website",
                                         "email", "gender", "sub",
                                         "phone_number_verified",
                                         "given_name", "profile",
                                         "phone_number", "updated_at",
                                         "middle_name", "name", "locale",
                                         "email_verified",
                                         "preferred_username", "zoneinfo",
                                         "family_name"],
                    "scopes_supported": ["profile", "email", "address", "phone",
                                         "offline_access"],
                    "request_object_signing_alg_values_supported": [
                        "RS256", "RS384", "RS512", "ES256", "ES384",
                        "ES512", "HS256", "HS384", "HS512", "PS256",
                        "PS384", "PS512", "none"],
                    "token_endpoint_auth_signing_alg_values_supported": [
                        "RS256", "RS384", "RS512", "ES256", "ES384",
                        "ES512", "HS256", "HS384", "HS512", "PS256",
                        "PS384", "PS512"],
                    "acr_values_supported": ["PASSWORD"],
                    "issuer": _base_url,
                    "jwks_uri": "{}/static/jwks_tE2iLbOAqXhe8bqh.json".format(_base_url),
                    "authorization_endpoint": "{}/authorization".format(_base_url),
                    "token_endpoint": "{}/token".format(_base_url),
                })
            }
        }
        with responses.RequestsMock() as rsps:
            rsps.add("GET",
                     resp["openid-configuration"]["url"],
                     body=resp["openid-configuration"]["response"].to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            client = self.rph.client_setup('foo')

        assert client.service_context.issuer == _base_url
        c2 = self.rph.find_client_by_issuer_id('foo')
        assert c2.service_context.issuer == _base_url

    def test_begin(self):
        res = self.rph.begin(issuer_id='foobar')
        assert set(res.keys()) == {'url', 'request', 'method'}

        client = self.rph.find_client_by_issuer_id("foobar")

        part = urlsplit(res['url'])
        assert part.scheme == 'https'
        assert part.netloc == 'foobar.com'
        assert part.path == '/login/oauth/authorize'
        query = parse_qs(part.query)

        assert set(query.keys()) == {'state', 'client_id', 'redirect_uri', 'response_type', 'scope'}

        # nonce and state are created on the fly so can't check for those
        assert query['client_id'] == ['eeeeeeeee']
        assert query['redirect_uri'] == ['https://example.com/rp/authz_cb/foobar']
        assert query['response_type'] == ['code']
        assert query['scope'] == ['user public_repo']

    def test_get_session_information(self):
        request_info = self.rph.begin(issuer_id='foobar')
        _session = self.rph.get_session_information(request_info["request"]['state'])
        assert self.rph.client_configs['foobar']['issuer'] == _session['iss']

    def test_get_client_from_session_key(self):
        request_info = self.rph.begin(issuer_id='foobar')
        _state_val = request_info["request"]['state']
        cli1 = self.rph.get_client_from_session_key(_state_val)
        _session = self.rph.get_session_information(_state_val)
        cli2 = self.rph.find_client_by_issuer_url(_session['iss'])
        assert cli1 == cli2

    def test_finalize_auth(self):
        request_info = self.rph.begin(issuer_id='foobar')
        _state_val = request_info["request"]['state']
        _session = self.rph.get_session_information(_state_val)
        client = self.rph.find_client_by_issuer_url(_session['iss'])

        auth_response = AuthorizationResponse(code='access_code', state=_state_val)
        resp = client.finalize_auth(response=auth_response.to_dict(), issuer=_session['iss'])
        assert set(resp.keys()) == {'state', 'code'}
        aresp = client.service['authorization'].service_context.state.get_item(
            AuthorizationResponse, 'auth_response', _state_val)
        assert set(aresp.keys()) == {'state', 'code'}

    def test_finalize(self):
        request_info = self.rph.begin(issuer_id='foobar')
        _state_val = request_info["request"]['state']
        _session = self.rph.get_session_information(_state_val)
        client = self.rph.find_client_by_issuer_url(_session['iss'])

        auth_response = AuthorizationResponse(code='access_code', state=_state_val)

        token_response = AccessTokenResponse(refresh_token="refresh_with_me",
                                             access_token="access_token",
                                             token_type="Bearer")

        with responses.RequestsMock() as rsps:
            rsps.add("POST",
                     client.service_context.provider_info["token_endpoint"],
                     body=token_response.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            resp = client.finalize(response=auth_response.to_dict(), issuer=_session['iss'])

        assert set(resp.keys()) == {'state', 'token'}
        assert resp["token"] == "access_token"
