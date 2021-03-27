import os
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from cryptojwt.key_jar import init_key_jar
from oidcmsg.oidc import AccessTokenResponse
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import JRD
from oidcmsg.oidc import Link
from oidcmsg.oidc import OpenIDSchema
from oidcmsg.oidc import ProviderConfigurationResponse
from oidcmsg.oidc import RegistrationResponse
from oidcservice import rndstr
import pytest
import responses

from oidcrp.rp_handler import RPHandler

BASE_URL = 'https://example.com/rp'

CLIENT_PREFS = {
    "application_type": "web",
    "application_name": "rphandler",
    "contacts": ["ops@example.com"],
    "response_types": ["code", "id_token", "id_token token", "code id_token",
                       "code id_token token", "code token"],
    "scope": ["openid", "profile", "email", "address", "phone"],
    "token_endpoint_auth_method": "client_secret_basic",
    "verify_args": {"allow_mismatching_uris": True}
}

CLIENT_BEHAVIOUR = {
    "application_type": "web",
    "application_name": "rphandler",
    "contacts": ["ops@example.com"],
    "response_type": "code",
    "scope": ["openid", "profile", "email", "address", "phone"],
    "token_endpoint_auth_method": "client_secret_basic",
    "verify_args": {"allow_mismatching_uris": True}
}

CLIENT_CONFIG = {
    "": {
        "client_preferences": CLIENT_PREFS,
        "redirect_uris": None,
        "services": {
            'web_finger': {
                'class': 'oidcservice.oidc.webfinger.WebFinger'
            },
            "discovery": {
                'class': 'oidcservice.oidc.provider_info_discovery'
                         '.ProviderInfoDiscovery'
            },
            'registration': {
                'class': 'oidcservice.oidc.registration.Registration'
            },
            'authorization': {
                'class': 'oidcservice.oidc.authorization.Authorization'
            },
            'access_token': {
                'class': 'oidcservice.oidc.access_token.AccessToken'
            },
            'refresh_access_token': {
                'class': 'oidcservice.oidc.refresh_access_token'
                         '.RefreshAccessToken'
            },
            'userinfo': {
                'class': 'oidcservice.oidc.userinfo.UserInfo'
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
                "https://foobar.com/login/oauth/access_token",
            "userinfo_endpoint":
                "https://api.foobar.com/user"
        },
        'services': {
            'authorization': {
                'class': 'oidcservice.oidc.authorization.Authorization'
            },
            'access_token': {
                'class': 'oidcservice.oidc.access_token.AccessToken'
            },
            'userinfo': {
                'class': 'oidcservice.oidc.userinfo.UserInfo',
                'kwargs': {'conf': {'default_authn_method': ''}}
            },
            'refresh_access_token': {
                'class': 'oidcservice.oidc.refresh_access_token'
                         '.RefreshAccessToken'
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
                'class': 'oidcservice.oidc.authorization.Authorization'
            },
            'access_token': {
                'class': 'oidcservice.oidc.access_token.AccessToken'
            },
            'userinfo': {
                'class': 'oidcservice.oidc.userinfo.UserInfo',
                'kwargs': {'conf': {'default_authn_method': ''}}
            },
            "discovery": {
                'class': 'oidcservice.oidc.provider_info_discovery.ProviderInfoDiscovery'
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

GITHUB_KEY = init_key_jar(
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
                             keyjar=CLI_KEY, module_dirs=['oidc'])

    def test_pick_config(self):
        cnf = self.rph.pick_config('foobar')
        assert cnf['issuer'] == "https://foobar.com/login/oauth/authorize"

        cnf = self.rph.pick_config('')
        assert 'issuer' not in cnf

    def test_setup_static_client(self):
        client = self.rph.client_setup('foobar')
        assert set(client.service.keys()) == {'authorization', 'accesstoken',
                                              'userinfo', 'refresh_token'}

        _context = client.service_context

        assert _context.get('client_id') == 'eeeeeeeee'
        assert _context.get('client_secret') == 'aaaaaaaaaaaaaaaaaaaa'
        assert _context.get('issuer') == "https://foobar.com/login/oauth/authorize"

        assert _context.get('provider_info') is not None
        assert set(_context.get('provider_info').keys()) == {
            'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'issuer'
        }

        assert _context.get('behaviour') == {
            "response_type": "code",
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": 'client_secret_basic'
        }

        for service_type in ['authorization', 'accesstoken', 'userinfo']:
            _srv = client.service[service_type]
            _endp = client.service_context.get('provider_info')[_srv.endpoint_name]
            assert _srv.endpoint == _endp

    def test_setup_client_dynamic(self):
        _base_url = CLIENT_CONFIG["foo"]["issuer"]
        resp = {
            "openid-configuration": {
                "url": "{}/.well-known/openid-configuration".format(_base_url),
                "response": ProviderConfigurationResponse(**{
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
                    "response_types_supported": ["code", "id_token",
                                                 "id_token token",
                                                 "code id_token",
                                                 "code token",
                                                 "code id_token token"],
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
                    "scopes_supported": ["openid", "profile", "email",
                                         "address", "phone",
                                         "offline_access", "openid"],
                    "userinfo_signing_alg_values_supported": [
                        "RS256", "RS384", "RS512",
                        "ES256", "ES384", "ES512",
                        "HS256", "HS384", "HS512",
                        "PS256", "PS384", "PS512", "none"],
                    "id_token_signing_alg_values_supported": [
                        "RS256", "RS384", "RS512",
                        "ES256", "ES384", "ES512",
                        "HS256", "HS384", "HS512",
                        "PS256", "PS384", "PS512", "none"],
                    "request_object_signing_alg_values_supported": [
                        "RS256", "RS384", "RS512", "ES256", "ES384",
                        "ES512", "HS256", "HS384", "HS512", "PS256",
                        "PS384", "PS512", "none"],
                    "token_endpoint_auth_signing_alg_values_supported": [
                        "RS256", "RS384", "RS512", "ES256", "ES384",
                        "ES512", "HS256", "HS384", "HS512", "PS256",
                        "PS384", "PS512"],
                    "userinfo_encryption_alg_values_supported": [
                        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
                        "A128KW", "A192KW", "A256KW",
                        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
                    "id_token_encryption_alg_values_supported": [
                        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
                        "A128KW", "A192KW", "A256KW",
                        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
                    "request_object_encryption_alg_values_supported": [
                        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "A128KW",
                        "A192KW", "A256KW", "ECDH-ES", "ECDH-ES+A128KW",
                        "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
                    "userinfo_encryption_enc_values_supported": [
                        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
                        "A128GCM", "A192GCM", "A256GCM"],
                    "id_token_encryption_enc_values_supported": [
                        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
                        "A128GCM", "A192GCM", "A256GCM"],
                    "request_object_encryption_enc_values_supported": [
                        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
                        "A128GCM", "A192GCM", "A256GCM"],
                    "acr_values_supported": ["PASSWORD"],
                    "issuer": _base_url,
                    "jwks_uri": "{}/static/jwks_tE2iLbOAqXhe8bqh.json".format(_base_url),
                    "authorization_endpoint": "{}/authorization".format(_base_url),
                    "token_endpoint": "{}/token".format(_base_url),
                    "userinfo_endpoint": "{}/userinfo".format(_base_url),
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

    def test_setup_client_dynamic_registration(self):
        resp = {
            "webfinger": {
                "url": "https://op.example.com/.well-known/webfinger?"
                       "rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer&"
                       "resource=acct%3Adiana%40op.example.com",
                "response": JRD(subject='diana@localhost',
                                links=[Link(rel='http://openid.net/specs/connect/1.0/issuer',
                                            href="https://op.example.com")])
            },
            "openid-configuration": {
                "url": "https://op.example.com/.well-known/openid-configuration",
                "response": ProviderConfigurationResponse(**{
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
                    "response_types_supported": ["code", "id_token",
                                                 "id_token token",
                                                 "code id_token",
                                                 "code token",
                                                 "code id_token token"],
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
                    "scopes_supported": ["openid", "profile", "email",
                                         "address", "phone",
                                         "offline_access", "openid"],
                    "userinfo_signing_alg_values_supported": [
                        "RS256", "RS384", "RS512",
                        "ES256", "ES384", "ES512",
                        "HS256", "HS384", "HS512",
                        "PS256", "PS384", "PS512", "none"],
                    "id_token_signing_alg_values_supported": [
                        "RS256", "RS384", "RS512",
                        "ES256", "ES384", "ES512",
                        "HS256", "HS384", "HS512",
                        "PS256", "PS384", "PS512", "none"],
                    "request_object_signing_alg_values_supported": [
                        "RS256", "RS384", "RS512", "ES256", "ES384",
                        "ES512", "HS256", "HS384", "HS512", "PS256",
                        "PS384", "PS512", "none"],
                    "token_endpoint_auth_signing_alg_values_supported": [
                        "RS256", "RS384", "RS512", "ES256", "ES384",
                        "ES512", "HS256", "HS384", "HS512", "PS256",
                        "PS384", "PS512"],
                    "userinfo_encryption_alg_values_supported": [
                        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
                        "A128KW", "A192KW", "A256KW",
                        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
                    "id_token_encryption_alg_values_supported": [
                        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
                        "A128KW", "A192KW", "A256KW",
                        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
                    "request_object_encryption_alg_values_supported": [
                        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "A128KW",
                        "A192KW", "A256KW", "ECDH-ES", "ECDH-ES+A128KW",
                        "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
                    "userinfo_encryption_enc_values_supported": [
                        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
                        "A128GCM", "A192GCM", "A256GCM"],
                    "id_token_encryption_enc_values_supported": [
                        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
                        "A128GCM", "A192GCM", "A256GCM"],
                    "request_object_encryption_enc_values_supported": [
                        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
                        "A128GCM", "A192GCM", "A256GCM"],
                    "acr_values_supported": ["PASSWORD"],
                    "issuer": DYNAMIC_OP_BASEURL,
                    "jwks_uri": "{}/static/jwks_tE2iLbOAqXhe8bqh.json".format(DYNAMIC_OP_BASEURL),
                    "authorization_endpoint": "{}/authorization".format(DYNAMIC_OP_BASEURL),
                    "token_endpoint": "{}/token".format(DYNAMIC_OP_BASEURL),
                    "userinfo_endpoint": "{}/userinfo".format(DYNAMIC_OP_BASEURL),
                    "registration_endpoint": "{}/registration".format(DYNAMIC_OP_BASEURL),
                    "end_session_endpoint": "{}/end_session".format(DYNAMIC_OP_BASEURL)
                })
            },
            "registration":{
                "url": 'https://op.example.com/registration',
                "response": RegistrationResponse(**{
                    "application_type": "web",
                    "application_name": "rphandler",
                    "contacts": ["ops@example.com"],
                    "response_types": ["code"],
                    "scope": ["openid", "profile", "email", "address", "phone"],
                    "token_endpoint_auth_method": "client_secret_basic",
                    "client_id": "abcdefghijkl",
                    "client_secret": rndstr(24),
                    "redirect_uris": ['https://example.com/rp/authz_cb']
                })
            }
        }
        with responses.RequestsMock() as rsps:
            rsps.add("GET",
                     resp["webfinger"]["url"],
                     body=resp["webfinger"]["response"].to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)
            rsps.add("GET",
                     resp["openid-configuration"]["url"],
                     body=resp["openid-configuration"]["response"].to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)
            rsps.add("POST",
                     resp["registration"]["url"],
                     body=resp["registration"]["response"].to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            client = self.rph.client_setup(user='acct:diana@op.example.com')

        assert client.service_context.issuer == DYNAMIC_OP_BASEURL

        cb = client.service_context.callbacks
        assert set(cb.keys()) == {'code', 'implicit', 'form_post', '__hex'}
        _hash = cb['__hex']

        assert cb['code'] == 'https://example.com/rp/authz_cb/{}'.format(_hash)
        assert cb['implicit'] == 'https://example.com/rp/authz_im_cb/{}'.format(_hash)
        assert cb['form_post'] == 'https://example.com/rp/authz_fp_cb/{}'.format(_hash)

        assert self.rph.find_client_by_issuer_id(_hash).service_context.issuer == 'https://op.example.com'

    def test_begin(self):
        res = self.rph.begin(issuer_id='foobar')
        assert set(res.keys()) == {'url', 'request', 'method'}

        client = self.rph.find_client_by_issuer_id("foobar")

        part = urlsplit(res['url'])
        assert part.scheme == 'https'
        assert part.netloc == 'foobar.com'
        assert part.path == '/login/oauth/authorize'
        query = parse_qs(part.query)

        assert set(query.keys()) == {'nonce', 'state', 'client_id',
                                     'redirect_uri', 'response_type', 'scope'}

        # nonce and state are created on the fly so can't check for those
        assert query['client_id'] == ['eeeeeeeee']
        assert query['redirect_uri'] == ['https://example.com/rp/authz_cb/foobar']
        assert query['response_type'] == ['code']
        assert query['scope'] == ['user public_repo openid']

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
        userinfo_response = OpenIDSchema(**{
            "sub": 'jane_doe',
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe",
            "email": "janedoe@example.com"
        })

        with responses.RequestsMock() as rsps:
            rsps.add("POST",
                     client.service_context.provider_info["token_endpoint"],
                     body=token_response.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)
            rsps.add("GET",
                     client.service_context.provider_info["userinfo_endpoint"],
                     body=userinfo_response.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            resp = client.finalize(response=auth_response.to_dict(), issuer=_session['iss'])

        assert set(resp.keys()) == {'userinfo', 'state', 'token', 'id_token'}
        assert resp["id_token"] is None
        assert resp["userinfo"]["sub"] == "jane_doe"
        assert resp["token"] == "access_token"