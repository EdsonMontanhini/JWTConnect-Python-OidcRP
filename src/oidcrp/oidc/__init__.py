import json
import logging
import traceback
from typing import Optional

from cryptojwt import KeyJar
from cryptojwt import as_unicode
from cryptojwt.key_bundle import keybundle_from_local_file
from oidcmsg import verified_claim_name
from oidcmsg.exception import MessageException
from oidcmsg.exception import NotForMe
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oauth2 import is_error_message
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import Claims
from oidcmsg.oidc.session import BackChannelLogoutRequest
from oidcservice import rndstr
from oidcservice.client_auth import BearerHeader
from oidcservice.exception import OidcServiceError
from oidcservice.oidc import DEFAULT_SERVICES

from oidcrp import ConfigurationError
from oidcrp import OperationsError
from oidcrp.util import userinfo_in_id_token

try:
    from json import JSONDecodeError
except ImportError:  # Only works for >= 3.5
    _decode_err = ValueError
else:
    _decode_err = JSONDecodeError

from oidcrp import oauth2

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------

# This should probably be part of the configuration
MAX_AUTHENTICATION_AGE = 86400

PREFERENCE2PROVIDER = {
    # "require_signed_request_object": "request_object_algs_supported",
    "request_object_signing_alg": "request_object_signing_alg_values_supported",
    "request_object_encryption_alg":
        "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc":
        "request_object_encryption_enc_values_supported",
    "userinfo_signed_response_alg": "userinfo_signing_alg_values_supported",
    "userinfo_encrypted_response_alg":
        "userinfo_encryption_alg_values_supported",
    "userinfo_encrypted_response_enc":
        "userinfo_encryption_enc_values_supported",
    "id_token_signed_response_alg": "id_token_signing_alg_values_supported",
    "id_token_encrypted_response_alg":
        "id_token_encryption_alg_values_supported",
    "id_token_encrypted_response_enc":
        "id_token_encryption_enc_values_supported",
    "default_acr_values": "acr_values_supported",
    "subject_type": "subject_types_supported",
    "token_endpoint_auth_method": "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg":
        "token_endpoint_auth_signing_alg_values_supported",
    "response_types": "response_types_supported",
    'grant_types': 'grant_types_supported'
}

PROVIDER2PREFERENCE = dict([(v, k) for k, v in PREFERENCE2PROVIDER.items()])

PROVIDER_DEFAULT = {
    "token_endpoint_auth_method": "client_secret_basic",
    "id_token_signed_response_alg": "RS256",
}


class FetchException(Exception):
    pass


class RP(oauth2.Client):
    authorization_response = AuthorizationResponse
    authorization_request = AuthorizationRequest

    def __init__(self,
                 base_url: Optional[str] = "",
                 client_authn_factory=None,
                 keyjar: Optional[KeyJar] = None,
                 config: Optional[dict] = None,
                 httplib=None,
                 httpc_params: Optional[dict] = None,
                 **kwargs):

        if config:
            _srvs = config.get("services") or DEFAULT_SERVICES
        else:
            _srvs = DEFAULT_SERVICES

        oauth2.Client.__init__(self, base_url=base_url, client_authn_factory=client_authn_factory,
                               keyjar=keyjar, config=config,
                               httplib=httplib, services=_srvs, httpc_params=httpc_params)

    def dynamic_provider_info_discovery(self):
        """
        This is about performing dynamic Provider Info discovery
        """
        try:  # Is there a dynamic provider discovery service defined
            self.service['provider_info']
        except KeyError:
            raise ConfigurationError('Can not do dynamic provider info discovery')
        else:
            if not self.service_context.issuer:
                try:
                    self.service_context.issuer = self.service_context.config['srv_discovery_url']
                except KeyError:
                    pass

            response = self.do_request('provider_info')
            if is_error_message(response):
                raise OidcServiceError(response['error'])

    def load_registration_response(self):
        """
        If the client has been statically registered that information
        must be provided during the configuration. If expected to be
        done dynamically this method will do dynamic client registration.

        """
        if not self.service_context.client_id:
            try:
                response = self.do_request('registration')
            except KeyError:
                raise ConfigurationError('No registration info')
            except Exception as err:
                logger.error(err)
                raise
            else:
                if 'error' in response:
                    raise OidcServiceError(response.to_json())

                if "verify_args" in self.service_context.client_preferences:
                    _allow_mismatch = self.service_context.client_preferences["verify_args"].get(
                        "allow_mismatching_uris", False)
                    if _allow_mismatch is False:
                        # Should verify that the redirect_uris I get back are the once I sent in
                        # the request.
                        # Why should the OP mess with this ? Who knows !
                        _uris = [uri for uri in self.service_context.redirect_uris if
                                 uri in response["redirect_uris"]]
                        if _uris != self.service_context.redirect_uris:
                            raise OperationsError("OP messing with my redirect_uris")

    def fetch_distributed_claims(self, userinfo, callback=None):
        """

        :param userinfo: A :py:class:`oidcmsg.message.Message` sub class
            instance
        :param callback: A function that can be used to fetch things
        :return: Updated userinfo instance
        """
        try:
            _csrc = userinfo["_claim_sources"]
        except KeyError:
            pass
        else:
            for csrc, spec in _csrc.items():
                if "endpoint" in spec:
                    if "access_token" in spec:
                        cauth = BearerHeader()
                        httpc_params = cauth.construct(
                            service=self.service['userinfo'],
                            access_token=spec['access_token'])
                        _resp = self.http.send(spec["endpoint"], 'GET',
                                               **httpc_params)
                    else:
                        if callback:
                            token = callback(spec['endpoint'])
                            cauth = BearerHeader()
                            httpc_params = cauth.construct(
                                service=self.service['userinfo'],
                                access_token=token)
                            _resp = self.http.send(
                                spec["endpoint"], 'GET', **httpc_params)
                        else:
                            _resp = self.http.send(spec["endpoint"], 'GET')

                    if _resp.status_code == 200:
                        _uinfo = json.loads(_resp.text)
                    else:  # There shouldn't be any redirect
                        raise FetchException(
                            'HTTP error {}: {}'.format(_resp.status_code,
                                                       _resp.reason))

                    claims = [value for value, src in
                              userinfo["_claim_names"].items() if src == csrc]

                    if set(claims) != set(_uinfo.keys()):
                        logger.warning(
                            "Claims from claim source doesn't match what's in "
                            "the userinfo")

                    # only add those I expected
                    for key in claims:
                        userinfo[key] = _uinfo[key]

        return userinfo

    def init_authorization(self, req_args=None):
        """
        Constructs the URL that will redirect the user to the authorization
        endpoint of the OP/AS.

        :param req_args: Non-default Request arguments
        :return: A dictionary with 2 keys: **url** The authorization redirect
            URL and **state** the key to the session information in the
            state data store.
        """

        request_args = {
            'redirect_uri': self.service_context.redirect_uris[0],
            'scope': self.service_context.behaviour['scope'],
            'response_type': self.service_context.behaviour['response_type']
        }

        _req_args = self.service_context.config.get("request_args")
        if _req_args:
            if 'claims' in _req_args:
                _req_args["claims"] = Claims(**_req_args["claims"])
            request_args.update(_req_args)

        # Need a new state for a new authorization request
        _state = self.service_context.state.create_state(self.service_context.issuer)
        request_args['state'] = _state
        _nonce = rndstr(24)
        request_args['nonce'] = _nonce
        self.service_context.state.store_nonce2state(_nonce, _state)

        logger.debug('Authorization request args: {}'.format(request_args))

        _srv = self.service['authorization']
        _info = _srv.get_request_parameters(request_args=request_args)
        self.service_context.state.store_item(_info["request"], "auth_request", _state)
        logger.debug('Authorization info: {}'.format(_info))
        return _info

    def get_user_info(self, state, access_token='', **kwargs):
        """
        use the access token previously acquired to get some userinfo

        :param client: A Client instance
        :param state: The state value, this is the key into the session
            data store
        :param access_token: An access token
        :param kwargs: Extra keyword arguments
        :return: A :py:class:`oidcmsg.oidc.OpenIDSchema` instance
        """

        if access_token:
            request_args = {'access_token': access_token}
        else:
            request_args = self.service_context.state.multiple_extend_request_args(
                {}, state, ['access_token'],
                ['auth_response', 'token_response', 'refresh_token_response'])

        resp = self.do_request('userinfo', state=state, request_args=request_args, **kwargs)
        if is_error_message(resp):
            raise OidcServiceError(resp['error'])

        return resp

    def get_provider_info(self):
        if not self.service_context.provider_info:
            self.dynamic_provider_info_discovery()
            return self.service_context.provider_info['issuer']
        else:
            _pi = self.service_context.provider_info
            for key, val in _pi.items():
                # Set the service endpoints in the services I supply.
                # All service endpoint parameters in provider info has
                # a name ending in '_endpoint' so I can look specifically
                # for those
                if key.endswith("_endpoint"):
                    for _srv in self.service.values():
                        # Every service has an endpoint_name assigned
                        # when initiated. This name *MUST* match the
                        # endpoint names used in the provider info
                        if _srv.endpoint_name == key:
                            _srv.endpoint = val

            if 'keys' in _pi:
                _kj = self.service_context.keyjar
                for typ, _spec in _pi['keys'].items():
                    if typ == 'url':
                        for _iss, _url in _spec.items():
                            _kj.add_url(_iss, _url)
                    elif typ == 'file':
                        for kty, _name in _spec.items():
                            if kty == 'jwks':
                                _kj.import_jwks_from_file(_name, self.service_context.issuer)
                            elif kty == 'rsa':  # PEM file
                                _kb = keybundle_from_local_file(_name, "der", ["sig"])
                                _kj.add_kb(self.service_context.issuer, _kb)
                    else:
                        raise ValueError('Unknown provider JWKS type: {}'.format(typ))

            try:
                return self.service_context.provider_info['issuer']
            except KeyError:
                _iss = self.service_context.issuer
                self.service_context.provider_info['issuer'] = _iss
                return _iss

    def do_client_registration(self):
        """
        Prepare for and do client registration if configured to do so
        """

        if not self.service_context.redirect_uris:
            self.add_callbacks(self.service_context)

        # This should only be interesting if the client supports Single Log Out
        if self.service_context.post_logout_redirect_uris is not None:
            self.service_context.post_logout_redirect_uris = [self.service_context.base_url]

        if not self.service_context.client_id:
            self.load_registration_response()

    def get_access_and_id_token(self, authorization_response=None, state=''):
        """
        There are a number of services where access tokens and ID tokens can
        occur in the response. This method goes through the possible places
        based on the response_type the client uses.

        :param authorization_response: The Authorization response
        :param state: The state key (the state parameter in the
            authorization request)
        :return: A dictionary with 2 keys: **access_token** with the access
            token as value and **id_token** with a verified ID Token if one
            was returned otherwise None.
        """
        if authorization_response is None:
            if state:
                authorization_response = self.service_context.state.get_item(
                    AuthorizationResponse, 'auth_response', state)
            else:
                raise ValueError(
                    'One of authorization_response or state must be provided')

        if not state:
            state = authorization_response['state']

        authreq = self.service_context.state.get_item(
            AuthorizationRequest, 'auth_request', state)
        _resp_type = set(authreq['response_type'])

        access_token = None
        id_token = None
        if _resp_type in [{'id_token'}, {'id_token', 'token'},
                          {'code', 'id_token', 'token'}]:
            id_token = authorization_response['__verified_id_token']

        if _resp_type in [{'token'}, {'id_token', 'token'}, {'code', 'token'},
                          {'code', 'id_token', 'token'}]:
            access_token = authorization_response["access_token"]
        elif _resp_type in [{'code'}, {'code', 'id_token'}]:

            # get the access token
            token_resp = self.get_access_token(state)
            if is_error_message(token_resp):
                return False, "Invalid response %s." % token_resp["error"]

            access_token = token_resp["access_token"]

            try:
                id_token = token_resp['__verified_id_token']
            except KeyError:
                pass

        return {'access_token': access_token, 'id_token': id_token}

    def logout(self, state, client=None, post_logout_redirect_uri=''):
        """
        Does a RP initiated logout from an OP. After logout the user will be
        redirect by the OP to a URL of choice (post_logout_redirect_uri).

        :param state: Key to an active session
        :param client: Which client to use
        :param post_logout_redirect_uri: If a special post_logout_redirect_uri
            should be used
        :return: A US
        """
        try:
            srv = client.service['end_session']
        except KeyError:
            raise OidcServiceError("Does not know how to logout")

        if post_logout_redirect_uri:
            request_args = {
                "post_logout_redirect_uri": post_logout_redirect_uri
            }
        else:
            request_args = {}

        resp = srv.get_request_parameters(state=state,
                                          request_args=request_args)

        return resp

    def clear_session(self, state):
        self.service_context.state.remove_state(state)

    def finalize(self, issuer, response):
        """
        The third of the high level methods that a user of this Class should
        know about.
        Once the consumer has redirected the user back to the
        callback URL there might be a number of services that the client should
        use. Which one those are are defined by the client configuration.

        :param issuer: Who sent the response
        :param response: The Authorization response as a dictionary
        :returns: A dictionary with two claims:
            **state** The key under which the session information is
            stored in the data store and
            **error** and encountered error or
            **userinfo** The collected user information
        """

        authorization_response = self.finalize_auth(response=response, issuer=issuer)

        if is_error_message(authorization_response):
            return {
                'state': authorization_response['state'],
                'error': authorization_response['error']
            }

        _state = authorization_response['state']
        token = self.get_access_and_id_token(authorization_response, state=_state)

        if 'userinfo' in self.service and token['access_token']:
            inforesp = self.get_user_info(
                state=authorization_response['state'],
                access_token=token['access_token'])

            if isinstance(inforesp, ResponseMessage) and 'error' in inforesp:
                return {
                    'error': "Invalid response %s." % inforesp["error"],
                    'state': _state
                }

        elif token['id_token']:  # look for it in the ID Token
            inforesp = userinfo_in_id_token(token['id_token'])
        else:
            inforesp = {}

        logger.debug("UserInfo: %s", inforesp)

        try:
            _sid_support = self.service_context.provider_info[
                'backchannel_logout_session_supported']
        except KeyError:
            try:
                _sid_support = self.service_context.provider_info[
                    'frontchannel_logout_session_supported']
            except:
                _sid_support = False

        if _sid_support:
            try:
                sid = token['id_token']['sid']
            except KeyError:
                pass
            else:
                self.service_context.state.store_sid2state(sid, _state)

        _id_token = token.get("id_token")
        if _id_token:
            self.service_context.state.store_sub2state(_id_token['sub'], _state)

        return {
            'userinfo': inforesp,
            'state': authorization_response['state'],
            'token': token['access_token'],
            'id_token': token['id_token']
        }

def backchannel_logout(client, request='', request_args=None):
    """

    :param request: URL encoded logout request
    :return:
    """

    if request:
        req = BackChannelLogoutRequest().from_urlencoded(as_unicode(request))
    else:
        req = BackChannelLogoutRequest(**request_args)

    kwargs = {
        'aud': client.service_context.client_id,
        'iss': client.service_context.issuer,
        'keyjar': client.service_context.keyjar,
        'allowed_sign_alg': client.service_context.registration_response.get(
            "id_token_signed_response_alg", "RS256")
    }

    try:
        req.verify(**kwargs)
    except (MessageException, ValueError, NotForMe) as err:
        raise MessageException('Bogus logout request: {}'.format(err))

    # Find the subject through 'sid' or 'sub'

    try:
        sub = req[verified_claim_name('logout_token')]['sub']
    except KeyError:
        try:
            sid = req[verified_claim_name('logout_token')]['sid']
        except KeyError:
            raise MessageException('Neither "sid" nor "sub"')
        else:
            _state = client.service_context.state.get_state_by_sid(sid)
    else:
        _state = client.service_context.state.get_state_by_sub(sub)

    return _state
