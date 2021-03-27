import hashlib
from json import JSONDecodeError
import logging
import sys
import traceback
from typing import Any
from typing import Optional

from cryptojwt import KeyJar
from cryptojwt.key_bundle import keybundle_from_local_file
from cryptojwt.utils import as_bytes
from oidcmsg.exception import FormatError
from oidcmsg.impexp import ImpExp
from oidcmsg.item import DLDict
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oauth2 import is_error_message
from oidcmsg.time_util import time_sans_frac
from oidcservice import rndstr
from oidcservice.client_auth import factory as ca_factory
from oidcservice.exception import OidcServiceError
from oidcservice.exception import ParseError
from oidcservice.oauth2 import DEFAULT_SERVICES
from oidcservice.service import REQUEST_INFO
from oidcservice.service import SUCCESSFUL
from oidcservice.service import Service
from oidcservice.service import init_services
from oidcservice.service_context import ServiceContext

from oidcrp import ConfigurationError
from oidcrp.http import HTTPLib
from oidcrp.util import do_add_ons
from oidcrp.util import get_deserialization_method

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

Version = "2.0"


class ExpiredToken(Exception):
    pass


# =============================================================================


class Client(ImpExp):
    parameter = {
        "client_id": "",
        "httpc_params": {},
        "issuer": "",
        "issuer_id": "",
        "service": DLDict,
        "service_context": ServiceContext,
    }

    authorization_response = AuthorizationResponse
    authorization_request = AuthorizationRequest

    def __init__(self,
                 base_url: Optional[str] = "",
                 client_authn_factory: Optional[Any] = None,
                 keyjar: Optional[KeyJar] = None,
                 config: Optional[dict] = None,
                 httplib=None,
                 services: Optional[dict] = None,
                 jwks_uri: Optional[str] = '',
                 httpc_params: Optional[dict] = None,
                 hash_seed: Optional[str] = ""):
        """

        :param client_authn_factory: Factory that this client can use to
            initiate a client authentication class.
        :param keyjar: A py:class:`oidcmsg.key_jar.KeyJar` instance
        :param config: Configuration information passed on to the
            :py:class:`oidcservice.service_context.ServiceContext`
            initialization
        :param httplib: A HTTP client to use
        :param services: A list of service definitions
        :param jwks_uri: A jwks_uri
        :param httpc_params: HTTP request arguments
        :return: Client instance
        """

        ImpExp.__init__(self)

        if config is None:
            config = {}

        if httpc_params is None:
            httpc_params = {"verify": True}

        self.http = httplib or HTTPLib(httpc_params)

        self.service_context = ServiceContext(base_url=base_url,
                                              keyjar=keyjar,
                                              config=config,
                                              jwks_uri=jwks_uri,
                                              httpc_params=httpc_params)

        self.client_id = self.issuer = ""
        for attr in ["issuer", "client_id"]:
            val = self.service_context.get(attr)
            if val:
                setattr(self, attr, val)

        _cam = client_authn_factory or ca_factory

        _srvs = services or DEFAULT_SERVICES

        self.service = init_services(_srvs, self.service_context, _cam)

        if 'add_ons' in config:
            do_add_ons(config['add_ons'], self.service)

        # just ignore verify_ssl until it goes away
        self.verify_ssl = httpc_params.get("verify", True)

        if hash_seed:
            self.hash_seed = as_bytes(hash_seed)
        else:
            self.hash_seed = as_bytes(rndstr(32))

    def do_request(self, request_type, response_body_type="", request_args=None,
                   **kwargs):

        _srv = self.service[request_type]

        _request_info = _srv.get_request_parameters(request_args=request_args, **kwargs)

        if not response_body_type:
            response_body_type = _srv.response_body_type

        logger.debug('do_request info: {}'.format(_request_info))

        try:
            _state = kwargs['state']
        except:
            _state = ''
        return self.service_request(_srv, response_body_type=response_body_type,
                                    state=_state, **_request_info)

    def set_client_id(self, client_id):
        self.client_id = client_id
        self.service_context.client_id = client_id

    def get_response(self, service, url, method="GET", body=None, response_body_type="",
                     headers=None, **kwargs):
        """

        :param url:
        :param method:
        :param body:
        :param response_body_type:
        :param headers:
        :param kwargs:
        :return:
        """
        try:
            resp = self.http(url, method, data=body, headers=headers)
        except Exception as err:
            logger.error('Exception on request: {}'.format(err))
            raise

        if 300 <= resp.status_code < 400:
            return {'http_response': resp}

        if resp.status_code < 300:
            if "keyjar" not in kwargs:
                kwargs["keyjar"] = service.service_context.keyjar
            if not response_body_type:
                response_body_type = service.response_body_type

            if response_body_type == 'html':
                return resp.text

            if body:
                kwargs['request_body'] = body

        return self.parse_request_response(service, resp,
                                           response_body_type, **kwargs)

    def service_request(self, service: Service,
                        url: Optional[str] = "",
                        method: Optional[str] = "GET",
                        body=None,
                        response_body_type: Optional[str] = "",
                        headers: Optional[dict] = None, **kwargs):
        """
        The method that sends the request and handles the response returned.
        This assumes that the response arrives in the HTTP response.

        :param service: Service instance
        :param url: The URL to which the request should be sent
        :param method: Which HTTP method to use
        :param body: A message body if any
        :param response_body_type: The expected format of the body of the
            return message
        :param headers: HTTP headers
        :return: A cls or ResponseMessage instance or the HTTP response
            instance if no response body was expected.
        """

        if headers is None:
            headers = {}

        if not url:
            url = service.service_context.provider_info[service.endpoint_name]

        logger.debug(REQUEST_INFO.format(url, method, body, headers))

        try:
            response = service.get_response_ext(url, method, body, response_body_type, headers,
                                                **kwargs)
        except AttributeError:
            response = self.get_response(service, url, method, body, response_body_type, headers,
                                         **kwargs)

        if 'error' in response:
            pass
        else:
            try:
                kwargs['key'] = kwargs['state']
            except KeyError:
                pass

            service.update_service_context(response, **kwargs)
        return response

    def parse_request_response(self, service, reqresp, response_body_type='',
                               state="", **kwargs):
        """
        Deal with a self.http response. The response are expected to
        follow a special pattern, having the attributes:

            - headers (list of tuples with headers attributes and their values)
            - status_code (integer)
            - text (The text version of the response)
            - url (The calling URL)

        :param service: A :py:class:`oidcservice.service.Service` instance
        :param reqresp: The HTTP request response
        :param response_body_type: If response in body one of 'json', 'jwt' or
            'urlencoded'
        :param state: Session identifier
        :param kwargs: Extra keyword arguments
        :return:
        """

        # if not response_body_type:
        #     response_body_type = self.response_body_type

        if reqresp.status_code in SUCCESSFUL:
            logger.debug('response_body_type: "{}"'.format(response_body_type))
            _deser_method = get_deserialization_method(reqresp)

            if _deser_method != response_body_type:
                logger.warning(
                    'Not the body type I expected: {} != {}'.format(
                        _deser_method, response_body_type))
            if _deser_method in ['json', 'jwt', 'urlencoded']:
                value_type = _deser_method
            else:
                value_type = response_body_type

            logger.debug('Successful response: {}'.format(reqresp.text))

            try:
                return service.parse_response(reqresp.text, value_type,
                                              state, **kwargs)
            except Exception as err:
                logger.error(err)
                raise
        elif reqresp.status_code in [302, 303]:  # redirect
            return reqresp
        elif reqresp.status_code == 500:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise ParseError("ERROR: Something went wrong: %s" % reqresp.text)
        elif 400 <= reqresp.status_code < 500:
            logger.error('Error response ({}): {}'.format(reqresp.status_code,
                                                          reqresp.text))
            # expecting an error response
            _deser_method = get_deserialization_method(reqresp)
            if not _deser_method:
                _deser_method = 'json'

            try:
                err_resp = service.parse_response(reqresp.text, _deser_method)
            except FormatError:
                if _deser_method != response_body_type:
                    try:
                        err_resp = service.parse_response(reqresp.text,
                                                          response_body_type)
                    except (OidcServiceError, FormatError):
                        raise OidcServiceError("HTTP ERROR: %s [%s] on %s" % (
                            reqresp.text, reqresp.status_code, reqresp.url))
                else:
                    raise OidcServiceError("HTTP ERROR: %s [%s] on %s" % (
                        reqresp.text, reqresp.status_code, reqresp.url))
            except JSONDecodeError:  # So it's not JSON assume text then
                err_resp = {'error': reqresp.text}

            err_resp['status_code'] = reqresp.status_code
            return err_resp
        else:
            logger.error('Error response ({}): {}'.format(reqresp.status_code,
                                                          reqresp.text))
            raise OidcServiceError("HTTP ERROR: %s [%s] on %s" % (
                reqresp.text, reqresp.status_code, reqresp.url))

    def create_callbacks(self, issuer):
        """
        To mitigate some security issues the redirect_uris should be OP/AS
        specific. This method creates a set of redirect_uris unique to the
        OP/AS.

        :param issuer: Issuer ID
        :return: A set of redirect_uris
        """
        _hash = hashlib.sha256()
        _hash.update(self.hash_seed)
        _hash.update(as_bytes(issuer))
        _hex = _hash.hexdigest()
        return {
            'code': "{}/authz_cb/{}".format(self.service_context.base_url, _hex),
            'implicit': "{}/authz_im_cb/{}".format(self.service_context.base_url, _hex),
            'form_post': "{}/authz_fp_cb/{}".format(self.service_context.base_url, _hex),
            '__hex': _hex
        }

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
            'redirect_uri': self.service_context.get('redirect_uris')[0],
            'scope': self.service_context.get('behaviour')['scope'],
            'response_type': self.service_context.get('behaviour')['response_type']
        }

        _req_args = self.service_context.config.get("request_args")
        if _req_args:
            request_args.update(_req_args)

        # Need a new state for a new authorization request
        _state = self.service_context.state.create_state(self.service_context.get('issuer'))
        request_args['state'] = _state

        logger.debug('Authorization request args: {}'.format(request_args))

        _srv = self.service['authorization']
        _info = _srv.get_request_parameters(request_args=request_args)
        self.service_context.state.store_item(_info["request"], "auth_request", _state)
        logger.debug('Authorization info: {}'.format(_info))
        return _info

    def finalize_auth(self, response, issuer):
        """
        Given the response returned to the redirect_uri, parse and verify it.

        :param issuer: An Issuer ID
        :param response: The authorization response as a dictionary
        :return: An :py:class:`oidcmsg.oidc.AuthorizationResponse` or
            :py:class:`oidcmsg.oauth2.AuthorizationResponse` instance.
        """
        _srv = self.service['authorization']
        try:
            authorization_response = _srv.parse_response(response, sformat='dict')
        except Exception as err:
            logger.error('Parsing authorization_response: {}'.format(err))
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            logger.debug('Authz response: {}'.format(authorization_response.to_dict()))

        if is_error_message(authorization_response):
            return authorization_response

        try:
            _iss = self.service_context.state.get_iss(authorization_response['state'])
        except KeyError:
            raise KeyError('Unknown state value')

        if _iss != issuer:
            logger.error('Issuer problem: {} != {}'.format(_iss, issuer))
            # got it from the wrong bloke
            raise ValueError('Impersonator {}'.format(issuer))

        _srv.update_service_context(authorization_response, key=authorization_response['state'])
        self.service_context.state.store_item(authorization_response, "auth_response",
                                              authorization_response['state'])
        return authorization_response

    def get_client_authn_method(self, endpoint):
        """
        Return the client authentication method a client wants to use a
        specific endpoint

        :param endpoint: The endpoint at which the client has to authenticate
        :return: The client authentication method
        """
        if endpoint == 'token_endpoint':
            try:
                am = self.service_context.get('behaviour')['token_endpoint_auth_method']
            except KeyError:
                return ''
            else:
                if isinstance(am, str):
                    return am
                else:  # a list
                    return am[0]

    def get_access_token(self, state):
        """
        Use the 'accesstoken' service to get an access token from the OP/AS.

        :param state: The state key (the state parameter in the
            authorization request)
        :return: A :py:class:`oidcmsg.oidc.AccessTokenResponse` or
            :py:class:`oidcmsg.oauth2.AuthorizationResponse`
        """
        logger.debug('get_accesstoken')

        authorization_response = self.service_context.state.get_item(
            self.authorization_response, 'auth_response', state)
        authorization_request = self.service_context.state.get_item(
            self.authorization_request, 'auth_request', state)

        req_args = {
            'code': authorization_response['code'],
            'state': state,
            'redirect_uri': authorization_request['redirect_uri'],
            'grant_type': 'authorization_code',
            'client_id': self.service_context.get('client_id'),
            'client_secret': self.service_context.get('client_secret')
        }
        logger.debug('request_args: {}'.format(req_args))
        try:
            tokenresp = self.do_request(
                'accesstoken', request_args=req_args,
                authn_method=self.get_client_authn_method("token_endpoint"),
                state=state
            )
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            if is_error_message(tokenresp):
                raise OidcServiceError(tokenresp['error'])

        return tokenresp

    def refresh_access_token(self, state, scope=''):
        """
        Refresh an access token using a refresh_token. When asking for a new
        access token the RP can ask for another scope for the new token.

        :param state: The state key (the state parameter in the
            authorization request)
        :param scope: What the returned token should be valid for.
        :return: A :py:class:`oidcmsg.oidc.AccessTokenResponse` instance
        """
        if scope:
            req_args = {'scope': scope}
        else:
            req_args = {}

        try:
            tokenresp = self.do_request(
                'refresh_token',
                authn_method=self.get_client_authn_method("token_endpoint"),
                state=state, request_args=req_args
            )
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            if is_error_message(tokenresp):
                raise OidcServiceError(tokenresp['error'])

        return tokenresp

    def load(self, item):
        for attr, cls in self.parameter.items():
            if attr not in item:
                continue
            if attr == "service":
                continue

            setattr(self, attr, self.load_attr(cls, item[attr]))

        self.service = DLDict()
        self.service.load(item["service"], service_context=self.service_context)
        return self

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
        Prepare for and do client registration if configured to do so.
        Not implemented for OAuth2 clients yet.
        """
        pass

    def add_callbacks(self, service_context):
        _callbacks = self.create_callbacks(service_context.provider_info['issuer'])
        service_context.redirect_uris = [v for k, v in _callbacks.items() if not k.startswith('__')]
        service_context.callbacks = _callbacks
        return _callbacks

    def get_valid_access_token(self, state):
        """
        Find a valid access token.

        :param state:
        :return: An access token if a valid one exists and when it
            expires. Otherwise raise exception.
        """

        exp = 0
        token = None
        indefinite = []
        now = time_sans_frac()

        for cls, typ in [(AccessTokenResponse, 'refresh_token_response'),
                         (AccessTokenResponse, 'token_response'),
                         (AuthorizationResponse, 'auth_response')]:
            try:
                response = self.service_context.state.get_item(cls, typ, state)
            except KeyError:
                pass
            else:
                if 'access_token' in response:
                    access_token = response["access_token"]
                    try:
                        _exp = response['__expires_at']
                    except KeyError:  # No expiry date, lives for ever
                        indefinite.append((access_token, 0))
                    else:
                        if _exp > now and _exp > exp:  # expires sometime in the future
                            exp = _exp
                            token = (access_token, _exp)

        if indefinite:
            return indefinite[0]
        else:
            if token:
                return token
            else:
                raise OidcServiceError('No valid access token')

    def finalize(self, issuer, response):
        """
        The third of the high level methods that a user of this Class should
        know about.
        Once the consumer has redirected the user back to the
        callback URL there might be a number of services that the client should
        use. Which one those are are defined by the client configuration.

        :param issuer: Who sent the response
        :param response: The Authorization response as a dictionary
        :returns: A dictionary with a couple of claims:
            **state** The key under which the session information is
            stored in the data store and
            **error** and encountered error or
        """

        authorization_response = self.finalize_auth(response=response, issuer=issuer)

        if is_error_message(authorization_response):
            return {
                'state': authorization_response['state'],
                'error': authorization_response['error']
            }

        _state = authorization_response['state']
        token_response = self.get_access_token(state=_state)

        return {
            "state": _state,
            "token": token_response["access_token"]
        }
