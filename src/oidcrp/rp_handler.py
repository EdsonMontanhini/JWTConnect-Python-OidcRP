import logging
import sys
import traceback

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode
from oidcmsg.exception import MessageException
from oidcmsg.exception import NotForMe
from oidcmsg.impexp import ImpExp
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oauth2 import is_error_message
from oidcmsg.oidc import AccessTokenResponse
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import Claims
from oidcmsg.oidc import OpenIDSchema
from oidcmsg.oidc import verified_claim_name
from oidcmsg.oidc.session import BackChannelLogoutRequest
from oidcmsg.time_util import time_sans_frac
from oidcservice import rndstr
from oidcservice.exception import OidcServiceError

from oidcrp import oidc
from oidcrp.oauth2 import Client
from oidcrp.util import add_path

logger = logging.getLogger(__name__)

SUCCESSFUL = [200, 201, 202, 203, 204, 205, 206]


def token_secret_key(sid):
    return "token_secret_%s" % sid


SERVICE_NAME = "OIC"
CLIENT_CONFIG = {}

DEFAULT_SEVICES = {
    'web_finger': {'class': 'oidcservice.oidc.webfinger.WebFinger'},
    'discovery': {'class': 'oidcservice.oidc.provider_info_discovery.ProviderInfoDiscovery'},
    'registration': {'class': 'oidcservice.oidc.registration.Registration'},
    'authorization': {'class': 'oidcservice.oidc.authorization.Authorization'},
    'access_token': {'class': 'oidcservice.oidc.access_token.AccessToken'},
    'refresh_access_token': {'class': 'oidcservice.oidc.refresh_access_token.RefreshAccessToken'},
    'userinfo': {'class': 'oidcservice.oidc.userinfo.UserInfo'}
}

DEFAULT_CLIENT_PREFS = {
    'application_type': 'web',
    'application_name': 'rphandler',
    'response_types': ['code', 'id_token', 'id_token token', 'code id_token', 'code id_token token',
                       'code token'],
    'scope': ['openid'],
    'token_endpoint_auth_method': 'client_secret_basic'
}

# Using PKCE is default
DEFAULT_CLIENT_CONFIGS = {
    "": {
        "client_preferences": DEFAULT_CLIENT_PREFS,
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
}

DEFAULT_KEY_DEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

DEFAULT_RP_KEY_DEFS = {
    'private_path': 'private/jwks.json',
    'key_defs': DEFAULT_KEY_DEFS,
    'public_path': 'static/jwks.json',
    'read_only': False
}


class RPHandler(ImpExp):
    parameter = {
        "base_url": "",
        "client_authn_factory": None,
        "client_configs": {},
        "clients": ["oidcrp.oidc.RP"],
        "hash_seed": "",
        "httpc_params": {},
        "jwks_uri": "",
        "jwks": {},
        "keyjar": KeyJar,
        "services": {}
    }

    def __init__(self, base_url, client_configs=None, service_configs=None, keyjar=None,
                 hash_seed="", verify_ssl=True, client_authn_factory=None,
                 client_cls=None, http_lib=None, httpc_params=None,
                 **kwargs):
        ImpExp.__init__(self)

        self.base_url = base_url
        if hash_seed:
            self.hash_seed = as_bytes(hash_seed)
        else:
            self.hash_seed = as_bytes(rndstr(32))

        _jwks_path = kwargs.get('jwks_path')
        if keyjar is None:
            self.keyjar = init_key_jar(**DEFAULT_RP_KEY_DEFS, issuer_id='')
            self.keyjar.import_jwks_as_json(self.keyjar.export_jwks_as_json(True, ''), base_url)
            if _jwks_path is None:
                _jwks_path = DEFAULT_RP_KEY_DEFS['public_path']
        else:
            self.keyjar = keyjar

        if _jwks_path:
            self.jwks_uri = add_path(base_url, _jwks_path)
        else:
            self.jwks_uri = ""
            if len(self.keyjar):
                self.jwks = self.keyjar.export_jwks()
            else:
                self.jwks = {}

        self.extra = kwargs

        self.client_cls = client_cls or oidc.RP
        if service_configs is None:
            self.service_configs = DEFAULT_SEVICES
        else:
            self.service_configs = service_configs

        self.client_authn_factory = client_authn_factory

        if client_configs is None:
            self.client_configs = DEFAULT_CLIENT_CONFIGS
        else:
            self.client_configs = client_configs

        # keep track on which RP instance that serves with OP
        self.clients = []
        self.httplib = http_lib

        if not httpc_params:
            self.httpc_params = {'verify': verify_ssl}
        else:
            self.httpc_params = httpc_params

        if not self.keyjar.httpc_params:
            self.keyjar.httpc_params = self.httpc_params

    def find_client_by_redirect_uri(self, redirect_uri: str) -> Client:
        for _rp in self.clients:
            if redirect_uri in _rp.service_context.redirect_uris:
                return _rp

    def find_client_by_issuer_url(self, url: str) -> Client:
        for _client in self.clients:
            if url == _client.service_context.issuer:
                return _client

    def state2issuer(self, state):
        """
        Given the state value find the Issuer ID of the OP/AS that state value
        was used against.
        Will raise a KeyError if the state is unknown.

        :param state: The state value
        :return: An Issuer ID
        """
        for _client in self.clients:
            try:
                _iss = _client.service_context.state.get_iss(state)
            except KeyError:
                continue
            else:
                if _iss:
                    return _iss
        return None

    def pick_config(self, issuer):
        """
        From the set of client configurations pick one based on the issuer ID.
        Will raise a KeyError if issuer is unknown.

        :param issuer: Issuer ID
        :return: A client configuration
        """
        return self.client_configs[issuer]

    def get_session_information(self, key, client=None):
        """
        This is the second of the methods users of this class should know about.
        It will return the complete session information as an
        :py:class:`oidcservice.state_interface.State` instance.

        :param key: The session key (state)
        :return: A State instance
        """
        if not client:
            client = self.get_client_from_session_key(key)

        return client.service_context.state.get_state(key)

    def init_client(self, issuer):
        """
        Initiate a Client instance. Specifically which Client class is used
        is decided by configuration.

        :param issuer: An issuer ID
        :return: A Client instance
        """
        try:
            _cnf = self.pick_config(issuer)
        except KeyError:
            _cnf = self.pick_config('')
            _cnf['issuer'] = issuer

        try:
            _services = _cnf['services']
        except KeyError:
            _services = self.service_configs

        try:
            client = self.client_cls(
                base_url=self.base_url,
                client_authn_factory=self.client_authn_factory,
                config=_cnf, httplib=self.httplib,
                httpc_params=self.httpc_params)
        except Exception as err:
            logger.error('Failed initiating client: {}'.format(err))
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise

        client.service_context.keyjar.load(self.keyjar.dump())
        # client.service_context.base_url = self.base_url
        client.service_context.jwks_uri = self.jwks_uri
        return client

    def client_setup(self, iss_id='', user=''):
        """
        First if no issuer ID is given then the identifier of the user is
        used by the webfinger service to try to find the issuer ID.
        Once the method has an issuer ID and if no client is bound to this issuer
        one is created and initiated with
        the necessary information for the client to be able to communicate
        with the OP/AS that has the provided issuer ID.

        :param iss_id: The issuer ID
        :param user: A user identifier
        :return: A :py:class:`oidcservice.oidc.Client` instance
        """

        logger.info('client_setup: iss_id={}, user={}'.format(iss_id, user))

        if not iss_id:
            if not user:
                raise ValueError('Need issuer or user')

            logger.debug("Connecting to previously unknown OP")
            temporary_client = self.init_client('')
            temporary_client.do_request('webfinger', resource=user)
        else:
            temporary_client = None

        client = self.find_client_by_issuer_id(iss_id)
        if client is None:
            if temporary_client:
                client = temporary_client
            else:
                logger.debug("Creating new client: %s", iss_id)
                client = self.init_client(iss_id)
        else:
            return client

        logger.debug("Get provider info")
        client.get_provider_info()

        logger.debug("Do client registration")
        client.do_client_registration()

        if iss_id:  # static identifier
            client.issuer_id = iss_id
        else:  # dynamic identifier
            client.issuer_id = client.service_context.callbacks["__hex"]

        self.clients.append(client)
        return client

    def find_client_by_issuer_id(self, issuer_id):
        for client in self.clients:
            if issuer_id == client.issuer_id:
                return client

    def begin(self, issuer_id='', user_id=''):
        """
        This is the first of the 3 high level methods that most users of this
        library should confine them self to use.
        If will use client_setup to produce a Client instance ready to be used
        against the OP/AS the user wants to use.
        Once it has the client it will construct an Authorization
        request.

        :param issuer_id: Issuer ID
        :param user_id: A user identifier
        :return: A dictionary containing **url** the URL that will redirect the
            user to the OP/AS and **state** the session key which will
            allow higher level code to access session information.
        """

        # Get the client instance that has been assigned to this issuer
        client = self.client_setup(issuer_id, user_id)

        try:
            res = client.init_authorization()
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            return res

    # ----------------------------------------------------------------------
    def get_client_from_session_key(self, session_key):
        for client in self.clients:
            try:
                client.service_context.state.get_iss(session_key)
            except:
                continue
            else:
                return client

    @staticmethod
    def get_response_type(client):
        """
        Return the response_type a specific client wants to use.

        :param client: A Client instance
        :return: The response_type
        """
        return client.service_context.behaviour['response_types'][0]

    def get_access_token(self, state, client=None):
        """
        Use the 'accesstoken' service to get an access token from the OP/AS.

        :param state: The state key (the state parameter in the
            authorization request)
        :param client: A Client instance
        :return: A :py:class:`oidcmsg.oidc.AccessTokenResponse` or
            :py:class:`oidcmsg.oauth2.AuthorizationResponse`
        """
        logger.debug('get_accesstoken')

        if client is None:
            client = self.get_client_from_session_key(state)

        return client.get_access_token(state)

    def refresh_access_token(self, state, client=None, scope=''):
        """
        Refresh an access token using a refresh_token. When asking for a new
        access token the RP can ask for another scope for the new token.

        :param client: A Client instance
        :param state: The state key (the state parameter in the
            authorization request)
        :param scope: What the returned token should be valid for.
        :return: A :py:class:`oidcmsg.oidc.AccessTokenResponse` instance
        """
        if client is None:
            client = self.get_client_from_session_key(state)

        return client.refresh_access_token(state=state, scope=scope)

    def get_user_info(self, state, client=None, access_token='', **kwargs):
        """
        use the access token previously acquired to get some userinfo

        :param client: A Client instance
        :param state: The state value, this is the key into the session
            data store
        :param access_token: An access token
        :param kwargs: Extra keyword arguments
        :return: A :py:class:`oidcmsg.oidc.OpenIDSchema` instance
        """
        if client is None:
            client = self.get_client_from_session_key(state)

        return client.get_user_info(state=state, access_token=access_token, **kwargs)

    @staticmethod

    def get_access_and_id_token(self, authorization_response=None, state='', client=None):
        if not client:
            client = self.get_client_from_session_key(state)

        return client.get_access_and_id_token(authorization_response=authorization_response,
                                              state=state)

    # noinspection PyUnusedLocal
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

        client = self.find_client_by_issuer_url(issuer)
        return client.finalize_auth(response=response, issuer=issuer)

    def has_active_authentication(self, state):
        """
        Find out if the user has an active authentication

        :param state:
        :return: True/False
        """

        client = self.get_client_from_session_key(state)

        # Look for Id Token in all the places where it can be
        _arg = client.service_context.state.multiple_extend_request_args(
            {}, state, ['__verified_id_token'],
            ['auth_response', 'token_response', 'refresh_token_response'])

        if _arg:
            _now = time_sans_frac()
            exp = _arg['__verified_id_token']['exp']
            return _now < exp
        else:
            return False

    def get_valid_access_token(self, state):
        """
        Find a valid access token.

        :param state:
        :return: An access token if a valid one exists and when it
            expires. Otherwise raise exception.
        """

        client = self.get_client_from_session_key(state)
        return client.get_valid_access_token(state)

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
        if client is None:
            client = self.get_client_from_session_key(state)

        return client.logout(state=state, post_logout_redirect_uri=post_logout_redirect_uri)

    def clear_session(self, state):
        client = self.get_client_from_session_key(state)
        client.clear_session(state)


