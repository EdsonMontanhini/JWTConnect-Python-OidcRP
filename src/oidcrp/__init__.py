import logging

from oidcservice.exception import OidcServiceError

__author__ = 'Roland Hedberg'
__version__ = '1.1.0'

logger = logging.getLogger(__name__)


class HandlerError(Exception):
    pass


class ConfigurationError(Exception):
    pass


class HttpError(OidcServiceError):
    pass


class OperationsError(Exception):
    pass