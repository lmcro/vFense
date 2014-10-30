import logging
import logging.config
from vFense._constants import VFENSE_LOGGING_CONFIG

from vFense.core.status_codes import GenericCodes
from vFense.core.results import Results, ApiResultKeys

from vFense.core.user._db_model import UserKeys, UserCollections
from vFense.core.user._constants import DefaultUsers
from vFense.core.user._db import fetch_user

from vFense.core.permissions._constants import Permissions
from vFense.core.permissions._db import validate_permission_for_user
from vFense.core.group._db_model import GroupKeys

from vFense.core._db import retrieve_object
from vFense.core.decorators import time_it
from vFense.utils.security import Crypto

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


def return_results_for_permissions(
    username, granted, status_code,
    permission, uri, method
    ):
    """Return the vFense supported results for permissions
    Args:
        username (str): The name of the user
        granted (boolean): True or False
        status_code (int): The status_code of the validation
        permission (str): The permission used
        uri (str): The api call
        method (str): The http method used to make this call
    Basic Usage:

    Return:
        Dictionary of the failed response.
        {
            'rv_status_code': 1019,
            'message': 'Permission denied for user admin',
            'http_method': 'POST',
            'uri': '/foo',
            'http_status': 403
        }

    """
    results = None
    if not granted and status_code == GenericCodes.PermissionDenied:
        results = (
            Results(
                username, uri, method
            ).permission_denied()
        )

    elif not granted and status_code == GenericCodes.InvalidPermission:
        data = {
            ApiResultKeys.DATA: (
                {
                    GroupKeys.Permissions: [permission]
                }
            )
        }
        results = (
            Results(
                username, uri, method
            ).invalid_permission(**data)
        )

    elif not granted and status_code == GenericCodes.InvalidId:
        results = (
            Results(
                username, uri, method
            ).invalid_id()
        )

    return(results)


def verify_permission_for_user(
    username, permission,
    view_name=None, all_views=False):
    """Verify if a user has permission to this resource.
    Args:
        username (str): The name of the user.
        permission (str): The permission to be verified.

    Kwargs:
        view_name (str): Name of the view that is being verified.

    Basic Usage:
        >>> from vFense.core.permissions.permissions import verify_permission_for_user
        >>> username = 'admin'
        >>> permission = 'install'
        >>> verify_permission_for_user(username, permission)

    Returns:
        Returns a Tuple (Boolean, status_code)

    """
    granted = False
    status_code = GenericCodes.PermissionDenied
    if username == DefaultUsers.GLOBAL_ADMIN:
        granted = True
        status_code = GenericCodes.PermissionGranted
        return(granted, status_code)

    try:
        user_exist = fetch_user(username)
        if permission in Permissions().get_valid_permissions() and user_exist:
            if not view_name:
                view_name = user_exist.get(UserKeys.CurrentView)

            granted = (
                validate_permission_for_user(
                    username, view_name, permission
                )
            )

            if granted:
                status_code = GenericCodes.PermissionGranted

        elif not permission in Permissions.get_valid_permissions():
            status_code = GenericCodes.InvalidPermission

        elif not user_exist:
            status_code = GenericCodes.InvalidId

    except Exception as e:
        logger.exception(e)

    return(granted, status_code)


@time_it
def authenticate_user(username, password):
    authenticated = False
    try:
        user_exist = retrieve_object(username, UserCollections.Users)
        if user_exist:
            if user_exist[UserKeys.Enabled]:
                original_encrypted_password = (
                    user_exist[UserKeys.Password].encode('utf-8')
                )
                password_verified = (
                    Crypto().verify_bcrypt_hash(
                        password, original_encrypted_password
                    )
                )
                if password_verified:
                    authenticated = True

    except Exception as e:
        logger.exception(e)

    return(authenticated)
