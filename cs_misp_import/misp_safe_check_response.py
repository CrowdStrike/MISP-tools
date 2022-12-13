from json import JSONDecodeError
#from pathlib import Path
from typing import (
    Dict,
    List,
    Union,
    # Optional,
    # MutableMapping,
    # Tuple
    )
#from requests.auth import AuthBase
from pymisp import (
    PyMISPUnexpectedResponse,
    MISPServerError,
#    NoURL,
    # NoKey,
    # MISPRole,
    # MISPUser,
    # MISPUserSetting,
    # PyMISPError,
    __version__
    
    )
from pymisp.api import brotli_supported
import requests
import logging



logger = logging.getLogger("pymisp")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
#rfh = logging.handlers.RotatingFileHandler("misp_import.log", maxBytes=20971520, backupCount=5)
#rfh.setLevel(logging.INFO)
# if args.debug:
#     logger.setLevel(logging.DEBUG)
#     ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(name)s/%(threadName)-13s %(message)s"))
#ch2.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(name)s/%(threadName)-10s %(message)s"))
logger.addHandler(ch)
logger.propagate = False



def safe_check_response(self, response: requests.Response, lenient_response_type: bool = False, expect_json: bool = False) -> Union[Dict, str]:
    """Check if the response from the server is not an unexpected error"""
    if len(response.text) == 0:
        return {}
    if response.status_code >= 500:
        # headers_without_auth = {i: response.request.headers[i] for i in response.request.headers if i != 'Authorization'}
        # logger.critical(everything_broken.format(headers_without_auth, response.request.body, response.text))
        try:
            fail_msg = f"Error code 500: {response.json()['message']}"
            raise MISPServerError(fail_msg)
        except (JSONDecodeError, KeyError) as err:
            raise MISPServerError(f"Error code 500: {response.text}")

    if 400 <= response.status_code < 500:
        # The server returns a json message with the error details
        try:
            error_message = response.json()
        except Exception:
            raise MISPServerError(f'Error code {response.status_code}:\n{response.text}')

        #logger.error(f'Something went wrong ({response.status_code}): {error_message}')
        return {'errors': (response.status_code, error_message)}

    # At this point, we had no error.

    try:
        response_json = response.json()
        #logger.debug(response_json)
        #logger.info(response_json)
        if isinstance(response_json, dict) and response_json.get('response') is not None:
            # Cleanup.
            response_json = response_json['response']
        return response_json
    except Exception:
        #logger.debug(response.text)
        if expect_json:
            error_msg = f'Unexpected response (size: {len(response.text)}) from server: {response.text}'
            raise PyMISPUnexpectedResponse(error_msg)
        if lenient_response_type and not response.headers['Content-Type'].startswith('application/json'):
            return response.text
        if not response.content:
            # Empty response
            #logger.error('Got an empty response.')
            return {'errors': 'The response is empty.'}
        return response.text

# def safe_pymisp_init(self, url: str, key: str, ssl: bool = True, debug: bool = False, proxies: Optional[MutableMapping[str, str]] = None,
#                      cert: Optional[Union[str, Tuple[str, str]]] = None, auth: AuthBase = None, tool: str = '',
#                      timeout: Optional[Union[float, Tuple[float, float]]] = None,
#                      http_headers: Optional[Dict[str, str]]=None
#                      ):

#         if not url:
#             raise NoURL('Please provide the URL of your MISP instance.')
#         if not key:
#             raise NoKey('Please provide your authorization key.')

#         self.root_url: str = url
#         self.key: str = key
#         self.ssl: bool = ssl
#         self.proxies: Optional[MutableMapping[str, str]] = proxies
#         self.cert: Optional[Union[str, Tuple[str, str]]] = cert
#         self.auth: Optional[AuthBase] = auth
#         self.tool: str = tool
#         self.timeout: Optional[Union[float, Tuple[float, float]]] = timeout
#         self.__session = requests.Session()  # use one session to keep connection between requests
#         if brotli_supported():
#             self.__session.headers['Accept-Encoding'] = ', '.join(('br', 'gzip', 'deflate'))
#         if http_headers:
#             self.__session.headers.update(http_headers)

#         self.global_pythonify = False

#         self.resources_path = Path(__file__).parent / 'data'
#         if debug:
#             logger.setLevel(logging.DEBUG)
#             logger.info('To configure logging in your script, leave it to None and use the following: import logging; logging.getLogger(\'pymisp\').setLevel(logging.DEBUG)')

#         try:
#             # Make sure the MISP instance is working and the URL is valid
#             response = self.recommended_pymisp_version
#             if 'errors' in response:
#                 logger.warning(response['errors'][0])
#             else:
#                 pymisp_version_tup = tuple(int(x) for x in __version__.split('.'))
#                 recommended_version_tup = tuple(int(x) for x in response['version'].split('.'))
#                 if recommended_version_tup < pymisp_version_tup[:3]:
#                     logger.info(f"The version of PyMISP recommended by the MISP instance ({response['version']}) is older than the one you're using now ({__version__}).")
#                     logger.info("If you have a problem, please upgrade the MISP instance or use an older PyMISP version.")
#                 elif pymisp_version_tup[:3] < recommended_version_tup:
#                     logger.warning(f"The version of PyMISP recommended by the MISP instance ({response['version']}) is newer than the one you're using now ({__version__}).")
#                     logger.info("Please upgrade PyMISP.")

#             misp_version = self.misp_instance_version
#             if 'version' in misp_version:
#                 self._misp_version = tuple(int(v) for v in misp_version['version'].split('.'))

#             # Get the user information
#             self._current_user: MISPUser
#             self._current_role: MISPRole
#             self._current_user_settings: List[MISPUserSetting]
#             self._current_user, self._current_role, self._current_user_settings = self.get_user(pythonify=True, expanded=True)
#         except Exception as e:
#             raise PyMISPError(f'Unable to connect to MISP ({self.root_url}). Please make sure the API key and the URL are correct (http/https is required): {e}')

#         try:
#             self.describe_types = self.describe_types_remote
#         except Exception:
#             self.describe_types = self.describe_types_local

#         self.categories = self.describe_types['categories']
#         self.types = self.describe_types['types']
#         self.category_type_mapping = self.describe_types['category_type_mappings']
#         self.sane_default = self.describe_types['sane_defaults']
