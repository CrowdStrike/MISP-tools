import logging
from functools import reduce
try:
    from falconpy import Intel, __version__ as FALCONPY_VERSION
except ImportError as no_falconpy:
    raise SystemExit(
        "The CrowdStrike FalconPy package must be installed to use this program."
        ) from no_falconpy

current = FALCONPY_VERSION.split(".")
requested = "0.9.0".split(".")
if bool(float(f"{current[0]}.{current[1]}") < float(f"{requested[0]}.{requested[1]}")):
    raise SystemExit("This application requires FalconPy v0.9.0 or greater.")


class IntelAPIClient:
    """This class provides the interface for the CrowdStrike Intel API."""

    def __init__(self, client_id, client_secret, crowdstrike_url, api_request_max, use_ssl: bool = True, logger: logging.Logger = None):
        """Construct an instance of the IntelAPIClient class.

        :param client_id: CrowdStrike API Client ID
        :param client_secret: CrowdStrike API Client Secret
        :param crowdstrike_url: CrowdStrike Base URL / Base URL shortname
        :param api_request_max [int]: Maximum number of records to return per API request
        :param use_ssl [bool]: Enable SSL validation to the CrowdStrike Cloud (default: True)
        """
        self.falcon = Intel(client_id=client_id, client_secret=client_secret, base_url=crowdstrike_url, ssl_verify=use_ssl)
        self.valid_report_types = ["csa", "csir", "csit", "csgt", "csdr", "csia", "csmr", "csta", "cswr"]
        self.request_size_limit = api_request_max
        self.log = logger

    def get_reports(self, start_time):
        """Get all the reports that were updated after a certain moment in time (UNIX).

        :param start_time: unix time of the oldest report you want to pull
        """
        reports = []
        offset = 0
        total = 0
        first_run = True

        while offset < total or first_run:
            resp_json = self.falcon.query_report_entities(
                sort="last_modified_date.asc",
                filter=f'last_modified_date:>{start_time}',
                limit=self.request_size_limit,
                offset=offset
                )["body"]
            self.__check_metadata(resp_json)

            total = resp_json.get('meta', {}).get('pagination', {}).get('total')
            offset += resp_json.get('meta', {}).get('pagination', {}).get('limit')
            first_run = False

            reports.extend(resp_json.get('resources', []))

        return reports

    def get_indicators(self, start_time, include_deleted):
        """Get all the indicators that were updated after a certain moment in time (UNIX).

        :param start_time: unix time of the oldest indicator you want to pull
        :param include_deleted [bool]: include indicators marked as deleted
        """
        indicators_in_request = []
        first_run = True

        while len(indicators_in_request) == self.request_size_limit or first_run:
            resp_json = self.falcon.query_indicator_entities(
                sort="_marker.asc",
                filter=f"_marker:>='{start_time}'",
                limit=self.request_size_limit,
                include_deleted=include_deleted
                )["body"]

            first_run = False

            indicators_in_request = resp_json.get('resources', [])
            if indicators_in_request:
                total_found = reduce(lambda d, key: d.get(key, None) if isinstance(d, dict) else None,
                                     "meta.pagination.total".split("."),
                                     resp_json
                                     )
                log_msg = f"Retrieved {len(indicators_in_request)} of {total_found} remaining indicators."
                self.log.info(log_msg)
            else:
                break

            yield indicators_in_request

            last_marker = indicators_in_request[-1].get('_marker', '')
            if last_marker == '':
                break
            start_time = last_marker

    def get_actors(self, start_time):
        """Get all the actors that were updated after a certain moment in time (UNIX).

        :param start_time: unix time of the oldest actor you want to pull
        """
        actors = []
        offset = 0
        total = 0
        first_run = True

        while offset < total or first_run:
            resp_json = self.falcon.query_actor_entities(
                sort="last_modified_date.asc",
                filter=f'last_modified_date:>{start_time}',
                limit=self.request_size_limit,
                offset=offset
                )["body"]

            total = resp_json.get('meta', {}).get('pagination', {}).get('total')
            offset += resp_json.get('meta', {}).get('pagination', {}).get('limit')
            first_run = False

            actors.extend(resp_json.get('resources', []))

        return actors

    @staticmethod
    def __check_metadata(resp_json):
        if (resp_json.get('meta', {}).get('pagination', {}).get('total') is None) \
                or (resp_json.get('meta', {}).get('pagination', {}).get('limit') is None):
            raise Exception(f'Unable to decode pagination metadata from response. Response is {resp_json}.')