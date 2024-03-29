import logging
from functools import reduce
import datetime
from .helper import thousands
from .report_type import ReportType
from .adversary import Adversary
try:
    from falconpy import Intel, __version__ as FALCONPY_VERSION
except ImportError as no_falconpy:
    raise SystemExit(
        "The CrowdStrike FalconPy package must be installed to use this program."
        ) from no_falconpy
from ._version import __version__ as MISPImportVersion

current = FALCONPY_VERSION.split(".")
requested = "0.9.0".split(".")
if bool(float(f"{current[0]}.{current[1]}") < float(f"{requested[0]}.{requested[1]}")):
    raise SystemExit("This application requires FalconPy v0.9.0 or greater.")


class IntelAPIClient:
    """This class provides the interface for the CrowdStrike Intel API."""

    def __init__(self,
                 client_id,
                 client_secret,
                 crowdstrike_url,
                 api_request_max,
                 ext_headers,
                 proxies,
                 use_ssl: bool = True,
                 logger: logging.Logger = None
                 ):
        """Construct an instance of the IntelAPIClient class.

        :param client_id: CrowdStrike API Client ID
        :param client_secret: CrowdStrike API Client Secret
        :param crowdstrike_url: CrowdStrike Base URL / Base URL shortname
        :param api_request_max [int]: Maximum number of records to return per API request
        :param use_ssl [bool]: Enable SSL validation to the CrowdStrike Cloud (default: True)
        """
        
        ua = f"crowdstrike-misp-import/{MISPImportVersion}"
        self.falcon = Intel(client_id=client_id,
                            client_secret=client_secret,
                            base_url=crowdstrike_url,
                            ssl_verify=use_ssl,
                            user_agent=ua,
                            ext_headers=ext_headers,
                            proxy=proxies
                            )
        self.valid_report_types = [x.name.lower() for x in ReportType]
        self.request_size_limit = api_request_max
        self.log = logger

    def get_reports(self, start_time, report_filter: str = None):
        """Get all the reports that were updated after a certain moment in time (UNIX).

        :param start_time: unix time of the oldest report you want to pull
        """
        reports = []
        offset = 0
        total = 0
        first_run = True
        format_string = "%Y-%m-%dT%H:%M:%SZ"
        filter_string = f"created_date:>'{datetime.datetime.utcfromtimestamp(start_time).strftime(format_string)}'"
        if report_filter:
            rcnt = 0
            for rpt_type in report_filter.split(","):
                if rpt_type.lower() in self.valid_report_types:
                    self.log.info("Retrieving CrowdStrike %s reports.", rpt_type.upper())
                    filter_string = f"{filter_string}{'+(' if not rcnt else ','}name:*'{rpt_type.upper()}-*'"
                rcnt += 1
            filter_string = f"{filter_string})"
        else:
            self.log.info("Retrieving all available report types.")

        while offset < total or first_run:
            resp_json = self.falcon.query_report_entities(
                sort="last_modified_date.asc",
                filter=filter_string,
                fields="__full__",
                limit=self.request_size_limit,
                offset=offset
                )
            if "body" in resp_json:
                resp_json = resp_json["body"]
            #self.__check_metadata(resp_json)

            total = resp_json.get('meta', {}).get('pagination', {}).get('total', 0)
            offset += resp_json.get('meta', {}).get('pagination', {}).get('limit', 5000)
            first_run = False

            resources = resp_json.get('resources', [])
            if resources:
                reports.extend(resp_json.get('resources', []))

        return reports

    def get_indicators(self, start_time, include_deleted, type_list: str = None) -> list:
        """Get all the indicators that were updated after a certain moment in time (UNIX).

        :param start_time: unix time of the oldest indicator you want to pull
        :param include_deleted [bool]: include indicators marked as deleted
        """
        indicators_in_request = []
        first_run = True
        while len(indicators_in_request) == self.request_size_limit or first_run:
            # Recalculate our filter based off of our new marker
            filter_string = f"_marker:>='{start_time}'+deleted:false"
            if type_list:
                filter_string = f"{filter_string}+("
                for typ in type_list.split(","):
                    filter_string = f"{filter_string}type:'{typ.lower()}',"
                filter_string = f"{filter_string[:-1]})"

            resp_json = self.falcon.query_indicator_entities(
                sort="_marker.asc",
                filter=filter_string,
                limit=self.request_size_limit,
                include_deleted=include_deleted
                )
            if "body" in resp_json:
                resp_json = resp_json["body"]

            first_run = False

            indicators_in_request = resp_json.get('resources', [])
            if indicators_in_request:
                total_found = reduce(lambda d, key: d.get(key, None) if isinstance(d, dict) else None,
                                     "meta.pagination.total".split("."),
                                     resp_json
                                     )
                self.log.info("Retrieved %s of %s remaining indicators.",
                              thousands(len(indicators_in_request)),
                              thousands(total_found)
                              )
            else:
                break

            yield indicators_in_request

            last_marker = indicators_in_request[-1].get('_marker', '')
            if last_marker == '':
                break
            start_time = last_marker

    def get_actors(self, start_time, actor_filter: str = None):
        """Get all the actors that were updated after a certain moment in time (UNIX).

        :param start_time: unix time of the oldest actor you want to pull
        """
        actors = []
        offset = 0
        total = 0
        first_run = True
        filter_string = None
        if actor_filter:
            filter_string = ""
            for act_type in actor_filter.split(","):
                if act_type.upper() in [x.name for x in Adversary]:
                    self.log.info("Retrieving %s branch adversaries.", act_type.title())
                    filter_string = f"{filter_string if filter_string else '('}{',' if filter_string else ''}name:*'*{act_type.upper()}'"
        else:
            self.log.info("Retrieving all adversaries.")
        format_string = "%Y-%m-%dT%H:%M:%SZ"
        # This is pretty ugly
        filter_string = f"{filter_string if filter_string else ''}{')' if filter_string else ''}"
        filter_string = f"{filter_string}{'+' if filter_string else ''}(first_activity_date:>='{datetime.datetime.utcfromtimestamp(start_time).strftime(format_string)}'"
        filter_string = f"{filter_string},created_date:>='{datetime.datetime.utcfromtimestamp(start_time).strftime(format_string)}')"

        while offset < total or first_run:
            resp_json = self.falcon.query_actor_entities(
                sort="last_modified_date.asc",
                filter=filter_string,
                limit=self.request_size_limit,
                offset=offset
                )
            if "body" in resp_json:
                resp_json = resp_json["body"]

            total = resp_json.get('meta', {}).get('pagination', {}).get('total', 0)
            offset += resp_json.get('meta', {}).get('pagination', {}).get('limit', 5000)
            first_run = False

            actors.extend(resp_json.get('resources', []))

        return actors

    def get_actor_name_list(self):
        """Get all the actors names and IDs in an easy to search list."""
        actors = []
        resp_json = self.falcon.query_actor_entities(sort="last_modified_date.asc")["body"]

        for actor in resp_json.get("resources", []):
            actors.append({"name": actor["name"], "id": actor["id"]})

        return actors


    @staticmethod
    def __check_metadata(resp_json):
        if (resp_json.get('meta', {}).get('pagination', {}).get('total') is None) \
                or (resp_json.get('meta', {}).get('pagination', {}).get('limit') is None):
            raise Exception(f'Unable to decode pagination metadata from response. Response is {resp_json}.')
