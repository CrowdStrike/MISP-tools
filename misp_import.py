"""CrowdStrike Falcon Intel API to MISP Import utility.

 ___ ___ ___ _______ _______
|   Y   |   |   _   |   _   |     _______                             __
|.      |.  |   1___|.  1   |    |_     _|.--------.-----.-----.----.|  |_.-----.----.
|. [_]  |.  |____   |.  ____|     _|   |_ |        |  _  |  _  |   _||   _|  -__|   _|
|:  |   |:  |:  1   |:  |        |_______||__|__|__|   __|_____|__|  |____|_____|__|
|::.|:. |::.|::.. . |::.|                          |__|
`--- ---`---`-------`---'                                   CrowdStrike FalconPy v0.8.0+

By accessing or using this script, sample code, application programming interface, tools, and/or associated
documentation (if any) (collectively, “Tools”), You (i) represent and warrant that You are entering into this Agreement
on behalf of a company, organization or another legal entity (“Entity”) that is currently a customer or partner of
CrowdStrike, Inc.(“CrowdStrike”), and (ii) have the authority to bind such Entity and such Entity agrees to be bound by
this Agreement. CrowdStrike grants Entity a non-exclusive, non-transferable, non-sublicensable, royalty free and limited
license to access and use the Tools solely for Entity’s internal business purposes and in accordance with its
obligations under any agreement(s) it may have with CrowdStrike. Entity acknowledges and agrees that CrowdStrike and its
licensors retain all right, title and interest in and to the Tools, and all intellectual property rights embodied
therein, and that Entity has no right, title or interest therein except for the express licenses granted hereunder and
that Entity will treat such Tools as CrowdStrike’s confidential information.

THE TOOLS ARE PROVIDED “AS-IS” WITHOUT WARRANTY OF ANY KIND, WHETHER EXPRESS, IMPLIED OR STATUTORY OR OTHERWISE.
CROWDSTRIKE SPECIFICALLY DISCLAIMS ALL SUPPORT OBLIGATIONS AND ALL WARRANTIES, INCLUDING WITHOUT LIMITATION, ALL IMPLIED
WARRANTIES OF MERCHANTABILITY, FITNESS FOR PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
CROWDSTRIKE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
THE USE OF THE TOOLS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

© Copyright CrowdStrike 2019-2021
"""
import argparse
from concurrent.futures import thread
import configparser
from configparser import ConfigParser, ExtendedInterpolation
import datetime
import logging
import os
from enum import Enum
from functools import reduce
import urllib3
import concurrent.futures
import itertools
import atexit
from falconpy import Intel
from pymisp import ExpandedPyMISP, MISPObject, MISPEvent, MISPAttribute, MISPOrganisation


def graceful_close():
    print("Shutting down background threads, please wait...")


class MaliciousConfidence(Enum):
    """Malicious Confidence enumerator."""

    UNVERIFIED = 4
    LOW = 3
    MEDIUM = 2
    HIGH = 1


class IntelAPIClient:
    """This class provides the interface for the CrowdStrike Intel API."""

    def __init__(self, client_id, client_secret, crowdstrike_url, api_request_max, use_ssl: bool = True):
        """Construct an instance of the IntelAPIClient class.

        :param client_id: CrowdStrike API Client ID
        :param client_secret: CrowdStrike API Client Secret
        :param crowdstrike_url: CrowdStrike Base URL / Base URL shortname
        :param api_request_max [int]: Maximum number of records to return per API request
        :param use_ssl [bool]: Enable SSL validation to the CrowdStrike Cloud (default: True)
        """
        self.falcon = Intel(client_id=client_id, client_secret=client_secret, base_url=crowdstrike_url, ssl_verify=use_ssl)
        self.valid_report_types = ["csa", "csir", "csit", "csgt", "csia", "csmr", "csta", "cswr"]
        self.request_size_limit = api_request_max

        self._is_valid_report = lambda report: any(report.get('name') and report.get('name').lower().startswith(valid_type)
                                                   for valid_type in self.valid_report_types)

    def get_reports(self, start_time):
        """Get all the reports that were updated after a certain moment in time (UNIX).

        :param start_time: unix time of the oldest report you want to pull
        """
        reports = []
        offset = 0
        total = 0
        first_run = True

        while offset < total or first_run:
            params = {"sort": "last_modified_date.asc",
                      "filter": f'last_modified_date:>{start_time}',
                      'limit': self.request_size_limit,
                      'offset': offset}
            resp_json = self.falcon.query_report_entities(parameters=params)["body"]
            self.__check_metadata(resp_json)

            total = resp_json.get('meta', {}).get('pagination', {}).get('total')
            offset += resp_json.get('meta', {}).get('pagination', {}).get('limit')
            first_run = False

            reports.extend(resp_json.get('resources', []))

        valid_reports = [report for report in reports if self._is_valid_report(report)]
        return valid_reports

    def get_indicators(self, start_time, include_deleted, push_func = None):
        """Get all the indicators that were updated after a certain moment in time (UNIX).

        :param start_time: unix time of the oldest indicator you want to pull
        :param include_deleted [bool]: include indicators marked as deleted
        """
        def _do_query(start):
            params = {"sort": "_marker.asc",
                      "filter": f"_marker:>='{start}'",
                      'limit': self.request_size_limit,
                      }
            if include_deleted:
                params['include_deleted'] = True

            resp_json = self.falcon.query_indicator_entities(parameters=params)["body"]

            indicators_in_request = resp_json.get('resources', [])
            if indicators_in_request:
                total_found = reduce(lambda d, key: d.get(key, None) if isinstance(d, dict) else None,
                                     "meta.pagination.total".split("."),
                                     resp_json
                                     )
                log_msg = f"Retrieved {len(indicators_in_request)} of {total_found} remaining indicators."
                print(log_msg)
                logging.info(log_msg)
            # else:
            #     break
                # Push the indicator to MISP using a seperate thread
                if push_func is not None:
                    #push_func(indicators_in_request)
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        executor.submit(push_func, indicators_in_request)
                    # concurrent.futures.ThreadPoolExecutor().submit(push_func, indicators_in_request)

#            indicators.extend(indicators_in_request)

            # last_marker = indicators_in_request[-1].get('_marker', '')

            return indicators_in_request

            

        indicators = []
        indicators_in_request = []
        first_run = True

        # THREADED
        # with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
        #     futures = {
        #         executor.submit(_do_query, start_time)
        #     }
        #     while futures:
        #         done, futures = concurrent.futures.wait(
        #             futures, return_when=concurrent.futures.FIRST_COMPLETED
        #         )
        #         for fut in done:
        #             returned = fut.result()
        #             if indicators:
        #                 indicators.extend(returned)
        #                 last_marker = returned[-1].get('_marker', '')
        #                 futures.add(executor.submit(_do_query, last_marker))

        # ORIGINAL CODE

        while len(indicators_in_request) == self.request_size_limit or first_run:
            params = {"sort": "_marker.asc",
                      "filter": f"_marker:>='{start_time}'",
                      'limit': self.request_size_limit,
                      }
            if include_deleted:
                params['include_deleted'] = True

            
            resp_json = self.falcon.query_indicator_entities(parameters=params)["body"]

            first_run = False

            indicators_in_request = resp_json.get('resources', [])
            if indicators_in_request:
                total_found = reduce(lambda d, key: d.get(key, None) if isinstance(d, dict) else None,
                                     "meta.pagination.total".split("."),
                                     resp_json
                                     )
                log_msg = f"Retrieved {len(indicators_in_request)} of {total_found} remaining indicators."
                print(log_msg)
                logging.info(log_msg)
            else:
                break
            # Push the indicator to MISP using a seperate thread
            if push_func is not None:
                #with concurrent.futures.ProcessPoolExecutor() as executor:
                # Might play with the max_workers value a bit
                
                #with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                #    executor.submit(push_func, indicators_in_request)
                concurrent.futures.ThreadPoolExecutor().submit(push_func, indicators_in_request)

            indicators.extend(indicators_in_request)

            last_marker = indicators_in_request[-1].get('_marker', '')
            if last_marker == '':
                break
            start_time = last_marker

        return indicators

    def get_actors(self, start_time):
        """Get all the actors that were updated after a certain moment in time (UNIX).

        :param start_time: unix time of the oldest actor you want to pull
        """
        actors = []
        offset = 0
        total = 0
        first_run = True

        while offset < total or first_run:
            params = {"sort": "last_modified_date.asc",
                      "filter": f'last_modified_date:>{start_time}',
                      'limit': self.request_size_limit,
                      'offset': offset}
            resp_json = self.falcon.query_actor_entities(parameters=params)["body"]

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


class ReportsImporter:
    """Tool used to import reports from the Crowdstrike Intel API and push them as events in MISP through the MISP API."""

    def __init__(self, misp_client, intel_api_client, crowdstrike_org_uuid, reports_timestamp_filename, settings):
        """Construct an instance of the ReportsImporter class.

        :param misp_client: MISP API client object
        :param intel_api_client: CrowdStrike Intel API client object
        :param crowdstrike_org_uuid: UUID for the CrowdStrike organization within the MISP instance
        :param reports_timestamp_filename: Filename for the reports _marker tracking file

        """
        self.misp = misp_client
        self.intel_api_client = intel_api_client
        self.reports_timestamp_filename = reports_timestamp_filename
        self.settings = settings
        org = MISPOrganisation()
        org.uuid = crowdstrike_org_uuid
        self.crowdstrike_org = self.misp.get_organisation(org, True)

    def process_reports(self, reports_days_before, events_already_imported):
        """Pull and process reports.

        :param reports_days_before: in case on an initialisation run, this is the age of the reports pulled in days
        :param events_already_imported: the events already imported in misp, to avoid duplicates
        """
        start_get_events = int((datetime.date.today() - datetime.timedelta(reports_days_before)).strftime("%s"))
        if os.path.isfile(self.reports_timestamp_filename):
            with open(self.reports_timestamp_filename, 'r', encoding="utf-8") as ts_file:
                line = ts_file.readline()
                start_get_events = int(line)

        log_msg = "Started getting reports from Crowdstrike Intel API and pushing them as events in MISP."
        print(log_msg)
        logging.info(log_msg)
        time_send_request = datetime.datetime.now()
        reports = self.intel_api_client.get_reports(start_get_events)
        log_msg = f"Got {str(len(reports))} reports from the Crowdstrike Intel API."
        print(log_msg)
        logging.info(log_msg)

        if len(reports) == 0:
            with open(self.reports_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                ts_file.write(time_send_request.strftime("%s"))
        else:
            for report in reports:
                report_name = report.get('name')
                if report_name is not None:
                    if events_already_imported.get(report_name) is not None:
                        continue

                event = self.create_event_from_report(report)
                if event is not None:
                    try:
                        event = self.misp.add_event(event, True)
                        for tag in self.settings["CrowdStrike"]["reports_tags"].split(","):
                            self.misp.tag(event, tag)
                        for rtype in self.intel_api_client.valid_report_types:
                            if rtype.upper() in report.get('name', None):
                                self.misp.tag(event, rtype.upper())
                        if report_name is not None:
                            events_already_imported[report_name] = True
                    except Exception as err:
                        logging.warning("Could not add or tag event %s.\n%s", event.info, str(err))
                else:
                    logging.warning("Failed to create a MISP event for report %s.", report)

                if report.get('last_modified_date') is None:
                    logging.warning("Failed to confirm report %s in file.", report)
                    continue

                with open(self.reports_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                    ts_file.write(str(report.get('last_modified_date')))

        logging.info("Finished getting reports from Crowdstrike Intel API and pushing them as events in MISP.")

    def create_event_from_report(self, report):
        """Create a MISP event from a Intel report."""
        event = MISPEvent()
        event.analysis = 2
        event.orgc = self.crowdstrike_org

        if report.get('name'):
            event.info = report.get('name')
        else:
            logging.warning("Report %s missing name field.", report.get('id'))

        if report.get('url'):
            event.add_attribute('link', report.get('url'))
        else:
            logging.warning("Report %s missing url field.", report.get('id'))

        if report.get('short_description'):
            event.add_attribute('comment', report.get('short_description'))
        else:
            logging.warning("Report %s missing short_description field.", report.get('id'))

        for actor in report.get('actors', []):
            if actor.get('name'):
                event.add_attribute('threat-actor', actor.get('name'))
            else:
                logging.warning("Actor from report %s missing name field.", report.get('id'))

        for country in report.get('target_countries', []):
            if country.get('value'):
                country_object = MISPObject('victim')
                country_object.add_attribute('regions', country.get('value'))
                event.add_object(country_object)
            else:
                logging.warning("Target country from report %s missing value field.", report.get('id'))

        for industry in report.get('target_industries', []):
            if industry.get('value'):
                industry_object = MISPObject('victim')
                industry_object.add_attribute('sectors', industry.get('value'))
                event.add_object(industry_object)
            else:
                logging.warning("Target industry from report %s missing value field.", report.get('id'))

        return event


class IndicatorsImporter:
    """Tool used to import indicators from the Crowdstrike Intel API.

    Adds them as objects attached to the events in MISP coresponding to the Crowdstrike Intel Reports they are related to.

    :param misp_client: client for a MISP instance
    :param intel_api_client: client for the Crowdstrike Intel API
    """

    def __init__(self,
                 misp_client,
                 intel_api_client,
                 crowdstrike_org_uuid,
                 indicators_timestamp_filename,
                 import_all_indicators,
                 delete_outdated,
                 settings
                 ):
        """Construct an instance of the IndicatorsImporter class."""
        self.misp = misp_client
        self.intel_api_client = intel_api_client
        self.indicators_timestamp_filename = indicators_timestamp_filename
        self.import_all_indicators = import_all_indicators
        self.delete_outdated = delete_outdated
        self.settings = settings
        org = MISPOrganisation()
        org.uuid = crowdstrike_org_uuid
        self.crowdstrike_org = self.misp.get_organisation(org, True)
        self.already_imported = None
        self.reports_ids = {}

    def get_cs_reports_from_misp(self):
        """Retrieve any report events in MISP based upon tag."""
        logging.info("Checking for previous events.")
        events = self.misp.search_index(tags=[self.settings["CrowdStrike"]["reports_unique_tag"]])
        for event in events:
            if event.get('info'):
                self.reports_ids[event.get('info').split(' ', 1)[0]] = event
            else:
                logging.warning("Event %s missing info field.", event)

    def process_indicators(self, indicators_days_before, events_already_imported):
        """Pull and process indicators.

        :param indicators_days_before: in case on an initial run, this is the age of the indicators pulled in days
        :param events_already_imported: the events already imported in misp, to avoid duplicates
        """
        start_get_events = int((datetime.date.today() - datetime.timedelta(indicators_days_before)).strftime("%s"))
        if os.path.isfile(self.indicators_timestamp_filename):
            with open(self.indicators_timestamp_filename, 'r', encoding="utf-8") as ts_file:
                line = ts_file.readline()
                start_get_events = int(line)

        # Let's see if we can't speed this up a bit
        self.already_imported = events_already_imported
        self.get_cs_reports_from_misp() # Added to occur before
        logging.info("Started getting indicators from Crowdstrike Intel API and pushing them in MISP.")
        time_send_request = datetime.datetime.now()
        indicators = self.intel_api_client.get_indicators(start_get_events, self.delete_outdated, self.push_indicators)
        logging.info("Got %i indicators from the Crowdstrike Intel API.", len(indicators))

        if len(indicators) == 0:
            with open(self.indicators_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                ts_file.write(time_send_request.strftime("%s"))
        #else:
            #self.get_cs_reports_from_misp()
            #self.push_indicators(indicators, events_already_imported)

        logging.info("Finished getting indicators from Crowdstrike Intel API and pushing them in MISP.")

    def push_indicators(self, indicators, events_already_imported = None):
        """Push valid indicators into MISP."""
        def threaded_indicator_push(indicator):
            FINISHED = False
            if self.import_all_indicators or len(indicator.get('reports', [])) > 0:

                indicator_name = indicator.get('indicator')

                if self.delete_outdated and indicator_name is not None and indicator.get('deleted', False):
                    events = self.misp.search_index(eventinfo=indicator_name, pythonify=True)
                    for event in events:
                        self.misp.delete_event(event)
                        try:
                            events_already_imported.pop(indicator_name)
                        except Exception as err:
                            logging.debug("indicator %s was marked as deleted in intel API but is not stored in MISP."
                                          " skipping.\n%s",
                                          indicator_name,
                                          str(err)
                                          )
                        logging.warning('deleted indicator %s', indicator_name)
                    FINISHED = True
                if not FINISHED:
                    if indicator_name is not None:
                        if events_already_imported.get(indicator_name) is not None:
                            FINISHED = True
                if not FINISHED:
                    self.__create_object_for_indicator(indicator)

                    related_to_a_misp_report = False
                    indicator_value = indicator.get('indicator')
                    if indicator_value:
                        for report in indicator.get('reports', []):
                            event = self.reports_ids.get(report)
                            if event:
                                related_to_a_misp_report = True
                                indicator_object = self.__create_object_for_indicator(indicator)
                                if indicator_object:
                                    try:
                                        if isinstance(indicator_object, MISPObject):
                                            self.misp.add_object(event, indicator_object, True)
                                        elif isinstance(indicator_object, MISPAttribute):
                                            self.misp.add_attribute(event, indicator_object, True)
                                    except Exception as err:
                                        logging.warning("Could not add object or attribute %s for event %s.\n%s",
                                                        indicator_object,
                                                        event,
                                                        str(err)
                                                        )
                    else:
                        logging.warning("Indicator %s missing indicator field.", indicator.get('id'))

                    if related_to_a_misp_report or self.import_all_indicators:
                        self.__add_indicator_event(indicator)
                        if indicator_name is not None:
                            events_already_imported[indicator_name] = True

            if indicator.get('last_updated') is None:
                logging.warning("Failed to confirm indicator %s in file.", indicator)
                FINISHED = True

            if not FINISHED:
                with open(self.indicators_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                    ts_file.write(str(indicator.get('last_updated')))

            return indicator.get("id", True)



        THREAD_COUNT = 20
        if events_already_imported == None:
            events_already_imported = self.already_imported
        with concurrent.futures.ThreadPoolExecutor() as executor:
            
            futures = {
                executor.submit(threaded_indicator_push, task)
                for task in itertools.islice(indicators, THREAD_COUNT)
            }
        while futures:
            done, futures = concurrent.futures.wait(
                futures, return_when=concurrent.futures.FIRST_COMPLETED
            )
            for fut in done:
                logging.debug("Thread completed %s.", fut.result())

            for task in itertools.islice(indicators, len(done)):
                futures.add(
                    executor.submit(threaded_indicator_push, task)
                )

        # for ind in indicators:
        #     threaded_indicator_push(ind)
            # if self.import_all_indicators or len(indicator.get('reports', [])) > 0:

            #     indicator_name = indicator.get('indicator')

            #     if self.delete_outdated and indicator_name is not None and indicator.get('deleted', False):
            #         events = self.misp.search_index(eventinfo=indicator_name, pythonify=True)
            #         for event in events:
            #             self.misp.delete_event(event)
            #             try:
            #                 events_already_imported.pop(indicator_name)
            #             except Exception as err:
            #                 logging.debug("indicator %s was marked as deleted in intel API but is not stored in MISP."
            #                               " skipping.\n%s",
            #                               indicator_name,
            #                               str(err)
            #                               )
            #             logging.warning('deleted indicator %s', indicator_name)
            #         continue

            #     if indicator_name is not None:
            #         if events_already_imported.get(indicator_name) is not None:
            #             continue

            #     self.__create_object_for_indicator(indicator)

            #     related_to_a_misp_report = False
            #     indicator_value = indicator.get('indicator')
            #     if indicator_value:
            #         for report in indicator.get('reports', []):
            #             event = self.reports_ids.get(report)
            #             if event:
            #                 related_to_a_misp_report = True
            #                 indicator_object = self.__create_object_for_indicator(indicator)
            #                 if indicator_object:
            #                     try:
            #                         if isinstance(indicator_object, MISPObject):
            #                             self.misp.add_object(event, indicator_object, True)
            #                         elif isinstance(indicator_object, MISPAttribute):
            #                             self.misp.add_attribute(event, indicator_object, True)
            #                     except Exception as err:
            #                         logging.warning("Could not add object or attribute %s for event %s.\n%s",
            #                                         indicator_object,
            #                                         event,
            #                                         str(err)
            #                                         )
            #     else:
            #         logging.warning("Indicator %s missing indicator field.", indicator.get('id'))

            #     if related_to_a_misp_report or self.import_all_indicators:
            #         self.__add_indicator_event(indicator)
            #         if indicator_name is not None:
            #             events_already_imported[indicator_name] = True

            # if indicator.get('last_updated') is None:
            #     logging.warning("Failed to confirm indicator %s in file.", indicator)
            #     continue

            # with open(self.indicators_timestamp_filename, 'w', encoding="utf-8") as ts_file:
            #     ts_file.write(str(indicator.get('last_updated')))
            
        logging.info("Pushed %i indicators to MISP.", len(indicators))

    def __add_indicator_event(self, indicator):
        """Add an indicator event for the indicator specified."""
        event = MISPEvent()
        event.analysis = 2
        event.orgc = self.crowdstrike_org

        indicator_value = indicator.get('indicator')
        if indicator_value:
            event.info = indicator_value
            indicator_object = self.__create_object_for_indicator(indicator)
            if indicator_object:
                if isinstance(indicator_object, MISPObject):
                    event.add_object(indicator_object)
                elif isinstance(indicator_object, MISPAttribute):
                    event.add_attribute(indicator_object.type, indicator_object.value)
                else:
                    logging.warning("Couldn't add indicator object to the event corresponding to MISP event %s.",
                                    indicator_value
                                    )
        else:
            logging.warning("Indicator %s missing indicator field.", indicator.get('id'))

        malicious_confidence = indicator.get('malicious_confidence')
        if malicious_confidence is None:
            logging.warning("Indicator %s missing malicious_confidence field.", indicator.get('id'))
        else:
            try:
                event.threat_level_id = MaliciousConfidence[malicious_confidence.upper()].value
            except AttributeError:
                logging.warning("Could not map malicious_confidence level with value %s", malicious_confidence)

        for actor in indicator.get('actors', []):
            event.add_attribute('threat-actor', actor)

        for target in indicator.get('targets', []):
            industry_object = MISPObject('victim')
            industry_object.add_attribute('sectors', target)
            event.add_object(industry_object)

        try:
            event = self.misp.add_event(event, True)
            for tag in self.settings["CrowdStrike"]["indicators_tags"].split(","):
                self.misp.tag(event, tag)
            if indicator.get('type', None):
                self.misp.tag(event, indicator.get('type').upper())
        except Exception as err:
            logging.warning("Could not add or tag event %s.\n%s", event.info, str(err))

        for malware_family in indicator.get('malware_families', []):
            galaxy = self.settings["Galaxy"].get(malware_family)
            if galaxy is not None:
                try:
                    self.misp.tag(event, galaxy)
                except Exception as err:
                    logging.warning("Could not add event %s in galaxy/cluster.\n%s", event.info, str(err))
            else:
                logging.warning("Don't know how to map malware_family %s to a MISP galaxy.", malware_family)

    @staticmethod
    def __create_object_for_indicator(indicator):
        """Create the appropriate MISP event object for the indicator (based upon type)."""
        if not indicator.get('type') or not indicator.get('indicator'):
            logging.warning("Indicator %s missing type or indicator field.", indicator.get('id'))
            return False

        indicator_type = indicator.get('type')
        indicator_value = indicator.get('indicator')

        # Type, Object_Type, Attribute Name
        ind_objects = [
            ["hash_md5", "file", "md5"],
            ["hash_sha256", "file", "sha256"],
            ["hash_sha1", "file", "sha1"],
            ["file_name", "file", "filename"],
            ["mutex_name", "mutex", "name"],
            ["password", "credential", "password"],
            ["url", "url", "url"],
            ["email_address", "email", "reply-to"],
            ["username", "credential", "username"],
            ["bitcoin_address", "btc-transaction", "btc-address"],
            ["registry", "registry-key", "key"],
            ["x509_serial", "x509", "serial-number"],
            ["file_path", "file", "fullpath"],
            ["email_subject", "email", "subject"],
            ["coin_address", "coin-address", "address"],
            ["x509_subject", "x509", "subject"],
            ["device_name", "device", "name"],
            ["hash_imphash", "pe", "imphash"]
        ]

        for ind_obj in ind_objects:
            if indicator_type == ind_obj[0]:
                indicator_object = MISPObject(ind_obj[1])
                indicator_object.add_attribute(ind_obj[2], indicator_value)
                return indicator_object

        # Type, Category, Attribute Type
        ind_attributes = [
            ["domain", "Network activity", "domain"],
            ["campaign_id", "Attribution", "campaign-id"],
            ["ip_address", "Network activity", "ip-src"],
            ["service_name", "Artifacts Dropped", "windows-service-name"],
            ["user_agent", "Network activity", "user-agent"],
            ["port", "Network activity", "port"]
        ]

        for ind_att in ind_attributes:
            if indicator_type == ind_att[0]:
                indicator_attribute = MISPAttribute()
                indicator_attribute.category = ind_att[1]
                indicator_attribute.type = ind_att[2]
                indicator_attribute.value = indicator_value
                return indicator_attribute

        # Not found, log the miss
        logging.warning("Unable to map indicator type %s to a MISP object or attribute.", indicator.get('type'))
        return False


class ActorsImporter:
    """Tool used to import actors from the Crowdstrike Intel API and push them as events in MISP through the MISP API.

    :param misp_client: client for a MISP instance
    :param intel_api_client: client for the Crowdstrike Intel API
    """

    def __init__(self, misp_client, intel_api_client, crowdstrike_org_uuid, actors_timestamp_filename, settings, unknown = "UNIDENTIFIED"):
        """Construct an instance of the ActorsImporter class."""
        self.misp = misp_client
        self.intel_api_client = intel_api_client
        self.actors_timestamp_filename = actors_timestamp_filename
        org = MISPOrganisation()
        org.uuid = crowdstrike_org_uuid
        self.crowdstrike_org = self.misp.get_organisation(org, True)
        self.settings = settings
        self.unknown = unknown

    def process_actors(self, actors_days_before, events_already_imported):
        """Pull and process actors.

        :param actors_days_before: in case on an initialisation run, this is the age of the actors pulled in days
        :param events_already_imported: the events already imported in misp, to avoid duplicates
        """
        start_get_events = int((datetime.date.today() - datetime.timedelta(actors_days_before)).strftime("%s"))
        if os.path.isfile(self.actors_timestamp_filename):
            with open(self.actors_timestamp_filename, 'r', encoding="utf-8") as ts_file:
                line = ts_file.readline()
                start_get_events = int(line)

        logging.info("Started getting actors from Crowdstrike Intel API and pushing them as events in MISP.")
        time_send_request = datetime.datetime.now()
        actors = self.intel_api_client.get_actors(start_get_events)
        logging.info("Got %i actors from the Crowdstrike Intel API.", len(actors))

        if events_already_imported.get(self.unknown) is None:
            unknown_actor = {
                "name": self.unknown,
                "url": "",
                "short_description": "Unidentified actor",
                "known_as": self.unknown,   
                # "first_activity": "",
                # "last_activity": "",    # Intetionally not populating these fields
                # "target_countries": "",
                # "target_regions": ""
            }
            create_unknown = self.create_event_from_actor(unknown_actor)
            if not create_unknown:
                logging.warning("Unable to create unknown actor generic event.")
            try:
                unkn = self.misp.add_event(create_unknown, True)
                for tag in self.settings["CrowdStrike"]["actors_tags"].split(","):
                    self.misp.tag(unkn, tag)
                self.misp.tag(unkn, self.unknown)
                events_already_imported[self.unknown] = True
            except Exception as err:
                logging.warning("Could not add or tag unknown actor event.")

        if len(actors) == 0:
            with open(self.actors_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                ts_file.write(time_send_request.strftime("%s"))
        else:
            for actor in actors:

                actor_name = actor.get('name')
                if actor_name is not None:
                    if events_already_imported.get(actor_name) is not None:
                        continue

                event = self.create_event_from_actor(actor)
                if not event:
                    logging.warning("Failed to create a MISP event for actor %s.", actor)
                    continue

                try:
                    event = self.misp.add_event(event, True)
                    for tag in self.settings["CrowdStrike"]["actors_tags"].split(","):
                        self.misp.tag(event, tag)
                    # Create an actor specific tag
                    actor_tag = actor_name.split(" ")[1]
                    self.misp.tag(event, actor_tag)
                    if actor_name is not None:
                        events_already_imported[actor_name] = True
                except Exception as err:
                    logging.warning("Could not add or tag event %s.\n%s", event.info, str(err))

                if actor.get('last_modified_date') is None:
                    logging.warning("Failed to confirm actor %s in file.", actor)
                    continue

                with open(self.actors_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                    ts_file.write(str(actor.get('last_modified_date')))

        logging.info("Finished getting actors from Crowdstrike Intel API and pushing them as events in MISP.")

    def create_event_from_actor(self, actor):
        """Create a MISP event for a valid Actor."""
        event = MISPEvent()
        event.analysis = 2
        event.orgc = self.crowdstrike_org

        if actor.get('name'):
            event.info = actor.get('name')
        else:
            logging.warning("Actor %s missing field name.", actor.get('id'))

        if actor.get('url'):
            event.add_attribute('link', actor.get('url'))
        else:
            logging.warning("Actor %s missing field url.", actor.get('id'))

        if actor.get('short_description'):
            event.add_attribute('comment', actor.get('short_description'))
        else:
            logging.warning("Actor %s missing field short_description.", actor.get('id'))

        if actor.get('known_as'):
            known_as_object = MISPObject('organization')
            known_as_object.add_attribute('alias', actor.get('known_as'))
            event.add_object(known_as_object)
        else:
            logging.warning("Actor %s missing field known_as.", actor.get('id'))

        had_timestamp = False
        timestamp_object = MISPObject('timestamp')

        if actor.get('first_activity_date'):
            timestamp_object.add_attribute('first-seen',
                                           datetime.datetime.utcfromtimestamp(actor.get('first_activity_date')).isoformat()
                                           )
            had_timestamp = True
        else:
            logging.warning("Actor %s missing field first_activity_date.", actor.get('id'))

        if actor.get('last_activity_date'):
            timestamp_object.add_attribute('last-seen',
                                           datetime.datetime.utcfromtimestamp(actor.get('last_activity_date')).isoformat()
                                           )
            had_timestamp = True
        else:
            logging.warning("Actor %s missing field last_activity_date.", actor.get('id'))

        if had_timestamp:
            event.add_object(timestamp_object)

        for country in actor.get('target_countries', []):
            if country.get('value'):
                country_object = MISPObject('victim')
                country_object.add_attribute('regions', country.get('value'))
                event.add_object(country_object)
            else:
                logging.warning("Target country from actor %s is missing value field.", actor.get('id'))

        for industry in actor.get('target_industries', []):
            if industry.get('value'):
                industry_object = MISPObject('victim')
                industry_object.add_attribute('sectors', industry.get('value'))
                event.add_object(industry_object)
            else:
                logging.warning("Target country from actor %s is missing value field.", actor.get('id'))

        return event


class CrowdstrikeToMISPImporter:
    """Tool used to import indicators and reports from the Crowdstrike Intel API.

    :param intel_api_client: client for the Crowdstrike Intel API
    :param import_settings: dictionary containing settings specified in settings.py
    :param provided_arguments: dictionary containing provided command line arguments
    """

    def __init__(self, intel_api_client, import_settings, provided_arguments, settings):
        """Construct an instance of the CrowdstrikeToMISPImporter class."""
        confirm_settings = ["misp_url", "misp_auth_key", "crowdstrike_org_uuid", "reports_timestamp_filename",
                            "indicators_timestamp_filename", "actors_timestamp_filename"
                            ]
        for item in confirm_settings:
            try:
                _ = import_settings[item]
            except KeyError as err:
                err_msg = ("%s value must be specified in the settings.py file."
                           " Please check your configuration and retry.\n%s",
                           item,
                           err
                           )
                logging.error(err_msg)
                raise SystemExit(err_msg) from err

        self.misp_client = ExpandedPyMISP(import_settings["misp_url"],
                                          import_settings["misp_auth_key"],
                                          import_settings["misp_enable_ssl"],
                                          False
                                          )
        self.config = provided_arguments
        self.settings = settings
        self.unique_tags = {
            "reports": import_settings["reports_unique_tag"],
            "indicators": import_settings["indicators_unique_tag"],
            "actors": import_settings["actors_unique_tag"],
        }

        self.event_ids = {}

        if self.config["reports"]:
            self.reports_importer = ReportsImporter(self.misp_client,
                                                    intel_api_client,
                                                    import_settings["crowdstrike_org_uuid"],
                                                    import_settings["reports_timestamp_filename"],
                                                    self.settings
                                                    )
        if self.config["related_indicators"] or self.config["all_indicators"]:
            self.indicators_importer = IndicatorsImporter(self.misp_client, intel_api_client,
                                                          import_settings["crowdstrike_org_uuid"],
                                                          import_settings["indicators_timestamp_filename"],
                                                          self.config["all_indicators"],
                                                          self.config["delete_outdated_indicators"],
                                                          self.settings
                                                          )
        if self.config["actors"]:
            self.actors_importer = ActorsImporter(self.misp_client, intel_api_client, import_settings["crowdstrike_org_uuid"],
                                                  import_settings["actors_timestamp_filename"], self.settings, import_settings["unknown_mapping"])

    def clean_crowdstrike_events(self, clean_reports, clean_indicators, clean_actors):
        """Delete events from a MISP instance."""
        tags = []
        if clean_reports:
            tags.append(self.unique_tags["reports"])
        if clean_indicators:
            tags.append(self.unique_tags["indicators"])
        if clean_actors:
            tags.append(self.unique_tags["actors"])

        if clean_reports or clean_indicators or clean_actors:
            events = self.misp_client.search_index(tags=tags)
            for event in events:
                self.misp_client.delete_event(event)
            logging.info("Finished cleaning up Crowdstrike related events from MISP.")

    def clean_old_crowdstrike_events(self, max_age):
        """Remove events from MISP that are dated greater than the specified max_age value."""
        if max_age is not None:
            timestamp_max = int((datetime.date.today() - datetime.timedelta(max_age)).strftime("%s"))
            events = self.misp_client.search(tags=[self.unique_tags["reports"],
                                                   self.unique_tags["indicators"],
                                                   self.unique_tags["actors"]
                                                   ],
                                             timestamp=[0, timestamp_max]
                                             )
            for event in events:
                self.misp_client.delete_event(event)
            logging.info("Finished cleaning up Crowdstrike related events from MISP.")

    def import_from_crowdstrike(self,
                                reports_days_before: int = 7,
                                indicators_days_before: int = 7,
                                actors_days_before: int = 7
                                ):
        """Import reports and events from Crowdstrike Intel API.

        :param reports_days_before: in case on an initial run, this is the age of the reports pulled in days
        :param indicators_days_before: in case on an initial run, this is the age of the indicators pulled in days
        :param actors_days_before: in case on an initial run, this is the age of the actors pulled in days
        """
        if self.config["reports"]:
            self.reports_importer.process_reports(reports_days_before, self.event_ids)
        if self.config["related_indicators"] or self.config["all_indicators"]:
            self.indicators_importer.process_indicators(indicators_days_before, self.event_ids)
        if self.config["actors"]:
            self.actors_importer.process_actors(actors_days_before, self.event_ids)

    def import_from_misp(self, tags):
        """Retrieve existing MISP events."""
        events = self.misp_client.search_index(tags=tags)
        for event in events:
            if event.get('info'):
                self.event_ids[event.get('info')] = True
            else:
                logging.warning("Event %s missing info field.", event)


def parse_command_line():
    """Parse the running command line provided by the user."""
    parser = argparse.ArgumentParser(description="Tool used to import reports and indicators from Crowdstrike Intel"
                                                 "API into a MISP instance.")
    parser.add_argument("--clean_reports", action="store_true", help="Set this to run a cleaning round on reports.")
    parser.add_argument("--clean_indicators", action="store_true", help="Set this to run a cleaning round on indicators.")
    parser.add_argument("--clean_actors", action="store_true", help="Set this to run a cleaning round on actors,")
    parser.add_argument("--debug", action="store_true", help="Set this to activate debug logs.")
    parser.add_argument("--max_age", type=int,
                        help="Maximum age of the objects to be stored in MISP in days."
                             " Objects older than that will be deleted."
                        )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--related_indicators", action="store_true",
                       help="Set this to only import indicators related to reports."
                       )
    group.add_argument("--all_indicators", action="store_true", help="Set this to import all indicators.")
    parser.add_argument("--delete_outdated_indicators", action='store_true',
                        help="Set this to check if the indicators you are imported have been marked as deleted and"
                             " if they have been already inserted, delete them."
                        )
    parser.add_argument("--reports", action="store_true", help="Set this to import reports.")
    parser.add_argument("--actors", action="store_true", help="Set this to import actors.")
    parser.add_argument("--config", dest="config_file", help="Path to local configuration file", required=False)
    return parser.parse_args()


def perform_local_cleanup(args: argparse.Namespace, importer: CrowdstrikeToMISPImporter, settings: configparser.ConfigParser):
    """Remove local offset cache files to reset the marker for data pulls from the CrowdStrike API."""
    try:
        importer.clean_crowdstrike_events(args.clean_reports, args.clean_indicators, args.clean_actors)
        if args.clean_reports and os.path.isfile(settings["CrowdStrike"]["reports_timestamp_filename"]):
            os.remove(settings["CrowdStrike"]["reports_timestamp_filename"])
            logging.info("Finished resetting CrowdStrike Report offset.")
        if args.clean_indicators and os.path.isfile(settings["CrowdStrike"]["indicators_timestamp_filename"]):
            os.remove(settings["CrowdStrike"]["indicators_timestamp_filename"])
            logging.info("Finished resetting CrowdStrike Indicator offset.")
        if args.clean_actors and os.path.isfile(settings["CrowdStrike"]["actors_timestamp_filename"]):
            os.remove(settings["CrowdStrike"]["actors_timestamp_filename"])
            logging.info("Finished resetting CrowdStrike Actor offset.")
    except Exception as err:
        logging.exception(err)
        raise SystemExit(err) from err


def retrieve_tags(args: argparse.Namespace, settings):
    """Retrieve all tags used for CrowdStrike elements within MISP (broken out by type)."""
    tags = []
    if args.reports:
        tags.append(settings["CrowdStrike"]["reports_unique_tag"])
    if args.related_indicators or args.all_indicators:
        tags.append(settings["CrowdStrike"]["indicators_unique_tag"])
    if args.actors:
        tags.append(settings["CrowdStrike"]["actors_unique_tag"])

    return tags


def main():
    """Implement Main routine."""
    # Retrieve our command line and parse out any specified arguments
    args = parse_command_line()
    if not args.config_file:
        args.config_file = "misp_import.ini"

    settings = ConfigParser(interpolation=ExtendedInterpolation())
    settings.read(args.config_file)

    try:
        if not settings["MISP"]["misp_enable_ssl"]:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except AttributeError:
        # Not specified, default to enable warnings
        pass

    
    # logging.root.setLevel(logging.INFO)
    LOG_LEVEL = logging.INFO
    if args.debug:
        #logging.root.setLevel(logging.DEBUG)
        LOG_LEVEL = logging.DEBUG
    logging.basicConfig(filename="misp-import.log", encoding="utf-8", level=LOG_LEVEL)

    # Interface to the CrowdStrike Falcon Intel API
    intel_api_client = IntelAPIClient(settings["CrowdStrike"]["client_id"],
                                      settings["CrowdStrike"]["client_secret"],
                                      settings["CrowdStrike"]["crowdstrike_url"],
                                      int(settings["CrowdStrike"]["api_request_max"]),
                                      False if "F" in settings["CrowdStrike"]["api_enable_ssl"].upper() else True
                                      )
    # Dictionary of settings provided by settings.py
    import_settings = {
        "misp_url": settings["MISP"]["misp_url"],
        "misp_auth_key": settings["MISP"]["misp_auth_key"],
        "crowdstrike_org_uuid": settings["MISP"]["crowdstrike_org_uuid"],
        "reports_timestamp_filename": settings["CrowdStrike"]["reports_timestamp_filename"],
        "indicators_timestamp_filename": settings["CrowdStrike"]["indicators_timestamp_filename"],
        "actors_timestamp_filename": settings["CrowdStrike"]["actors_timestamp_filename"],
        "reports_unique_tag": settings["CrowdStrike"]["reports_unique_tag"],
        "indicators_unique_tag": settings["CrowdStrike"]["indicators_unique_tag"],
        "actors_unique_tag": settings["CrowdStrike"]["actors_unique_tag"],
        "unknown_mapping": settings["CrowdStrike"]["unknown_mapping"],
        "misp_enable_ssl": False if "F" in settings["MISP"]["misp_enable_ssl"].upper() else True
    }
    # Dictionary of provided command line arguments
    provided_arguments = {
        "reports": args.reports,
        "related_indicators": args.related_indicators,
        "all_indicators": args.all_indicators,
        "delete_outdated_indicators": args.delete_outdated_indicators,
        "actors": args.actors
    }
    importer = CrowdstrikeToMISPImporter(intel_api_client, import_settings, provided_arguments, settings)

    if args.clean_reports or args.clean_indicators or args.clean_actors:
        perform_local_cleanup(args, importer, settings)

    if args.reports or args.actors or args.related_indicators or args.all_indicators:
        try:
            # Retrieve all tags for selected options
            tags = retrieve_tags(args, settings)
            # Retrieve all events from MISP matching these tags
            importer.import_from_misp(tags)
            # Import new events from CrowdStrike into MISP
            importer.import_from_crowdstrike(int(settings["CrowdStrike"]["init_reports_days_before"]),
                                             int(settings["CrowdStrike"]["init_indicators_days_before"]),
                                             int(settings["CrowdStrike"]["init_actors_days_before"])
                                             )
        except Exception as err:
            logging.exception(err)
            raise SystemExit(err) from err

    if args.max_age is not None:
        try:
            importer.clean_old_crowdstrike_events(args.max_age)
        except Exception as err:
            logging.exception(err)
            raise SystemExit(err) from err


if __name__ == '__main__':
    atexit.register(graceful_close)
    main()
