#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

© Copyright CrowdStrike 2019-2022
"""
import argparse
from concurrent.futures import thread
import configparser
from configparser import ConfigParser, ExtendedInterpolation
import datetime
import logging
import os
import requests
import time
from enum import Enum
from functools import reduce
import urllib3
import concurrent.futures
import itertools
import atexit
try:
    from falconpy import Intel
except ImportError as no_falconpy:
    raise SystemExit(
        "The CrowdStrike FalconPy package must be installed to use this program."
        ) from no_falconpy
try:
    from pymisp import ExpandedPyMISP, MISPObject, MISPEvent, MISPAttribute, MISPOrganisation
except ImportError as no_pymisp:
    raise SystemExit(
        "The PyMISP package must be installed to use this program."
        ) from no_pymisp
from cs_misp_import import (
    ActorsImporter, IndicatorsImporter, ReportsImporter,
    IntelAPIClient, MISP
)


def graceful_close():
    print("Shutting down background threads, please wait...")


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

        self.misp_client = MISP(import_settings["misp_url"],
                                import_settings["misp_auth_key"],
                                import_settings["misp_enable_ssl"],
                                False,
                                max_threads=import_settings["max_threads"]
                                )
        self.max_threads = int(import_settings["max_threads"])
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
            with concurrent.futures.ThreadPoolExecutor(self.max_threads) as executor:
                executor.map(self.misp_client.delete_event, self.misp_client.search_index(tags=tags))
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
            with concurrent.futures.ThreadPoolExecutor(self.max_threads) as executor:
                executor.map(self.misp_client.delete_event, events)
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
    
    
    thread_count = settings["MISP"].get("max_threads", min(32, (os.cpu_count() or 1) * 4))
    if not thread_count:
        thread_count = min(32, (os.cpu_count() or 1) * 4)

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
        "max_threads": thread_count,
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
