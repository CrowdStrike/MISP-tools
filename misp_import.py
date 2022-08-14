#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""CrowdStrike Falcon Intel API to MISP Import utility.

 ___ ___ ___ _______ _______
|   Y   |   |   _   |   _   |     _______                             __
|.      |.  |   1___|.  1   |    |_     _|.--------.-----.-----.----.|  |_.-----.----.
|. [_]  |.  |____   |.  ____|     _|   |_ |        |  _  |  _  |   _||   _|  -__|   _|
|:  |   |:  |:  1   |:  |        |_______||__|__|__|   __|_____|__|  |____|_____|__|
|::.|:. |::.|::.. . |::.|                          |__|
`--- ---`---`-------`---'                                   CrowdStrike FalconPy v0.9.0+

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

© Copyright CrowdStrike 2019-2022
"""
import argparse
from configparser import ConfigParser, ExtendedInterpolation
import logging
import os
import urllib3
from cs_misp_import import (
    IntelAPIClient, CrowdstrikeToMISPImporter, MISP_BANNER, FINISHED_BANNER
)

def parse_command_line():
    """Parse the running command line provided by the user."""
    parser = argparse.ArgumentParser(description="Tool used to import reports and indicators from Crowdstrike Intel"
                                                 "API into a MISP instance.")
    parser.add_argument("--clean_reports", action="store_true", help="Set this to run a cleaning round on reports.")
    parser.add_argument("--clean_indicators", action="store_true", help="Set this to run a cleaning round on indicators.")
    parser.add_argument("--clean_actors", "--clean_adversaries", dest="clean_actors", action="store_true", help="Set this to run a cleaning round on adversaries.")
    parser.add_argument("--debug", action="store_true", help="Set this to activate debug logs.")
    parser.add_argument("--max_age", type=int,
                        help="Maximum age of the objects to be stored in MISP in days."
                             " Objects older than that will be deleted."
                        )
    #group = parser.add_mutually_exclusive_group()
    # group.add_argument("--related_indicators", action="store_true",
    #                    help="Set this to only import indicators related to reports."
    #                    )
    parser.add_argument("--indicators", action="store_true", help="Set this to import all indicators.")
    parser.add_argument("--force", action="store_true", help="Ignore previous timestamp and use minutes setting from ini file.")
    parser.add_argument("--delete_outdated_indicators", action='store_true',
                        help="Set this to check if the indicators you are imported have been marked as deleted and"
                             " if they have been already inserted, delete them."
                        )
    parser.add_argument("--reports", action="store_true", help="Set this to import reports.")
    parser.add_argument("--actors", "--adversaries", dest="actors", action="store_true", help="Set this to import adversaries.")
    parser.add_argument("--config", dest="config_file", help="Path to local configuration file", required=False)
    parser.add_argument("--no_dupe_check",
                        dest="no_dupe_check",
                        help="Enable or disable duplicate checking on import, defaults to False.",
                        required=False,
                        action="store_true"
                        )
    parser.add_argument("--clean_tags",
                        dest="clean_tags",
                        help="Remove all CrowdStrike tags from the MISP instance",
                        required=False,
                        action="store_true"
                        )
    return parser.parse_args()


def perform_local_cleanup(args: argparse.Namespace,
                          importer: CrowdstrikeToMISPImporter,
                          settings: ConfigParser
                          ):
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
            logging.info("Finished resetting CrowdStrike Adversary offset.")
    except Exception as err:
        logging.exception(err)
        raise SystemExit(err) from err


def retrieve_tags(args: argparse.Namespace, settings):
    """Retrieve all tags used for CrowdStrike elements within MISP (broken out by type)."""
    tags = []
    if args.reports:
        tags.append(settings["CrowdStrike"]["reports_unique_tag"])
    if args.indicators:
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

    galaxy_maps = ConfigParser(interpolation=ExtendedInterpolation())
    galaxy_maps.read(settings["MISP"].get("galaxy_map_file", "galaxy.ini"))


    try:
        if not settings["MISP"]["misp_enable_ssl"]:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except AttributeError:
        # Not specified, default to enable warnings
        pass

    logger = logging.getLogger("misp_import")
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    
    
    #LOG_LEVEL = logging.INFO
    ch.setLevel(logging.INFO)
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
        #LOG_LEVEL = logging.DEBUG
    #logging.basicConfig(filename="misp-import.log", level=LOG_LEVEL)
    ch.setFormatter(logging.Formatter("[%(asctime)s] (%(levelname)s) %(message)s"))
    logger.addHandler(ch)
    logger.propagate = False

    # Off we go!
    logger.info(MISP_BANNER)
    

    # Interface to the CrowdStrike Falcon Intel API
    intel_api_client = IntelAPIClient(settings["CrowdStrike"]["client_id"],
                                      settings["CrowdStrike"]["client_secret"],
                                      settings["CrowdStrike"]["crowdstrike_url"],
                                      int(settings["CrowdStrike"]["api_request_max"]),
                                      False if "F" in settings["CrowdStrike"]["api_enable_ssl"].upper() else True,
                                      logger
                                      )
    # Dictionary of settings provided by settings.py
    import_settings = {
        "misp_url": settings["MISP"]["misp_url"],
        "misp_auth_key": settings["MISP"]["misp_auth_key"],
        "crowdstrike_org_uuid": settings["MISP"]["crowdstrike_org_uuid"],
        "reports_timestamp_filename": settings["CrowdStrike"]["reports_timestamp_filename"],
        "indicators_timestamp_filename": settings["CrowdStrike"]["indicators_timestamp_filename"],
        "actors_timestamp_filename": settings["CrowdStrike"]["actors_timestamp_filename"],
#        "reports_unique_tag": settings["CrowdStrike"]["reports_unique_tag"],
#        "indicators_unique_tag": settings["CrowdStrike"]["indicators_unique_tag"],
#        "actors_unique_tag": settings["CrowdStrike"]["actors_unique_tag"],
        "unknown_mapping": settings["CrowdStrike"]["unknown_mapping"],
        "max_threads": settings["MISP"].get("max_threads", None),
        "miss_track_file": settings["MISP"].get("miss_track_file", "no_galaxy_mapping.log"),
        "misp_enable_ssl": False if "F" in settings["MISP"]["misp_enable_ssl"].upper() else True,
        "galaxy_map": galaxy_maps["Galaxy"],
        "force_indicators": args.force
    }
    
    if not import_settings["unknown_mapping"]:
        import_settings["unknown_mapping"] = "Unidentified"
    # Dictionary of provided command line arguments
    provided_arguments = {
        "reports": args.reports,
#        "related_indicators": args.related_indicators,
        "indicators": args.indicators,
        "delete_outdated_indicators": args.delete_outdated_indicators,
        "actors": args.actors
    }
    importer = CrowdstrikeToMISPImporter(intel_api_client, import_settings, provided_arguments, settings, logger=logger)

    if args.clean_reports or args.clean_indicators or args.clean_actors:
        perform_local_cleanup(args, importer, settings)

    if args.clean_tags:
        importer.remove_crowdstrike_tags()

    if args.reports or args.actors or args.indicators:
        try:
            # Commenting out dupe checking for now - 08.14 jshcodes@CrowdStrike
            # if not args.no_dupe_check:
            #     # Retrieve all tags for selected options
            #     tags = retrieve_tags(args, settings)
            #     # Retrieve all events from MISP matching these tags
            #     importer.import_from_misp(tags)
            # Import new events from CrowdStrike into MISP
            importer.import_from_crowdstrike(int(settings["CrowdStrike"]["init_reports_days_before"]),
                                             int(settings["CrowdStrike"]["init_indicators_minutes_before"]),
                                             int(settings["CrowdStrike"]["init_actors_days_before"])
                                             )
        except Exception as err:
            logger.exception(err)
            raise SystemExit(err) from err

    if args.max_age is not None:
        try:
            importer.clean_old_crowdstrike_events(args.max_age)
        except Exception as err:
            logger.exception(err)
            raise SystemExit(err) from err

    logger.info(FINISHED_BANNER)

if __name__ == '__main__':
    main()
