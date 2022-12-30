#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""CrowdStrike Falcon Threat Intelligence to MISP Import utility.

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
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from configparser import ConfigParser, ExtendedInterpolation
from threading import main_thread
import time
import logging
import os
import urllib3
from cs_misp_import import (
    IntelAPIClient,
    CrowdstrikeToMISPImporter,
    MISP_BANNER,
    FINISHED_BANNER,
    WARNING_BANNER,
    MUSHROOM,
    ReportType,
    Adversary,
    display_banner,
    VERSION,
    check_config
)

def parse_command_line() -> Namespace:
    """Parse the running command line provided by the user."""
    parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("-cr", "--clean_reports", action="store_true", dest="clean_reports", help="Set this to run a cleaning round on reports.")
    parser.add_argument("-ci", "--clean_indicators", action="store_true", dest="clean_indicators", help="Set this to run a cleaning round on indicators.")
    parser.add_argument("-ca", "--clean_actors", "--clean_adversaries", dest="clean_actors", action="store_true", help="Set this to run a cleaning round on adversaries.")
    parser.add_argument("-d", "--debug", action="store_true", dest="debug", help="Set this to activate debug logs.")
    parser.add_argument("-m", "--max_age", type=int, dest="max_age",
                        help="Maximum age of the objects to be stored in MISP in days."
                             " Objects older than that will be deleted."
                        )
    #group = parser.add_mutually_exclusive_group()
    # group.add_argument("--related_indicators", action="store_true",
    #                    help="Set this to only import indicators related to reports."
    #                    )
    parser.add_argument("-i", "--indicators", action="store_true", help="Set this to import all indicators.")
    parser.add_argument("-f", "--force", action="store_true", help="Force operation.")
    parser.add_argument("-do", "--delete_outdated_indicators", action='store_true',
                        help="Set this to check if the indicators you are importing have been marked as deleted and"
                             " if they have been already inserted, delete them."
                        )
    parser.add_argument("-r", "--reports", action="store_true", help="Set this to import reports.")
    parser.add_argument("-a", "--actors", "--adversaries", dest="actors", action="store_true", help="Set this to import adversaries.")
    parser.add_argument("-p", "--publish", dest="publish", help="Publish events upon creation.", action="store_true", required=False, default=False)
    parser.add_argument("-t", "--type", "--report_type", "--indicator_type", "--adversary_type", dest="type", help="Import only this type.", required=False, default=False)
    parser.add_argument("-c", "--config", dest="config_file", help="Path to local configuration file", required=False)
    parser.add_argument("-nd", "--no_dupe_check",
                        dest="no_dupe_check",
                        help="Enable or disable duplicate checking on import, defaults to False.",
                        required=False,
                        action="store_true"
                        )
    parser.add_argument("-nb", "--no_banner",
                        dest="no_banner",
                        help="Enable or disable ASCII banners in logfile output, "
                        "defaults to False (enable banners).",
                        required=False,
                        action="store_true"
                        )
    parser.add_argument("-ct", "--clean_tags",
                        dest="clean_tags",
                        help="Remove all CrowdStrike tags from the MISP instance",
                        required=False,
                        action="store_true"
                        )
    parser.add_argument("-l", "--logfile",
                        help="Log file for logging output",
                        required=False,
                        default="misp_import.log"
                        )
    #exclus = parser.add_mutually_exclusive_group("exclusive arguments")
    parser.add_argument("--all", "--fullmonty",
                        help="Import Adversaries, Reports and Indicators",
                        required=False,
                        default=False,
                        dest="fullmonty",
                        action="store_true"
                        )
    parser.add_argument("--obliterate",
                        help="Remove all CrowdStrike data",
                        required=False,
                        default=False,
                        dest="obliterate",
                        action="store_true"
                        )
    parsed = parser.parse_args()

    if parsed.obliterate and parsed.fullmonty:
        parser.error("You cannot run Obliterate and the Full Monty at the same time.")

    if parsed.obliterate:
        bold = "\033[1m"
        undie = "\033[4m"
        endmark = "\033[0m"
        yellow = "\033[33m"
        red = "\033[31m"
        lightred = "\033[91m"
        magenta = "\033[35m"
        cyan = "\033[36m"
        print(f"{red}\n")
        new_warning_banner = WARNING_BANNER.replace("@", f"{red}@{endmark}")
        new_warning_banner = new_warning_banner.replace("!", f"{lightred}!{endmark}")
        new_warning_banner = new_warning_banner.replace(":", f"{yellow}:{endmark}")
        print(f"{'😱 ' * 25}\n")
        print(new_warning_banner)
        print(endmark)
        confirmed = input(
            f"{'😱 ' * 25}\n\nObliterate is a destructive operation that will remove "
            f"{bold}{undie}all CrowdStrike data{endmark}\nfrom your MISP instance. There is "
            "no going back once this process completes.\n\n"
            "Are you sure you want to do this?\n\n[Enter 'yes' to continue] ==> ")
        if confirmed.upper() not in [
            "YES", "FOR SURE", "ABSOLUTELY", "UH... OK", "DESTRUCT SEQUENCE ONE, CODE ONE, ONE-A"
            ]:
            raise SystemExit("Data obliteration has been cancelled. Phew! 😌")
        if confirmed.upper() != "YES":
            print("\nThat's not 'yes', but I'll accept it anyway...\n")

        print(MUSHROOM.format(
            yellow, endmark, red, endmark, yellow, endmark, lightred, endmark, yellow, endmark,
            bold, endmark, cyan, endmark, bold, endmark, cyan, endmark, bold, endmark, cyan,
            endmark, bold, endmark, magenta, endmark, bold, endmark
            ))
        time.sleep(1)
    
    return parsed



def do_finished(logg: logging.Logger, arg_parser: ArgumentParser):
    display_banner(banner=FINISHED_BANNER,
                   logger=logg,
                   fallback="FINISHED",
                   hide_cool_banners=arg_parser.no_banner
                   )


def perform_local_cleanup(args: Namespace,
                          importer: CrowdstrikeToMISPImporter,
                          settings: ConfigParser,
                          log_device: logging.Logger
                          ):
    """Remove local offset cache files to reset the marker for data pulls from the CrowdStrike API."""
    try:
        importer.clean_crowdstrike_events(args.clean_reports, args.clean_indicators, args.clean_actors)
        if args.clean_reports and os.path.isfile(settings["CrowdStrike"]["reports_timestamp_filename"]):
            os.remove(settings["CrowdStrike"]["reports_timestamp_filename"])
            log_device.info("Finished resetting CrowdStrike Report offset.")
        if args.clean_indicators and os.path.isfile(settings["CrowdStrike"]["indicators_timestamp_filename"]):
            os.remove(settings["CrowdStrike"]["indicators_timestamp_filename"])
            log_device.info("Finished resetting CrowdStrike Indicator offset.")
        if args.clean_actors and os.path.isfile(settings["CrowdStrike"]["actors_timestamp_filename"]):
            os.remove(settings["CrowdStrike"]["actors_timestamp_filename"])
            log_device.info("Finished resetting CrowdStrike Adversary offset.")
    except Exception as err:
        log_device.exception(err)
        raise SystemExit(err) from err


def retrieve_tags(tag_type: str, settings):
    """Retrieve all tags used for CrowdStrike elements within MISP (broken out by type)."""
    tags = []
    if tag_type == "reports":
        for report_type in [r for r in dir(ReportType) if "__" not in r]:
            tags.append(f"CrowdStrike:report:type: {report_type}")
    # No indicators dupe checking atm - jshcodes@CrowdStrike / 08.18.22
    # if args.indicators:
    #     tags.append(settings["CrowdStrike"]["indicators_unique_tag"])
    if tag_type == "actors":
        for adv_type in [a for a in dir(Adversary) if "__" not in a]:
            tags.append(f"CrowdStrike:adversary:branch: {adv_type}")

    return tags


def main():
    """Implement Main routine."""
    # Retrieve our command line and parse out any specified arguments
    args = parse_command_line()
    if not args.config_file:
        args.config_file = "misp_import.ini"
    if args.fullmonty:
        args.actors = True
        args.reports = True
        args.indicators = True
    if args.obliterate:
        args.clean_actors = True
        args.clean_reports = True
        args.clean_indicators = True
        args.clean_tags = True
    splash = logging.getLogger("misp_tools")
    splash.setLevel(logging.INFO)
    main_log = logging.getLogger("processor")
    main_log.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    #rfh = RotatingFileHandler(args.logfile, maxBytes=20971520, backupCount=5)
    #rfh.setLevel(logging.INFO)
    #rfh2 = RotatingFileHandler(args.logfile, maxBytes=20971520, backupCount=5)
    #rfh2.setLevel(logging.INFO)
    ch2 = logging.StreamHandler()
    ch2.setLevel(logging.INFO)
    if args.debug:
        main_log.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
        ch2.setLevel(logging.DEBUG)
        #rfh.setLevel(logging.DEBUG)
        #rfh2.setLevel(logging.DEBUG)

    ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(name)-13s %(message)s"))
    #rfh.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(name)-13s %(message)s"))
    ch2.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(name)s/%(threadName)-10s %(message)s"))
    #rfh2.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(name)s/%(threadName)-10s %(message)s"))
    splash.addHandler(ch)
    #splash.addHandler(rfh)
    main_log.addHandler(ch2)
    #main_log.addHandler(rfh2)
    splash.propagate = False
    main_log.propagate = False

    # Off we go!
    display_banner(banner=MISP_BANNER,
                   logger=splash,
                   fallback=f"MISP Import for CrowdStrike Threat Intelligence v{VERSION}",
                   hide_cool_banners=args.no_banner
                   )

    if not check_config.validate_config(args.config_file, args.debug, args.no_banner):
        do_finished(splash, args)
        raise SystemExit("Invalid configuration specified, unable to continue.")

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


    # Interface to the CrowdStrike Falcon Intel API
    intel_api_client = IntelAPIClient(settings["CrowdStrike"]["client_id"],
                                      settings["CrowdStrike"]["client_secret"],
                                      settings["CrowdStrike"]["crowdstrike_url"],
                                      int(settings["CrowdStrike"]["api_request_max"]),
                                      False if "F" in settings["CrowdStrike"]["api_enable_ssl"].upper() else True,
                                      main_log
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
        "force": args.force,
        "no_banners": args.no_banner,
        "no_dupe_check": args.no_dupe_check,
        "type": args.type,
        "publish": args.publish
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
    importer = CrowdstrikeToMISPImporter(intel_api_client, import_settings, provided_arguments, settings, logger=main_log)

    if args.clean_reports or args.clean_indicators or args.clean_actors:
        perform_local_cleanup(args, importer, settings, main_log)

    if args.clean_tags:
        importer.remove_crowdstrike_tags()

    if args.reports or args.actors or args.indicators:
        #try:
        if not args.no_dupe_check:
            
            # Retrieve all tags for selected options
            if args.actors:
                tags = retrieve_tags("actors", settings)
                importer.import_from_misp(tags, style="actors")
            if args.reports:

                # Reports dupe identification is a little customized
                tags = retrieve_tags("reports", settings)
                importer.import_from_misp(tags, style="reports")
            #if args.indicators:
                # Load report IDs for indicator attribution
                #tags = retrieve_tags("reports", settings)
                #importer.import_from_misp(tags, style="reports")
                # Indicators looks up pre-existing indicators in it's own module

        # Import new events from CrowdStrike into MISP
        importer.import_from_crowdstrike(int(settings["CrowdStrike"]["init_reports_days_before"]),
                                            int(settings["CrowdStrike"]["init_indicators_minutes_before"]),
                                            int(settings["CrowdStrike"]["init_actors_days_before"])
                                            )
        #except Exception as err:
        #    main_log.exception(err)
        #    raise SystemExit(err) from err

    if args.max_age is not None:
        try:
            importer.clean_old_crowdstrike_events(args.max_age, args.type)
        except Exception as err:
            main_log.exception(err)
            raise SystemExit(err) from err
    do_finished(splash, args)


if __name__ == '__main__':

    thread = main_thread()
    thread.name = "main"
    main()
