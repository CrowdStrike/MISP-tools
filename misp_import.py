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
from dataclasses import dataclass
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from configparser import ConfigParser, ExtendedInterpolation
from threading import main_thread
import time
import logging
import os
import urllib3
from cs_misp_import.indicator_type import IndicatorType
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

    parser.add_argument("-f", "--force",
                        action="store_true",
                        help="Force operation.")

    parser.add_argument("-d", "--debug",
                        action="store_true",
                        dest="debug",
                        help="Activate debug logs.")

    parser.add_argument("-i", "--indicators",
                        action="store_true",
                        help="Import all indicators.")

    parser.add_argument("-r", "--reports",
                        action="store_true",
                        help="Set this to import reports.")

    parser.add_argument("-a", "--actors",
                        action="store_true",
                        dest="actors",
                        help="Set this to import adversaries.")

    parser.add_argument("-cr", "--clean_reports",
                        action="store_true",
                        dest="clean_reports",
                        help="Run a cleaning round on reports.")

    parser.add_argument("-ci", "--clean_indicators",
                        action="store_true",
                        dest="clean_indicators",
                        help="Run a cleaning round on indicators.")

    parser.add_argument("-ca", "--clean_actors",
                        action="store_true",
                        dest="clean_actors",
                        help="Run a cleaning round on adversaries.")

    parser.add_argument("-do", "--delete_outdated_indicators",
                        action='store_true',
                        help="Delete imported indicators that are marked as deleted.")

    parser.add_argument("-c", "--config",
                        dest="config_file",
                        help="Path to local configuration file.",
                        required=False, default="misp_import.ini")

    parser.add_argument("-v", "--verbose_tagging",
                        action="store_false",
                        dest="verbose",
                        help="Disable verbose tagging.",
                        required=False, default=True)

    parser.add_argument("--obliterate",
                        action="store_true",
                        dest="obliterate",
                        help="Remove all CrowdStrike data.",
                        required=False, default=False)

    parser.add_argument("-l", "--logfile",
                        help="Log file for logging output.",
                        required=False, default="misp_import.log")

    parser.add_argument("-p", "--publish",
                        action="store_true",
                        dest="publish",
                        help="Publish events upon creation.",
                        required=False, default=False)

    parser.add_argument("--all", "--fullmonty",
                        action="store_true",
                        dest="fullmonty",
                        help="Import Adversaries, Reports and Indicators.",
                        required=False, default=False)

    parser.add_argument("-nh", "--no_hashes",
                        action="store_true",
                        dest="nohash",
                        help="Do not import SHA1, SHA256 or MD5 hash indicators.",
                        required=False, default=False)

    parser.add_argument("-ct", "--clean_tags",
                        action="store_true",
                        dest="clean_tags",
                        help="Remove all CrowdStrike tags from the MISP instance.",
                        required=False)

    parser.add_argument("-t", "--type",
                        type=str,
                        dest="type",
                        help="Import only this type (report, indicator, adversary).",
                        required=False, default=False)

    parser.add_argument("-nd", "--no_dupe_check",
                        action="store_true",
                        dest="no_dupe_check",
                        help="Enable or disable duplicate checking on import, defaults to False.",
                        required=False)

    parser.add_argument("-nb", "--no_banner",
                        action="store_true",
                        dest="no_banner",
                        help="Disable ASCII banners in logfile output, defaults to False (enable banners).",
                        required=False)

    parser.add_argument("-m", "--max_age",
                        type=int,
                        dest="max_age",
                        help="Maximum age of objects to be stored in MISP in days."" Objects older will be deleted.")

    parsed = parser.parse_args()

    if parsed.obliterate and parsed.fullmonty:
        parser.error("You cannot run Obliterate and the Full Monty at the same time.")

    # Delete EVERYTHING
    if parsed.obliterate:
        parsed.clean_actors = True
        parsed.clean_reports = True
        parsed.clean_indicators = True
        parsed.clean_tags = True
        bold = "\033[1m"
        undie = "\033[4m"
        endmark = "\033[0m"
        print(f"{'😱 ' * 25}\n")
        print(WARNING_BANNER)
        confirmed = input(
            f"{'😱 ' * 25}\n\nObliterate is a destructive operation that will remove "
            f"{bold}{undie}all CrowdStrike data{endmark}\nfrom your MISP instance. There is "
            "no going back once this process completes.\n\n"
            "Are you sure you want to do this?\n\n[Enter 'yes' to continue] ==> ")
        if confirmed.upper() != "YES":
            raise SystemExit("Data obliteration has been cancelled. Phew! 😌")
        print(MUSHROOM)
        time.sleep(1)

    if parsed.fullmonty:
        parsed.actors = True
        parsed.reports = True
        parsed.indicators = True

    if parsed.nohash:
        hash_exclude = ["HASH_MD5", "HASH_SHA1", "HASH_SHA256"]
        parsed.type = ",".join(
            [it.name for it in IndicatorType if it.name not in hash_exclude])

    return parsed


@dataclass
class Loggers:
    """Loggers dataclass."""
    splash: logging.Logger
    main: logging.Logger


class ConfigHandler:
    """ConfigParser Handler.

        :param str config_file: ini config file name
    """
    def __init__(self, config_file):
        self.config_file = config_file
        self.settings = {}
        self.galaxy_maps = {}
        self.import_settings = {}
        self.proxies = {}
        self.ex_headers = {}

    def load_settings_file(self) -> None:
        """Parse the settings ini file using ConfigParser."""
        self.settings = ConfigParser(interpolation=ExtendedInterpolation())
        # optionxform preserves casing for keys within the settings file
        self.settings.optionxform = str
        self.settings.read(self.config_file)

        try:
            if not self.settings["MISP"]["misp_enable_ssl"]:
                urllib3.disable_warnings(
                    urllib3.exceptions.InsecureRequestWarning)
        except AttributeError:
            pass

    def load_galaxy_maps_file(self) -> None:
        """Parse the galaxy mappings ini file using ConfigParser."""
        self.galaxy_maps = ConfigParser(interpolation=ExtendedInterpolation())
        self.galaxy_maps.read(self.settings["MISP"].get("galaxy_map_file",
                                                        "galaxy.ini"))

    def configure_proxy(self) -> None:
        """Parse settings dictionary to set proxy."""
        if "PROXY" in self.settings:
            if "http" in self.settings["PROXY"]:
                self.proxies["http"] = self.settings["PROXY"]["http"]
            if "https" in self.settings["PROXY"]:
                self.proxies["https"] = self.settings["PROXY"]["https"]

    def configure_extra_headers(self) -> None:
        """Parse settings dictionary to set extra headers."""
        if "EXTRA_HEADERS" in self.settings:
            for head_i, head_v in self.settings["EXTRA_HEADERS"].items():
                self.ex_headers[head_i] = head_v

    def create_import_settings(self, args: Namespace) -> None:
        """Return a dictionary of assigned settings from the configuration file."""
        self.import_settings = {
            "misp_url": self.settings["MISP"]["misp_url"],
            "misp_auth_key": self.settings["MISP"]["misp_auth_key"],
            "crowdstrike_org_uuid": self.settings["MISP"]["crowdstrike_org_uuid"],
            "reports_timestamp_filename": self.settings["CrowdStrike"]["reports_timestamp_filename"],
            "indicators_timestamp_filename": self.settings["CrowdStrike"]["indicators_timestamp_filename"],
            "actors_timestamp_filename": self.settings["CrowdStrike"]["actors_timestamp_filename"],
            "unknown_mapping": self.settings["CrowdStrike"]["unknown_mapping"],
            "max_threads": self.settings["MISP"].get("max_threads", None),
            "miss_track_file": self.settings["MISP"].get("miss_track_file", "no_galaxy_mapping.log"),
            "misp_enable_ssl": False if "F" in self.settings["MISP"]["misp_enable_ssl"].upper() else True,
            "galaxy_map": self.galaxy_maps["Galaxy"],
            "force": args.force,
            "no_banners": args.no_banner,
            "no_dupe_check": args.no_dupe_check,
            "type": args.type,
            "publish": args.publish,
            "verbose_tags": args.verbose,
            "ext_headers": self.ex_headers,
            "proxy": self.proxies,
            "actor_map": {}
        }
        if not self.import_settings["unknown_mapping"]:
            self.import_settings["unknown_mapping"] = "Unidentified"

    def build(self, args: Namespace) -> None:
        """Initialize dictionary mappings for Crowdstrike/MISP API."""
        self.load_settings_file()
        self.load_galaxy_maps_file()
        self.configure_proxy()
        self.configure_extra_headers()
        self.create_import_settings(args)


class ImportHandler:
    """Construct an instance of the ImportHandler class.

        :param ConfigHandler config: Config class
        :param IntelAPIClient api_client: CrowdStrike API client
        :param logging logger: logging class
        :param Namespace args: ArgumentParser class
    """
    def __init__(self,
                 config: ConfigHandler,
                 api_client: IntelAPIClient,
                 logger: logging,
                 args: Namespace):
        self.config = config
        self.api_client = api_client
        self.logger = logger
        self.args = args
        self.importer = CrowdstrikeToMISPImporter(
            self.api_client,
            self.config.import_settings,
            self.build_provided_arguments(),
            self.config.settings,
            logger=self.logger
        )

    def build_provided_arguments(self) -> dict:
        """Return a dictionary of mapped argument settings."""
        return {
            "reports": self.args.reports,
            "indicators": self.args.indicators,
            "delete_outdated_indicators": self.args.delete_outdated_indicators,
            "actors": self.args.actors
        }

    def retrieve_tags(self, tag_type: str) -> list:
        """
        Retrieve all tags used for CrowdStrike elements within MISP
        (broken out by type).
        """
        tags = []
        if tag_type == "reports":
            for report_type in [r.value for r in ReportType]:
                tags.append(f"crowdstrike:report-type=\"{report_type}\"")
        if tag_type == "actors":
            for adv_type in [a.name for a in Adversary]:
                tags.append(f"crowdstrike:branch=\"{adv_type}\"")

        return tags

    def perform_local_cleanup(self) -> None:
        """Remove local offset cache files to reset the marker for data pulls from the CrowdStrike API."""
        try:
            self.importer.clean_crowdstrike_events(
                self.args.clean_reports,
                self.args.clean_indicators,
                self.args.clean_actors)

            # Delete reports file using filename from config
            if self.args.clean_reports and os.path.isfile(self.config.settings["CrowdStrike"]["reports_timestamp_filename"]):
                os.remove(self.config.settings["CrowdStrike"]["reports_timestamp_filename"])
                self.logger.info("Finished resetting CrowdStrike Report offset.")

            # Delete indicators file using filename from config
            if self.args.clean_indicators and os.path.isfile(self.config.settings["CrowdStrike"]["indicators_timestamp_filename"]):
                os.remove(self.config.settings["CrowdStrike"]["indicators_timestamp_filename"])
                self.logger.info("Finished resetting CrowdStrike Indicator offset.")

            # Delete actors file using filename from config
            if self.args.clean_actors and os.path.isfile(self.config.settings["CrowdStrike"]["actors_timestamp_filename"]):
                os.remove(self.config.settings["CrowdStrike"]["actors_timestamp_filename"])
                self.logger.info("Finished resetting CrowdStrike Adversary offset.")
        except Exception as err:
            self.logger.exception(err)
            raise SystemExit(err) from err

    def import_new_events(self) -> None:
        """Check for duplicates, begin import process."""
        if self.args.reports or self.args.actors or self.args.indicators:
            # Conditional for duplicate checking
            if not self.args.no_dupe_check:

                # Retrieve all tags for selected options
                if self.args.actors:
                    tags = self.retrieve_tags("actors")
                    self.importer.import_from_misp(tags, style="actors")
                if self.args.reports:

                    # Reports dupe identification is a little customized
                    tags = self.retrieve_tags("reports")
                    self.importer.import_from_misp(tags, style="reports")

            # Import new events from CrowdStrike into MISP
            self.importer.import_from_crowdstrike(
                int(self.config.settings["CrowdStrike"]["init_reports_days_before"]),
                int(self.config.settings["CrowdStrike"]["init_indicators_minutes_before"]),
                int(self.config.settings["CrowdStrike"]["init_actors_days_before"])
                )

    def build(self) -> None:
        """Initialize import staging."""
        if self.args.clean_reports or self.args.clean_indicators or self.args.clean_actors:
            self.perform_local_cleanup()
        if self.args.clean_tags:
            self.importer.remove_crowdstrike_tags()

        # Using parsed arguments, import actors/reports/indicators
        self.import_new_events()

        if self.args.max_age is not None:
            try:
                self.importer.clean_old_crowdstrike_events(self.args.max_age, self.args.type)
            except Exception as err:
                self.logger.exception(err)
                raise SystemExit(err) from err


def setup_logging(args: Namespace) -> Loggers:
    """Initialize logging handlers"""
    splash = logging.getLogger("misp_tools")
    splash.setLevel(logging.INFO)
    main_log = logging.getLogger("processor")
    main_log.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch2 = logging.StreamHandler()
    ch2.setLevel(logging.INFO)
    if args.debug:
        main_log.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
        ch2.setLevel(logging.DEBUG)

    ch.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)-8s"
        "%(name)-13s %(message)s"))
    ch2.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)-8s"
        "%(name)s/%(threadName)-10s %(message)s"))
    splash.addHandler(ch)
    main_log.addHandler(ch2)
    splash.propagate = False
    main_log.propagate = False

    return Loggers(splash=splash, main=main_log)


def create_intel_api_client(config: ConfigHandler,
                            main_log: logging.Logger) -> IntelAPIClient:
    """Initialize the CrowdStrike API client."""
    return IntelAPIClient(
        config.settings["CrowdStrike"]["client_id"],
        config.settings["CrowdStrike"]["client_secret"],
        config.settings["CrowdStrike"]["crowdstrike_url"],
        int(config.settings["CrowdStrike"]["api_request_max"]),
        config.ex_headers,
        config.proxies,
        config.settings["CrowdStrike"]["api_enable_ssl"],
        main_log
    )


def do_finished(logg: logging.Logger, args: ArgumentParser) -> None:
    """Print the FINISHED_BANNER."""
    display_banner(
        banner=FINISHED_BANNER,
        logger=logg,
        fallback="FINISHED",
        hide_cool_banners=args.no_banner
    )


def print_intro(logg: logging.Logger, args: ArgumentParser) -> None:
    """Print the MISP_BANNER"""
    display_banner(
        banner=MISP_BANNER,
        logger=logg,
        fallback=f"MISP Import for CrowdStrike Threat Intelligence v{VERSION}",
        hide_cool_banners=args.no_banner
    )


def main():
    """Implement Main routine."""
    args = parse_command_line()
    # Initialize main and splash loggers
    loggers = setup_logging(args)

    print_intro(loggers.splash, args)

    if not check_config.validate_config(args.config_file,
                                        args.debug,
                                        args.no_banner):
        do_finished(loggers.splash, args)
        raise SystemExit(
            "Invalid configuration specified, unable to continue.")
    # Utilize ConfigParser to build various settings, galaxy maps
    config = ConfigHandler(args.config_file)
    config.build(args)

    intel_api_client = create_intel_api_client(config, loggers.main)
    # Handle deletion/importing of CrowdStrike data locally and on MISP
    import_handler = ImportHandler(config, intel_api_client,
                                   loggers.main, args)
    import_handler.build()

    do_finished(loggers.splash, args)


if __name__ == '__main__':
    thread = main_thread()
    thread.name = "main"
    main()
