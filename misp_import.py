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
from cs_misp_import.indicator_type import IndicatorType
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
# from cs_misp_import.helper import confirm_boolean_param

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
    
    parser.add_argument("-o", "--obliterate",        
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
    
    parser.add_argument("-al", "--fullmonty",         
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
                        help="Enable or disable ASCII banners in logfile output, defaults to False (enable banners).", 
                        required=False)
    
    parser.add_argument("-m", "--max_age",           
                        type=int,             
                        dest="max_age",          
                        help="Maximum age of the objects to be stored in MISP in days."" Objects older than that will be deleted.")


    parsed = parser.parse_args()

    # exclus = parser.add_mutually_exclusive_group("exclusive arguments")
    # group = parser.add_mutually_exclusive_group()
    # group.add_argument("--related_indicators", action="store_true",
    #                    help="Set this to only import indicators related to reports."
    #                    )

    if parsed.obliterate and parsed.fullmonty:
        parser.error("You cannot run Obliterate and the Full Monty at the same time.")

    # Delete EVERYTHING
    if parsed.obliterate:
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
    
    if parsed.obliterate:
        parsed.clean_actors = True
        parsed.clean_reports = True
        parsed.clean_indicators = True
        parsed.clean_tags = True
    
    if parsed.nohash:
        hash_exclude = ["HASH_MD5", "HASH_SHA1", "HASH_SHA256"]
        parsed.type = ",".join([it.name for it in IndicatorType if it.name not in hash_exclude])
    
    return parsed

def init_logging(debug_flag: bool):
    """Initialize logging for misp_tools and processor"""
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
    if debug_flag:
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
    return (splash, main_log)

def load_configuration_files(config_file: str):
    """ Parse the ini files using ConfigParser"""
    # Parse configuraion file
    settings = ConfigParser(interpolation=ExtendedInterpolation())
    settings.optionxform = str  # Don't lowercase configuration keys
    settings.read(config_file)

    # Parse galaxy mappings
    galaxy_maps = ConfigParser(interpolation=ExtendedInterpolation())
    galaxy_maps.read(settings["MISP"].get("galaxy_map_file", "galaxy.ini"))

    return (settings, galaxy_maps)

def define_setting_headers(settings: ConfigParser):
    """Sets the headers based on the used configuration file"""
    try:
        if not settings["MISP"]["misp_enable_ssl"]:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except AttributeError:
        # Not specified, default to enable warnings
        pass

    # Configure the proxy if specified
    proxies = {}
    if "PROXY" in settings:
        # Only the two proxies (http / https) are allowed
        if "http" in settings["PROXY"]:
            proxies["http"] = settings["PROXY"]["http"]
        if "https" in settings["PROXY"]:
            proxies["https"] = settings["PROXY"]["https"]

    # Set any extra headers to pass to the APIs
    extra_headers = {}
    if "EXTRA_HEADERS" in settings:
        for header_item,header_value in settings["EXTRA_HEADERS"].items():
            set_val = header_value
            # MISP only allows str or bytes header values
            # try:
            #     set_val = int(header_value)
            # except ValueError:
            #     if header_value.lower() in ["true", "false"]:
            #         set_val = confirm_boolean_param(header_value)

            extra_headers[header_item] = set_val
    return (proxies, extra_headers)

def create_intel_api_client(settings: ConfigParser, 
                            proxies: dict, 
                            extra_headers: dict, 
                            main_log: logging.Logger):
    """Initializes the CrowdStrike API client"""
    return IntelAPIClient(settings["CrowdStrike"]["client_id"],
                                      settings["CrowdStrike"]["client_secret"],
                                      settings["CrowdStrike"]["crowdstrike_url"],
                                      int(settings["CrowdStrike"]["api_request_max"]),
                                      extra_headers,
                                      proxies,
                                      False if "F" in settings["CrowdStrike"]["api_enable_ssl"].upper() else True,
                                      main_log
                                      )

def create_import_settings(settings: ConfigParser, 
                           galaxy_maps: ConfigParser, 
                           args: Namespace, 
                           proxies: dict, 
                           extra_headers: dict):
    """Returns a dictionary of assigned settings from the configuration file"""
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
        "publish": args.publish,
        "verbose_tags": args.verbose,
        "ext_headers": extra_headers,
        "proxy": proxies,
        "actor_map": {}
    }
    if not import_settings["unknown_mapping"]:
        import_settings["unknown_mapping"] = "Unidentified"
    
    return import_settings

def build_provided_arguments(args: Namespace) -> dict:
    """Returns a dictionary of mapped argument settings"""
    return {
        "reports": args.reports,
        "indicators": args.indicators,
#        "delete_outdated_indicators": args.delete_outdated_indicators,
        "actors": args.actors
    }

def perform_local_cleanup(args: Namespace,
                          importer: CrowdstrikeToMISPImporter,
                          settings: ConfigParser,
                          log_device: logging.Logger
                          ):
    """Remove local offset cache files to reset the marker for data pulls from the CrowdStrike API."""
    try:

        importer.clean_crowdstrike_events(args.clean_reports, args.clean_indicators, args.clean_actors)
        
        # Delete reports file using filename from config
        if args.clean_reports and os.path.isfile(settings["CrowdStrike"]["reports_timestamp_filename"]):
            os.remove(settings["CrowdStrike"]["reports_timestamp_filename"])
            log_device.info("Finished resetting CrowdStrike Report offset.")
        
        # Delete indicators file using filename from config
        if args.clean_indicators and os.path.isfile(settings["CrowdStrike"]["indicators_timestamp_filename"]):
            os.remove(settings["CrowdStrike"]["indicators_timestamp_filename"])
            log_device.info("Finished resetting CrowdStrike Indicator offset.")
        
        # Delete actors file using filename from config
        if args.clean_actors and os.path.isfile(settings["CrowdStrike"]["actors_timestamp_filename"]):
            os.remove(settings["CrowdStrike"]["actors_timestamp_filename"])
            log_device.info("Finished resetting CrowdStrike Adversary offset.")
    
    except Exception as err:
        log_device.exception(err)
        raise SystemExit(err) from err

def retrieve_tags(tag_type: str, settings: ConfigParser):
    """Retrieve all tags used for CrowdStrike elements within MISP (broken out by type)."""
    tags = []
    if tag_type == "reports":
        for report_type in [r.value for r in ReportType]:
            tags.append(f"crowdstrike:report-type=\"{report_type}\"")
    # No indicators dupe checking atm - jshcodes@CrowdStrike / 08.18.22
    # if args.indicators:
    #     tags.append(settings["CrowdStrike"]["indicators_unique_tag"])
    if tag_type == "actors":
        #tags.append(f"crowdstrike:report-type=\"Adversary Detail Report\"")
        for adv_type in [a.name for a in Adversary]:
            tags.append(f"crowdstrike:branch=\"{adv_type}\"")

    return tags
   
def import_new_events(args:Namespace, 
                      importer:CrowdstrikeToMISPImporter, 
                      settings:ConfigParser):
    """Checks for duplicates, begins import process"""
    if args.reports or args.actors or args.indicators:
        # Conditional for duplicate checking
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

def do_finished(logg: logging.Logger, arg_parser: ArgumentParser):
    """Prints the FINISHED_BANNER"""
    display_banner(banner=FINISHED_BANNER,
                   logger=logg,
                   fallback="FINISHED",
                   hide_cool_banners=arg_parser.no_banner
                   )

def main():
    """Implement Main routine."""
    args = parse_command_line()
    splash,main_log = init_logging(args.debug)
    display_banner(banner=MISP_BANNER, logger=splash, fallback=f"MISP Import for CrowdStrike Threat Intelligence v{VERSION}", hide_cool_banners=args.no_banner)

    if not check_config.validate_config(args.config_file, args.debug, args.no_banner):
        do_finished(splash, args)
        raise SystemExit("Invalid configuration specified, unable to continue.")

    settings, galaxy_maps  = load_configuration_files(args.config_file)
    proxies, extra_headers = define_setting_headers(settings)
    intel_api_client       = create_intel_api_client(settings, proxies, extra_headers, main_log)
    import_settings        = create_import_settings(settings, galaxy_maps, args, proxies, extra_headers)
    provided_arguments     = build_provided_arguments(args)
    
    importer = CrowdstrikeToMISPImporter(intel_api_client, import_settings, provided_arguments, settings, logger=main_log)

    if args.clean_reports or args.clean_indicators or args.clean_actors:
        perform_local_cleanup(args, importer, settings, main_log)
    if args.clean_tags:
        importer.remove_crowdstrike_tags()

    import_new_events(args, importer, settings)

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
