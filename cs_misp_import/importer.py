import datetime
import logging

import concurrent.futures

from .actors import ActorsImporter
from .indicators import IndicatorsImporter
from .reports import ReportsImporter
from .threaded_misp import MISP


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
        self.config = provided_arguments
        self.settings = settings
        self.unique_tags = {
            "reports": import_settings["reports_unique_tag"],
            "indicators": import_settings["indicators_unique_tag"],
            "actors": import_settings["actors_unique_tag"],
        }
        self.import_settings = import_settings

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
                                                          self.settings,
                                                          self.import_settings
                                                          )
        if self.config["actors"]:
            self.actors_importer = ActorsImporter(self.misp_client, intel_api_client, import_settings["crowdstrike_org_uuid"],
                                                  import_settings["actors_timestamp_filename"], self.settings, import_settings["unknown_mapping"])

    def clean_crowdstrike_events(self, clean_reports, clean_indicators, clean_actors, starting, ending):
        """Delete events from a MISP instance."""

        tags = []
        if clean_reports:
            tags.append(self.unique_tags["reports"])
        if clean_indicators:
            tags.append(self.unique_tags["indicators"])
        if clean_actors:
            tags.append(self.unique_tags["actors"])
        time_step = -28800  # *Modem noise*
        ending = ending - time_step
        if clean_reports or clean_indicators or clean_actors:
            self.misp_client.deleted_event_count = 0
            # threaded_request(self.misp_client.delete_event, self.misp_client.search_index(tags=tags), self.max_threads)
            for page_time in range(ending, starting, time_step):
                with concurrent.futures.ThreadPoolExecutor(self.misp_client.thread_count) as executor:
                    executor.map(self.misp_client.delete_event, self.misp_client.search_index(tags=tags, minimal=True, timestamp=page_time))
                logging.info("Finished cleaning up a batch of Crowdstrike related events from MISP, %i events deleted.", self.misp_client.deleted_event_count)

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
            with concurrent.futures.ThreadPoolExecutor(self.misp_client.thread_count) as executor:
                executor.map(self.misp_client.delete_event, events)
            logging.info("Finished cleaning up Crowdstrike related events from MISP.")

    def import_from_crowdstrike(self,
                                reports_days_before: int = 7,
                                indicators_days_before: int = 7,
                                actors_days_before: int = 7,
                                starting: int = None,
                                ending: int = None
                                ):
        """Import reports and events from Crowdstrike Intel API.

        :param reports_days_before: in case on an initial run, this is the age of the reports pulled in days
        :param indicators_days_before: in case on an initial run, this is the age of the indicators pulled in days
        :param actors_days_before: in case on an initial run, this is the age of the actors pulled in days
        """
        if self.config["reports"]:
            self.reports_importer.process_reports(reports_days_before, self.event_ids)
        if self.config["related_indicators"] or self.config["all_indicators"]:
            self.indicators_importer.process_indicators(indicators_days_before, self.event_ids, starting, ending)
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