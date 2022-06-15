import datetime
import logging
import os

try:
    from pymisp import MISPObject, MISPEvent, MISPOrganisation
except ImportError as no_pymisp:
    raise SystemExit(
        "The PyMISP package must be installed to use this program."
        ) from no_pymisp


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

        if report.get("target_countries", None):
            for country in report.get('target_countries', []):
                if country.get('value'):
                    country_object = MISPObject('victim')
                    country_object.add_attribute('regions', country.get('value'))
                    event.add_object(country_object)
                else:
                    logging.warning("Target country from report %s missing value field.", report.get('id'))
        if report.get("target_industries", None):
            for industry in report.get('target_industries', []):
                if industry.get('value'):
                    industry_object = MISPObject('victim')
                    industry_object.add_attribute('sectors', industry.get('value'))
                    event.add_object(industry_object)
                else:
                    logging.warning("Target industry from report %s missing value field.", report.get('id'))

        return event
