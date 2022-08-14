"""CrowdStrike Reports MISP event import.

@@@@@@@   @@@@@@@@  @@@@@@@    @@@@@@   @@@@@@@   @@@@@@@   @@@@@@
@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@  @@@@@@@
@@!  @@@  @@!       @@!  @@@  @@!  @@@  @@!  @@@    @@!    !@@
!@!  @!@  !@!       !@!  @!@  !@!  @!@  !@!  @!@    !@!    !@!
@!@!!@!   @!!!:!    @!@@!@!   @!@  !@!  @!@!!@!     @!!    !!@@!!
!!@!@!    !!!!!:    !!@!!!    !@!  !!!  !!@!@!      !!!     !!@!!!
!!: :!!   !!:       !!:       !!:  !!!  !!: :!!     !!:         !:!
:!:  !:!  :!:       :!:       :!:  !:!  :!:  !:!    :!:        !:!
::   :::   :: ::::   ::       ::::: ::  ::   :::     ::    :::: ::
 :   : :  : :: ::    :         : :  :    :   : :     :     :: : :
"""
import datetime
from logging import Logger
import os
import time
import concurrent.futures

try:
    from pymisp import MISPObject, MISPEvent, MISPAttribute, ExpandedPyMISP
except ImportError as no_pymisp:
    raise SystemExit(
        "The PyMISP package must be installed to use this program."
        ) from no_pymisp

from .adversary import Adversary
from .report_type import ReportType
from .helper import confirm_boolean_param, gen_indicator, REPORTS_BANNER
from .intel_client import IntelAPIClient

class ReportsImporter:
    """Tool used to import reports from the Crowdstrike Intel API and push them as events in MISP through the MISP API."""

    def __init__(self,
                 misp_client: ExpandedPyMISP,
                 intel_api_client: IntelAPIClient,
                 crowdstrike_org_uuid: str,
                 reports_timestamp_filename: str,
                 settings: dict,
                 import_settings: dict,
                 logger: Logger
                 ):
        """Construct and return an instance of the ReportsImporter class.

        Arguments
        ----
        misp_client : ExpandedPyMISP
            MISP API client object
        intel_api_client : IntelAPIClient
            CrowdStrike Falcon Intel API client object
        crowdstrike_org_uuid : str
            UUID for the CrowdStrike organization within the MISP instance
        reports_timestamp_filename : str
            Filename for the reports _marker tracking file
        settings : dict
            Dictionary of configuration settings
        import_settings : dict
            Dictionary of import settings
        logger : logging.Logger
            Logging object

        Returns
        ----
        (class) Newly constructed instance of the ReportsImporter class.
        """
        self.misp = misp_client
        self.intel_api_client = intel_api_client
        self.reports_timestamp_filename = reports_timestamp_filename
        self.settings = settings
        self.import_settings = import_settings
        self.crowdstrike_org = self.misp.get_organisation(crowdstrike_org_uuid, True)
        self.log = logger
        self.events_already_imported: dict = {}

    def batch_report_detail(self, id_list: list or str) -> dict:
        """Retrieve extended report details for the ID list provided.
        
        Arguments
        ----
        id_list : list or str
            List of report IDs to retrieve from the CrowdStrike Falcon Intel API.

        Returns
        ----
        (dict) Dictionary containing API response.
        """
        return self.intel_api_client.falcon.get_report_entities(ids=id_list, fields="__full__")["body"]["resources"]

    def batch_import_reports(self, report, rpt_detail, ind_list):
        report_name = report.get('name')
        if report_name is not None:
            if self.events_already_imported.get(report_name) is None:
                event: MISPEvent = self.create_event_from_report(report, rpt_detail, ind_list)
                if event is not None:
                    try:
                        #for tag in self.settings["CrowdStrike"]["reports_tags"].split(","):
                        #    event.add_tag(tag)
                        #for rtype in self.intel_api_client.valid_report_types:
                        #    if rtype.upper() in report.get('name', None):
                        #        event.add_tag(f"CrowdStrike:report: {rtype.upper()}")
                        self.events_already_imported[report_name] = True
                        event = self.misp.add_event(event, True)
                        self.log.debug("%s report created.", report_name)
                    except Exception as err:
                        self.log.warning("Could not add or tag event %s.\n%s", event.info, str(err))
                else:
                    self.log.warning("Failed to create a MISP event for report %s.", report)

                if report.get('last_modified_date') is None:
                    self.log.warning("Failed to confirm report %s in file.", report)
                else:
                    if report.get('last_modified_date') > self.last_pos:
                        self.last_pos = report.get("last_modified_date")

    def get_indicator_detail(self, id_list):
        def query_api(filter_str: str):
            return self.intel_api_client.falcon.query_indicator_entities(
                sort="_marker.asc",
                filter=filter_str,
                limit=5000
            )
        start_time = ""
        startup = True
        returned = []
        marker_check = ""
        while len(returned) > 0 or startup:
            startup = False
            if start_time:
                marker_check = f"_marker:>='{start_time}'+"
            filters = f"{marker_check}reports:{id_list}"
            indicator_lookup = query_api(filters)
            fcnt = 0
            if not isinstance(indicator_lookup, bytes):
                if indicator_lookup["status_code"] == 429:
                    fcnt += 1
                    if fcnt > 3:
                        raise SystemExit("Too many API communication issues.")
                    time.sleep(1*fcnt)
                    indicator_lookup = query_api(filters)
            else:
                indicator_lookup = query_api(filters)

            try:       
                returned = indicator_lookup["body"].get("resources", {})
            
                if returned:
                    yield returned

                    last_marker = returned[-1].get('_marker', '')
                    if last_marker == '' or last_marker == start_time:
                        break
                    start_time = last_marker
            except TypeError:
                pass

    def batch_related_indicators(self, ids):
        found = []
        for indicators_page in self.get_indicator_detail(id_list=ids):
            found.extend(indicators_page)
        return found

    def process_reports(self, reports_days_before, events_already_imported):
        """Pull and process reports.

        :param reports_days_before: in case on an initialisation run, this is the age of the reports pulled in days
        :param events_already_imported: the events already imported in misp, to avoid duplicates
        """
        self.log.info(REPORTS_BANNER)
        start_get_events = int((
            datetime.datetime.today() + datetime.timedelta(days=-int(min(reports_days_before, 366)))
        ).timestamp())
        if os.path.isfile(self.reports_timestamp_filename):
            with open(self.reports_timestamp_filename, 'r', encoding="utf-8") as ts_file:
                line = ts_file.readline()
                if line:
                    start_get_events = int(line)

        log_msg = f"Start getting reports from Crowdstrike Intel API and pushing them as events in MISP (past {reports_days_before} days)."
        self.log.info(log_msg)
        time_send_request = datetime.datetime.now()
        reports = self.intel_api_client.get_reports(start_get_events)
        log_msg = f"Got {str(len(reports))} reports from the Crowdstrike Intel API."
        self.log.info(log_msg)

        if len(reports) == 0:
            with open(self.reports_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                ts_file.write(str(int(time_send_request.timestamp())))
        else:
            #adversary_events = self.misp.get_adversaries()
            report_ids = [rep.get("name").split(" ")[0] for rep in reports]
            rep_batches = [report_ids[i:i+500] for i in range(0, len(report_ids), 500)]
            # Batched retrieval of extended report details
            details = []
            with concurrent.futures.ThreadPoolExecutor(self.misp.thread_count) as executor:
                futures = {
                    executor.submit(self.batch_report_detail, rep) for rep in rep_batches
                }
                for fut in concurrent.futures.as_completed(futures):
                    details.extend(fut.result())

            self.log.info(f"Retrieved extended report details for {len(details)} reports")

            # Batched retrieval of related indicator details
            indicator_list = []
            batches = [report_ids[i:i+200] for i in range(0, len(report_ids), 200)]
            with concurrent.futures.ThreadPoolExecutor(self.misp.thread_count) as executor:
                futures = {
                    executor.submit(self.batch_related_indicators, bat) for bat in batches
                }
                for fut in concurrent.futures.as_completed(futures):
                    indicator_list.extend(fut.result())

            self.log.info(f"{len(indicator_list)} related indicators found")
            self.last_pos = reports[-1].get('last_modified_date', '')

            # Threaded insert of report events into MISP instance
            reported = []
            with concurrent.futures.ThreadPoolExecutor(self.misp.thread_count) as executor:
                futures = {
                    executor.submit(self.batch_import_reports, rp, details, indicator_list) for rp in reports
                }
                for fut in concurrent.futures.as_completed(futures):
                    reported.append(fut.done())

                with open(self.reports_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                    ts_file.write(str(int(self.last_pos)))


        self.log.info("Finished importing %i Crowdstrike Intel reports as events in MISP.", len(reports))

    def add_actor_detail(self, report: dict, event: MISPEvent) -> MISPEvent:
        for actor in report.get('actors', []):
            if actor.get('name'):
                actor_detail = self.intel_api_client.falcon.get_actor_entities(ids=actor.get("id"))
                if actor_detail["status_code"] == 200:
                    actor_detail = actor_detail["body"]["resources"][0]
                actor_name = actor.get('name').split(" ")
                first = actor_detail.get("first_activity_date", 0)
                last = actor_detail.get("last_activity_date", 0)
                actor_proper_name = " ".join([n.title() for n in actor.get("name", "").split(" ")])
                actor_att = {
                    "type": "threat-actor",
                    "value": actor_proper_name,
                }
                if first:
                    actor_att["first_seen"] = first
                if last:
                    actor_att["last_seen"] = last
                att = event.add_attribute(**actor_att)
                for stem in actor_name:
                    for adversary in Adversary:
                        if adversary.name == stem.upper():
                            # Can't cross-tag with this as we're using it for delete
                            #event.add_tag(f"CrowdStrike:adversary:branch: {stem.upper()}")
                            event.add_attribute_tag(f"CrowdStrike:adversary:branch: {stem.upper()}", att.uuid)
                event.add_tag(f"CrowdStrike:report:adversary: {actor.get('name')}")
                 # Event level only
#                for tag in self.settings["CrowdStrike"]["actors_tags"].split(","):
#                    event.add_attribute_tag(tag, att.uuid)

        return event

    def add_indicator_detail(self, event: MISPEvent, report_id: str, indicator_list: list) -> MISPEvent:
        if report_id:
            ind_list = [i for i in indicator_list if report_id in i.get("reports")]
            indicator_count = len(ind_list)
            if indicator_count:
                self.log.debug("Retrieved %i indicators detailed within report %s", indicator_count, report_id)
            for ind in ind_list:
                galaxies = []
                galaxy_tags = []
                for malware_family in ind.get('malware_families', []):
                    galaxy = self.import_settings["galaxy_map"].get(malware_family)
                    if galaxy:
                        galaxies.append(galaxy)
                    else:
                        galaxy_tags.append(malware_family)
                indicator_object = gen_indicator(ind, self.settings["CrowdStrike"]["indicators_tags"].split(","))
                if isinstance(indicator_object, MISPObject):
                    event.add_object(indicator_object)

                elif isinstance(indicator_object, MISPAttribute):
                    ind_seen = {}
                    if ind.get("published_date"):
                        ind_seen["first_seen"] = ind.get("published_date")
                    if ind.get("last_updated"):
                        ind_seen["last_seen"] = ind.get("last_updated")
                    added = event.add_attribute(indicator_object.type, indicator_object.value, category=indicator_object.category, **ind_seen)
                    event.add_attribute_tag(f"CrowdStrike:indicator:type: {indicator_object.type.upper()}", added.uuid)
                    # Event level only
                    #for tag in self.settings["CrowdStrike"]["indicators_tags"].split(","):
                    #    event.add_attribute_tag(tag, added.uuid)
                if confirm_boolean_param(self.settings["TAGGING"].get("tag_unknown_galaxy_maps", False)):
                    for gal in list(set(galaxy_tags)):
                        event.add_tag(f'CrowdStrike:malware:unmapped="{gal}"')
                if galaxy_tags:
                    if confirm_boolean_param(self.settings["TAGGING"].get("taxonomic_WORKFLOW", False)):
                        event.add_tag('workflow:todo="add-missing-misp-galaxy-cluster-values"')
                for galactic in list(set(galaxies)):
                    event.add_tag(galactic)

        return event

    def add_victim_detail(self, report: dict, event: MISPEvent) -> MISPEvent:
        victim = None
        # Targeted countries
        if report.get("target_countries", None):
            region_list = [c.get('value') for c in report.get('target_countries', [])]
            for country in region_list:
                if not victim:
                    victim = MISPObject("victim")
                vic = victim.add_attribute('regions', country)
                vic.add_tag(f"CrowdStrike:target:location: {country.upper()}")
                # Also create a target-location attribute for this value  (Too noisy?)
                # reg = event.add_attribute('target-location', country)
                # event.add_attribute_tag(f"CrowdStrike:target: {country.upper()}", reg.uuid)

        # Targeted industries
        if report.get("target_industries", None):
            for industry in report.get('target_industries', []):
                sector = industry.get('value', None)
                if sector:
                    if not victim:
                        victim = MISPObject("victim")
                    vic = victim.add_attribute('sectors', sector)
                    vic.add_tag(f"CrowdStrike:target:sector: {sector.upper()}")
            if victim:
                event.add_object(victim)

        return event

    def add_report_content(self, report: dict, event: MISPEvent, details: dict, report_id: str, seen: dict) -> MISPEvent:
        attributes: list[MISPAttribute] = []
        # report_tag = None
        # for rtype in [r for r in dir(ReportType) if "__" not in r]: #self.intel_api_client.valid_report_types:
        #     if report.get('name', None).startswith(rtype.upper()):
        #         report_tag = rtype.upper()
        rpt_cat = "Internal reference"
        short_desc = details.get("short_description")
        if not short_desc:
            short_desc = report.get("short_description")
        if short_desc:
            rpt = MISPObject("report")
            if report_id:
                attributes.append(rpt.add_attribute("case-number", report_id, category=rpt_cat, **seen))
            attributes.append(rpt.add_attribute("type", "Report", category=rpt_cat, **seen))
            attributes.append(rpt.add_attribute("summary", short_desc, category=rpt_cat, **seen))
            attributes.append(rpt.add_attribute("link", report.get("url"), **seen))
            if details.get("attachments"):
                for attachment in details.get("attachments"):
                    attributes.append(rpt.add_attribute("report-file", attachment.get("url"), **seen))
            event.add_object(rpt)

        # Report Annotation and full text
        if details.get('description'):
            annot = MISPObject("annotation")
            attributes.append(annot.add_attribute("text", details.get("description"), category=rpt_cat, **seen))
            attributes.append(annot.add_attribute("format", "text", category=rpt_cat, **seen))
            attributes.append(annot.add_attribute("type", "Full Report", category=rpt_cat, **seen))
            attributes.append(annot.add_attribute("ref", report.get("url"), **seen))
            event.add_object(annot)

            event.add_event_report(report.get("name"), details.get("description"))

        for att in attributes:
            # Event level only
            #for tag in self.settings["CrowdStrike"]["reports_tags"].split(","):
            #    event.add_attribute_tag(tag, att.uuid)
            if att.value not in ["text", "Full Report", "Report", report_id]:
                event.add_attribute_tag(f"CrowdStrike:report:{report_id.lower().replace('-',': ')}", att.uuid)
            #if report_tag:
            #    event.add_attribute_tag(f"CrowdStrike:report: {report_tag.upper()}", att.uuid)

        return event

    def create_event_from_report(self, report, report_details, indicator_list) -> MISPEvent:
        """Create a MISP event from a Intel report."""
        if report.get('name'):
            event = MISPEvent()
            event.analysis = 2
            event.orgc = self.crowdstrike_org
            # Extended report details lookup
            details = {}
            for det in report_details:
                if det.get("id") == report.get("id"):
                    details = det
            report_name = report.get('name')
            # Report / Event name
            event.info = report_name
            # Report ID
            report_id = report_name.split(" ")[0]
            # Report type tag
            report_type = None
            report_type_id = report_id.split("-")[0]
            for rpt_type in [r for r in dir(ReportType) if "__" not in r]:
                if rpt_type == report_type_id:
                    report_type = ReportType[rpt_type].value
            if "Q" in report_id.upper():
                report_type = "Quarterly Report"
            event.add_tag(f"CrowdStrike:report:type: {report_type_id}")
            event.add_tag(f"CrowdStrike:report: {report_type.upper()}")
            # First / Last seen timestamps
            seen = {}
            if details.get("created_date"):
                seen["first_seen"] = details.get("created_date")
            if details.get("last_modified_date"):
                seen["last_seen"] = details.get("last_modified_date")

            # Actors - Attribution attributes
            event = self.add_actor_detail(report, event)
            # Victim Object
            event = self.add_victim_detail(report, event)
            # Report indicators
            event = self.add_indicator_detail(event, report_id, indicator_list)
            # Formatted report link and content
            event = self.add_report_content(report, event, details, report_id, seen)
            # TYPE Taxonomic tag, all events
            if confirm_boolean_param(self.settings["TAGGING"].get("taxonomic_TYPE", False)):
                event.add_tag('type:CYBINT')
            # INFORMATION-SECURITY-DATA-SOURCE Taxonomic tag, all events
            if confirm_boolean_param(self.settings["TAGGING"].get("taxonomic_INFORMATION-SECURITY-DATA-SOURCE", False)):
                event.add_tag('information-security-data-source:integrability-interface="api"')
                event.add_tag('information-security-data-source:originality="original-source"')
                event.add_tag('information-security-data-source:type-of-source="security-product-vendor-website"')
            if confirm_boolean_param(self.settings["TAGGING"].get("taxonomic_IEP", False)):
                event.add_tag('iep:commercial-use="MUST NOT"')
                event.add_tag('iep:provider-attribution="MUST"')
                event.add_tag('iep:unmodified-resale="MUST NOT"')
            if confirm_boolean_param(self.settings["TAGGING"].get("taxonomic_IEP2", False)):
                if confirm_boolean_param(self.settings["TAGGING"].get("taxonomic_IEP2_VERSION", False)):
                    event.add_tag('iep2-policy:iep_version="2.0"')
                event.add_tag('iep2-policy:attribution="must"')
                event.add_tag('iep2-policy:unmodified_resale="must-not"')
            if confirm_boolean_param(self.settings["TAGGING"].get("taxonomic_TLP", False)):
                event.add_tag("tlp:amber")

        else:
            self.log.warning("Report %s missing name field.", report.get('id'))

        return event