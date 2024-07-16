"""CrowdStrike Adversary (Actor) MISP event import.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |                         |::.. . |
`-------'                         `-------'

   @@@@@@   @@@@@@@   @@@  @@@  @@@@@@@@  @@@@@@@    @@@@@@    @@@@@@   @@@@@@@   @@@ @@@
  @@@@@@@@  @@@@@@@@  @@@  @@@  @@@@@@@@  @@@@@@@@  @@@@@@@   @@@@@@@@  @@@@@@@@  @@@ @@@
  @@!  @@@  @@!  @@@  @@!  @@@  @@!       @@!  @@@  !@@       @@!  @@@  @@!  @@@  @@! !@@
  !@!  @!@  !@!  @!@  !@!  @!@  !@!       !@!  @!@  !@!       !@!  @!@  !@!  @!@  !@! @!!
  @!@!@!@!  @!@  !@!  @!@  !@!  @!!!:!    @!@!!@!   !!@@!!    @!@!@!@!  @!@!!@!    !@!@!
  !!!@!!!!  !@!  !!!  !@!  !!!  !!!!!:    !!@!@!     !!@!!!   !!!@!!!!  !!@!@!      @!!!
  !!:  !!!  !!:  !!!  :!:  !!:  !!:       !!: :!!        !:!  !!:  !!!  !!: :!!     !!:
  :!:  !:!  :!:  !:!   ::!!:!   :!:       :!:  !:!      !:!   :!:  !:!  :!:  !:!    :!:
  ::   :::   :::: ::    ::::     :: ::::  ::   :::  :::: ::   ::   :::  ::   :::     ::
   :   : :  :: :  :      :      : :: ::    :   : :  :: : :     :   : :   :   : :     :
"""
import datetime
import logging
import os
import time
import concurrent.futures

try:
    from pymisp import MISPObject, MISPEvent, ExpandedPyMISP, MISPGalaxyCluster, MISPGalaxyClusterElement
except ImportError as no_pymisp:
    raise SystemExit(
        "The PyMISP package must be installed to use this program."
        ) from no_pymisp
from markdownify import markdownify
from .adversary import Adversary
from .adversary_motivations import AdversaryMotivation
from .helper import (
    ADVERSARIES_BANNER,
    confirm_boolean_param,
    display_banner,
    get_threat_actor_galaxy_id,
    get_actor_galaxy_map,
    add_cluster_elements,
    normalize_locale,
    normalize_sector,
    get_region_galaxy_map,
    normalize_threatmatch,
    taxonomic_event_tagging
    )

class ActorsImporter:
    """Tool used to import actors from the Crowdstrike Intel API and push them as events in MISP through the MISP API.

    :param misp_client: client for a MISP instance
    :param intel_api_client: client for the Crowdstrike Intel API
    """

    def __init__(self, misp_client, intel_api_client, crowdstrike_org_uuid, actors_timestamp_filename, distribution, sharing_group_id, settings, import_settings, logger = None):
        """Construct an instance of the ActorsImporter class."""
        self.misp: ExpandedPyMISP = misp_client
        self.intel_api_client = intel_api_client
        self.actors_timestamp_filename = actors_timestamp_filename
        self.crowdstrike_org = self.misp.get_organisation(crowdstrike_org_uuid, True)
        self.distribution = distribution
        self.sharing_group_id = sharing_group_id
        self.settings = settings
        self.unknown = import_settings.get("unknown_mapping", "UNIDENTIFIED")
        self.import_settings = import_settings
        self.log: logging.Logger = logger
        self.regions = get_region_galaxy_map(misp_client)

    def adversary_galaxy_tag(self, actor: str):
        return self.import_settings["actor_map"][actor.upper()]["tag_name"]


    def batch_import_actors(self, act, act_det, already):
        def do_update(evt):
            return self.misp.add_event(evt, True)

        actor_name = act.get('name')
        act_detail = Adversary[actor_name.split(" ")[1].upper()].value
        info_str = f"ADV-{act.get('id')} {actor_name} ({act_detail})"
        returned = False
        if actor_name is not None:
            if already.get(info_str) is None:
                event: MISPEvent = self.create_event_from_actor(act, act_det)
                self.log.debug("Created adversary event for %s", act.get('name'))
                if event:
                    for tag in self.settings["CrowdStrike"]["actors_tags"].split(","):
                        event.add_tag(tag)
                    # Create an actor specific tag
                    actor_tag = actor_name.split(" ")[1]
                    event.add_tag(f"crowdstrike:branch=\"{actor_tag}\"")
                    if actor_name is not None:
                        already[actor_name] = True
                    success = False
                    max_tries = 3
                    for cur_try in range(max_tries):
                        try:
                            do_update(event)
                            success = True
                        except Exception as err:
                            timeout = 0.3 * 2 ** cur_try
                            self.log.warning("Could not add or tag event %s. Will retry in %s seconds.\n%s", event.info, timeout, str(err))
                            time.sleep(timeout)
                    if not success:
                        self.log.warning("Unable to add event %s.", event.info)

                    if act.get('last_modified_date'):
                        ts_check = 0
                        if os.path.exists(self.actors_timestamp_filename):
                            with open(self.actors_timestamp_filename, 'r', encoding="utf-8") as ts_file:
                                ts_check = ts_file.read()
                        # This might be a little over the top
                        nowstamp = None
                        try:
                            if int(act.get('last_modified_date')) > int(ts_check):
                                nowstamp = act.get('last_modified_date')
                        except ValueError:
                            nowstamp = int(datetime.datetime.today().timestamp())
                        if nowstamp:
                            with open(self.actors_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                                ts_file.write(str(int(nowstamp)+1))
                    returned = True
                else:
                    self.log.warning("Failed to create a MISP event for actor %s.", act)
            else:
                self.log.debug("Actor %s already exists, skipping", actor_name)

        return returned


    def process_actors(self, actors_days_before, events_already_imported):
        """Pull and process actors.

        :param actors_days_before: in case on an initialisation run, this is the age of the actors pulled in days
        :param events_already_imported: the events already imported in misp, to avoid duplicates
        """
        display_banner(banner=ADVERSARIES_BANNER,
                       logger=self.log,
                       fallback="BEGIN ADVERSARIES IMPORT",
                       hide_cool_banners=self.import_settings["no_banners"]
                       )
        start_get_events = int((
            datetime.datetime.today() + datetime.timedelta(days=-int(min(actors_days_before, 7300)))
        ).timestamp())

        # Galaxy Clusters
        self.log.info("Start Threat Actor galaxy cluster alignment")
        actors = self.intel_api_client.get_actors(start_get_events, self.import_settings["type"])
        self.log.info("Got %i adversaries from the Crowdstrike Intel API.", len(actors))
        actor_map = get_actor_galaxy_map(self.misp, self.intel_api_client, self.import_settings["type"])
        act_id_list = [x.get("id") for x in actors if x["name"] not in actor_map]
        if act_id_list:
            act_detail = self.intel_api_client.falcon.get_actor_entities(
                ids=act_id_list,
                fields="__full__"
                )["body"]["resources"]
        else:
            act_detail = []
        # Set any inbound CS cluster elements
        for mapped in actor_map.values():
            cluster = self.misp.get_galaxy_cluster(mapped["uuid"])
            details = {}
            for det in [d for d in act_detail if d.get("id") == mapped["cs_id"]]:
                details = det
                add_cluster_elements(details, details, cluster)

        # Create Threat Actor Galaxy Clusters for missing CS adversaries
        for act in [a for a in actors if a["name"] not in actor_map]:
            details = {}
            for det in act_detail:
                if det.get("id") == act.get("id"):
                    details = det
            cluster = MISPGalaxyCluster()
            cluster["distribution"] = 1
            cluster["authors"] = ["CrowdStrike"]
            cluster["type"] = "threat-actor"
            cluster["default"] = False
            cluster["source"] = "CrowdStrike"
            cluster["description"] = details["description"]
            cluster["value"] = act["name"].upper()
            cluster.Orgc = self.crowdstrike_org
            add_cluster_elements(act, details, cluster)

            cluster_result = self.misp.add_galaxy_cluster(get_threat_actor_galaxy_id(self.misp), cluster)
            actor_map[act['name'].upper()] = {
                "uuid": cluster_result["GalaxyCluster"]["uuid"],
                "tag_name": cluster_result["GalaxyCluster"]["tag_name"],
                "custom": True,
                "name": cluster_result["GalaxyCluster"]["value"],
                "id": cluster_result["GalaxyCluster"]["id"],
                "deleted": cluster_result["GalaxyCluster"]["deleted"],
                "cs_name": act["name"].upper(),
                "cs_id": act["id"]
            }
        # Restore any soft deleted CrowdStrike adversary threat actor clusters
        for act in [a["id"] for a in actor_map.values() if a["deleted"]]:
            # -ca does a hard delete so this will be skipped.
            self.misp._check_json_response(self.misp._prepare_request("POST", f"galaxy_clusters/restore/{act}"))

        self.import_settings["actor_map"] = actor_map
        self.log.info("Threat Actor galaxy alignment complete.")

        if os.path.isfile(self.actors_timestamp_filename):
            with open(self.actors_timestamp_filename, 'r', encoding="utf-8") as ts_file:
                line = ts_file.readline()
                if line:
                    start_get_events = int(line)
        self.log.info(f"Start importing CrowdStrike Adversaries as events into MISP (past {actors_days_before} days).")
        time_send_request = datetime.datetime.now()

        #actors = self.intel_api_client.get_actors(start_get_events, self.import_settings["type"])
        if len(actors) == 0:
            with open(self.actors_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                ts_file.write(str(int(time_send_request.timestamp())))
        else:
            actor_details = self.intel_api_client.falcon.get_actor_entities(ids=[x.get("id") for x in actors], fields="__full__")["body"]["resources"]
            reported = 0
            with concurrent.futures.ThreadPoolExecutor(self.misp.thread_count, thread_name_prefix="thread") as executor:
                futures = {
                    executor.submit(self.batch_import_actors, ac, actor_details, events_already_imported) for ac in actors
                }
                for fut in concurrent.futures.as_completed(futures):
                    if fut.result():
                        reported += 1
            self.log.info("Completed import of %i CrowdStrike adversaries into MISP.", reported)

        self.log.info("Finished importing CrowdStrike Adversaries as events into MISP.")


    @staticmethod
    def int_ref_handler(evt, kc_name, kc_detail, kcatt: MISPObject = None, galaxy_tag: str = None):
        sum_id = None
        goal_cat = "External analysis"
        if kc_name.title() == "Installation":
            goal_cat = "Payload installation"
        if kc_name.title() in ["Weaponization", "Delivery"]:
            goal_cat = "Payload delivery"
        if kc_name.title() in ["Objectives", "Reconnaissance"]:
            goal_cat = "External analysis"
        if kc_name.lower() == "command and control":
            goal_cat = "Network activity"
        if not isinstance(kc_detail, list):
            kc_detail = kc_detail.replace("\t", "").replace("&nbsp;", "")
        if kc_detail not in ["Unknown", "N/A"]:
            sum_id = kcatt.add_attribute("goals", kc_detail, disable_correlation=True, category=goal_cat)
            if kc_name.lower().strip() == "objectives":
                kc_name = "Actions on Objectives"
            sum_id.add_tag(f"kill-chain:{kc_name}")
            if galaxy_tag:
                sum_id.add_tag(galaxy_tag)
            evt.add_tag(f"kill-chain:{kc_name}")


    def create_event_from_actor(self, actor, act_details) -> MISPEvent():
        """Create a MISP event for a valid Actor."""

        event = MISPEvent()
        event.analysis = 2
        event.orgc = self.crowdstrike_org

        # Set distribution level
        event.distribution = self.distribution
        # Set sharing group
        if self.distribution == "4":
            event.sharing_group_id = self.sharing_group_id
        event.extends_uuid = ""
        if self.import_settings["publish"]:
            event.published = True
        if actor.get('first_activity_date'):
            event.date = actor.get("first_activity_date")
        elif actor.get('last_activity_date'):
            event.date = actor.get("last_activity_date")

        details = {}
        for det in act_details:
            if det.get("id") == actor.get("id"):
                details = det
        # Actor name, slug and branch
        actor_name = actor.get("name", None)
        actor_proper_name = " ".join([n.title() for n in actor.get("name", "").split(" ")])
        slug = details.get("slug", actor_name.lower().replace(" ", "-"))
        actor_branch = actor_name.split(" ")[1].upper()

        actor_region = ""
        verbosity = self.import_settings["verbose_tags"]
        if actor_name:
            for act_reg in [adv for adv in dir(Adversary) if "__" not in adv]:
                if act_reg in actor_branch:
                    actor_region = f" ({Adversary[act_reg].value})"
            event.info = f"ADV-{actor.get('id')} {actor_name}{actor_region}"
            actor_att = {
                "type": "threat-actor",
                "value": actor_proper_name,
            }
            # Timestamps
            had_timestamp = False
            timestamp_object = MISPObject('timestamp')
            actor_att["first_seen"] = actor.get("first_activity_date", 0)
            if not actor_att["first_seen"]:
                self.log.warning("Adversary %s missing field first_activity_date.", actor_name)
            actor_att["last_seen"] = actor.get("last_activity_date", 0)
            if not actor_att["last_seen"]:
                self.log.warning("Adversary %s missing field last_activity_date.", actor_name)
            if actor_att.get("last_seen", 0) < actor_att.get("first_seen", 0):
                # Seems counter-intuitive
                actor_att["first_seen"] = actor.get("last_activity_date")
                actor_att["last_seen"] = actor.get("first_activity_date")
            if actor_att["first_seen"] == 0:
                actor_att["first_seen"] = actor_att["last_seen"]
            if actor_att["first_seen"]:
                timestamp_object.add_attribute('first-seen', datetime.datetime.utcfromtimestamp(actor_att["first_seen"]).isoformat())
                had_timestamp = True

            if actor_att["last_seen"]:
                timestamp_object.add_attribute('last-seen', datetime.datetime.utcfromtimestamp(actor_att["last_seen"]).isoformat())
                had_timestamp = True

            ta = event.add_attribute(**actor_att, disable_correlation=True)
            ta.add_tag(self.adversary_galaxy_tag(actor_name))
            actor_split = actor_name.split(" ")
            actor_branch = actor_split[1] if len(actor_split) > 1 else actor_split[0]
            event.add_attribute_tag(f"crowdstrike:branch=\"{actor_branch}\"", ta.uuid)
            if had_timestamp:
                event.add_object(timestamp_object)

            # Create the organization object for this actor
            known_as_object = MISPObject('organization')
            kao_name = known_as_object.add_attribute("name",
                                                     actor_proper_name,
                                                     disable_correlation=True,
                                                     category="Attribution",
                                                     first_seen=datetime.datetime.utcfromtimestamp(actor_att["first_seen"]).isoformat(),
                                                     last_seen=datetime.datetime.utcfromtimestamp(actor_att["last_seen"]).isoformat()
                                                     )
            kao_ts = known_as_object.add_attribute("date-of-inception",
                                                   datetime.datetime.utcfromtimestamp(actor_att["first_seen"]).isoformat(),
                                                   disable_correlation=True,
                                                   category="External analysis"
                                                   )
            kao_name.add_tag(self.adversary_galaxy_tag(actor_name))
            kao_ts.add_tag(self.adversary_galaxy_tag(actor_name))
            # All actor reports are of the adversary report type
            event.add_tag("crowdstrike:report-type=\"Adversary Report\"")
            # All actor reports are considered Threat Actor Updates
            event.add_tag("threatmatch:alert-type=\"Threat Actor Updates\"")
            # All adversary events are considered "complete" from a workflow perspective.
            if confirm_boolean_param(self.settings["TAGGING"].get("taxonomic_WORKFLOW", False)):
                event.add_tag("workflow:state=\"complete\"")

            if actor_name.upper() in self.import_settings["actor_map"]:
                event.add_tag(self.adversary_galaxy_tag(actor_name))
            else:
                event.add_tag(f"CrowdStrike:adversary: {actor_name}")

            if details.get('url'):
                event.add_attribute('link', details.get('url'), disable_correlation=True)

            # Adversary description
            reg_desc = details.get("description", None)
            if reg_desc:
                kao_desc = known_as_object.add_attribute("description", reg_desc, disable_correlation=True, category="External analysis")
                kao_desc.add_tag(self.adversary_galaxy_tag(actor_name))
                # Report Annotation and full text
                rich_desc = details.get("rich_text_description", None)
                long_desc = details.get("long_description", None)
                if long_desc or rich_desc:
                    # Moving over to just using the event report for the MD formatted content
                    md_version = markdownify(rich_desc)
                    if not md_version:
                        md_version = long_desc
                    if not md_version:
                        md_version = reg_desc

                event.add_event_report(event.info, md_version.replace("\t", "").replace("      ", ""))

            # Adversary type
            act_type = details.get("actor_type", None)
            if act_type:
                event.add_tag(f"crowdstrike:type=\"{act_type.upper()}\"")

            # Adversary motives
            motive_list = []
            motives = details.get("motivations", None)
            if motives:
                motive_list = [m.get("value") for m in motives]
                to_set = []
                for mname in motive_list:
                    if mname.upper() == "STATE-SPONSORED":
                        if "state-responsibility:state-prohibited-but-inadequate." in to_set:
                            to_set.pop(to_set.index("state-responsibility:state-prohibited-but-inadequate."))
                        to_set.append("state-responsibility:state-coordinated")
                    elif mname.upper() in ["CRIMINAL", "HACKTIVISM"]:
                        if not "state-responsibility:state-coordinated" in to_set:
                            to_set.append("state-responsibility:state-prohibited-but-inadequate.")
                        if mname.upper() == "HACKTIVISM":
                            event.add_tag("threatmatch:incident-type=\"Hacktivism Activity\"")
                    else:
                        event.add_tag(f"CrowdStrike:adversary:motivation: {mname.upper()}")
                for lab in to_set:
                    event.add_tag(lab)
            if motive_list:
                for mot in motive_list:
                    if mot.upper() in ["STATE-SPONSORED", "HACKTIVISM", "CRIMINAL"]:
                        known_as_object.add_attribute("type-of-organization", mot, disable_correlation=True, category="External analysis")

            # Adversary capability
            cap_val = None
            cap = details.get("capability", None)
            if cap:
                cap_val = cap.get("value")
                if cap_val:
                    event.add_tag(f"crowdstrike:capability=\"{cap_val.upper()}\"")
                    # Set adversary event threat level based upon adversary capability
                    if "BELOW" in cap_val.upper() or "LOW" in cap_val.upper():
                        event.threat_level_id = 3
                    elif "ABOVE" in cap_val.upper() or "HIGH" in cap_val.upper():
                        event.threat_level_id = 1
                    else:
                        event.threat_level_id = 2
            # Adversary threatmatch capabilities
            for caps in [c["value"] for c in details.get("capabilities", [])]:
                if caps.upper() != normalize_threatmatch(caps.upper()):
                    for match in normalize_threatmatch(caps.upper()).split(","):
                        event.add_tag(f"threatmatch:{match}")
            for objectives in [c["value"] for c in details.get("objectives", [])]:
                if objectives.upper() != normalize_threatmatch(objectives.upper()):
                    for match in normalize_threatmatch(objectives.upper()).split(","):
                        event.add_tag(f"threatmatch:{match}")
            # Kill chain elements
            kill_chain_detail = details.get("kill_chain")
            if kill_chain_detail:
                kc_att = MISPObject("intrusion-set")
                objectives = kill_chain_detail.get("actions_and_objectives", None)
                candc = kill_chain_detail.get("command_and_control", None)
                delivery = kill_chain_detail.get("delivery", None)
                exploitation = kill_chain_detail.get("exploitation", None)
                installation = kill_chain_detail.get("installation", None)
                reconnaissance = kill_chain_detail.get("reconnaissance", None)
                weaponization = kill_chain_detail.get("weaponization", None)
                adv_objectives = [o["value"] for o in details.get("objectives", [])]

                # Kill chain - Objectives
                if objectives:
                    self.int_ref_handler(event, "actions on objectives", objectives, kc_att, self.adversary_galaxy_tag(actor_name))

                # Kill chain - Command and Control
                if candc:
                    self.int_ref_handler(event, "command and control", candc, kc_att, self.adversary_galaxy_tag(actor_name))

                # Kill chain - Delivery
                if delivery:
                    self.int_ref_handler(event, "delivery", delivery, kc_att, self.adversary_galaxy_tag(actor_name))

                # Kill chain - Exploitation
                if exploitation:
                    if exploitation.replace("\t", "".replace("&nbsp;", "")) not in ["Unknown", "N/A"]:
                        #exploits = exploitation.replace("\t", "").replace("&nbsp;", "").split("\r\n")
                        for exploits in exploitation.replace("\t", "").replace("&nbsp;", "").split("\r\n"):
                            for exploit in exploits.split(","):
                                ex_id = event.add_attribute("vulnerability", exploit.upper(), category="External analysis")
                                if verbosity:
                                    event.add_attribute_tag("kill-chain:Exploitation", ex_id.uuid)
                                    event.add_tag("kill-chain:Exploitation")
                # Kill chain - Installation
                if installation:
                    self.int_ref_handler(event, "installation", installation, kc_att, self.adversary_galaxy_tag(actor_name))
                    
                # Kill chain - Reconnaissance
                if reconnaissance:
                    self.int_ref_handler(event, "reconnaissance", reconnaissance, kc_att, self.adversary_galaxy_tag(actor_name))
                # Kill chain - Weaponization
                if weaponization:
                    self.int_ref_handler(event, "weaponization", weaponization, kc_att, self.adversary_galaxy_tag(actor_name))

                if cap_val:
                    kc_att.add_attribute("resource_level", cap_val, disable_correlation=True, category="External analysis")
                if motive_list:
                    motlist = []
                    for mot in motive_list:
                        if mot.upper() in ["STATE-SPONSORED", "HACKTIVISM", "CRIMINAL"]:
                            primary = mot.title().replace("Sponsored", "sponsored")
                            if act_type:
                                primary = f"{primary} ({act_type.title()})"
                            motlist.append(primary)
                    for mot in motlist:
                        res = kc_att.add_attribute("primary-motivation", mot, disable_correlation=True, category="External analysis")
                        res.add_tag(self.adversary_galaxy_tag(actor_name))
                if adv_objectives:
                    objs_list = []
                    for objs in adv_objectives:
                        if objs.upper() in [a.name for a in AdversaryMotivation]:
                            objs_list.append(AdversaryMotivation[objs.upper()].value)
                    if objs_list:
                        for objective in objs_list:
                            res = kc_att.add_attribute("secondary-motivation", objective, disable_correlation=True, category="External analysis")
                            res.add_tag(self.adversary_galaxy_tag(actor_name))
                event.add_object(kc_att)

            if actor.get('known_as') or actor.get("origins"):
                if actor.get("known_as"):
                    aliased = [a.strip() for a in actor.get("known_as").split(",")]
                    for alias in [a for a in aliased if a]:
                        kao = known_as_object.add_attribute('alias', alias, disable_correlation=True, category="Attribution")
                        # Tag the aliases to the threat-actor attribution
                        if verbosity and kao:
                            kao.add_tag(f"crowdstrike:branch=\"{actor_branch}\"")
                            kao.add_tag(self.adversary_galaxy_tag(actor_name))
            
                for orig in actor.get("origins", []):
                    locale = orig.get("value")
                    if locale:
                        kar = event.add_attribute("country-of-residence", locale, disable_correlation=True)
                        event.add_tag(f"crowdstrike:origin=\"{locale.upper()}\"")
                        if verbosity:
                            event.add_attribute_tag(f"crowdstrike:origin=\"{locale.upper()}\"", kar.uuid)
            if known_as_object:
                event.add_object(known_as_object)

            # Adversary victim location
            if actor.get("target_countries"):
                region_list = [c.get('value') for c in actor.get('target_countries', [])]
                for region in region_list:
                    region = normalize_locale(region)
                    if region in self.regions:
                        self.log.debug("Regional match. Tagging %s", self.regions[region])
                        event.add_tag(self.regions[region])
                    else:
                        self.log.debug("Country match. Tagging %s.", region)
                        event.add_tag(f"misp-galaxy:target-information=\"{region}\"")

            # Adversary victim industry
            if actor.get("target_industries"):
                sector_list = [s.get('value') for s in actor.get('target_industries', [])]
                for sector in sector_list:
                    event.add_tag(f"misp-galaxy:sector=\"{normalize_sector(sector)}\"")
            # TYPE Taxonomic tag, all events
            event = taxonomic_event_tagging(event, self.settings["TAGGING"])

        else:
            self.log.warning("Adversary %s missing field name.", actor.get('id'))

        return event
