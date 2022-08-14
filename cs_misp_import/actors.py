f"""CrowdStrike Adversary (Actor) MISP event import.

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
    from pymisp import MISPObject, MISPEvent, ExpandedPyMISP
except ImportError as no_pymisp:
    raise SystemExit(
        "The PyMISP package must be installed to use this program."
        ) from no_pymisp

from .adversary import Adversary
from .helper import ADVERSARIES_BANNER, confirm_boolean_param

class ActorsImporter:
    """Tool used to import actors from the Crowdstrike Intel API and push them as events in MISP through the MISP API.

    :param misp_client: client for a MISP instance
    :param intel_api_client: client for the Crowdstrike Intel API
    """

    def __init__(self, misp_client, intel_api_client, crowdstrike_org_uuid, actors_timestamp_filename, settings, unknown = "UNIDENTIFIED", logger = None):
        """Construct an instance of the ActorsImporter class."""
        self.misp: ExpandedPyMISP = misp_client
        self.intel_api_client = intel_api_client
        self.actors_timestamp_filename = actors_timestamp_filename
        self.crowdstrike_org = self.misp.get_organisation(crowdstrike_org_uuid, True)
        self.settings = settings
        self.unknown = unknown
        self.log: logging.Logger = logger


    def batch_import_actors(self, act, act_det, already):
        actor_name = act.get('name')
        if actor_name is not None:
            if already.get(actor_name) is None:
                event: MISPEvent = self.create_event_from_actor(act, act_det)
                self.log.debug("Created adversary event for %s", act.get('name'))
                if event:
                    try:
                        #for tag in self.settings["CrowdStrike"]["actors_tags"].split(","):
                        #    event.add_tag(tag)
                        # Create an actor specific tag
                        actor_tag = actor_name.split(" ")[1]
                        event.add_tag(f"CrowdStrike:adversary:branch: {actor_tag}")
                        #event.add_tag(f"CrowdStrike:actor: {actor_tag}")
                        if actor_name is not None:
                            already[actor_name] = True
                        event = self.misp.add_event(event, True)
                    except Exception as err:
                        self.log.warning("Could not add or tag event %s.\n%s", event.info, str(err))

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

                else:
                    self.log.warning("Failed to create a MISP event for actor %s.", act)
        return True


    def process_actors(self, actors_days_before, events_already_imported):
        """Pull and process actors.

        :param actors_days_before: in case on an initialisation run, this is the age of the actors pulled in days
        :param events_already_imported: the events already imported in misp, to avoid duplicates
        """
        self.log.info(ADVERSARIES_BANNER)
        start_get_events = int((
            datetime.datetime.today() + datetime.timedelta(days=-int(min(actors_days_before, 730)))
        ).timestamp())

        if os.path.isfile(self.actors_timestamp_filename):
            with open(self.actors_timestamp_filename, 'r', encoding="utf-8") as ts_file:
                line = ts_file.readline()
                if line:
                    start_get_events = int(line)
        self.log.info("Started getting adversaries from Crowdstrike Intel API and pushing them as events in MISP.")
        time_send_request = datetime.datetime.now()
        actors = self.intel_api_client.get_actors(start_get_events)
        self.log.info("Got %i adversaries from the Crowdstrike Intel API.", len(actors))

        if len(actors) == 0:
            with open(self.actors_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                ts_file.write(str(int(time_send_request.timestamp())))
        else:
            actor_details = self.intel_api_client.falcon.get_actor_entities(ids=[x.get("id") for x in actors], fields="__full__")["body"]["resources"]
            reported = 0
            with concurrent.futures.ThreadPoolExecutor(self.misp.thread_count) as executor:
                futures = {
                    executor.submit(self.batch_import_actors, ac, actor_details, events_already_imported) for ac in actors
                }
                for fut in concurrent.futures.as_completed(futures):
                    if fut.result():
                        reported += 1
            self.log.info("Completed import of %i CrowdStrike adversaries into MISP.", reported)

        self.log.info("Finished getting adversaries from Crowdstrike Intel API and pushing them as events in MISP.")

    @staticmethod
    def create_internal_reference() -> MISPObject:
            inter = MISPObject("internal-reference")
            inter.add_attribute("type", "Adversary detail", disable_correlation=True)

            return inter

    def create_event_from_actor(self, actor, act_details) -> MISPEvent():
        """Create a MISP event for a valid Actor."""

        event = MISPEvent()
        event.analysis = 2
        event.orgc = self.crowdstrike_org
        details = {}
        for det in act_details:
            if det.get("id") == actor.get("id"):
                details = det

        actor_name = actor.get("name", None)
        actor_proper_name = " ".join([n.title() for n in actor.get("name", "").split(" ")])
        slug = details.get("slug", actor_name.lower().replace(" ", "-"))
        actor_region = ""
        if actor_name:
            for act_reg in [adv for adv in dir(Adversary) if "__" not in adv]:
                if act_reg in actor_name:
                    actor_region = f" ({Adversary[act_reg].value})"
            event.info = f"ADV-{actor.get('id')} {actor_name}{actor_region}"
            actor_att = {
                "type": "threat-actor",
                "value": actor_proper_name,
            }
            event.add_tag(f"CrowdStrike:adversary: {actor_name}")

            if details.get('url'):
                event.add_attribute('link', details.get('url'))

            to_reference: list[MISPObject] = []
            adversary_detail = False
            if details.get('description'):
                internal = self.create_internal_reference()
                internal.add_attribute("identifier", "Description", disable_correlation=True)
                desc_id = internal.add_attribute('comment', details.get('description'))
                adversary_detail = True

            act_type = details.get("actor_type", None)
            if act_type:
                if not adversary_detail:
                    internal = self.create_internal_reference()
                    adversary_detail = True
                act_type_object = MISPObject("internal-reference")
                act_type_object.add_attribute("type", "Adversary detail", disable_correlation=True)
                at_id = act_type_object.add_attribute("identifier", "Actor type", disable_correlation=True)
                sum_id = act_type_object.add_attribute('comment', act_type.title())
                event.add_tag(f"CrowdStrike:adversary:type: {act_type.upper()}")
                to_reference.append(event.add_object(act_type_object))
                event.add_attribute_tag(f"CrowdStrike:adversary:actor-type: {act_type.upper()}", sum_id.uuid)
                event.add_attribute_tag(f"CrowdStrike:adversary:actor-type: {actor_name}", at_id.uuid)
                event.add_attribute_tag(f"CrowdStrike:adversary:{slug}: ACTOR TYPE", sum_id.uuid)
                event.add_attribute_tag(f"CrowdStrike:adversary:{slug}:actor-type: {act_type.upper()}", at_id.uuid)
                internal.add_reference(act_type_object.uuid, "Adversary detail")

            motives = details.get("motivations", None)
            if motives:
                motive = "\n".join([m.get("value") for m in motives])
                if not adversary_detail:
                    internal = self.create_internal_reference()
                    adversary_detail = True
                motive_object = MISPObject("internal-reference")
                motive_object.add_attribute("type", "Adversary detail", disable_correlation=True)
                mot_id = motive_object.add_attribute("identifier", "Motivation", disable_correlation=True)
                sum_id = motive_object.add_attribute('comment', motive)
                to_reference.append(event.add_object(motive_object))
                event.add_attribute_tag(f"CrowdStrike:adversary:motivation: {actor_name}", mot_id.uuid)
                event.add_attribute_tag(f"CrowdStrike:adversary:{slug}: MOTIVATION", sum_id.uuid)
                for m in motives:
                    if m.get('value'):
                        event.add_attribute_tag(f"CrowdStrike:adversary:{slug}:motivation: {m.get('value').upper()}", sum_id.uuid)
                internal.add_reference(motive_object.uuid, "Adversary detail")

            cap = details.get("capability", None)
            if cap:
                cap_val = cap.get("value")
                if cap_val:
                    if not adversary_detail:
                        internal = self.create_internal_reference()
                        adversary_detail = True
                    cap_object = MISPObject("internal-reference")
                    cap_object.add_attribute("type", "Adversary detail", disable_correlation=True)
                    cp_id = cap_object.add_attribute("identifier", "Capability", disable_correlation=True)
                    sum_id = cap_object.add_attribute('comment', cap_val)
                    event.add_tag(f"CrowdStrike:adversary:capability: {cap_val.upper()}")
                    to_reference.append(event.add_object(cap_object))
                    event.add_attribute_tag(f"CrowdStrike:adversary:{slug}:capability: {cap_val.upper()}", sum_id.uuid)
                    event.add_attribute_tag(f"CrowdStrike:adversary:capability: {actor_name}", cp_id.uuid)
                    event.add_attribute_tag(f"CrowdStrike:adversary:{slug}: CAPABILITY", sum_id.uuid)
                    event.add_attribute_tag(f"CrowdStrike:adversary:capability: {cap_val.upper()}", cp_id.uuid)
                    internal.add_reference(cap_object.uuid, "Adversary detail")
                    # Set adversary event threat level based upon adversary capability
                    if "BELOW" in cap_val.upper() or "LOW" in cap_val.upper():
                        event.threat_level_id = 3
                    elif "ABOVE" in cap_val.upper() or "HIGH" in cap_val.upper():
                        event.threat_level_id = 1
                    else:
                        event.threat_level_id = 2

            kill_chain_detail = details.get("kill_chain")
            
            if kill_chain_detail:
                objectives = kill_chain_detail.get("actions_and_objectives", None)
                candc = kill_chain_detail.get("command_and_control", None)
                delivery = kill_chain_detail.get("delivery", None)
                exploitation = kill_chain_detail.get("exploitation", None)
                installation = kill_chain_detail.get("installation", None)
                reconnaissance = kill_chain_detail.get("reconnaissance", None)
                weaponization = kill_chain_detail.get("weaponization", None)

                if not adversary_detail:
                    internal = self.create_internal_reference()
                    adversary_detail = True

                if objectives:
                    objective_object = MISPObject("internal-reference")
                    objective_object.add_attribute("type", "Adversary detail", disable_correlation=True)
                    objective_object.add_attribute("identifier", "Objectives", disable_correlation=True)
                    sum_id = objective_object.add_attribute("comment", objectives.replace("\t", "").replace("&nbsp;", ""))
                    to_reference.append(event.add_object(objective_object))
                    event.add_attribute_tag(f"CrowdStrike:adversary:objectives: {actor_name}", sum_id.uuid)
                    event.add_attribute_tag(f"CrowdStrike:adversary:{slug}: OBJECTIVES", sum_id.uuid)
                    internal.add_reference(objective_object.uuid, "Adversary detail")
                if candc:
                    candc_object = MISPObject("internal-reference")
                    candc_object.add_attribute("type", "Adversary detail", disable_correlation=True)
                    candc_object.add_attribute("identifier", "Command and Control", disable_correlation=True)
                    sum_id = candc_object.add_attribute("comment", candc.replace("\t", "").replace("&nbsp;", ""))
                    to_reference.append(event.add_object(candc_object))
                    event.add_attribute_tag(f"CrowdStrike:adversary:command-and-control: {actor_name}", sum_id.uuid)
                    event.add_attribute_tag(f"CrowdStrike:adversary:{slug}: COMMAND AND CONTROL", sum_id.uuid)
                    internal.add_reference(candc_object.uuid, "Adversary detail")
                if delivery:
                    delivery_object = MISPObject("internal-reference")
                    delivery_object.add_attribute("type", "Adversary detail", disable_correlation=True)
                    delivery_object.add_attribute("identifier", "Delivery", disable_correlation=True)
                    sum_id = delivery_object.add_attribute("comment", delivery.replace("\t", "").replace("&nbsp;", ""))
                    to_reference.append(event.add_object(delivery_object))
                    event.add_attribute_tag(f"CrowdStrike:adversary:delivery: {actor_name}", sum_id.uuid)
                    event.add_attribute_tag(f"CrowdStrike:adversary:{slug}: DELIVERY", sum_id.uuid)
                    internal.add_reference(delivery_object.uuid, "Adversary detail")
                if exploitation:
                    exploitation_object = MISPObject("internal-reference")
                    if exploitation.replace("\t", "".replace("&nbsp;", "")) not in ["Unknown", "N/A"]:
                        exploitation_object.add_attribute("type", "Adversary detail", disable_correlation=True)
                        exploitation_object.add_attribute("identifier", "Exploitation", disable_correlation=True)
                        exploits = exploitation.replace("\t", "").replace("&nbsp;", "").split("\r\n")
                        ex_id = exploitation_object.add_attribute("comment", exploitation.replace("\t", "").replace("&nbsp;", ""))
                        to_reference.append(event.add_object(exploitation_object))
                        event.add_attribute_tag(f"CrowdStrike:adversary:{slug}: EXPLOITATION", ex_id.uuid)
                        event.add_attribute_tag(f"CrowdStrike:adversary:exploitation: {actor_name}", ex_id.uuid)
                        for exptt in [exp for exp in exploits if exp]:
                            if exptt not in ["Unknown", "N/A"]:
                                for exploit in [a.strip() for a in exptt.split(",")]:
                                    if len(exploit.split(" ")) <= 4:
                                        event.add_attribute_tag(f"CrowdStrike:adversary:exploitation: {exploit.upper()}", ex_id.uuid)
                                        #event.add_attribute_tag(f"CrowdStrike:adversary:{slug}:exploitation: {exploit}", ex_id.uuid)


                    internal.add_reference(exploitation_object.uuid, "Adversary detail")

                if installation:
                    installation_object = MISPObject("internal-reference")
                    installation_object.add_attribute("type", "Adversary detail", disable_correlation=True)
                    installation_object.add_attribute("identifier", "Installation", disable_correlation=True)
                    sum_id = installation_object.add_attribute("comment", installation.replace("\t", "").replace("&nbsp;", ""))
                    to_reference.append(event.add_object(installation_object))
                    event.add_attribute_tag(f"CrowdStrike:adversary:installation: {actor_name}", sum_id.uuid)
                    event.add_attribute_tag(f"CrowdStrike:adversary:{slug}: INSTALLATION", sum_id.uuid)
                    internal.add_reference(installation_object.uuid, "Adversary detail")
                if reconnaissance:
                    reconnaissance_object = MISPObject("internal-reference")
                    reconnaissance_object.add_attribute("type", "Adversary detail", disable_correlation=True)
                    reconnaissance_object.add_attribute("identifier", "Reconnaissance", disable_correlation=True)
                    sum_id = reconnaissance_object.add_attribute("comment", reconnaissance.replace("\t", "").replace("&nbsp;", ""))
                    to_reference.append(event.add_object(reconnaissance_object))
                    event.add_attribute_tag(f"CrowdStrike:adversary:reconnaissance: {actor_name}", sum_id.uuid)
                    event.add_attribute_tag(f"CrowdStrike:adversary:{slug}: RECONNAISSANCE", sum_id.uuid)
                    internal.add_reference(reconnaissance_object.uuid, "Adversary detail")
                if weaponization:
                    weaponization_object = MISPObject("internal-reference")
                    weaponization_object.add_attribute("type", "Adversary detail", disable_correlation=True)
                    weaponization_object.add_attribute("identifier", "Weaponization", disable_correlation=True)
                    sum_id = weaponization_object.add_attribute("comment", weaponization.replace("\t", "").replace("&nbsp;", ""))
                    to_reference.append(event.add_object(weaponization_object))
                    event.add_attribute_tag(f"CrowdStrike:adversary:weaponization: {actor_name}", sum_id.uuid)
                    event.add_attribute_tag(f"CrowdStrike:adversary:{slug}: WEAPONIZATION", sum_id.uuid)
                    internal.add_reference(weaponization_object.uuid, "Adversary detail")
                for ref in to_reference:
                    internal.add_reference(ref.uuid, "Adversary detail")
                    for web in to_reference:
                        if web.uuid != ref.uuid:
                            web.add_reference(ref.uuid, "Adversary detail")
            if adversary_detail:       
                event.add_object(internal)
                if details.get('description'):
                    event.add_attribute_tag(f"CrowdStrike:adversary:description: {actor_name}", desc_id.uuid)
                    event.add_attribute_tag(f"CrowdStrike:adversary:{slug}: DESCRIPTION", desc_id.uuid)

            had_timestamp = False
            timestamp_object = MISPObject('timestamp')

            if actor.get('first_activity_date'):
                timestamp_object.add_attribute('first-seen',
                                            datetime.datetime.utcfromtimestamp(actor.get('first_activity_date')).isoformat()
                                            )
                had_timestamp = True

                actor_att["first_seen"] = actor.get("first_activity_date")

            else:
                self.log.warning("Adversary %s missing field first_activity_date.", actor.get('id'))

            if actor.get('last_activity_date'):
                timestamp_object.add_attribute('last-seen',
                                            datetime.datetime.utcfromtimestamp(actor.get('last_activity_date')).isoformat()
                                            )
                had_timestamp = True

                actor_att["last_seen"] = actor.get("last_activity_date")


            else:
                self.log.warning("Adversary %s missing field last_activity_date.", actor.get('id'))
            ta = event.add_attribute(**actor_att)
            actor_split = actor_name.split(" ")
            actor_branch = actor_split[1] if len(actor_split) > 1 else actor_split[0]
            event.add_attribute_tag(f"CrowdStrike:adversary:branch: {actor_branch}", ta.uuid)
            if had_timestamp:
                event.add_object(timestamp_object)

            if actor.get('known_as') or actor.get("origins"):
                if actor.get("known_as"):
                    known_as_object = MISPObject('organization')
                    aliased = [a.strip() for a in actor.get("known_as").split(",")]
                    for alias in aliased:
                        kao = known_as_object.add_attribute('alias', alias)
                        kao.add_tag(f"CrowdStrike:adversary:branch: {actor_branch}")
                        kao.add_tag(f"CrowdStrike:adversary:{slug}:alias: {alias.upper()}")
                        # Tag the aliases to the threat-actor attribution
                        event.add_attribute_tag(f"CrowdStrike:adversary:{slug}:alias: {alias.upper()}", ta.uuid)
                    event.add_object(known_as_object)
                for orig in actor.get("origins", []):
                    locale = orig.get("value")
                    if locale:
                        kar = event.add_attribute("country-of-residence", locale)
                        event.add_attribute_tag(f"CrowdStrike:adversary:{slug}:origin: {locale.upper()}", kar.uuid)
                        event.add_attribute_tag(f"CrowdStrike:adversary:origin: {locale.upper()}", kar.uuid)
                        event.add_tag(f"CrowdStrike:adversary:origin: {locale.upper()}")


            victim = None
            region_list = [c.get('value') for c in actor.get('target_countries', [])]
            for region in region_list:
            #for country in actor.get('target_countries', []):
                
                #region = country.get('value')
                #if region:
                if not victim:
                    victim = MISPObject("victim")
                vic = victim.add_attribute('regions', region)
                vic.add_tag(f"CrowdStrike:target:location: {region.upper()}")
                vic.add_tag(f"CrowdStrike:adversary:{slug}:target:location: {region.upper()}")
                #vic.add_tag(f"CrowdStrike:adversary:{slug}:target: LOCATION")

            sector_list = [s.get('value') for s in actor.get('target_industries', [])]
            for sector in sector_list:
                #sector = industry.get('value', None)
                #if sector:
                if not victim:
                    victim = MISPObject("victim")
                vic = victim.add_attribute('sectors', sector)
                vic.add_tag(f"CrowdStrike:adversary:{slug}:target:sector: {sector.upper()}")
                #vic.add_tag(f"CrowdStrike:adversary:{slug}:target: SECTOR")
                vic.add_tag(f"CrowdStrike:target:sector: {sector.upper()}")
                event.add_object(victim)
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
            self.log.warning("Adversary %s missing field name.", actor.get('id'))

        return event