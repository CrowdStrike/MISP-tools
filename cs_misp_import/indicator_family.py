import os
import sys
from logging import Logger
from pymisp import ExpandedPyMISP, MISPEvent
from concurrent.futures import ThreadPoolExecutor, as_completed
from .indicator_type import IndicatorType
from .adversary import Adversary
from .helper import confirm_boolean_param
from .confidence import MaliciousConfidence
import concurrent.futures
from threading import Lock

def convert_event(fam: dict, logg: Logger):
    ev = MISPEvent()
    ev.from_dict(**fam)
    if ev.info:
        logg.info(f"Processed {ev.info}")
    return ev


def retrieve_family_events(misp_client: ExpandedPyMISP,
                           feed_list: list,
                           log_util: Logger,
                           drange: str = ""
                           ):

    tag_search_base = ['crowdstrike:indicator:malware%']
    #ind_type_names = [i for i in dir(IndicatorType) if "__" not in i]
    #tag_search = [f"{tag_search_base}{ind_tn}" for ind_tn in ind_type_names]
    families = misp_client.search(eventinfo="Malware Family: %", timestamp=drange)

    log_util.info("Retrieved %i CrowdStrike indicator malware family events from MISP.", len(families))

    with concurrent.futures.ThreadPoolExecutor(misp_client.thread_count, thread_name_prefix="thread") as executor:
        futures = {
            executor.submit(convert_event, family, log_util) for family in families
        }
        for fut in futures:
            feed_list.append(fut.result())

    # for family in families:
    #     ev = MISPEvent()
    #     ev.from_dict(**family)
    #     feed_list.append(ev)
    return feed_list


def check_and_set_threat_level(ind, mal: MISPEvent, log_util: Logger):
    if ind.get("malicious_confidence"):
        update_threat_level = False
        ind_level = MaliciousConfidence[ind["malicious_confidence"].upper()].value
        if not ind_level:
            ind_level = 4
        try:
            if not mal.threat_level_id:
                update_threat_level = True
            else:
                if int(mal.threat_level_id) > int(ind_level):
                    update_threat_level = True
        except AttributeError:
            update_threat_level = True
        if update_threat_level:
            try:
                mal.threat_level_id = ind_level
            except AttributeError:
                log_util.debug("Could not set attribute level on %s", mal.info)

            log_util.debug("Updated %s event threat level to %s",
                            mal.info,
                            ind["malicious_confidence"].upper()
                            )

    return mal


def get_affiliated_branches(ind):
    branches = []
    actors = []
    for actor in ind.get("actors", []):
        for adv in [a for a in dir(Adversary) if "__" not in a]:
            try:
                actor = actor.replace(adv, f" {adv}")
                branch = actor.split(" ")[1]
                branches.append(branch)
                actors.append(actor)
            except IndexError:
                # No branch
                branch = None
    return branches, actors


def create_family_event(settings, impsettings, cs_org: str, distribution: int, sharing_group_id: int, fam_name: str, log_util: Logger, branch_list: list, actor_list: list):
    log_util.debug("Start creation of malware family event object")
    event_to_tag = MISPEvent()
    event_to_tag.analysis = 2
    event_to_tag.orgc = cs_org
    event_to_tag.distribution = distribution
    if distribution == "4":
        event_to_tag.sharing_group_id = sharing_group_id
    event_to_tag.info = f"Malware Family: {fam_name}"
    event_to_tag.add_tag(f'crowdstrike:indicator:malware:family="{fam_name}"')
    galaxy = impsettings["galaxy_map"].get(fam_name)
    if galaxy is not None:
        event_to_tag.add_tag(galaxy)
    # TYPE Taxonomic tag, all events
    if confirm_boolean_param(settings["TAGGING"].get("taxonomic_TYPE", False)):
        event_to_tag.add_tag('type:CYBINT')
    # INFORMATION-SECURITY-DATA-SOURCE Taxonomic tag, all events
    if confirm_boolean_param(settings["TAGGING"].get("taxonomic_INFORMATION-SECURITY-DATA-SOURCE", False)):
        event_to_tag.add_tag('information-security-data-source:integrability-interface="api"')
        event_to_tag.add_tag('information-security-data-source:originality="original-source"')
        event_to_tag.add_tag('information-security-data-source:type-of-source="security-product-vendor-website"')
    if confirm_boolean_param(settings["TAGGING"].get("taxonomic_IEP", False)):
        event_to_tag.add_tag('iep:commercial-use="MUST NOT"')
        event_to_tag.add_tag('iep:provider-attribution="MUST"')
        event_to_tag.add_tag('iep:unmodified-resale="MUST NOT"')
    if confirm_boolean_param(settings["TAGGING"].get("taxonomic_IEP2", False)):
        if confirm_boolean_param(settings["TAGGING"].get("taxonomic_IEP2_VERSION", False)):
            event_to_tag.add_tag('iep2-policy:iep_version="2.0"')
        event_to_tag.add_tag('iep2-policy:attribution="must"')
        event_to_tag.add_tag('iep2-policy:unmodified_resale="must-not"')
    if confirm_boolean_param(settings["TAGGING"].get("taxonomic_TLP", False)):
        event_to_tag.add_tag("tlp:amber")

    for branch in branch_list:
        event_to_tag.add_tag(f"crowdstrike:adversary:branch: {branch}")

    custom_tag_list = settings["CrowdStrike"]["indicators_tags"].split(",")
    for tag_val in custom_tag_list:
        event_to_tag.add_tag(tag_val)
    if impsettings["publish"]:
        event_to_tag.published = True



    for actor in actor_list:

        # actor_detail = self.intel_api_client.falcon.get_actor_entities(ids=actor.get("id"))
        # if actor_detail["status_code"] == 200:
        #     actor_detail = actor_detail["body"]["resources"][0]

        # first = actor_detail.get("first_activity_date", 0)
        # last = actor_detail.get("last_activity_date", 0)
        actor_proper_name = " ".join([n.title() for n in actor.split(" ")])
        actor_att = {
            "type": "threat-actor",
            "value": actor_proper_name,
        }
        # if first:
        #     actor_att["first_seen"] = first
        # if last:
        #     actor_att["last_seen"] = last
        # if actor_att.get("last_seen", 0) < actor_att.get("first_seen", 0):
        #     actor_att["first_seen"] = actor.get("last_activity_date")
        #     actor_att["last_seen"] = actor.get("first_activity_date")

        event_to_tag.add_attribute(**actor_att)

    log_util.debug("Complete initial malware family object creation")    

    return event_to_tag


def find_or_create_family_event(ind,
                                settings,
                                imp_settings,
                                org_id: str,
                                distribution: int,
                                sharing_group_id: int,
                                log_util: Logger,
                                misp_client: ExpandedPyMISP,
                                feed_list: list,
                                branches: list,
                                actors: list
                                ):
    try:
        returned = None
        preexisting = False
        for malware in ind.get('malware_families', []):
            log_util.debug("Malware Family identified: %s", malware)
            cs_search = f"Malware Family: {malware}"
            evt = [e for e in feed_list if cs_search == e.info]
            if evt:
                log_util.debug("Found existing malware family event for %s", malware)
                returned = evt[0]
                preexisting = True
            else:
                returned = create_family_event(settings,
                                               imp_settings,
                                               org_id,
                                               distribution,
                                               sharing_group_id,
                                               malware,
                                               log_util,
                                               branches,
                                               actors
                                               )
                if returned:
                    log_util.debug("Successfully created malware family event for %s", malware)
                else:
                    log_util.debug("Unable to create malware family event for %s", malware)

                if returned and not preexisting:
                    misp_client.add_event(returned)
                    feed_list.append(returned)  # Shared resource
    except Exception as mal_error:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        log_util.error(str(mal_error))
        log_util.error("%s (#%i) %s", exc_type, exc_tb.tb_lineno, fname)

    return returned, feed_list