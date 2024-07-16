from logging import Logger
from pymisp import ExpandedPyMISP, MISPEvent
from concurrent.futures import ThreadPoolExecutor, as_completed
from .indicator_type import IndicatorType
from .helper import confirm_boolean_param

def get_feed_tags(do_not: bool = False):
    tag_search_base = "crowdstrike:indicator:feed:type: "
    ind_type_names = [i for i in dir(IndicatorType) if "__" not in i]
    exclusive = ""
    if do_not:
        exclusive = "!"
    tag_search = [f"{exclusive}{tag_search_base}{ind_tn}" for ind_tn in ind_type_names]
    return tag_search

def retrieve_or_create_feed_events(settings,
                                   impsettings,
                                   org_id: str,
                                   distribution: int,
                                   sharing_group_id: int,
                                   misp_client: ExpandedPyMISP,
                                   feed_list: list,
                                   log_util: Logger
                                   ):

    title_base = settings['CrowdStrike'].get('indicator_type_title', 'Indicator Type:')
    # tag_search_base = "crowdstrike:indicator:feed:type: "
    ind_type_names = [i for i in dir(IndicatorType) if "__" not in i]
    # tag_search = [f"{tag_search_base}{ind_tn}" for ind_tn in ind_type_names]
    tag_search = get_feed_tags()
    feeds = misp_client.search_index(tags=tag_search)

    def _batch_create_feed(iname: str, already_created: list):
        returned = False
        if f"{title_base} {IndicatorType[iname].value}" not in already_created:
            feed = MISPEvent()
            feed.analysis = 2
            feed.orgc = org_id
            feed.distribution = distribution
            if distribution == "4":
                feed.sharing_group_id = sharing_group_id
            feed.info = f"{title_base} {IndicatorType[iname].value}"
            feed.add_tag(f"crowdstrike:indicator:feed:type: {iname.upper()}")
            # TYPE Taxonomic tag, all events
            if confirm_boolean_param(settings["TAGGING"].get("taxonomic_TYPE", False)):
                feed.add_tag('type:CYBINT')
            # INFORMATION-SECURITY-DATA-SOURCE Taxonomic tag, all events
            if confirm_boolean_param(settings["TAGGING"].get("taxonomic_INFORMATION-SECURITY-DATA-SOURCE", False)):
                feed.add_tag('information-security-data-source:integrability-interface="api"')
                feed.add_tag('information-security-data-source:originality="original-source"')
                feed.add_tag('information-security-data-source:type-of-source="security-product-vendor-website"')
            if confirm_boolean_param(settings["TAGGING"].get("taxonomic_IEP", False)):
                feed.add_tag('iep:commercial-use="MUST NOT"')
                feed.add_tag('iep:provider-attribution="MUST"')
                feed.add_tag('iep:unmodified-resale="MUST NOT"')
            if confirm_boolean_param(settings["TAGGING"].get("taxonomic_IEP2", False)):
                if confirm_boolean_param(settings["TAGGING"].get("taxonomic_IEP2_VERSION", False)):
                    feed.add_tag('iep2-policy:iep_version="2.0"')
                feed.add_tag('iep2-policy:attribution="must"')
                feed.add_tag('iep2-policy:unmodified_resale="must-not"')
            if confirm_boolean_param(settings["TAGGING"].get("taxonomic_TLP", False)):
                feed.add_tag("tlp:amber")
            custom_tag_list = settings["CrowdStrike"]["indicators_tags"].split(",")
            for tag_val in custom_tag_list:
                feed.add_tag(tag_val)
            if impsettings["publish"]:
                feed.published = True

            misp_client.add_event(feed)
            feed_list.append(feed)

            returned = True

        return returned


    feed_names = []
    for fd in feeds:
        do_add = True
        for f in feed_list:
            if fd.get("info") == f.info:
                do_add = False
        if do_add:
            ev = MISPEvent()
            ev.from_dict(**fd)
            feed_list.append(ev)
        feed_names.append(fd.get("info"))
    feed_names = list(set(feed_names))
    created = 0
    skipped = 0
    with ThreadPoolExecutor(misp_client.thread_count, thread_name_prefix="thread") as executor:
        futures = {
            executor.submit(_batch_create_feed, indname, feed_names) for indname in ind_type_names
        }
        for fut in as_completed(futures):
            if fut.result():
                created += 1
            else:
                skipped += 1

    if skipped:
        log_util.info("Retrieved %i CrowdStrike indicator type events from MISP.", skipped)

    if created:
        log_util.info("Adding %i CrowdStrike indicator type events to MISP.", created)

    return feed_list