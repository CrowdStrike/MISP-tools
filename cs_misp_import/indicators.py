"""CrowdStrike Indicator MISP event import.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |                         |::.. . |
`-------'                         `-------'

@@@  @@@  @@@  @@@@@@@   @@@   @@@@@@@   @@@@@@   @@@@@@@   @@@@@@   @@@@@@@    @@@@@@
@@@  @@@@ @@@  @@@@@@@@  @@@  @@@@@@@@  @@@@@@@@  @@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@
@@!  @@!@!@@@  @@!  @@@  @@!  !@@       @@!  @@@    @@!    @@!  @@@  @@!  @@@  !@@
!@!  !@!!@!@!  !@!  @!@  !@!  !@!       !@!  @!@    !@!    !@!  @!@  !@!  @!@  !@!
!!@  @!@ !!@!  @!@  !@!  !!@  !@!       @!@!@!@!    @!!    @!@  !@!  @!@!!@!   !!@@!!
!!!  !@!  !!!  !@!  !!!  !!!  !!!       !!!@!!!!    !!!    !@!  !!!  !!@!@!     !!@!!!
!!:  !!:  !!!  !!:  !!!  !!:  :!!       !!:  !!!    !!:    !!:  !!!  !!: :!!        !:!
:!:  :!:  !:!  :!:  !:!  :!:  :!:       :!:  !:!    :!:    :!:  !:!  :!:  !:!      !:!
 ::   ::   ::   :::: ::   ::   ::: :::  ::   :::     ::    ::::: ::  ::   :::  :::: ::
:    ::    :   :: :  :   :     :: :: :   :   : :     :      : :  :    :   : :  :: : :

"""
import logging
import os
import sys
from threading import Lock
from datetime import datetime, timedelta
import concurrent.futures
from requests.exceptions import SSLError, ConnectionError
from cs_misp_import.indicator_feeds import retrieve_or_create_feed_events
from .helper import (
    gen_indicator,
    INDICATORS_BANNER,
    display_banner,
    thousands,
    get_actor_galaxy_map
    )
from .indicator_type import IndicatorType
from .indicator_feeds import retrieve_or_create_feed_events
from .indicator_family import check_and_set_threat_level, find_or_create_family_event, get_affiliated_branches, retrieve_family_events
from .indicator_tags import (
    tag_attribute_actor,
    tag_attribute_family,
    tag_attribute_targets
)
try:
    from pymisp import MISPEvent, MISPAttribute, ExpandedPyMISP, MISPServerError
except ImportError as no_pymisp:
    raise SystemExit(
        "The PyMISP package must be installed to use this program."
        ) from no_pymisp

class IndicatorsImporter:
    """Tool used to import indicators from the Crowdstrike Intel API.

    Adds them as objects attached to the events in MISP coresponding to the Crowdstrike Intel Reports they are related to.

    :param misp_client: client for a MISP instance
    :param intel_api_client: client for the Crowdstrike Intel API
    :param crowdstrike_org_uuid: UUID for the CrowdStrike organization within MISP
    :param indicators_timestamp_filename: Name of the indicator position tracking file
    :param import_all_indicators: Force import of all available indicators
    :param delete_outdated: Delete indicators flagged as outdated / expired. Not currently implemented.
    :param settings: Application settings (Namespace)
    :param import_settings: Import settings (Namespace)
    :param logger: Log utility
    """
    MISSING_GALAXIES = []
    def __init__(self,
                 misp_client,
                 intel_api_client,
                 crowdstrike_org_uuid,
                 indicators_timestamp_filename,
                 import_all_indicators,
                 delete_outdated,
                 settings,
                 import_settings,
                 logger
                 ):
        """Construct an instance of the IndicatorsImporter class."""
        self.misp: ExpandedPyMISP = misp_client
        self.intel_api_client = intel_api_client
        self.indicators_timestamp_filename = indicators_timestamp_filename
        self.import_all_indicators = import_all_indicators
        self.delete_outdated = delete_outdated
        self.settings = settings
        self.crowdstrike_org = self.misp.get_organisation(crowdstrike_org_uuid, True)
        self.import_settings = import_settings
        self.galaxy_miss_file = import_settings.get("miss_track_file", "no_galaxy_mapping.log")
        self.log: logging.Logger = logger
        self.feeds = []
        self.dirty_feeds = {}
        self.existing_indicators = {}
        self.skipped = 0
        self.reload = []
        self.batch_update = 0
        self.actor_map = get_actor_galaxy_map(self.misp, self.intel_api_client, self.import_settings["type"])
        self.tag_map = {}
        self.not_found = []


    def process_indicators(self, indicators_mins_before):
        """Pull and process indicators.

        :param indicators_days_before: in case on an initial run, this is the age of the indicators pulled in days
        """
        # Primary entry point / Main thread
        display_banner(banner=INDICATORS_BANNER,
                       logger=self.log,
                       fallback="BEGIN INDICATORS IMPORT",
                       hide_cool_banners=self.import_settings["no_banners"]
                       )

        self.log.info("Retrieving lookup data for import of CrowdStrike indicators into MISP.")
        # Calculate our search start time based upon the number of minutes specified in
        # our config. Do this here in case our search for a timestamp file is unsuccessful.
        start_get_events = int((
            datetime.today() + timedelta(minutes=-int(min(indicators_mins_before, 20220)))
            ).timestamp())
        # Retrieve our previous timestamp from our timestamp tracking file.
        if not self.import_settings.get("force", False):  # Force overrides the saved timestamp.
            if os.path.isfile(self.indicators_timestamp_filename):  # First run doesn't have one of these.
                with open(self.indicators_timestamp_filename, 'r', encoding="utf-8") as ts_file:
                    line = ts_file.readline()
                    start_get_events = int(line)

        # Calculate this moment in case there are no indicators returned. Set
        # this timestamp here in case indicators show up while we are searching.
        time_send_request = datetime.now()

        # FEED EVENT SETUP
        self.feeds = retrieve_or_create_feed_events(
            self.settings, self.import_settings, self.crowdstrike_org, self.misp, self.feeds, self.log
        )

        # FAMILY EVENT SEARCH
        self.feeds = retrieve_family_events(self.misp, self.feeds, self.log, self.settings["MISP"]["misp_malware_family_range"])

        # MAIN INDICATORS PROCESSING
        self.log.info("Starting import of CrowdStrike indicators into MISP.")
        indicators_count = 0

        # Trying something different
        for indicators_page in self.intel_api_client.get_indicators(start_get_events,
                                                                    self.delete_outdated,
                                                                    self.import_settings["type"]
                                                                    ):
            self.push_indicators(indicators_page)
            indicators_count += len(indicators_page)
        # Load it all first
        # all_indicators = []
        # for indicators_page in self.intel_api_client.get_indicators(start_get_events,
        #                                                             self.delete_outdated,
        #                                                             self.import_settings["type"]
        #                                                             ):
        #     indicators_count += len(indicators_page)
        #     all_indicators.extend(indicators_page)
        # # This might break things
        # self.push_indicators(all_indicators)

        # Old way
        if indicators_count == 0:
            self._note_timestamp(time_send_request.timestamp())

        # New way
#        self._note_timestamp(time_send_request.timestamp())

        self.log.info("Finished importing %s CrowdStrike Threat Intelligence indicators into MISP. "
                      f"(%s existing indicators skipped)",
                      thousands(indicators_count),
                      thousands(self.skipped)
                      )


    def get_laundry(self):
        """Retrieve a dictionary of dirty events that need to be saved."""
        laundry = {}
        for fe in [f for f in self.feeds if f.info in self.dirty_feeds]:
            laundry[fe.info] = {
                "object": fe,
                "count": self.dirty_feeds[fe.info]
            }

        return laundry


    def indicator_thread(self, ind, batch_lock):
        """Add the indicator detail as attributes to related events. Executed as a thread."""
        iname = ind.get('indicator')
        if iname:
                # try:
            feed_return, fam_return = self.add_indicator_event(ind, batch_lock) # All sharing the same lock
            with batch_lock:
                self.batch_update += 1
            if self.batch_update % 100 == 0:
                self.log.info("%s indicators processed", thousands(self.batch_update))
                # except Exception as err:
                #     exc_type, _, exc_tb = sys.exc_info()
                #     fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                #     self.log.debug(str(err))
                #     self.log.error("%s (#%i) %s", exc_type, exc_tb.tb_lineno, fname)


        return {"feed": feed_return, "fam": fam_return}


    def event_thread(self, evt: MISPEvent, ind_count: int, lock: Lock):
        """Save the event and inform the log. Retry on failure. Executed as a thread."""
        successful = False
        save_start = datetime.now().timestamp()
        tries = 1
        while tries < 4 and not successful:
            try:
                self.misp.update_event(evt)
                successful = True
            except (SSLError, ConnectionError, MISPServerError):
                self.log.warning("Connection failure, could not save event. ¯\(°_o)/¯")
            duration = datetime.now().timestamp() - save_start
            if not successful:
                self.log.warning("Unable to update %s with new indicators after %.2f seconds.",
                                 evt.info,
                                 duration
                                 )
            else:
                self.log.info("Updated %s with %s new indicator%s after %.2f seconds.",
                              evt.info,
                              ind_count,
                              "s" if ind_count != 1 else "",
                              duration
                              )
                # Still testing if this increases performance
                # Minimum setting: 30 seconds
                # Maximum setting: 300 seconds (5 minutes)
                try:
                    refresh_tolerance = int(self.settings["MISP"].get(
                        "event_save_memory_refresh_interval", 60
                        ))
                    refresh_tolerance = max(30, min(300, refresh_tolerance))
                    if duration > refresh_tolerance:
                        pos = 0
                        for fe in self.feeds:
                            if fe.info == evt.info:
                                break
                            else:
                                pos += 1

                        refreshed = MISPEvent()
                        self.log.debug("Refreshing memory logged event: %s", evt.info)
                        confirm = 0
                        for newer in self.misp.search(uuid=evt.uuid):  # Should only ever return one
                            refreshed.from_dict(**newer)
                            with lock:  # Shared
                                self.feeds.pop(pos)
                                self.feeds.append(refreshed)
                            self.log.info("%s refreshed in memory.", evt.info)
                            if confirm:
                                self.log.warning("More events returned for refresh event than expected")
                            confirm += 1
                except Exception as oops:
                    exc_type, _, exc_tb = sys.exc_info()
                    pyfname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    self.log.error(str(oops))
                    self.log.error("%s (#%i) %s", exc_type, exc_tb.tb_lineno, pyfname)
                    self.log.error("Could not refresh event in memory: %s", evt.info)

            tries += 1
        if not successful:
            self.log.error("Unable to update %s with %s new indicators.", evt.info, ind_count)

        return evt.info


    def process_indicator_batch(self, batch_to_process):
        """Process this individual batch of indicators. Spawns multiple threads."""
        thread_lock = Lock()
        self.batch_update = 0
        feed_success = 0
        feed_failed = 0
        fam_success = 0
        fam_failed = 0
        total_this_round = 0
        # Spawn multiple threads to process each indicator in the provided batch
        with concurrent.futures.ThreadPoolExecutor(self.misp.thread_count, thread_name_prefix="thread") as executor:
            futures = {
                executor.submit(self.indicator_thread, cur_ind, thread_lock)
                for cur_ind in batch_to_process
            }
            if not futures:
                return
            for fut in futures:
                total_this_round += 1
                if fut.result().get("feed"):
                    feed_success += 1
                else:
                    feed_failed += 1
                if fut.result().get("fam"):
                    fam_success += 1
                else:
                    fam_failed += 1

        return total_this_round, feed_success, feed_failed, fam_success, fam_failed


    def clean_laundry(self, batch_size, all_tot, f_failure, m_failure):
        """Save each of the events that have been flagged as dirty. Spawns multiple threads."""
        saved = []
        dirty = self.get_laundry()
        self.log.info(
            "This batch of %s produced %s indicators for %s events.",
            thousands(batch_size),
            thousands(all_tot),
            thousands(len(dirty)))
        self.log.info("%s indicator type and %s malware family event updates were skipped.",
            thousands(f_failure),
            thousands(m_failure)
            )
        thread_lock = Lock()
        # Spawn multiple threads to save any events that are dirty
        if dirty:
            with concurrent.futures.ThreadPoolExecutor(self.misp.thread_count, thread_name_prefix="thread") as executor:
                futures = {
                    executor.submit(self.event_thread, feed_data["object"], feed_data["count"], thread_lock)
                    for feed_data in dirty.values()
                }

                if not futures:
                    return

                for fut in futures:
                    saved.append(fut.result())

        return saved

    def push_indicators(self, indicators):
        """Push valid batches of indicators into MISP."""
        # This is the main application thread
        total_batch_start = datetime.now().timestamp()  # Batch start time
        # Retrieve the specified MISP update batch size using upper and lower bounds
        IND_BATCH_SIZE = max(50, min(25000, int(self.settings["MISP"].get("ind_attribute_batch_size", 500))))
        self.log.debug("Configuration states we should process batches of %s indicators.", thousands(IND_BATCH_SIZE))
        pushed_so_far = 0  # Track the total number of indicators processed
        # Cut our batch down to the MISP batch size specified in our configuration file
        ind_batches = [indicators[i:i+IND_BATCH_SIZE] for i in range(0, len(indicators), IND_BATCH_SIZE)]
        for batch in ind_batches:
            # Reset our sightings tracker
            self.misp.added_sightings_count = 0
            # Process each sub-batch of indicators and attach them to the events in memory
            self.log.info("Processing batch of %s indicators.", thousands(len(batch)))
            # The following line spawns multiple threads
            total, f_successes, f_failures, m_successes, m_failures = self.process_indicator_batch(batch)
            all_successes = f_successes + m_successes
            # Save the events in impacted by this batch of indicators
            # and remove the successful saves from our laundry basket
            for cleaned in self.clean_laundry(len(batch), all_successes, f_failures, m_failures):
                self.dirty_feeds.pop(cleaned)

            self.log.debug("Processed %s%s indicators for import into MISP.",
                           "another " if pushed_so_far > 0 else "",
                           thousands(len(batch))
                           )
            # Update our current position in the total batch
            pushed_so_far += len(batch)
            self.log.debug("%s have been pushed so far out of this batch of %s.", thousands(pushed_so_far), thousands(len(indicators)))

        batch_duration = datetime.now().timestamp() - total_batch_start  # Total time for the entire indicator run
        self.log.info("Pushed %s indicators into MISP in %.2f seconds.", thousands(len(indicators)), batch_duration)
        # Grab the latest timestamp from our list of processed indicators
        last_updated = next(i.get('last_updated') for i in reversed(indicators) if i.get('last_updated') is not None)
        # Save our position in the CrowdStrike Intel data feed by writing the timestamp
        # to a tracking file so we can start from the same spot next iteration
        self._note_timestamp(str(last_updated))


    @staticmethod
    def calculate_seen(ind, org):
        """Return a dictionary containing the first and last seen values for this indicator."""
        when_seen = {}
        if ind.get("published_date"):
            when_seen["first_seen"] = ind.get("published_date")
        if ind.get("last_updated"):
            when_seen["last_seen"] = ind.get("last_updated")
        when_seen["org"] = org

        return when_seen


    def process_attribute_tags(self, ind, uuid, tagging_list, t_lock, evt: MISPEvent):
        """Review the indicator labels and metadata, then tag the attribute accordingly. Executed as a thread."""
        try:
            did_branch, tagging_list = tag_attribute_actor(ind, tagging_list, self.actor_map, evt)
            # tagging_list = tag_attribute_malicious_confidence(ind, tagging_list)
            tagging_list = tag_attribute_targets(ind, tagging_list, evt)

            # did_threat, tagging_list = tag_attribute_threats(ind, tagging_list)
            # with t_lock:
            #     # Lock the thread since we're sharing the missing galaxy list
            #     tagging_list, self.MISSING_GALAXIES = tag_attribute_family(
            #         ind, tagging_list, self.import_settings, self.not_found,
            #         self.MISSING_GALAXIES, self.galaxy_miss_file, self.tag_map, self.misp, evt
            #         )
            
            # tagging_list = tag_attribute_labels(
            #    ind, tagging_list, self.log, did_branch, did_threat, self.settings, self.import_settings, evt
            #    )
            tagging_list, self.MISSING_GALAXIES = tag_attribute_family(
                    ind, tagging_list, self.import_settings, self.not_found,
                    self.MISSING_GALAXIES, self.galaxy_miss_file, self.tag_map, self.misp, evt
                    )
            for _tag in tagging_list:
                evt.add_attribute_tag(_tag, uuid)

            if evt.info not in self.dirty_feeds:
                #with t_lock:
                self.dirty_feeds.update({evt.info: 1})  # Shared
            else:
                #with t_lock:
                self.dirty_feeds[evt.info] += 1  # Shared

        except Exception as errored:
            exc_type, _, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.log.error(str(errored))
            self.log.error("%s (#%i) %s", exc_type, exc_tb.tb_lineno, fname)


    def add_and_tag_attribute(self, ind, ind_obj, evt: MISPEvent, when: dict, tlock: Lock):
        returned = 0
        try:
            self.process_attribute_tags(  # May be faster to pass the tags in as a list and then add_attribute
                ind, evt.add_attribute(ind_obj.type, ind_obj.value, **when).uuid, [], tlock, evt  # Correlate indicators
                )
            #evt.add_attribute(ind_obj.type, ind_obj.value, **when)
            returned = 1
            self.log.debug("Added %s indicators to event %s", ind_obj.value, evt.info)
        except Exception as oops:
            exc_type, _, exc_tb = sys.exc_info()
            pyfname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.log.error(str(oops))
            self.log.error("%s (#%i) %s", exc_type, exc_tb.tb_lineno, pyfname)
            self.log.error("Could not refresh event in memory: %s", evt.info)

        return returned


    def add_indicator_event(self, indicator, lock):
        """Add an indicator event or update an event for the indicator specified. Executed as a thread."""
        # Default returns
        feed_result = 0
        fam_result = 0
        try:
            itype = IndicatorType[indicator.get('type', None).upper()].value
        except KeyError:
            # This indicator type does not exist in our enumerator
            itype = None
        if not itype:
            with lock:
                self.skipped += 1
        else:
            cs_search = f"{self.settings['CrowdStrike'].get('indicator_type_title', 'Indicator Type:')} {itype}"
            # Search for an event of this type in our feed list
            evt = [e for e in self.feeds if cs_search == e.info]
            event: MISPEvent = evt[0] if evt else None
            # Create a malware family event if necessary and update the event list shared among the threads
            with lock:
                mal_event, self.feeds = find_or_create_family_event(indicator,
                                                                    self.settings,
                                                                    self.import_settings,
                                                                    self.crowdstrike_org,
                                                                    self.log,
                                                                    self.misp,
                                                                    self.feeds,
                                                                    *get_affiliated_branches(indicator)
                                                                    )

            indicator_value = indicator.get("indicator")
            if indicator_value:
                custom_tag_list = self.settings["CrowdStrike"]["indicators_tags"].split(",")
                indicator_object = gen_indicator(indicator, custom_tag_list)
                if indicator_object:
                    if isinstance(indicator_object, MISPAttribute):
                        seen = self.calculate_seen(indicator, self.crowdstrike_org)
                        if event:
                            feed_result = self.add_and_tag_attribute(
                                indicator, indicator_object, event, seen, lock
                            )

                        if mal_event:
                            #with lock:
                            #    mal_event = check_and_set_threat_level(indicator, mal_event, self.log)  # Shared event
                            fam_result = self.add_and_tag_attribute(
                                indicator, indicator_object, mal_event, seen, lock
                            )

                        if feed_result or fam_result:
                            self.log.debug("Creating attribute for indicator %s", indicator_value)

                    else:
                        self.log.warning("Couldn't generate indicator attribute %s to attach to event, skipping.",
                                        indicator_value
                                        )
            else:
                self.log.warning("Indicator %s missing indicator field.", indicator.get('id'))

        return feed_result, fam_result


    def _note_timestamp(self, timestamp):
        """Write the timestamp file for this run."""
        # Should only be called from the main thread
        with open(self.indicators_timestamp_filename, 'w', encoding="utf-8") as ts_file:
            ts_file.write(str(int(timestamp)))
        if self.MISSING_GALAXIES:
            for _galaxy in self.MISSING_GALAXIES:
                self.log.warning("No galaxy mapping found for %s malware family.", _galaxy)

            with open(self.galaxy_miss_file, "w", encoding="utf-8") as miss_file:
                miss_file.write("\n".join(self.MISSING_GALAXIES))
