import datetime
import logging
import os

try:
    from pymisp import MISPObject, MISPEvent, MISPOrganisation
except ImportError as no_pymisp:
    raise SystemExit(
        "The PyMISP package must be installed to use this program."
        ) from no_pymisp



class ActorsImporter:
    """Tool used to import actors from the Crowdstrike Intel API and push them as events in MISP through the MISP API.

    :param misp_client: client for a MISP instance
    :param intel_api_client: client for the Crowdstrike Intel API
    """

    def __init__(self, misp_client, intel_api_client, crowdstrike_org_uuid, actors_timestamp_filename, settings, unknown = "UNIDENTIFIED"):
        """Construct an instance of the ActorsImporter class."""
        self.misp = misp_client
        self.intel_api_client = intel_api_client
        self.actors_timestamp_filename = actors_timestamp_filename
        org = MISPOrganisation()
        org.uuid = crowdstrike_org_uuid
        self.crowdstrike_org = self.misp.get_organisation(org, True)
        self.settings = settings
        self.unknown = unknown

    def process_actors(self, actors_days_before, events_already_imported):
        """Pull and process actors.

        :param actors_days_before: in case on an initialisation run, this is the age of the actors pulled in days
        :param events_already_imported: the events already imported in misp, to avoid duplicates
        """
        start_get_events = int((datetime.date.today() - datetime.timedelta(actors_days_before)).strftime("%s"))
        if os.path.isfile(self.actors_timestamp_filename):
            with open(self.actors_timestamp_filename, 'r', encoding="utf-8") as ts_file:
                line = ts_file.readline()
                start_get_events = int(line)

        logging.info("Started getting actors from Crowdstrike Intel API and pushing them as events in MISP.")
        time_send_request = datetime.datetime.now()
        actors = self.intel_api_client.get_actors(start_get_events)
        logging.info("Got %i actors from the Crowdstrike Intel API.", len(actors))

        # if events_already_imported.get(self.unknown) is None:
        #     unknown_actor = {
        #         "name": self.unknown,
        #         "url": "",
        #         "short_description": "Unidentified actor",
        #         "known_as": self.unknown,   
        #         # "first_activity": "",
        #         # "last_activity": "",    # Intetionally not populating these fields
        #         # "target_countries": "",
        #         # "target_regions": ""
        #     }
        #     create_unknown = self.create_event_from_actor(unknown_actor)
        #     if not create_unknown:
        #         logging.warning("Unable to create unknown actor generic event.")
            # try:
            #     unkn = self.misp.add_event(create_unknown, True)
            #     for tag in self.settings["CrowdStrike"]["actors_tags"].split(","):
            #         self.misp.tag(unkn, tag)
            #     self.misp.tag(unkn, self.unknown)
            #     events_already_imported[self.unknown] = True
            # except Exception as err:
            #     logging.warning("Could not add or tag unknown actor event.")

        if len(actors) == 0:
            with open(self.actors_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                ts_file.write(time_send_request.strftime("%s"))
        else:
            for actor in actors:

                actor_name = actor.get('name')
                if actor_name is not None:
                    if events_already_imported.get(actor_name) is not None:
                        continue

                event = self.create_event_from_actor(actor)
                if not event:
                    logging.warning("Failed to create a MISP event for actor %s.", actor)
                    continue

                try:
                    event = self.misp.add_event(event, True)
                    for tag in self.settings["CrowdStrike"]["actors_tags"].split(","):
                        self.misp.tag(event, tag)
                    # Create an actor specific tag
                    actor_tag = actor_name.split(" ")[1]
                    self.misp.tag(event, actor_tag)
                    if actor_name is not None:
                        events_already_imported[actor_name] = True
                except Exception as err:
                    logging.warning("Could not add or tag event %s.\n%s", event.info, str(err))

                if actor.get('last_modified_date') is None:
                    logging.warning("Failed to confirm actor %s in file.", actor)
                    continue

                with open(self.actors_timestamp_filename, 'w', encoding="utf-8") as ts_file:
                    ts_file.write(str(actor.get('last_modified_date')))

        logging.info("Finished getting actors from Crowdstrike Intel API and pushing them as events in MISP.")

    def create_event_from_actor(self, actor):
        """Create a MISP event for a valid Actor."""
        event = MISPEvent()
        event.analysis = 2
        event.orgc = self.crowdstrike_org

        if actor.get('name'):
            event.info = actor.get('name')
        else:
            logging.warning("Actor %s missing field name.", actor.get('id'))

        if actor.get('url'):
            event.add_attribute('link', actor.get('url'))
        else:
            logging.warning("Actor %s missing field url.", actor.get('id'))

        if actor.get('short_description'):
            event.add_attribute('comment', actor.get('short_description'))
        else:
            logging.warning("Actor %s missing field short_description.", actor.get('id'))

        if actor.get('known_as'):
            known_as_object = MISPObject('organization')
            known_as_object.add_attribute('alias', actor.get('known_as'))
            event.add_object(known_as_object)
        else:
            logging.warning("Actor %s missing field known_as.", actor.get('id'))

        had_timestamp = False
        timestamp_object = MISPObject('timestamp')

        if actor.get('first_activity_date'):
            timestamp_object.add_attribute('first-seen',
                                           datetime.datetime.utcfromtimestamp(actor.get('first_activity_date')).isoformat()
                                           )
            had_timestamp = True
        else:
            logging.warning("Actor %s missing field first_activity_date.", actor.get('id'))

        if actor.get('last_activity_date'):
            timestamp_object.add_attribute('last-seen',
                                           datetime.datetime.utcfromtimestamp(actor.get('last_activity_date')).isoformat()
                                           )
            had_timestamp = True
        else:
            logging.warning("Actor %s missing field last_activity_date.", actor.get('id'))

        if had_timestamp:
            event.add_object(timestamp_object)

        for country in actor.get('target_countries', []):
            if country.get('value'):
                country_object = MISPObject('victim')
                country_object.add_attribute('regions', country.get('value'))
                event.add_object(country_object)
            else:
                logging.warning("Target country from actor %s is missing value field.", actor.get('id'))

        for industry in actor.get('target_industries', []):
            if industry.get('value'):
                industry_object = MISPObject('victim')
                industry_object.add_attribute('sectors', industry.get('value'))
                event.add_object(industry_object)
            else:
                logging.warning("Target country from actor %s is missing value field.", actor.get('id'))

        return event