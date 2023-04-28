"""Helper methods."""
from logging import Logger
from datetime import datetime, timedelta
from ._version import __version__ as MISP_IMPORT_VERSION
#from .intel_client import IntelAPIClient

try:
    from pymisp import MISPObject, MISPAttribute, ExpandedPyMISP, MISPGalaxyCluster
except ImportError as no_pymisp:
    raise SystemExit(
        "The PyMISP package must be installed to use this program."
        ) from no_pymisp

def gen_indicator(indicator, tag_list) -> MISPObject or MISPAttribute:
    """Create the appropriate MISP event object for the indicator (based upon type)."""
    if not indicator.get('type') or not indicator.get('indicator'):
        return False

    indicator_type = indicator.get('type')
    indicator_value = indicator.get('indicator')
    indicator_first = indicator.get("published_date", 0)
    indicator_last = indicator.get("last_updated", 0)
    # Type, Object_Type, Attribute Name
    ind_objects = [
        # ["hash_md5", "file", "md5"],
        # ["hash_sha256", "file", "sha256"],
        # ["hash_sha1", "file", "sha1"],
        # ["file_name", "file", "filename"],
        # ["mutex_name", "mutex", "name"],
        ["password", "credential", "password"],
        # ["url", "url", "url"],
        # ["email_address", "email", "reply-to"],
        ["username", "credential", "username"],
        # ["bitcoin_address", "btc-transaction", "btc-address"],
        # ["registry", "registry-key", "key"],
        ["x509_serial", "x509", "serial-number"],
        # ["file_path", "file", "fullpath"],
        # ["email_subject", "email", "subject"],
        # ["coin_address", "coin-address", "address"],
        ["x509_subject", "x509", "subject"],
        #["device_name", "device", "name"],
        # ["hash_imphash", "pe", "imphash"]
    ]

    for ind_obj in ind_objects:
        if indicator_type == ind_obj[0]:
            indicator_object = MISPObject(ind_obj[1])
            att = indicator_object.add_attribute(ind_obj[2], indicator_value)
            if indicator_first:
                att.first_seen = indicator_first
            if indicator_last:
                att.last_seen = indicator_last
            att.add_tag(f"CrowdStrike:indicator:type: {ind_obj[2].upper()}")
            for tag in tag_list:
                att.add_tag(tag)

            return indicator_object

    # Type, Category, Attribute Type
    ind_attributes = [
        ["hash_md5", "Artifacts dropped", "md5"],
        ["hash_sha256", "Artifacts dropped", "sha256"],
        ["hash_sha1", "Artifacts dropped", "sha1"],
        ["hash_imphash", "Artifacts dropped", "imphash"],
        ["file_name", "Artifacts dropped", "filename"],
        ["file_path", "Payload delivery", "filename"],
        ["url", "Network activity", "url"],
        ["mutex_name", "Artifacts dropped", "mutex"],
        ["bitcoin_address", "Financial fraud", "btc"],
        ["coin_address", "Financial fraud", "bic"],
        ["email_address", "Payload delivery", "email-reply-to"],
        ["email_subject", "Payload delivery", "email-subject"],
        ["registry", "Persistence mechanism", "regkey"],
        ["device_name", "Targeting data", "target-machine"],
        ["domain", "Network activity", "domain"],
        ["campaign_id", "Attribution", "campaign-id"],
        ["ip_address", "Network activity", "ip-src"],
        ["service_name", "Artifacts Dropped", "windows-service-name"],
        ["user_agent", "Network activity", "user-agent"],
        ["port", "Network activity", "port"]
    ]

    for ind_att in ind_attributes:
        if indicator_type == ind_att[0]:
            indicator_attribute = MISPAttribute()
            indicator_attribute.category = ind_att[1]
            indicator_attribute.type = ind_att[2]
            indicator_attribute.value = indicator_value
            for tag in tag_list:
                indicator_attribute.add_tag(tag)
            return indicator_attribute

    return False


def thousands(int_to_format: int):
    return f"{int_to_format:,}"


def format_seconds(val: int):
    parts = str(float(val)).split(".")
    front = thousands(int(parts[0]))
    back = f"{parts[1]:.2}"
    return ".".join([front, back])


def two_decimals(float_to_format: float):
    return f"{float_to_format:.2}"


def confirm_boolean_param(val: str or bool) -> bool:
    returned = False
    if "T" in str(val).upper():
        returned = True

    return returned


def display_banner(banner: str = None,
                   logger: Logger = None,
                   fallback: str = None,
                   hide_cool_banners: bool = False  # ASCII r00lz!
                   ):
    """Logging helper to handle banner disablement."""
    if banner and logger:
        if not hide_cool_banners:
            for line in banner.split("\n"):
                logger.info(line, extra={"key": ""})
        else:
            if fallback:
                logger.info(fallback, extra={"key": ""})

def get_threat_actor_galaxy_id(client: ExpandedPyMISP):
    # Retrieve the Threat Actors galaxy
    ta_galaxy_id = None
    galaxies = client.galaxies()
    for gal in galaxies:
        if gal["Galaxy"]["name"] == "Threat Actor":
            ta_galaxy_id = gal["Galaxy"]["uuid"]
    return ta_galaxy_id


def get_region_galaxy_map(mispclient: ExpandedPyMISP):
    region_map = {}
    galaxy_id = [g for g in mispclient.galaxies() if g["Galaxy"]["name"] == "Regions UN M49"][0]["Galaxy"]["uuid"]
    galaxy = mispclient.get_galaxy(galaxy_id)
    if "GalaxyCluster" in galaxy:
        for gal in galaxy["GalaxyCluster"]:
            region_map[" ".join(gal["value"].split(" ")[2:])] = gal["tag_name"]

    return region_map


def get_actor_galaxy_map(mispclient: ExpandedPyMISP,
                         intel_client,
                         type_filter
                         ):
    actor_map = {}
    # Retrieve the Threat Actors galaxy
    galaxy = mispclient.get_galaxy(get_threat_actor_galaxy_id(mispclient))
    # Review all available actors within the galaxy
    threat_actors = {}
    for gal in galaxy["GalaxyCluster"]:
        # print(gal)
        threat_actors[gal["value"]] = {
                "tag_name": gal["tag_name"],
                "uuid": gal["uuid"],
                "default": gal["default"],
                "name": gal["value"],
                "deleted": gal["deleted"],
                "id": gal["id"]
            }
    # Retrieve all CrowdStrike adversaries
    start_get_events = int((datetime.today() + timedelta(days=-7300)).timestamp())
    actors = intel_client.get_actors(start_get_events, type_filter)
    # Review all adversaries and map the CS names to existing actors
    for act in actors:
        for taname, taval in threat_actors.items():
            #print(taval)
            if taname.upper() == act["name"].upper():
                actor_map[taname.upper()] = {
                    "uuid": taval["uuid"],
                    "tag_name": taval["tag_name"],
                    "custom": not taval["default"],
                    "name": taval["name"],
                    "deleted": taval["deleted"],
                    "id": taval["id"],
                    "cs_name": act["name"].upper(),
                    "cs_id": act["id"]
                }
    for act in [a for a in actors if a["name"] not in actor_map]:
        not_set = True
        aliases = [a.strip().upper() for a in act["known_as"].split(",")]
        for taname, taval in threat_actors.items():
            if taname.upper() in aliases and not_set:
                actor_map[act['name'].upper()] = {
                    "uuid": taval["uuid"],
                    "tag_name": taval["tag_name"],
                    "custom": not taval["default"],
                    "name": taval["name"],
                    "deleted": taval["deleted"],
                    "id": taval["id"],
                    "cs_name": act["name"].upper(),
                    "cs_id": act["id"]
                }
                not_set = False
    return actor_map

def add_cluster_elements(actrec, actdet, clust: MISPGalaxyCluster):
# Adversary motivations
    motives = actdet.get("motivations", None)
    if motives:
        for mname in [m.get("value") for m in motives]:
            clust.add_cluster_element("motive", mname)
    # Adversary Synonyms
    if actrec.get('known_as'):
        for alias in [a.strip() for a in actrec.get("known_as").split(",")]:
            clust.add_cluster_element("synonyms", alias)
    # Adversary targets
    if actrec.get("target_countries"):
        for region in [c.get('value') for c in actrec.get('target_countries', [])]:
            clust.add_cluster_element("cfr-suspected-victims", region)
    # Adversary target categories
    if actrec.get("target_industries"):
        for sector in [s.get('value') for s in actrec.get('target_industries', [])]:
            clust.add_cluster_element("cfr-target-category", sector)
    # Actor origin
    if actrec.get("origins"):
        for orig in [o for o in actrec.get('origins', [])]:
            if len(orig.get("slug")) == 2:
                clust.add_cluster_element("country", orig.get("slug").upper())
            else:
                clust.add_cluster_element("region", orig.get("value"))
    # MITRE ATT&CK will happen here


def normalize_locale(locale_to_normalize: str):
    normalize = {
        "Russian Federation": "Russia",
        "Southeast Asia": "South-eastern Asia",
        "Subsaharan Africa": "Sub-Saharan Africa",
        "North America": "Northern America",
        "North Africa": "Northern Africa",
        "Middle East": "Western Asia",
        "Central Africa": "Middle Africa",
        "West Africa": "Western Africa",
        "East Africa": "Eastern Africa",
        "East Asia": "Asia",
        "South Asia": "Asia",
        "Latin America": "Latin America and the Caribbean",
        "Syrian Arab Republic": "Syria",
        "Libyan Arab Jamahiriya": "Libya",
        "Congo": "Republic of the Congo",
        "Côte D'Ivoire": "Ivory Coast",
        "Vatican City State": "Vatican",
        "St. Helena": "Saint Helena",
        "St. Martin": "Saint Martin",
        "Timor-Leste": "East Timor",
        "Bosnia/Herzegovina": "Bosnia and Herzegovina",
        "Macedonia": "North Macedonia",
        "Brunei Darussalam": "Brunei",
        "Macao": "Macau",
        "Virgin Islands, British": "British Virgin Islands",
        "Lao": "Laos"
    }
    if locale_to_normalize in normalize.keys():
        locale_to_normalize = normalize[locale_to_normalize]
    return locale_to_normalize


def normalize_killchain(kc_to_normalize: str):
    normalize = {
        "actions_and_objectives": "objectives",
        "actions_on_objectives": "objectives",
        "command_and_control": "command-control",
        "command and control": "command-control",
        "actions and objectives": "objectives",
        "actions on objectives": "objectives"
    }
    if kc_to_normalize.lower() in normalize:
        kc_to_normalize = normalize[kc_to_normalize.lower()]

    return kc_to_normalize

def normalize_sector(sector_to_normalize: str):
    normalize = {
        "Healthcare": "Health",
        "Universities": "Academia - University",
        "Higher Education": "Higher education",
        "Telecommunications": "Telecoms",
        "Telecom": "Telecoms",
        "Cryptocurrency": "Finance",
        "Industrials and Engineering": "Industrial",
        "Architectural and Engineering": "Construction",
        "Government": "Government, Administration",
        "Academic": "Academia - University",
        "Law Enforcement": "Police - Law enforcement",
        "Media": "News - Media",
        "Financial Services": "Finance",
        "Sports Organizations": "Sport",
        "Oil and Gas": "Oil",
        "Logistics": "Logistic",
        "Social Media": "Social networks",
        "National Government": "Country",
        "Opportunistic": "Other",
        "Transportation": "Transport",
        "Local Government": "Government, Administration",
        "Nuclear": "Energy",
        "International Government": "Diplomacy",
        "Political Parties": "Political party",
        "Utilities": "Infrastructure",
        "Dissident": "Dissidents",
        "Consumer Goods": "Retail",
        "Food and Beverage": "Food",
        "Computer Gaming": "Game",
        "Aviation": "Civil Aviation",
        "Real Estate": "Investment",
        "Chemicals": "Chemical",
        "Pharmaceutical": "Pharmacy",
        "Consulting and Professional Services": "Consulting",
        "Emergency Services": "Citizens",
        "Extractive": "Mining",
        "Nonprofit": "Civil society",
        "Research Entities": "Research - Innovation",
        "Vocational and Higher-Level Education": "Higher education",
        "Financial Management & Hedge Funds": "Investment",
        "Financial": "Finance"
    }
    if sector_to_normalize in normalize.keys():
        sector_to_normalize = normalize[sector_to_normalize]
    return sector_to_normalize 

# These are here because I didn't want us to have to import pyFiglet
ADVERSARIES_BANNER = """
  ____  ___    __ __    ___  ____    _____  ____  ____   ____    ___  _____
 /    T|   \  |  T  |  /  _]|    \  / ___/ /    T|    \ l    j  /  _]/ ___/
Y  o  ||    \ |  |  | /  [_ |  D  )(   \_ Y  o  ||  D  ) |  T  /  [_(   \_
|     ||  D  Y|  |  |Y    _]|    /  \__  T|     ||    /  |  | Y    _]\__  T
|  _  ||     |l  :  !|   [_ |    \  /  \ ||  _  ||    \  |  | |   [_ /  \ |
|  |  ||     | \   / |     T|  .  Y \    ||  |  ||  .  Y j  l |     T\    |
l__j__jl_____j  \_/  l_____jl__j\_j  \___jl__j__jl__j\_j|____jl_____j \___j
"""

INDICATORS_BANNER = """
 ____  ____   ___    ____    __   ____  ______   ___   ____    _____
l    j|    \ |   \  l    j  /  ] /    T|      T /   \ |    \  / ___/
 |  T |  _  Y|    \  |  T  /  / Y  o  ||      |Y     Y|  D  )(   \_
 |  | |  |  ||  D  Y |  | /  /  |     |l_j  l_j|  O  ||    /  \__  T
 |  | |  |  ||     | |  |/   \_ |  _  |  |  |  |     ||    \  /  \ |
 j  l |  |  ||     | j  l\     ||  |  |  |  |  l     !|  .  Y \    |
|____jl__j__jl_____j|____j\____jl__j__j  l__j   \___/ l__j\_j  \___j
"""
REPORTS_BANNER = """
 ____     ___  ____    ___   ____  ______  _____
|    \   /  _]|    \  /   \ |    \|      T/ ___/
|  D  ) /  [_ |  o  )Y     Y|  D  )      (   \_
|    / Y    _]|   _/ |  O  ||    /l_j  l_j\__  T
|    \ |   [_ |  |   |     ||    \  |  |  /  \ |
|  .  Y|     T|  |   l     !|  .  Y |  |  \    |
l__j\_jl_____jl__j    \___/ l__j\_j l__j   \___j
"""
MISP_BANNER = f"""
'##::::'##:'####::'######::'########:::::'########::'#######:::'#######::'##::::::::'######::
 ###::'###:. ##::'##... ##: ##.... ##::::... ##..::'##.... ##:'##.... ##: ##:::::::'##... ##:
 ####'####:: ##:: ##:::..:: ##:::: ##::::::: ##:::: ##:::: ##: ##:::: ##: ##::::::: ##:::..::
 ## ### ##:: ##::. ######:: ########:::::::: ##:::: ##:::: ##: ##:::: ##: ##:::::::. ######::
 ##. #: ##:: ##:::..... ##: ##.....::::::::: ##:::: ##:::: ##: ##:::: ##: ##::::::::..... ##:
 ##:.:: ##:: ##::'##::: ##: ##:::::::::::::: ##:::: ##:::: ##: ##:::: ##: ##:::::::'##::: ##:
 ##:::: ##:'####:. ######:: ##:::::::::::::: ##::::. #######::. #######:: ########:. ######::
..:::::..::....:::......:::..:::::::::::::::..::::::.......::::.......:::........:::......:::
           _____
            /  '
         ,-/-,__ __
        (_/  (_)/ (_
                     _______                        __ _______ __        __ __
                    |   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
                    |.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
                    |.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
                    |:  1   |                         |:  1   |
                    |::.. . |                         |::.. . |  Threat Intelligence v{MISP_IMPORT_VERSION}
                    `-------'                         `-------'
"""
DELETE_BANNER = """
______  _______        _______ _______ _______
|     \ |______ |      |______    |    |______
|_____/ |______ |_____ |______    |    |______
"""
IMPORT_BANNER = """
_____ _______  _____   _____   ______ _______
  |   |  |  | |_____] |     | |_____/    |
__|__ |  |  | |       |_____| |    \_    |
"""
CONFIG_BANNER = """
_______ _     _ _______ _______ _     _      _______  _____  __   _ _______ _____  ______
|       |_____| |______ |       |____/       |       |     | | \  | |______   |   |  ____
|_____  |     | |______ |_____  |    \_      |_____  |_____| |  \_| |       __|__ |_____|
"""
FINISHED_BANNER = r"""
 _______  __  .__   __.  __       _______. __    __   _______  _______
|   ____||  | |  \ |  | |  |     /       ||  |  |  | |   ____||       \
|  |__   |  | |   \|  | |  |    |   (----`|  |__|  | |  |__   |  .--.  |
|   __|  |  | |  . `  | |  |     \   \    |   __   | |   __|  |  |  |  |
|  |     |  | |  |\   | |  | .----)   |   |  |  |  | |  |____ |  '--'  |
|__|     |__| |__| \__| |__| |_______/    |__|  |__| |_______||_______/
"""
CHECKS_PASSED = r"""
____ _  _ ____ ____ _  _ ____    ___  ____ ____ ____ ____ ___
|    |__| |___ |    |_/  [__     |__] |__| [__  [__  |___ |  \
|___ |  | |___ |___ | \_ ___]    |    |  | ___] ___] |___ |__/
"""
CHECKS_FAILED = r"""
____ _  _ ____ ____ _  _ ____    ____ ____ _ _    ____ ___
|    |__| |___ |    |_/  [__     |___ |__| | |    |___ |  \
|___ |  | |___ |___ | \_ ___]    |    |  | | |___ |___ |__/
"""
WARNING_BANNER = r"""
@@@  @@@  @@@   @@@@@@   @@@@@@@   @@@  @@@  @@@  @@@  @@@   @@@@@@@@  @@@
@@@  @@@  @@@  @@@@@@@@  @@@@@@@@  @@@@ @@@  @@@  @@@@ @@@  @@@@@@@@@  @@@
@@!  @@!  @@!  @@!  @@@  @@!  @@@  @@!@!@@@  @@!  @@!@!@@@  !@@        @@!
!@!  !@!  !@!  !@!  @!@  !@!  @!@  !@!!@!@!  !@!  !@!!@!@!  !@!        !@
@!!  !!@  @!@  @!@!@!@!  @!@!!@!   @!@ !!@!  !!@  @!@ !!@!  !@! @!@!@  @!@
!@!  !!!  !@!  !!!@!!!!  !!@!@!    !@!  !!!  !!!  !@!  !!!  !!! !!@!!  !!!
!!:  !!:  !!:  !!:  !!!  !!: :!!   !!:  !!!  !!:  !!:  !!!  :!!   !!:
:!:  :!:  :!:  :!:  !:!  :!:  !:!  :!:  !:!  :!:  :!:  !:!  :!:   !::  :!:
 :::: :: :::   ::   :::  ::   :::   ::   ::   ::   ::   ::   ::: ::::   ::
  :: :  : :     :   : :   :   : :  ::    :   :    ::    :    :: :: :   :::
"""
MUSHROOM = r"""
    {}     _.-^^---....,,---;
     _--/                  `--_
    <                        >)
    |{}        {}KA-BOOM! {}       {} |
     \._                   _./
        ```--{}{}. . , ; .{}{}--'''{}
              {}| |   |
           {}{}.-={}{}||  | |{}{}=-.{}{}
           {}{}`-=#$%&%$#=-'{}{}
              | ;  :|
     {}_____{}.,-#%&$@%#&#~,.{}_____
         {}COMMAND  ACCEPTED{}
"""

INDICATOR_TYPES = {
    "hash_md5" : "md5",
    "hash_sha256" : "sha256",
    "hash_sha1" : "sha1",
    "hash_imphash" : "imphash",
    "file_name" : "filename",
    "file_path" : "filename",
    "url" : "url",
    "mutex_name" : "mutex",
    "bitcoin_address" : "btc",
    "coin_address" : "bic",
    "email_address" : "email-reply-to",
    "email_subject" : "email-subject",
    "registry" : "regkey",
    "device_name" : "target-machine",
    "domain" : "domain",
    "campaign_id" : "campaign-id",
    "ip_address" : "ip-src",
    "service_name" : "windows-service-name",
    "user_agent" : "user-agent",
    "port" : "port",
    # These are outstanding
    "password" : "",
    "username" : "",
    "x509_serial" : "",
    "x509_subject" : "",
}
