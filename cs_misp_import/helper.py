"""Helper methods."""
from ._version import __version__ as MISP_IMPORT_VERSION

try:
    from pymisp import MISPObject, MISPAttribute
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
                #for tag in tag_list:
                #    att.add_tag(tag)

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

                return indicator_attribute

        return False

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
'##::::'##:'####::'######::'########:::::'####:'##::::'##:'########:::'#######::'########::'########:
 ###::'###:. ##::'##... ##: ##.... ##::::. ##:: ###::'###: ##.... ##:'##.... ##: ##.... ##:... ##..::
 ####'####:: ##:: ##:::..:: ##:::: ##::::: ##:: ####'####: ##:::: ##: ##:::: ##: ##:::: ##:::: ##::::
 ## ### ##:: ##::. ######:: ########:::::: ##:: ## ### ##: ########:: ##:::: ##: ########::::: ##::::
 ##. #: ##:: ##:::..... ##: ##.....::::::: ##:: ##. #: ##: ##.....::: ##:::: ##: ##.. ##:::::: ##::::
 ##:.:: ##:: ##::'##::: ##: ##:::::::::::: ##:: ##:.:: ##: ##:::::::: ##:::: ##: ##::. ##::::: ##::::
 ##:::: ##:'####:. ######:: ##:::::::::::'####: ##:::: ##: ##::::::::. #######:: ##:::. ##:::: ##::::
..:::::..::....:::......:::..::::::::::::....::..:::::..::..::::::::::.......:::..:::::..:::::..:::::
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
 ______  _______  ______ _____ __   _      ______  _______        _______ _______ _______
 |_____] |______ |  ____   |   | \  |      |     \ |______ |      |______    |    |______
 |_____] |______ |_____| __|__ |  \_|      |_____/ |______ |_____ |______    |    |______
"""
IMPORT_BANNER = """
 ______  _______  ______ _____ __   _      _____ _______  _____   _____   ______ _______
 |_____] |______ |  ____   |   | \  |        |   |  |  | |_____] |     | |_____/    |
 |_____] |______ |_____| __|__ |  \_|      __|__ |  |  | |       |_____| |    \_    |
"""
FINISHED_BANNER = r"""
 _______ _____ __   _ _____ _______ _     _ _______ ______
 |______   |   | \  |   |   |______ |_____| |______ |     \
 |       __|__ |  \_| __|__ ______| |     | |______ |_____/
"""

INDICATOR_TYPES = [
    "hash_md5",
    "hash_sha256",
    "hash_sha1",
    "hash_imphash",
    "file_name",
    "file_path",
    "url",
    "mutex_name",
    "bitcoin_address",
    "coin_address",
    "email_address",
    "email_subject",
    "registry",
    "device_name",
    "domain",
    "campaign_id",
    "ip_address",
    "service_name",
    "user_agent",
    "port",
    "password",
    "username",
    "x509_serial",
    "x509_subject",
]
