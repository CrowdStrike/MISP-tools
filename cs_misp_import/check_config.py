"""Checks the configuration settings for the import."""
import os
from logging import basicConfig, getLogger, INFO, Logger, DEBUG
from configparser import ConfigParser
from datetime import datetime
from falconpy import BaseURL, Intel
from .helper import CONFIG_BANNER

BOOL_KEYS = [
    "api_enable_ssl", "misp_enable_ssl", "tag_unknown_galaxy_maps", "taxonomic_kill-chain",
    "taxonomic_information-security-data-source", "taxonomic_type", "taxonomic_iep",
    "taxonomic_iep2", "taxonomic_iep2_version", "taxonomic_tlp", "taxonomic_workflow"
]

REDACTED = ['client_id', 'client_secret', 'misp_auth_key']

class ConfigurationCheckResult:
    """Class to handle configuration check results."""

    def __init__(self, logger: Logger, extra: dict = None, _type: str = "info"):
        """Constructor for the ConfigurationCheckResult class."""
        self.msg = None
        self.log_type = _type
        self.log = logger
        self.extra = extra
        self.valid = True
        self.warns = 0
        self.errors = 0


    def put(self, msg: str):
        """Parse out the log type and display the log message appropriately."""
        msg = msg.split(":")
        self.log_type = msg[0].strip().lower()
        msg.pop(0)
        self.msg = ":".join(msg).strip()
        if self.log_type.lower() == "error":
            self.log.error(self.msg, extra=self.extra)
            self.valid = False
            self.errors += 1
        elif self.log_type.lower() == "warning":
            self.log.warning(self.msg, extra=self.extra)
            self.warns += 1
        elif self.log_type.lower() == "debug":
            self.log.debug(self.msg, extra=self.extra)
        elif self.log_type.lower() == "info":
            self.log.info(self.msg, extra=self.extra)
        elif self.log_type.lower() == "critical":
            self.log.critical(self.msg, extra=self.extra)
            self.valid = False
            self.errors += 1


    def total_warnings(self):
        """Return the total warning counts as a human readable string."""
        returned = ""
        if self.warns:
            returned = f"({self.warns} warning{'s' if self.warns != 1 else ''})"

        return returned


    def total_errors(self):
        """Return the total error counts as a human readable string."""
        returned = ""
        if self.errors:
            returned = f"{self.errors} configuration error{'s' if self.errors != 1 else ''} found"

        return returned


def config_logging(do_debug: bool = False):
    """Configure log formatting and return a Logger instance."""
    log_format = '[%(asctime)s] %(levelname)-8s %(name)s  %(key)-42s  %(message)s'
    basicConfig(format=log_format)
    logger = getLogger("config")
    if do_debug:
        logger.setLevel(DEBUG)
    else:
        logger.setLevel(INFO)

    return logger


def read_config_file(filename: str = "misp_import.ini"):
    """Consume the configuration file and return a ConfigParser instance."""
    conf_parser = ConfigParser()
    conf_parser.read(filename)

    return conf_parser


def not_found():
    """Display the invalid INI file message and raise an error condition."""
    #raise SystemExit(
    print(
        f"[{cur_time()}] CRITICAL config  Unable to read or parse configuration file"
        )
    return []


def is_valid_config(result: ConfigurationCheckResult):
    """Check for validity and display the result."""
    valid_config = False
    sev_detail = "INFO     config"
    if result.valid:
        print(
            f"[{cur_time()}] {sev_detail}  No configuration errors found {result.total_warnings()}"
            )
        valid_config = True
    else:

        print(
            f"[{cur_time()}] {sev_detail}  {result.total_errors()} {result.total_warnings()}"
            )

    return valid_config


def invalid_value(rslt: ConfigurationCheckResult, check_val: str):
    """Log an invalid value error."""
    rslt.put(f"ERROR: Invalid value specified ({check_val})")

    return False

def bool_str(check_val: str):
    """Confirm the provided string value represents a boolean."""
    returned = False
    if check_val.lower() in ["true", "false"]:
        returned = True

    return returned


def valid_uuid(uuid: str):
    """Confirm if the provided value is a valid UUID string and return a boolean."""
    is_valid = False
    uuid = uuid.split("-")
    if len(uuid[0]) == 8 and len(uuid[1]) == 4 and len(uuid[2]) == 4 and \
        len(uuid[3]) == 4 and len(uuid[4]) == 12:
        is_valid = True

    return is_valid


def valid_base(base: str):
    """Confirm if the provided value is a valid base_url string."""
    is_valid = False
    bases = [b.lower() for b in dir(BaseURL) if "__" not in b]
    bases.extend([BaseURL[b].value for b in dir(BaseURL) if "__" not in b])
    bases.extend(["us-1", "us-2", "us-1", "us-gov-1", "auto"])
    if base.lower() in bases:
        is_valid = True

    return is_valid


def failure(rslt: ConfigurationCheckResult, msg_str: str):
    """Process a failure log."""
    rslt.put(msg_str)

    return False


def warning(rslt: ConfigurationCheckResult, msg_str: str):
    """Process a warning log."""
    rslt.put(msg_str)

    return True


def generate_primer():
    """Returns a key primer to use for missing key identification."""
    primer = {
        "client_id": "CRITICAL",
        "client_secret": "CRITICAL",
        "misp_auth_key": "CRITICAL",
        "crowdstrike_url": "WARNING",
        "api_request_max": "ERROR",
        "api_enable_ssl": "ERROR",
        "misp_enable_ssl": "ERROR",
        "init_reports_days_before": "ERROR",
        "init_indicators_minutes_before": "ERROR",
        "init_actors_days_before": "ERROR",
        "galaxies_map_file": "WARNING",
        "crowdstrike_org_uuid": "ERROR",
        "max_threads": "WARNING"
    }
    bool_keys = {
        key_item: "WARNING" for key_item in BOOL_KEYS
    }
    primer.update(bool_keys)

    return primer


def check_for_missing(rslt: ConfigurationCheckResult, keyz: dict):
    """Check for any missing keys and handle the error based upon key criticality."""
    for check, check_val in keyz.items():
        rslt.extra = {"key": check, "section": None}
        if check_val == "WARNING":
            warning(rslt, "WARNING: Missing configuration parameter, using default")
        if check_val == "CRITICAL":
            failure(rslt, "CRITICAL: Missing configuration parameter")
        if check_val == "ERROR":
            failure(rslt, "ERROR: Missing configuration parameter")


def cur_time():
    """Return the current time in human readable format."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]


def validate_crowdstrike_creds(c_key: str,
                               c_val: str,
                               keyz: dict,
                               logg: ConfigurationCheckResult,
                               auth: dict
                               ):
    """Validate CrowdStrike client credential and base_url parameters."""
    if c_key == "client_id":  # 32 chars
        auth["creds"][c_key] = c_val
        keyz[c_key] = failure(logg,
            "CRITICAL: CrowdStrike client ID is formatted incorrectly",
            ) if len(c_val) != 32 else True
    if c_key == "client_secret":  # 40 chars
        auth["creds"][c_key] = c_val
        keyz[c_key] = failure(logg,
            "CRITICAL: CrowdStrike client secret is formatted incorrectly"
            ) if len(c_val) != 40 else True
    if c_key == "crowdstrike_url":
        auth["base_url"] = c_val
        keyz[c_key] = warning(logg,
            "WARNING: Non-standard CrowdStrike URL specified"
            ) if not valid_base(c_val) else True


def validate_misp_creds(c_key: str, c_val: str, keyz: dict, logg: ConfigurationCheckResult):
    """Validate MISP authorization key formatting."""
    if c_key == "misp_auth_key":  # 40 chars
        keyz[c_key] = failure(
            logg, "CRITICAL: MISP authorization key is formatted incorrectly"
            ) if len(c_val) != 40 else True


def validate_ssl(c_key: str, c_val: str, keyz: dict, logg: ConfigurationCheckResult):
    """Validate SSL encryption settings."""
    if c_key == "api_enable_ssl":
        keyz[c_key] = warning(
            logg, "WARNING: SSL is disabled for CrowdStrike API requests"
            ) if "f" in c_val.lower() else True
    if c_key == "misp_enable_ssl":
        keyz[c_key] = warning(
            logg, "WARNING: SSL is disabled for MISP API requests"
            ) if "f" in c_val.lower() else True


def validate_start_times(c_key: str, c_val: str, keyz: dict, logg: ConfigurationCheckResult):
    """Validate the default start times."""
    try:
        if c_key == "init_reports_days_before":
            keyz[c_key] = invalid(logg, c_val) if (0 > int(c_val) or int(c_val) > 365) else True
        if c_key == "init_indicators_minutes_before":
            keyz[c_key] = invalid(logg, c_val) if (0 > int(c_val) or int(c_val) > 20220) else True
        if c_key == "init_actors_days_before":
            keyz[c_key] = invalid(logg, c_val) if (0 > int(c_val) or int(c_val) > 730) else True
    except ValueError:
        keyz[c_key] = invalid(logg, c_val)


def validate_booleans(c_key: str, c_val: str, keyz: dict, logg: ConfigurationCheckResult):
    """Validate all boolean parameters."""
    if c_key in BOOL_KEYS:
        keyz[c_key] = invalid(logg, c_val) if not bool_str(c_val) else True


def validate_org_id(c_key: str, c_val: str, keyz: dict, logg: ConfigurationCheckResult):
    """Validate the CrowdStrike org UUID format."""
    if c_key == "crowdstrike_org_uuid":
        keyz[c_key] = invalid(logg, c_val) if not valid_uuid(c_val) else True


def validate_galaxies_mapping(c_key: str, c_val: str, keyz: dict, logg: ConfigurationCheckResult):
    """Validate the galaxy mapping file's existence."""
    if c_key == "galaxies_map_file":
        keyz[c_key] = warning(logg,
            "WARNING: Specified galaxy mapping file not found"
            ) if not os.path.exists(c_val) else True


def validate_api_limits(c_key: str, c_val: str, keyz: dict, logg: ConfigurationCheckResult):
    """Validate parameters relating to API limits."""
    if c_key == "api_request_max":
        try:
            keyz[c_key] = invalid(logg, c_val) if (5000 < int(c_val) or int(c_val) < 0) else True
        except ValueError:
            keyz[c_key] = invalid(logg, c_val)


def validate_max_threads(c_key: str, c_val: str, keyz: dict, logg: ConfigurationCheckResult):
    """Validate the max_threads parameter."""
    if c_key == "max_threads":
        try:
            hit = False
            if not c_val:
                c_val = 0
            if int(c_val) < 0:
                hit = invalid(logg, c_val)
            if int(c_val) > 64:
                hit = warning(logg, "WARNING: Potentially dangerous thread count specified")
            if hit:
                keyz[c_key] = hit
        except ValueError:
            keyz[c_key] = invalid(logg, c_val)


def validate_login(auth: dict, logg: ConfigurationCheckResult):
    """Validate that authentication generates a valid bearer token."""
    auth_check = Intel(creds=auth["creds"], base_url=auth["base_url"])
    if auth_check.token_status != 201:
        logg.extra = {"key": "authentication"}
        failure(logg, "CRITICAL: Invalid API credentials provided")
    auth = None


def show_debug_detail(c_key: str, c_val: str, _: dict, logg: ConfigurationCheckResult):
    """Show parameter value debug output."""
    dbg = c_val if c_key not in REDACTED else 'value redacted, check config file'
    logg.put(f"DEBUG: {dbg if c_val else 'value not specified'}")


def invalid(log_device: ConfigurationCheckResult, c_value: str):
    """Process invalid parameter value alerts."""
    return invalid_value(log_device, c_value)


def validate_config(config_file: str = None, debugging: bool = False, no_banner: bool = False):
    """Review the configuration contents for errors and report the results."""
    out = ConfigurationCheckResult(config_logging(debugging))
    if not no_banner:
        for line in CONFIG_BANNER.split("\n"):
            print(f"[{cur_time()}] INFO     config  {line}")
    else:
        print(f"[{cur_time()}] INFO     config  CHECK CONFIG")
    config = read_config_file(config_file)
    keys = generate_primer()
    auth_info = {"creds": {"client_id": "Not set", "client_secret": "Not set"}, "base_url": "auto"}
    for sect in config.sections() if config.sections() else not_found():
        for key in config[sect]:
            out.extra = {"key": key}
            val = config[sect].get(key)
            vals = [key, val, keys, out]
            show_debug_detail(*vals)
            validate_crowdstrike_creds(*vals, auth_info)
            validate_misp_creds(*vals)
            validate_ssl(*vals)
            validate_api_limits(*vals)
            validate_start_times(*vals)
            validate_booleans(*vals)
            validate_galaxies_mapping(*vals)
            validate_org_id(*vals)
            validate_max_threads(*vals)

    validate_login(auth_info, out)
    check_for_missing(out, keys)

    return is_valid_config(out)
