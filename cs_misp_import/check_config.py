"""Checks the configuration settings for the import."""
import os
from logging import basicConfig, getLogger, INFO, Logger, DEBUG
from configparser import ConfigParser
from datetime import datetime
from falconpy import BaseURL, Intel


BOOL_KEYS = [
    "api_enable_ssl", "misp_enable_ssl", "tag_unknown_galaxy_maps", "taxonomic_kill-chain",
    "taxonomic_information-security-data-source", "taxonomic_type", "taxonomic_iep", "taxonomic_iep2",
    "taxonomic_iep2_version", "taxonomic_tlp", "taxonomic_workflow"
]

REDACTED = ['client_id', 'client_secret', 'misp_auth_key']

class ConfigurationCheckResult:
    """This is an interesting way to do this..."""

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
    log_format = '[%(asctime)s] %(levelname)-8s %(name)s (%(key)s) %(message)s'
    basicConfig(format=log_format)
    logger = getLogger("config_check")
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
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    raise SystemExit(f"[{now}] CRITICAL config_check (NOT FOUND) Unable to read INI file or parse configuration sections")


def is_valid_config(result: ConfigurationCheckResult):
    """Check for validity and display the result."""
    valid_config = False
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    if result.valid:
        print(f"[{now}] INFO     config_check (VALID) No configuration errors found {result.total_warnings()}")
        valid_config = True
    else:
        print(f"[{now}] INFO     config_check (INVALID) {result.total_errors()} {result.total_warnings()}")

    return valid_config


def invalid_value(rslt: ConfigurationCheckResult, item: str, check_val: str):
    """Log an invalid value error."""
    rslt.put(f"ERROR: Invalid value specified for '{item}' ({check_val})")

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
    rslt.put(msg_str)

    return False


def warning(rslt: ConfigurationCheckResult, msg_str: str):
    rslt.put(msg_str)

    return True


def generate_primer():
    """Returns a key primer to use for missing key identification."""
    primer = {
        "client_id": "CRITICAL",
        "client_secret": "CRITICAL",
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
            warning(rslt, "WARNING: Missing configuration value, using default")
        if check_val == "CRITICAL":
            failure(rslt, "CRITICAL: Missing configuration value")
        if check_val == "ERROR":
            failure(rslt, "ERROR: Missing configuration value")


def validate_config(config_file: str = None, debugging: bool = False):
    """Review the configuration contents for errors and report the results."""
    config = read_config_file(config_file)
    out = ConfigurationCheckResult(config_logging(debugging))
    keys = generate_primer()
    test_creds = {"client_id": "Not set", "client_secret": "Not set", "base_url": "auto"}
    for sect in config.sections() if config.sections() else not_found():
        for key in config[sect]:
            out.extra = {"key": key, "section": sect}
            val = config[sect].get(key)
            invalid = lambda: invalid_value(out, key, val)
            fail = lambda m: failure(out, msg_str=f"{keys[key]}: {m}")
            alert = lambda m: warning(out, msg_str=f"{keys[key]}: {m}")
            dbg = val if key not in REDACTED else 'value redacted, check config file'
            out.put(f"DEBUG: {dbg}")
            if key == "client_id":  # 32 chars
                test_creds[key] = val
                keys[key] = fail(
                    "Client ID does not appear to be in the correct format"
                    ) if len(val) != 32 else True
            if key == "client_secret":  # 40 chars
                test_creds[key] = val
                keys[key] = fail(
                    "Client Secret does not appear to be in the correct format"
                    ) if len(val) != 40 else True
            if key == "crowdstrike_url":
                test_creds[key] = val
                keys[key] = alert(
                    "Non-standard CrowdStrike URL specified"
                    ) if not valid_base(val) else True
            if key == "api_request_max":
                keys[key] = invalid() if (5000 < int(val) or int(val) < 0) else True
            if key == "api_enable_ssl":
                keys[key] = alert(
                    "SSL encryption is disabled for CrowdStrike API requests"
                    ) if "f" in val.lower() else True
            if key == "misp_enable_ssl":
                keys[key] = alert(
                    "SSL encryption is disabled for MISP API requests"
                    ) if "f" in val.lower() else True
            if key == "init_reports_days_before":
                keys[key] = invalid() if (0 > int(val) or int(val) > 365) else True
            if key == "init_indicators_minutes_before":
                keys[key] = invalid() if (0 > int(val) or int(val) > 20220) else True
            if key == "init_actors_days_before":
                keys[key] = invalid() if (0 > int(val) or int(val) > 730) else True
            if key in BOOL_KEYS:
                keys[key] = invalid() if not bool_str(val) else True
            if key == "galaxies_map_file":
                keys[key] = alert(
                    "Specified galaxy mapping file not found"
                    ) if not os.path.exists(val) else True
            if key == "crowdstrike_org_uuid":
                keys[key] = invalid() if not valid_uuid(val) else True
            if key == "max_threads":
                hit = False
                if not val:
                    hit = invalid()
                    val = 0
                if int(val) > 64:
                    hit = alert("Potentially dangerous thread count specified")
                if hit:
                    keys[key] = hit

    auth_check = Intel(creds=test_creds)
    if auth_check.token_status != 201:
        out.extra = {"key": "authentication"}
        failure(out, "CRITICAL: Invalid API credentials provided")

    check_for_missing(out, keys)

    return is_valid_config(out)
