from enum import Enum

class IndicatorType(Enum):
    """CrowdStrike indicator type enumerator."""

    HASH_MD5 = "MD5 hashes"
    HASH_SHA256 = "SHA256 hashes"
    HASH_SHA1 = "SHA1 hashes"
    HASH_IMPHASH = "IMP hashes"
    FILE_NAME = "File names"
    FILE_PATH = "File directory paths"
    URL = "Web addresses"
    MUTEX_NAME = "Mutexes"
    BITCOIN_ADDRESS = "BTC addresses"
    COIN_ADDRESS = "BIC addresses"
    EMAIL_ADDRESS = "Email addresses"
    EMAIL_SUBJECT = "Email subjects"
    REGISTRY = "Registry key locations"
    DEVICE_NAME = "Device host names"
    DOMAIN = "Web domains"
    CAMPAIGN_ID = "Campaign IDs"
    IP_ADDRESS = "IP addresses"
    SERVICE_NAME = "Service names"
    USER_AGENT = "User-Agent strings"
    PERSONA_NAME = "Alias or persona name"
    PORT = "TCP ports"
    PASSWORD = "Password credentials"  # nosec  # unavoidable bandit false positive
    USERNAME = "Credential user names"
    X509_SERIAL = "Certificate serial numbers"
    X509_SUBJECT = "Certificate subjects"
    