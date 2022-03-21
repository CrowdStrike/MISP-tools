from enum import Enum

class MaliciousConfidence(Enum):
    """Malicious Confidence enumerator."""

    UNVERIFIED = 4
    LOW = 3
    MEDIUM = 2
    HIGH = 1
