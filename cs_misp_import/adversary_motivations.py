from enum import Enum

class AdversaryMotivation(Enum):
    """CrowdStrike adversary motivations enumerator."""

    INTELLIGENCEGATHERING = "Intelligence Gathering"
    DENIALOFSERVICE = "Denial of Service"
    DESTRUCTION = "Destruction"
    INTELLECTUALPROPERTYTHEFT = "Intellectual Property Theft"
    FINANCIALGAIN = "Financial Gain"
    DEFACEMENT = "Defacement"
