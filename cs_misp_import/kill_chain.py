from enum import Enum

class KillChain(Enum):
    """Kill chain enumerator."""

    ACTIONONOBJECTIVES = "Actions on Objectives"
    C2 = "Command and Control"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
