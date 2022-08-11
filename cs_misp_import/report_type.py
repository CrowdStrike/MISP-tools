from enum import Enum

class ReportType(Enum):
    """CrowdStrike report type enumerator."""

    CSA = "Alert"
    CSAR = "Annual Report"
    CSIR = "Intelligence Report"
    CSDR = "Daily Report"
    CSIT = "Intelligence Tip"
    CSGT = "Global Threat Analysis"
    CSIA = "Intelligence Assessment"  # Quarterly reports also are flagged with this
    CSMR = "Monthly Report"
    CSTA = "Threat Assessment"
    CSWR = "Weekly Report"
