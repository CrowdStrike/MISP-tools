from enum import Enum

class ReportType(Enum):
    """CrowdStrike report type enumerator."""

    ALERT = "Test Alert"
    CSA = "Alert"
    CSAR = "Annual Report"
    CSIR = "Intelligence Report"
    CSDR = "Daily Report"
    CSIT = "Intelligence Tip"
    CSGT = "Global Threat Analysis"
    CSIA = "Intelligence Assessment"  # Quarterly reports can also be flagged with this
    CSQR = "Quarterly Report"
    CSMR = "Monthly Report"
    CSTA = "Threat Assessment"
    CSWR = "Weekly Report"
    NOTICE = "Notice"
    GTAC = "Unmapped"
    TEST = "Test Report"
