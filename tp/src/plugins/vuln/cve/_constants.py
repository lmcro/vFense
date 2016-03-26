import os

from vFense.plugins.vuln._constants import DateValues


class CVEDataDir():
    PLUGIN_DIR = os.path.abspath(os.path.dirname(__file__))
    XML_DIR = os.path.join(PLUGIN_DIR, 'data/xml')
    NVD_MODIFIED_FILE = os.path.join(XML_DIR, 'nvdcve-Modified.xml.gz')
    NVD_MODIFIED_FILE_UNCOMPRESSED = (
        os.path.join(XML_DIR, 'nvdcve-Modified.xml.gz')
    )
    NVD_RECENT_FILE = os.path.join(XML_DIR, 'nvdcve-Recent.xml.gz')
    NVD_RECENT_FILE_UNCOMPRESSED = (
        os.path.join(XML_DIR, 'nvdcve-Recent.xml.gz')
    )
    NVD_CURRENT_FILE = (
        os.path.join(
            XML_DIR, 'nvdcve-%s.xml.gz' %
            (str(DateValues.CURRENT_YEAR))
        )
    )


class NVDFeeds():
    ENTRY = '{http://nvd.nist.gov/feeds/cve/1.2}entry'
    DESC = '{http://nvd.nist.gov/feeds/cve/1.2}desc'
    REFS = '{http://nvd.nist.gov/feeds/cve/1.2}refs'
    VULN_SOFT = '{http://nvd.nist.gov/feeds/cve/1.2}vuln_soft'


class CVEStrings():
    START_YEAR = 2002
    METRIC = 'metric'
    VALUE = 'value'
    CVSS_VECTOR = 'CVSS_vector'
    VENDOR = 'vendor'
    VENDOR_NAME = 'name'
    VENDOR_VERSIONS = 'versions'
    CVE_NAME = 'name'
    CVE_ID = 'seq'
    CVSS_SCORE = 'CVSS_score'
    CVSS_BASE_SCORE = 'CVSS_base_score'
    CVSS_EXPLOIT_SUBSCORE = 'CVSS_exploit_subscore'
    CVSS_IMPACT_SUBSCORE = 'CVSS_impact_subscore'
    CVSS_VERSION = 'CVSS_version'
    CVE_MODIFIED_DATE = 'modified'
    CVE_PUBLISHED_DATE = 'published'
    DESCRIPTION = 'description'
    DESCRIPTION_SOURCE = 'source'
    REF_URL = 'url'
    REF_SOURCE = 'source'
    REF_ID = 'id'
    NVD_TYPE = 'type'
    CVE_SEVERITY = 'severity'
    NVD_DOWNLOAD_URL = 'http://nvd.nist.gov/download/'
    NVDCVE_BASE = 'nvdcve-'
    NVDCVE_MODIFIED = 'nvdcve-Modified.xml.gz'
    NVD_MODIFIED_URL = NVD_DOWNLOAD_URL + NVDCVE_MODIFIED
    NVDCVE_RECENT = 'nvdcve-Recent.xml.gz'
    NVD_RECENT_URL = NVD_DOWNLOAD_URL + NVDCVE_RECENT


class CVEVectors():
    BASE_METRIC_AV = 'AV'
    BASE_METRIC_AC = 'AC'
    BASE_METRIC_Au = 'Au'
    BASE_METRIC_C = 'C'
    BASE_METRIC_I = 'I'
    BASE_METRIC_A = 'A'
    TEMPORAL_METRIC_E = 'E'
    TEMPORAL_METRIC_RL = 'RL'
    TEMPORAL_METRIC_RC = 'RC'
    ENVIRONMENTAL_METRIC_CDP = 'CDP'
    ENVIRONMENTAL_METRIC_TD = 'TD'
    ENVIRONMENTAL_METRIC_CR = 'CR'
    ENVIRONMENTAL_METRIC_IR = 'IR'
    ENVIRONMENTAL_METRIC_AR = 'AR'


class CVECategories():
    CSRF = 'CSRF'
    DDOS = 'Denial Of Service'
    CSS = 'Cross-site Scripting'
    SQLI = 'SQL Injection'
    MEM_CORRUPTION = 'Memory Corruption'
    SENSTIVE_INFORMATION = 'Sensitive Information'
    CODE_EXECUTION = 'Code Execution'
    FILE_INCLUSION = 'File_Inclusion'
    HTTP_RESPONSE_SPLITTING_ATTACKS = 'HTTP Response Splitting Attacks'
    BUFFER_OVERFLOW = 'buffer overflow'
    OVERFLOWS = 'Overflows'
    GAIN_PRIVILEGE = 'Gain Privilege'
    DIRECTORY_TRAVERSAL = 'Directory Traversal'
    BYPASS = 'Bypass'
    CATEGORIES = (
        [
            CSRF, DDOS, CSS, SQLI, MEM_CORRUPTION,
            SENSTIVE_INFORMATION, CODE_EXECUTION,
            FILE_INCLUSION, HTTP_RESPONSE_SPLITTING_ATTACKS,
            OVERFLOWS, GAIN_PRIVILEGE, DIRECTORY_TRAVERSAL,
            BYPASS, BUFFER_OVERFLOW
        ]
    )

#########CVS_BASE_VECTORS######################################3
CVSS_BASE_VECTORS = (
    {
        'AV': 'Access Vector',
        'AC': 'Access Complexity',
        'Au': 'Authentication',
        'C': 'Confidentiality Impact',
        'I': 'Integrity Impact',
        'A': 'Availability Impact'
    }
)

CVSS_BASE_VECTOR_AV_VALUES = (
    {
        'L': 'Local Access',
        'A': 'Adjacent Network',
        'N': 'Network',
    }
)

CVSS_BASE_VECTOR_AC_VALUES = (
    {
        'L': 'Low',
        'M': 'Medium',
        'H': 'High',
    }
)

CVSS_BASE_VECTOR_AU_VALUES = (
    {
        'N': 'None Required',
        'S': 'Requires single instance',
        'M': 'Requires multiple instances'
    }
)

CVSS_BASE_VECTOR_C_VALUES = (
    {
        'N': 'None',
        'P': 'Partial',
        'C': 'Complete'
    }
)

CVSS_BASE_VECTOR_I_VALUES = (
    {
        'N': 'None',
        'P': 'Partial',
        'C': 'Complete'
    }
)

CVSS_BASE_VECTOR_A_VALUES = (
    {
        'N': 'None',
        'P': 'Partial',
        'C': 'Complete'
    }
)

#########CVS_TEMPORAL_VECTORS######################################3

CVSS_TEMPORAL_VECTORS = (
    {
        'E': 'Exploitability',
        'RL': 'Remediation Level',
        'RC': 'Report Confidence',
    }
)

CVSS_TEMPORAL_VECTOR_E_VALUES = (
    {
        'U': 'Unproven',
        'P': 'Proof Of Concept',
        'F': 'Functional',
        'H': 'High',
        'ND': 'Not Defined',
    }
)

CVSS_TEMPORAL_VECTOR_RL_VALUES = (
    {
        'O': 'Official Fix',
        'T': 'Temporary Fix',
        'W': 'Work Around',
        'U': 'Unavailable',
        'ND': 'Not Defined',
    }
)

CVSS_TEMPORAL_VECTOR_RC_VALUES = (
    {
        'UC': 'Unconfirmed',
        'UR': 'Uncorroborated',
        'C': 'Confirmed',
        'ND': 'Not Defined',
    }
)

#########CVS_ENVIRONMENTAL_VECTORS######################################3

CVSS_ENVIRONMENTAL_VECTORS = (
    {
        'CDP': 'Collateral Damage Potential',
        'TD': 'Target Distribution',
        'CR': 'System Confidentiality Requirement',
        'IR': 'System Integrity Requirement',
        'AR': 'System Availability Requirement'
    }
)

CVSS_ENVIRONMENTAL_CDP_VALUES = (
    {
        'N': 'None',
        'L': 'Low',
        'LM': 'Low-Medium',
        'M': 'Medium',
        'MH': 'Medium-High',
        'H': 'High',
        'ND': 'Not Defined',
    }
)

CVSS_ENVIRONMENTAL_TD_VALUES = (
    {
        'N': 'None (0%)',
        'L': 'Low (1-25%)',
        'M': 'Medium (26-75%)',
        'H': 'High (76-100%)',
        'ND': 'Not Defined',
    }
)

CVSS_ENVIRONMENTAL_CR_VALUES = (
    {
        'L': 'Low',
        'M': 'Medium',
        'H': 'High',
        'ND': 'Not Defined',
    }
)

CVSS_ENVIRONMENTAL_IR_VALUES = (
    {
        'L': 'Low',
        'M': 'Medium',
        'H': 'High',
        'ND': 'Not Defined',
    }
)

CVSS_ENVIRONMENTAL_AR_VALUES = (
    {
        'L': 'Low',
        'M': 'Medium',
        'H': 'High',
        'ND': 'Not Defined',
    }
)
