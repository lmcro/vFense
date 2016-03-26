import os
import gc
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from lxml import etree
from re import sub
from vFense.plugins.vuln.cve import CveKey
from vFense.plugins.vuln.cve._constants import (
    CVEDataDir, NVDFeeds, CVEStrings, CVEVectors,
    CVSS_BASE_VECTORS, CVSS_BASE_VECTOR_AV_VALUES,
    CVSS_BASE_VECTOR_AC_VALUES, CVSS_BASE_VECTOR_AU_VALUES,
    CVSS_BASE_VECTOR_C_VALUES, CVSS_BASE_VECTOR_I_VALUES,
    CVSS_BASE_VECTOR_A_VALUES, CVSS_TEMPORAL_VECTORS,
    CVSS_TEMPORAL_VECTOR_E_VALUES, CVSS_TEMPORAL_VECTOR_RL_VALUES,
    CVSS_TEMPORAL_VECTOR_RC_VALUES, CVSS_ENVIRONMENTAL_VECTORS
)

from vFense.plugins.vuln.cve._db import insert_cve_data, update_cve_categories
from vFense.plugins.vuln.cve.downloader import start_nvd_xml_download
from vFense.utils.common import date_parser, timestamp_verifier
from vFense.db.client import r

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')


class NvdParser(object):
    """The purpose of this class, is to parse NVD/CVE XML 1.2 Data Files.
    """
    def get_entry_info(self, entry):
        """Parse the top level entry object in the XML file
        Args:
            entry (lxml.etree._Element): This is an lxml Element
        Returns:
            Dictionary
            {
                "cvss_vector": [
                    {
                        "metric": "Access Vector",
                        "value": "Network"
                    },
                    {
                        "metric": "Access Complexity",
                        "value": "Medium"
                    }
                ],
                "cve_sev": "Medium",
                "cve_id": "CVE-2009-5138",
                "cvss_base_score": "5.8",
                "cvss_exploit_subscore": "8.6",
                "cvss_version": "2.0",
                "cvss_impact_subscore": "4.9",
                "cvss_score": "5.8"
            }
        """
        data = {}
        attrib = entry.attrib
        data[CveKey.CveId] = attrib.get(CVEStrings.CVE_NAME)
        data[CveKey.CveSev] = attrib.get(CVEStrings.CVE_SEVERITY)
        data[CveKey.CvePublishedDate] = (
            r.epoch_time(
                timestamp_verifier(
                    date_parser(
                        attrib.get(CVEStrings.CVE_PUBLISHED_DATE)
                    )
                )
            )
        )
        data[CveKey.CveModifiedDate] = (
            r.epoch_time(
                timestamp_verifier(
                    date_parser(
                        attrib.get(CVEStrings.CVE_MODIFIED_DATE)
                    )
                )
            )
        )
        data[CveKey.CvssScore] = (
            attrib.get(CVEStrings.CVSS_SCORE)
        )
        data[CveKey.CvssBaseScore] = (
            attrib.get(CVEStrings.CVSS_BASE_SCORE)
        )
        data[CveKey.CvssImpactSubScore] = (
            attrib.get(CVEStrings.CVSS_IMPACT_SUBSCORE)
        )
        data[CveKey.CvssExploitSubScore] = (
            attrib.get(CVEStrings.CVSS_EXPLOIT_SUBSCORE)
        )
        data[CveKey.CvssVector] = (
            self._parse_vectors(attrib.get(CVEStrings.CVSS_VECTOR))
        )
        data[CveKey.CvssVersion] = (
            attrib.get(CVEStrings.CVSS_VERSION)
        )

        return(data)

    def get_descriptions(self, entry):
        """Parse the desc object under the top level entry object
        in the XML file.

        Args:
            entry (lxml.etree._Element): This is an lxml Element

        Returns:
            List of dictionaires
            [
                {
                    "source": "cve",
                    "description": "GnuTLS before 2.7.6, when the GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT flag is not enabled, treats version 1 X.509 certificates as intermediate CAs, whi
                        ch allows remote attackers to bypass intended restrictions by leveraging a X.509 V1 certificate from a trusted CA to issue new certificates, a different vulnerability tha
                        n CVE-2014-1959."
                }
            ]

        """
        list_of_descriptions = []
        for descript in entry:
            list_of_descriptions.append(
                {
                    CVEStrings.DESCRIPTION: descript.text,
                    CVEStrings.DESCRIPTION_SOURCE: descript.attrib.get(
                        CVEStrings.DESCRIPTION_SOURCE)
                }
            )

        return(list_of_descriptions)

    def get_refs(self, entry):
        """Parse the refs object under the top level entry object
        in the XML file.

        Args:
            entry (lxml.etree._Element): This is an lxml Element

        Returns:
            [
                {
                    "url": "https://gitorious.org/gnutls/gnutls/commit/c8dcbedd1fdc312f5b1a70fcfbc1afe235d800cd",
                    "source": "CONFIRM",
                    "id": "https://gitorious.org/gnutls/gnutls/commit/c8dcbedd1fdc312f5b1a70fcfbc1afe235d800cd"
                },
                {
                    "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1069301",
                    "source": "CONFIRM",
                    "id": "https://bugzilla.redhat.com/show_bug.cgi?id=1069301"
                },
                {
                    "url": "http://thread.gmane.org/gmane.comp.security.oss.general/12127",
                    "source": "MLIST",
                    "id": "[oss-security] 20140227 Re: CVE Request - GnuTLS corrects flaw in certificate verification (3.1.x/3.2.x)"
                },
            ]
        """
        list_of_refs = []
        for reference in entry:
            list_of_refs.append(
                {
                    CVEStrings.REF_ID: reference.text,
                    CVEStrings.REF_URL: reference.attrib.get(
                        CVEStrings.REF_URL
                    ),
                    CVEStrings.REF_SOURCE: reference.attrib.get(
                        CVEStrings.REF_SOURCE
                    ),
                }
            )

        return(list_of_refs)

    def get_vulns_soft(self, entry):
        """Parse the vuln_soft object under the top level entry object
        in the XML file.

        Args:
            entry (lxml.etree._Element): This is an lxml Element
        """
        vuln_soft_list = []
        for vulns_soft in entry:
            vuln_soft_dict = {}
            vuln_soft_dict[CVEStrings.VENDOR_VERSIONS] = []
            vulns = vulns_soft.getchildren()
            for vuln in vulns:
                vuln_soft_dict[CVEStrings.VENDOR] = (
                    vuln.attrib.get(CVEStrings.VENDOR)
                )
                vuln_soft_dict[CVEStrings.VENDOR_NAME] = (
                    vuln.attrib.get(CVEStrings.VENDOR_NAME)
                )
                vulns_versions = vuln.getchildren()
                for version in vulns_versions:
                    version_dict = {}
                    for key in version.keys():
                        version_dict[key] = version.attrib[key]
                    vuln_soft_dict[CVEStrings.VENDOR_VERSIONS].append(
                        version_dict
                    )
            vuln_soft_list.append(vuln_soft_dict)

        return(vuln_soft_list)

    def _parse_vectors(self, unformatted_vector):
        """Parse the vectors in the top level entry object in the XML file
        Args:
            unformatted_vector ():
        """
        translated_metric = None
        translated_value = None
        formatted_vectors = []
        if unformatted_vector:
            vectors = sub('\(|\)', '', unformatted_vector).split('/')
            for vector in vectors:
                metric, value = vector.split(':')
                translated_metric, translated_value = (
                    self._verify_vector(metric, value)
                )
                formatted_vectors.append(
                    {
                        CVEStrings.METRIC: translated_metric,
                        CVEStrings.VALUE: translated_value
                    }
                )

        return(formatted_vectors)

    def _verify_vector(self, metric, value):
        """Translate the cve vector acronyms into siomething understandable
        Args:
            metric (str): Example... AV|AC|Au|C|I|A
            value (str):  Example... L|A|N
        """
        translated_metric = None
        translated_value = None

        if metric in CVSS_BASE_VECTORS:
            translated_metric = CVSS_BASE_VECTORS[metric]

            if metric == CVEVectors.BASE_METRIC_AV:
                translated_value = CVSS_BASE_VECTOR_AV_VALUES[value]

            elif metric == CVEVectors.BASE_METRIC_AC:
                translated_value = CVSS_BASE_VECTOR_AC_VALUES[value]

            elif metric == CVEVectors.BASE_METRIC_Au:
                translated_value = CVSS_BASE_VECTOR_AU_VALUES[value]

            elif metric == CVEVectors.BASE_METRIC_C:
                translated_value = CVSS_BASE_VECTOR_C_VALUES[value]

            elif metric == CVEVectors.BASE_METRIC_I:
                translated_value = CVSS_BASE_VECTOR_I_VALUES[value]

            elif metric == CVEVectors.BASE_METRIC_A:
                translated_value = CVSS_BASE_VECTOR_A_VALUES[value]

        elif metric in CVSS_TEMPORAL_VECTORS:
            translated_metric = CVSS_TEMPORAL_VECTORS[metric]

            if metric == CVEVectors.TEMPORAL_METRIC_E:
                translated_value = CVSS_TEMPORAL_VECTOR_E_VALUES[value]

            elif metric == CVEVectors.TEMPORAL_METRIC_RL:
                translated_value = CVSS_TEMPORAL_VECTOR_RL_VALUES[value]

            elif metric == CVEVectors.TEMPORAL_METRIC_RC:
                translated_value = CVSS_TEMPORAL_VECTOR_RC_VALUES[value]

        elif metric in CVSS_ENVIRONMENTAL_VECTORS:
            translated_metric = CVSS_ENVIRONMENTAL_VECTORS[metric]

            # TODO(urgent): what happened to the BASE_VECTOR and
            # ENVIRONMENTAL_VECTOR dictionaries?

            if metric == CVEVectors.ENVIRONMENTAL_METRIC_CDP:
                translated_value = CVSS_ENVIRONMENTAL_CDP_VALUES[value]

            elif metric == CVEVectors.ENVIRONMENTAL_METRIC_TD:
                translated_value = CVSS_ENVIRONMENTAL_TD_VALUES[value]

            elif metric == CVEVectors.ENVIRONMENTAL_METRIC_CR:
                translated_value = CVSS_ENVIRONMENTAL_CR_VALUES[value]

            elif metric == CVEVectors.ENVIRONMENTAL_METRIC_IR:
                translated_value = CVSS_ENVIRONMENTAL_IR_VALUES[value]

            elif metric == CVEVectors.ENVIRONMENTAL_METRIC_AR:
                translated_value = CVSS_ENVIRONMENTAL_AR_VALUES[value]

        return(translated_metric, translated_value)


def parse_cve_and_udpatedb(
    download_latest_nvd=True,
    nvd_files=[
        CVEDataDir.NVD_RECENT_FILE_UNCOMPRESSED[:-3],
        CVEDataDir.NVD_MODIFIED_FILE_UNCOMPRESSED[:-3],
        CVEDataDir.NVD_CURRENT_FILE[:-3]
    ]
        ):

    """This begins the actual parsing of the xml files and loads up the data
        into the database
    Kwargs:
        download_latest_nvd (bool): Whether or not to download
            the latest nvd data
        nvd_files (list): This is a list of the files you want to parse
    """

    if download_latest_nvd:
        start_nvd_xml_download()
    parser = NvdParser()
    for nvd_file in nvd_files:
        cve_data_list = []
        cve_data = {}
        for event, entry in etree.iterparse(nvd_file, events=['start', 'end']):
            if entry.tag == NVDFeeds.ENTRY and event == 'start':
                cve_data = parser.get_entry_info(entry)

            if entry.tag == NVDFeeds.DESC and event == 'start':
                cve_data[CveKey.CveDescriptions] = \
                    parser.get_descriptions(entry)

            if entry.tag == NVDFeeds.REFS and event == 'start':
                cve_data[CveKey.CveRefs] = parser.get_refs(entry)

            #if entry.tag == NVDFeeds.VULN_SOFT and event == 'start':
            #    cve_data[CveKey.CveVulnsSoft] = parser.get_vulns_soft(entry)

            cve_data[CveKey.CveCategories] = []
            if entry.tag == NVDFeeds.ENTRY and event == 'end':
                for key in cve_data.keys():
                    if (key != CveKey.CveDescriptions and
                            key != CveKey.CveRefs and
                            key != CveKey.CveVulnsSoft and
                            key != CveKey.CvePublishedDate and
                            key != CveKey.CveCategories and
                            key != CveKey.CvssVector and
                            key != CveKey.CveModifiedDate):
                        cve_data[key] = unicode(cve_data[key])

                cve_data_list.append(cve_data)

            #entry.clear()
            #while entry.getprevious() is not None:
            #    del entry.getparent()[0]
            #del entry
        insert_cve_data(cve_data_list)
        del cve_data_list
        del cve_data
        gc.collect()


def load_up_all_xml_into_db():
    nvd_files = []
    if not os.path.exists(CVEDataDir.XML_DIR):
        os.makedirs(CVEDataDir.XML_DIR)
    xml_exists = os.listdir(CVEDataDir.XML_DIR)
    logger.info('starting cve/nvd update process')
    if not xml_exists:
        logger.info('downloading nvd/cve xml data files')
        start_nvd_xml_download()
    for directory, _, files in os.walk(CVEDataDir.XML_DIR):
        for xml_file in files:
            nvd_file = os.path.join(directory, xml_file)
            nvd_files.append(nvd_file)
    parse_cve_and_udpatedb(False, nvd_files)
    update_cve_categories()
    logger.info('finished cve/nvd update process')
    gc.collect()

#update_cve_categories()
#load_up_all_xml_into_db()
