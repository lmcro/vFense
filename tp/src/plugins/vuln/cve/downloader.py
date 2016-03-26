"CVE DOWNLOADER FOR TOPPATCH, NVD/CVE XML VERSION 1.2"
import gzip
import os
import requests
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from vFense.plugins.vuln.cve._constants import CVEDataDir, CVEStrings
from vFense.plugins.vuln._constants import DateValues

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')


def uncompress_and_write(compressed_file, dest_file):
    contents = gzip.open(compressed_file, 'rb').read()
    with open(dest_file, 'wb') as uncompressed:
        uncompressed.write(contents)
        uncompressed.close()
        os.remove(compressed_file)


def cve_downloader(url, file_path):
    """Http Downloader, that returns the status of the download
        and the size of the file
    Args:
        url (str): the full url path of the xml file.
        file_path (str): The full file patch, to where it is going to be saved.

    Basic Usage:
        >>> from vFense.plugins.vuln.cve.downloader import cve_downloader
        >>> cve_downloader

    Returns:
        Tuple (Boolean, file_size)
        (True, 186)
    """
    req = requests.get(url)
    xml = open(file_path, 'wb')
    if req.ok:
        xml.write(req.content)

    xml.close()

    return(req.ok, os.stat(file_path).st_size)


def log_status(status, size, url_path, nvd_path):
    """Log the status of the downloaded cve file
    Args:
        status (bool): True or False (Verify if the file downloaded)
        size (int): The size of the file that was downloaded.
        url_path (str): The full url of the file that was downloaded.
        nvd_path (str): The full path on disk of the file that was downloaded.

    """
    if status is True and size > 0:
        msg = '%s Downloaded to %s' % (url_path, nvd_path)
        logger.info(msg)
    elif status is False:
        msg = '%s Could not be downloaded' % (url_path)
        logger.warn(msg)
    else:
        msg = '%s Was downloaded to %s, but the size is %d' \
              % (url_path, nvd_path, size)
        logger.error(msg)


def start_nvd_xml_download():
    """The is the CVE/NVD Downloader
    Basic Usage:
        >>> from vFense.plugins.vuln.cve.downloader import start_nvd_xml_download
        >>> start_nvd_xml_download()
    """
    iter_year = CVEStrings.START_YEAR
    modified_uncompressed = os.path.join(
        CVEDataDir.XML_DIR, CVEStrings.NVDCVE_MODIFIED[:-3]
    )
    recent_uncompressed = os.path.join(
        CVEDataDir.XML_DIR, CVEStrings.NVDCVE_RECENT[:-3]
    )
    files_to_download = [
        (
            CVEStrings.NVD_MODIFIED_URL, CVEDataDir.NVD_MODIFIED_FILE,
            modified_uncompressed, iter_year
        ),
        (
            CVEStrings.NVD_RECENT_URL, CVEDataDir.NVD_RECENT_FILE,
            recent_uncompressed, iter_year
        )
    ]
    while iter_year <= DateValues.CURRENT_YEAR:
        compressed = CVEStrings.NVDCVE_BASE + str(iter_year) + '.xml.gz'
        uncompressed = compressed[:-3]
        full_url = CVEStrings.NVD_DOWNLOAD_URL + compressed
        full_nvd_compressed = os.path.join(CVEDataDir.XML_DIR, compressed)
        full_nvd_uncompressed = os.path.join(CVEDataDir.XML_DIR, uncompressed)
        files_to_download.append(
            (
                full_url, full_nvd_compressed, full_nvd_uncompressed, iter_year
            )
        )
        iter_year += 1
    if not os.path.exists(CVEDataDir.XML_DIR):
        os.makedirs(CVEDataDir.XML_DIR, 0755)

    # If we have not yet downloaded the 2002-now CVE's,
    # please download them now

    for nvd in files_to_download:
        if not os.path.exists(nvd[2]):
            xml_status = cve_downloader(nvd[0], nvd[1])
            uncompress_and_write(nvd[1], nvd[2])
            log_status(
                xml_status[0], xml_status[1], full_url, full_nvd_uncompressed
            )

        elif nvd[3] == DateValues.CURRENT_YEAR:
            # Always download the latest and the current year
            xml_status = cve_downloader(full_url, full_nvd_compressed)
            uncompress_and_write(full_nvd_compressed, full_nvd_uncompressed)
            log_status(
                xml_status[0], xml_status[1], full_url, full_nvd_uncompressed
            )

        else:
            msg = (
                "{0} and {1} already exists at {2}".format(
                    nvd[1], nvd[2], CVEDataDir.XML_DIR
                )
            )
            logger.info(msg)
        iter_year = iter_year + 1
