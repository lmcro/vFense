"CVE DOWNLOADER FOR TOPPATCH, NVD/CVE XML VERSION 1.2"
import os
import re
from time import sleep
import requests
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from time import sleep
from vFense.plugins.vuln.windows._constants import WindowsDataDir, \
    WindowsBulletinStrings

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')

def get_msft_bulletin_xlsx(xls_url, count=0):
    """Retrieve the Microsoft XLSX file.
    """

    downloaded = False
    data = None

    try:
        data = requests.get(xls_url, timeout=2)

        if data:
            if data.status_code == 200:
                downloaded = True

        return(downloaded, data)

    except Exception as e:
        sleep(5)
        if count <= 20:
            count += 1
            logger.exception(
                'failed to retrieve XLSX file from %s: count = %s'
                % (xls_url, str(count))
            )

            return(get_msft_bulletin_xlsx(xls_url, count))

        else:
            logger.exception(
                'Microsoft is not letting us get the XLSX file from %s'
                % WindowsBulletinStrings.XLS_DOWNLOAD_URL
            )

            return(downloaded, data)


def get_msft_bulletin_url(count=0):
    """Hack to retrieve the Microsoft XLSX url and name of the file.
    """

    xls_url = None
    xls_file_name = None

    try:
        main_url = requests.get(
            WindowsBulletinStrings.XLS_DOWNLOAD_URL, timeout=2
        )

        if main_url.status_code == 200:
            xls_url = re.search(
                '"(https?://download.microsoft.com/download.*.xlsx)",',
                main_url.content
            ).group(1)

            if xls_url:
                xls_file_name = xls_url.split('/')[-1]

        return(xls_url, xls_file_name)

    except Exception as e:
        sleep(5)
        if count <= 20:
            count += 1
            logger.exception(
                'failed to retrieve XLSX url from %s: count = %s'
                % (WindowsBulletinStrings.XLS_DOWNLOAD_URL, str(count))
            )

            return(get_msft_bulletin_url(count))
        else:
            logger.exception(
                'Microsoft is not letting us get the XLSX url from %s'
                % WindowsBulletinStrings.XLS_DOWNLOAD_URL
            )

            return(xls_url, xls_file_name)


def download_latest_xls_from_msft():
    """Download the lates Microsoft Security Bulletin excel spreadsheet
        and than store it on disk
    Returns:
        Tuple (Boolen, file_location)
    """

    downloaded = True
    xls_file_location = None

    if not os.path.exists(WindowsDataDir.XLS_DIR):
        os.makedirs(WindowsDataDir.XLS_DIR)

    xls_url, xls_file_name = get_msft_bulletin_url()

    if xls_url:
        xls_file_location = WindowsDataDir.XLS_DIR+'/'+xls_file_name
        file_downloaded, xls_data = get_msft_bulletin_xlsx(xls_url)

        if file_downloaded:
            xml_file = open(xls_file_location, 'wb')
            xml_file.write(xls_data.content)
            xml_file.close()

            if (xls_data.headers['content-length'] ==
                    str(os.stat(xls_file_location).st_size)):
                logger.info(
                    '%s downloaded to %s: file_size: %s matches content-length' %
                    (
                        xls_url,xls_file_location,
                        os.stat(xls_file_location).st_size
                    )
                )

            else:
                downloaded = False
                logger.warn(
                    '%s downloaded to %s: file_size: %s does not match the content-length' %
                    (
                        xls_url,xls_file_location,
                        os.stat(xls_file_location).st_size
                    )
                )

    return(downloaded, xls_file_location)

#download_latest_xls_from_msft()
