import os
import re
import gc
import sys
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from time import mktime
from datetime import datetime

from vFense.db.client import r

from vFense.utils.common import month_to_num_month
from vFense.plugins.vuln.common import build_bulletin_id
from vFense.plugins.vuln.ubuntu import *
from vFense.plugins.vuln.ubuntu._constants import *
from vFense.plugins.vuln.ubuntu._db import insert_bulletin_data

import requests
from BeautifulSoup import BeautifulSoup

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')

def format_data_to_insert_into_db(
    usn_id, details, cve_ids,
    apps_data, date_posted
    ):
    """Parse the ubuntu data and place it into a array
    Args:
        usn_id (str): The Ubuntu Bulletin Id.
        details (str): The description of the bulletin.
        cve_ids (list): List of cve ids.
        apps_data (list): List of dictionaries, containing
            the app name and version.
        date_posted (str) The time in epoch
    Returns:
        Dictionary inside of a list

    """

    data_to_insert = []
    for data in apps_data:
        string_to_build_id = ''
        for app in data[UbuntuSecurityBulletinKey.Apps]:
            string_to_build_id = (
                string_to_build_id +
                app['name'] +
                app['version']
            )

        string_to_build_id = (
            string_to_build_id +
            data[UbuntuSecurityBulletinKey.OsString]
        )

        bulletin_id = build_bulletin_id(string_to_build_id)
        try:
            if isinstance(details, unicode):
                details = details.decode('utf-8')
            elif isinstance(details, basestring):
                details = unicode(details.decode('utf-8'))
        except Exception as e:
            details = details.encode('utf-8').decode('utf-8')

        data_to_insert.append(
            {
                UbuntuSecurityBulletinKey.Id: bulletin_id,
                UbuntuSecurityBulletinKey.BulletinId: usn_id,
                UbuntuSecurityBulletinKey.Details: details,
                UbuntuSecurityBulletinKey.DatePosted: date_posted,
                UbuntuSecurityBulletinKey.Apps: data[UbuntuSecurityBulletinKey.Apps],
                UbuntuSecurityBulletinKey.OsString: data[UbuntuSecurityBulletinKey.OsString],
                UbuntuSecurityBulletinKey.CveIds: cve_ids
            }
        )

    return(data_to_insert)


def get_cve_info(cve_references):
    """Parse and retreive  cve ids
    Args:
        cve_references (str):
    """
    cve_ids = []
    for reference in cve_references:
        cve_ids.append(reference.text)
    return(cve_ids)


def parse_multiple_dd_tags(info):
    """Parse dt, dl, and dd tags, to retrieve the app data.
    Args:
        info (str):
    """
    app_info = []
    while True:
        if 'name' in dir(info):
            if info.name == 'dt' or info.name == 'dl' or info.name == 'dd':
                if info.a:
                    app_info.append(
                        {
                            'name': info.a.text,
                            'version': info.span.a.text
                        }
                    )
                else:
                    app_info.append(
                        {
                            'name': info.contents[0],
                            'version': info.span.text
                        }
                    )

                info = info.findNextSibling()
                if info:
                    if info.name != 'dd':
                        break
                else:
                    break
    return(info, app_info)


def get_app_info(info):
    """Parse dt, dl, and dd tags, to retrieve the app data
        and os_string.
    Args:
        info (str):
    """
    app_info = []
    app_info = []
    while True:
        app_data = {}
        if info.name == 'dt' or info.name == 'dl':
            if info.name == 'dt':
                app_data['os_string'] = info.text.replace(':', '')
                info, app_data['apps'] = (
                    parse_multiple_dd_tags(
                        info.findNextSibling()
                    )
                )

            elif info.name == 'dl':
                app_data['os_string'] = info.dt.text.replace(':', '')
                info, app_data['apps'] = (
                    parse_multiple_dd_tags(info.dd)
                )

            app_info.append(app_data)

            if not info:
                break

    return(app_info)

def get_date_posted(date_em):
    """Parse em tags, to retrieve the date posted
        and convert it to epoch.
    Args:
        date_em (str):
    """
    date_posted = u''
    try:
        day, month, year = date_em.text.split()
        day = int(re.sub('[a-zA-Z]+', '', day))
        month = month_to_num_month[re.sub(',', '', month)]
        year = int(year)
        date_posted = (
            r.epoch_time(mktime(datetime(year, month, day).timetuple()))
        )
    except Exception as e:
        logger.exception(e)

    return(date_posted)

def get_details(soup_details):
    """Parse the description in the ubuntu usn html file.
    Args:
        soup_details (str)
    """
    details = u''
    while True:
        tag = soup_details.findNext()
        if tag.name != 'h3':
            if tag.name == 'p':
                text = unicode(tag.text).encode(sys.stdout.encoding, 'replace').decode('utf-8')
                details = details + text + '\n\n'
        else:
            break
        soup_details = tag

    details = unicode(details).encode(sys.stdout.encoding, 'replace')
    return(details)

def write_content_to_file(file_location, url, content=None):
    """Write the html data to  file, so we can load this data from
        disk anytime we need to read from it.
    Args:
        file_location (str): The location of the file on disk.
        url (str): The url you will retreive.

    Returns:
        Tuple (content_of_file, boolean)
    """
    usn_file = open(file_location, 'wb')
    if not content:
        try:
            #print write_content_to_file.func_name, file_location, url
            usn_page = requests.get(url)
            content = usn_page.content
            usn_page.close()

        except Exception as e:
            write_content_to_file(file_location,url)

    completed = False
    if content:
        #content = unicode(usn_page.text).encode(sys.stdout.encoding, 'replace').decode('utf-8')
        completed = True
        usn_file.write(content)
        usn_file.close()
    return(content, completed)


def get_usn_uri(usn_uri):
    try:
        usn_page = requests.get(usn_uri, timeout=2)
        usn_page.close()
        if usn_page.ok:
            content = usn_page.content
            return(completed, True)

    except Exception as e:
        completed = False,
        content = None
        return(completed, content)


def get_url_content(usn_uri):
    """Retreive the content of the usn url
    Args:
        usn_uri (str): The uri you will retreive the content from.

    Returns:
        Tuple (content_of_file, boolean)
    """
    if re.search('^http', usn_uri):
        #Major hack, since some of the pages have the full url
        #insetad of the uri
        usn = usn_uri.split('/')[-1]
    else:
        usn = usn_uri.split('/')[-2]
        usn_uri = os.path.join(UbuntuUSNStrings.MAIN_URL, usn)

    content = None
    completed = False
    usn = usn_uri.split('/')[-1]
    usn_file_location = os.path.join(UbuntuDataDir.HTML_DIR, usn)
    if os.path.exists(usn_file_location):
        #Read html off of disk and check if the size is greater than 0
        #If it isn't grater than 0, than re get the file.
        if os.stat(usn_file_location).st_size > 0:
            content = open(usn_file_location, 'r').read()
            return(content, True)
        else:
            return get_usn_uri(usn_uri)

    else:
        #If the file doesn't exist, than retriev it and write it to file.
        #print get_url_content.func_name, usn_uri
        completed, content = get_usn_uri(usn_uri)
        content, completed = (
            write_content_to_file(
                usn_file_location,
                UbuntuUSNStrings.MAIN_URL + usn_uri,
                content
            )
        )
        return(content, completed)


def process_usn_page(usn_uri):
    """Process the entire USN page, for the data
        that we will parse in order to store into the
        database.
    Args:
        usn_uri (str): The uri, that you want to retreive
            from disk or from the usn page.

    """
    content, completed = get_url_content(usn_uri)
    details = ''
    date_posted = ''
    bulletin_id = ''
    app_info = []
    data = []
    cve_references = []
    if content:
        soup = BeautifulSoup(content.replace('<br />', '\n'))
        date_posted_em = soup.div.findNext('em')
        bulletin_h2 = soup.div.findNext('h2')
        details_h3 = soup.div.findNext('h3', text='Details')
        app_info_dl = soup.div.findAllNext('dl')
        cve_info_h3 = soup.div.findAllNext('h3', text='References')
        if date_posted_em:
            date_posted = get_date_posted(date_posted_em)

        if bulletin_h2:
            bulletin_id = bulletin_h2.text.split()[-1]
        else:
            return([], False)

        if details_h3:
            details = get_details(details_h3)
        else:
            return([], False)

        if len(app_info_dl) > 0:
            if len(app_info_dl[0]) > 1:
                app_info = get_app_info(app_info_dl[0])
            else:
                return([], False)

        if len(cve_info_h3) > 0:
            cve_references = (
                get_cve_info(
                    cve_info_h3[0].findAllNext('a', href=re.compile('.*cve'))
                )
            )
        data = (
            format_data_to_insert_into_db(
                bulletin_id, details, cve_references, app_info, date_posted
            )
        )
    return(data, completed)


def begin_usn_home_page_processing(next_page=None, full_parse=False):
    """Process the entire USN HOME page, for the data
        that we will parse in order to store into the
    Kwargs:
        next_page (str): The next page tp follow, to retrieve usn data from.
        full_parse (bool): The default is False, which means,
            just get the latest data from the home page

    """
    if next_page:
        url = UbuntuUSNStrings.MAIN_USN_URL + '/' + next_page
        try:
            main_page = requests.get(url, timeout=1)
        except Exception as e:
            return(begin_usn_home_page_processing(next_page, True))
    else:
        try:
            main_page = requests.get(UbuntuUSNStrings.MAIN_USN_URL)
        except Exception as e:
            return(begin_usn_home_page_processing(full_parse=True))

    try:
        if main_page.ok:
            soup = BeautifulSoup(main_page.content)
            main_page.close()
            next_page = (
                soup.find(
                    'a',
                    {
                        'href': re.compile(UbuntuUSNStrings.NEXT_PAGE)
                    },
                    text=re.compile('Next'),
                ).parent['href']
            )
            usn_uris = []
            eight = (
                soup.findAll(
                    'div',
                    {
                        'class': 'eight-col notice'
                    }
                )
            )
            for uri in eight:
                usn_uris.append(
                    uri.find(
                        'a',
                        {
                            'href': re.compile(UbuntuUSNStrings.USR_URI)
                        }
                    )['href']
                )

            if len(usn_uris) > 0:
                data = []
                for usn_uri in usn_uris:
                    data_to_update, ok = process_usn_page(usn_uri)
                    if ok:
                        data.extend(data_to_update)
                insert_bulletin_data(data)

            if full_parse:
                if next_page:
                    return(begin_usn_home_page_processing(next_page, True))

    except Exception as e:
        logger.exception(e)
    gc.collect()
    logger.info('finished ubuntu usn update process')
