from time import sleep
import logging

from vFense import VFENSE_LOGGING_CONFIG
from vFense.scheduler.jobManager import start_scheduler, job_exists, remove_job
from vFense.plugins.patching.apps.supported_apps.syncer import get_supported_apps
from vFense.plugins.vuln.cve.parser import parse_cve_and_udpatedb
from vFense.plugins.vuln.windows.parser import parse_bulletin_and_updatedb
from vFense.plugins.vuln.ubuntu.parser import begin_usn_home_page_processing

from vFense.core.agent.agent_uptime_verifier import all_agent_status
from vFense.jobs.jobs import remove_expired_jobs_and_update_operations
from vFense.errorz.status_codes import SchedulerCodes

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('admin_scheduler')

if __name__ == '__main__':

    sched = start_scheduler(redis_db=11)
    jobstore_name = 'administrative'
    username='admin'
    list_of_cron_jobs = [
        #{
        #    'name': 'get_supported_apps',
        #    'job': get_supported_apps,
        #    'hour': '0,6,12,18',
        #    'minute': 0,
        #    'max_instances': 1,
        #    'coalesce': True
        #},
        #{
        #    'name': 'get_agents_apps',
        #    'jobstore': jobstore_name,
        #    'job': get_agents_apps,
        #    'hour': '0,6,12,18',
        #    'minute': 1,
        #    'max_instances': 1,
        #    'coalesce': True
        #},
        {
            'name': 'parse_cve_and_udpatedb',
            'jobstore': jobstore_name,
            'job': parse_cve_and_udpatedb,
            'hour': '1,7,13',
            'minute': 5,
            'max_instances': 1,
            'coalesce': True
        },
        {
            'name': 'parse_bulletin_and_updatedb',
            'jobstore': jobstore_name,
            'job': parse_bulletin_and_updatedb,
            'hour': '0,12',
            'minute': 0,
            'max_instances': 1,
            'coalesce': True
        },
        {
            'name': 'begin_usn_home_page_processing',
            'jobstore': jobstore_name,
            'job': begin_usn_home_page_processing,
            'hour': '0,6,12',
            'minute': 30,
            'max_instances': 1,
            'coalesce': True
        },
        {
            'name': 'all_agent_status',
            'jobstore': jobstore_name,
            'job': all_agent_status,
            'hour': '*',
            'minute': '*/5',
            'max_instances': 1,
            'coalesce': True
        },
        {
            'name': 'remove_expired_jobs_and_update_operations',
            'jobstore': jobstore_name,
            'job': remove_expired_jobs_and_update_operations,
            'hour': '*',
            'minute': '*',
            'max_instances': 1,
            'coalesce': True
        },
    ]
    for job in list_of_cron_jobs:
        job_exist = True
        while job_exist:
            job_removed = (
                remove_job(
                    sched, job['name'],
                    jobstore_name,
                    username
                ).get('rv_status_code')
            )
            if job_removed == SchedulerCodes.ScheduleRemoved:
                logger.info('removed job %s' % (job['name']))

            job_exist = (
                job_exists(
                    sched=sched, jobname=job['name'],
                    username=username, customer_name=jobstore_name
                )
            )

            if job_exist:
                logger.info('job %s exists' % (job['name']))

        sched.add_cron_job(
            job['job'], hour=job['hour'],
            minute=job['minute'], name=job['name'],
            jobstore=jobstore_name,
            max_instances=job['max_instances'],
            coalesce=job['coalesce']
        )
        logger.info('job %s added' % (job['name']))

    while True:
        sleep(60)
