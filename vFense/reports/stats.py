import logging
import logging.config
from vFense._constants import VFENSE_LOGGING_CONFIG

from vFense.core.agent._db_model import *
from vFense.utils.common import *
from vFense.core.agent._db import (
    fetch_agent, fetch_agent_ids
)
from vFense.plugins.patching._db_model import *
from vFense.core.tag._db import fetch_agent_ids_in_tag
from vFense.core.results import *


def system_os_details(agent_info):
    data={
        "computer-name": agent_info.get(AgentKeys.ComputerName),
        "os-type": agent_info.get(AgentKeys.OsCode),
        "os-name": agent_info.get(AgentKeys.OsString),
        "system-arch": agent_info.get('bit_type'),
        "machine-type": agent_info.get(AgentKeys.MachineType),
    }

    return data


def system_hardware_details(agent_info):
    hardware_info=agent_info.get(AgentKeys.Hardware, {})

    data = {
        "computer-name": agent_info.get(AgentKeys.ComputerName),
        "cpu": hardware_info.get('cpu'),
        "disk": hardware_info.get('storage'),
        "display": hardware_info.get('display'),
        "ram": hardware_info.get('memory'),
    }

    return data

def system_network_details(agent_info):
    hardware_info=agent_info.get(AgentKeys.Hardware)

    data = {
        "computer-name":agent_info.get(AgentKeys.ComputerName),
        "network":hardware_info.get('nic'),
    }

    return data


def system_cpu_stats(agent_info):
    monit_stats = agent_info.get('monit_stats', {})
    cpu_stats = monit_stats.get('cpu', {})

    data = {
        "computer-name": agent_info.get(AgentKeys.ComputerName),
        "last-updated-at": monit_stats.get('timestamp'),
        "idle": cpu_stats.get('idle'),
        "user": cpu_stats.get('user'),
        "system": cpu_stats.get('system')
    }

    return data


def system_memory_stats(agent_info):
    monit_stats=agent_info.get('monit_stats', {})
    memory_stats=monit_stats.get('memory', {})

    data = {
        "computer-name": agent_info.get(AgentKeys.ComputerName),
        "last-updated-at": monit_stats.get('timestamp'),
        "total": memory_stats.get('total'),
        "used": memory_stats.get('used'),
        "used-percentage": memory_stats.get('used_percent'),
        "free": memory_stats.get('free'),
        "free-percent": memory_stats.get('free_percent')
    }

    return data


def system_disk_stats(agent_info):
    monit_stats = agent_info.get('monit_stats', {})
    file_system = monit_stats.get('file_system', {})

    data ={
        "computer-name": agent_info.get(AgentKeys.ComputerName),
        "disk-usage":file_system
    }

    return data


def get_agentids(os_code=None, view_name=None, tag_id=None):
    agentids=[]

    agent_ids_for_tag_id= fetch_agent_ids_in_tag(tag_id=tag_id)
    agent_ids_for_os_customer=fetch_agent_ids(agent_os=os_code,view_name=view_name)
    agentids=list(set(agent_ids_for_tag_id + agent_ids_for_os_customer))

    return agentids


def systems_os_details(username, view_name, os_code=None,
        tag_id=None, uri=None, method=None):
    systems_os_details=[]
    agentids=get_agentids(
        os_code=os_code, view_name=view_name, tag_id=tag_id
    )

    for agentid in agentids:
        agent_info = fetch_agent(agentid)
        system_detail = system_os_details(agent_info=agent_info)
        systems_os_details.append(system_detail)

    try:
        data = systems_os_details
        results = Results(
            username, uri, method,
        ).information_retrieved(data, len(data))

    except Exception as e:
        logger.exception(e)
        results = Results(
            username, uri, method
        ).something_broke('Systems_os_details', 'failed to retrieve data', e)

    return results


def systems_hardware_details (username, view_name, os_code=None,
        tag_id=None, uri=None, method=None):

    systems_hardware_details=[]
    agentids=get_agentids(
        os_code=os_code, view_name=view_name, tag_id=tag_id
    )

    for agentid in agentids:
        agent_info = fetch_agent(agentid)
        hardware_detail = system_hardware_details(agent_info=agent_info)
        systems_hardware_details.append(hardware_detail)

    try:
        data = systems_hardware_details
        results = Results(
            username, uri, method,
        ).information_retrieved(data, len(data))

    except Exception as e:
        logger.exception(e)
        results = Results(
            username, uri, method
        ).something_broke(
            'Systems_hardware_details', 'failed to retrieve data', e
        )

    return results


def systems_cpu_details (username, view_name, os_code=None,
        tag_id=None, uri=None, method=None):
    systems_cpu_details=[]
    agentids=get_agentids(os_code=os_code, view_name=view_name, tag_id=tag_id)
    for agentid in agentids:
        agent_info=fetch_agent(agentid)
        cpu_stats=system_cpu_stats(agent_info)
        systems_cpu_details.append(cpu_stats)

    try:
        data = systems_cpu_details
        results = (
                Results(
                    username, uri, method,
                    ).information_retrieved(data, len(data))
                )

    except Exception as e:
        logger.exception(e)
        results = (
                Results(
                    username, uri, method
                    ).something_broke('Systems_cpu_details', 'failed to retrieve data', e)
                )
    return(results)

def systems_memory_stats(username, view_name, os_code=None,
        tag_id=None, uri=None, method=None):

    systems_memory_details=[]
    agentids = get_agentids(
        os_code=os_code, view_name=view_name, tag_id=tag_id
    )

    for agentid in agentids:
        agent_info = fetch_agent(agentid)
        memory_stats = system_memory_stats(agent_info)
        systems_memory_details.append(memory_stats)

    try:
        data = systems_memory_details
        results = Results(
            username, uri, method,
        ).information_retrieved(data, len(data))

    except Exception as e:
        logger.exception(e)
        results = Results(
            username, uri, method
        ).something_broke('Systems_os_details', 'failed to retrieve data', e)

    return results


def systems_disk_stats(username, view_name, os_code=None,
        tag_id=None, uri=None, method=None):

    systems_disk_details = []
    agentids = get_agentids(
        os_code=os_code, view_name=view_name, tag_id=tag_id
    )

    for agentid in agentids:
        agent_info = fetch_agent(agentid)
        disk_stats = system_disk_stats(agent_info)
        systems_disk_details.append(disk_stats)

    try:
        data = systems_disk_details
        results = Results(
            username, uri, method,
        ).information_retrieved(data, len(data))

    except Exception as e:
        logger.exception(e)
        results = Results(
            username, uri, method
        ).something_broke('Systems_os_details', 'failed to retrieve data', e)

    return results

def systems_network_details(username, view_name, os_code=None,
        tag_id=None, uri=None, method=None):

    systems_network_infos = []
    agentids = get_agentids(os_code=os_code, view_name=view_name, tag_id=tag_id)

    for agentid in agentids:
        agent_info = fetch_agent(agentid)
        network_details = system_network_details(agent_info)
        systems_network_infos.append(network_details)

    try:
        data = systems_network_infos
        results = Results(
            username, uri, method,
        ).information_retrieved(data, len(data))

    except Exception as e:
        logger.exception(e)
        results = Results(
            username, uri, method
        ).something_broke('Systems_os_details', 'failed to retrieve data', e)

    return results
