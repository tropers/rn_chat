#!/usr/bin/env python
"""
Main entrypoint.
"""

import time
import logging
from typing import List

import docker

from p2pcontainer import P2PContainer

logger = logging.getLogger(__name__)

def getlines(container: P2PContainer) -> List[str]:
    """
    Parse lines from container and return them in a list.
    """
    line = getline(container)
    lines: List[str] = []

    while line != '':
        lines.append(line)
        line = getline(container)

    return lines

def getline(container: P2PContainer) -> str:
    """
    Read a line from the container socket and parse as string.
    """
    buffer = ''

    try:
        c = container.read_from_container(1).decode('utf-8')

        while c != '\n':
            buffer += c
            c = container.read_from_container(1).decode('utf-8')
    except BlockingIOError:
        return buffer

    return buffer

def print_container_output(container: P2PContainer):
    """
    Parse all lines retrieved from a container and log them
    including the containers name.
    """
    print(*(f'{container.container_name}: {line}'
          for line in getlines(container)), sep='\n')

def log_container_output(container: P2PContainer):
    """
    Log the output from the container using the logger.
    """
    for line in getlines(container):
        logger.info('%s: %s', container.container_name, line)

# TODO
def test_two_clients_connect(client: docker.Client):
    p2p_containers = {
        'p2p_test_01': P2PContainer(client, 'p2p_test_01', 'p2p_test_01'),
        'p2p_test_02': P2PContainer(client, 'p2p_test_02', 'p2p_test_02'),
    }

    for container in p2p_containers.values():
        container.start()

    time.sleep(1)
    p2p_containers['p2p_test_01'].p2p_connect(
        p2p_containers['p2p_test_02'].get_container_ip())

    time.sleep(1)
    for container in p2p_containers.values():
        log_container_output(container)

    time.sleep(1)
    for container in p2p_containers.values():
        container.stop()

def main():
    """
    Main method.
    """

    logging.basicConfig(level=logging.INFO)
    client = docker.from_env()

    # Create containers and start them
    p2p_containers = {
        'p2p_test_01': P2PContainer(client, 'p2p_test_01', 'p2p_test_01'),
        'p2p_test_02': P2PContainer(client, 'p2p_test_02', 'p2p_test_02'),
        'p2p_test_03': P2PContainer(client, 'p2p_test_03', 'p2p_test_03'),
    }

    for container in p2p_containers.values():
        container.start()

    # Connect test clients with eachother
    time.sleep(1)
    p2p_containers['p2p_test_01'].p2p_connect(
        p2p_containers['p2p_test_02'].get_container_ip())

    time.sleep(1)
    p2p_containers['p2p_test_03'].p2p_connect(
        p2p_containers['p2p_test_01'].get_container_ip())

    time.sleep(1)
    p2p_containers['p2p_test_01'].p2p_send_message('Worked!')
    p2p_containers['p2p_test_02'].p2p_send_message('This one also worked!')
    p2p_containers['p2p_test_03'].p2p_send_message('Also worked!')

    # Test connection teardown for clients
    time.sleep(1)
    for container in p2p_containers.values():
        print_container_output(container)

    p2p_containers['p2p_test_02'].p2p_quit()
    p2p_containers.pop('p2p_test_02')

    time.sleep(1)
    for container in p2p_containers.values():
        container.p2p_list()

    p2p_containers['p2p_test_04'] = P2PContainer(client, 'p2p_test_04', 'p2p_test_04')
    p2p_containers['p2p_test_04'].start()
    p2p_containers['p2p_test_04'].p2p_connect(
        p2p_containers['p2p_test_03'].get_container_ip())

    time.sleep(1)
    p2p_containers['p2p_test_04'].p2p_send_message('Howdy everyone!')

    time.sleep(2)
    for container in p2p_containers.values():
        print_container_output(container)

    time.sleep(1)
    for container in p2p_containers.values():
        container.stop()

if __name__ == '__main__':
    main()
