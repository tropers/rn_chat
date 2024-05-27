#! python3
import time
from typing import List

import docker

from p2pcontainer import P2PContainer

def getlines(container: P2PContainer) -> List[str]:
    line = getline(container)
    lines: List[str] = []

    print(line)
    while line != '':
        lines.append(line)
        line = getline(container)

    return lines

def getline(container: P2PContainer) -> str:
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
    for line in getlines(container):
        print(f'{container.container_name}: \
            {line}')

if __name__ == '__main__':
    # Create container and start it
    client = docker.from_env()

    p2p_containers = [
        P2PContainer(client, 'p2p_test_01', 'p2p_test_01'),
        P2PContainer(client, 'p2p_test_02', 'p2p_test_02'),
        P2PContainer(client, 'p2p_test_03', 'p2p_test_03'),
    ]

    for container in p2p_containers:
        container.start()

    time.sleep(1)
    p2p_containers[0].p2p_connect(p2p_containers[1].get_container_ip())
    print_container_output(p2p_containers[0])

    time.sleep(1)
    p2p_containers[0].p2p_connect(p2p_containers[2].get_container_ip())
    print_container_output(p2p_containers[0])

    time.sleep(1)
    p2p_containers[0].p2p_send_message('Worked!')
    p2p_containers[1].p2p_send_message('This one also worked!')
    p2p_containers[2].p2p_send_message('Also worked!')

    # Since we are non-blocking, wait for a while to get the output
    time.sleep(1)
    for container in p2p_containers:
        print_container_output(container)

    time.sleep(1)
    p2p_containers[1].p2p_quit()
    p2p_containers.remove(p2p_containers[1])

    time.sleep(1)
    for container in p2p_containers:
        container.p2p_list()

    time.sleep(2)
    for container in p2p_containers:
        print_container_output(container)

    # time.sleep(1)
    # for container in p2p_containers:
    #     container.stop()
