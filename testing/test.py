#!/usr/bin/env python
"""
Main entrypoint.
"""

import time
import logging
from typing import List
import unittest

import docker

from p2pcontainer import P2PContainer
from test_timeout import TestTimeout, TestTimeoutException

READ_BYTES = 255

logger = logging.getLogger(__name__)

def wait_for_string(container: P2PContainer, string: str) -> List[str]:
    """
    Reads from container socket until search string ('string' parameter) is found
    in the stdout of the container.
    WARNING: Blocks until string is found.
    """
    buffer = ''

    while string not in buffer:
        try:
            buffer += container.read_from_container(READ_BYTES).decode('utf-8')
        except BlockingIOError:
            time.sleep(1)

    return buffer

class P2PTest(unittest.TestCase):
    """
    P2PTest implements test cases testing the p2p chat application by spawning
    docker containers and then interacting with the applications through
    stdin / stdout.
    """
    client = docker.from_env()

    def test01_two_clients_connect(self):
        """
        Tests connecting two p2p chat applications.
        """
        p2p_containers = {
            'p2p_test_01': P2PContainer(self.client, 'p2p_test_01', 'p2p_test_01'),
            'p2p_test_02': P2PContainer(self.client, 'p2p_test_02', 'p2p_test_02'),
        }

        for container in p2p_containers.values():
            container.start()

        time.sleep(1)
        p2p_containers['p2p_test_01'].p2p_connect(
            p2p_containers['p2p_test_02'].get_container_ip())

        # with TestTimeout(10):
        #     self.assertTrue(any('INFO: p2p_test_02 joined the chat.' in line for line in \
        #                wait_for_string(p2p_containers['p2p_test_01'],
        #                                'INFO: p2p_test_02 joined the chat.')))

        with TestTimeout(10):
            _ = [logger.info('p2p_test_01: %s', line) for line in wait_for_string(
                p2p_containers['p2p_test_01'],
                'INFO: p2p_test_02 joined the chat.').split('\n')]

        # with self.assertRaises(TestTimeoutException):
        #     with TestTimeout(10):
        #         self.assertTrue(any('INFO: p2p_test_02 joined the chat.' in line for line in \
        #                    wait_for_string(p2p_containers['p2p_test_01'],
        #                                    'INFO: p2p_test_01 joined the chat.')))

        # with TestTimeout(10):
        #     self.assertTrue(any('INFO: p2p_test_01 joined the chat.' in line for line in \
        #                wait_for_string(p2p_containers['p2p_test_02'],
        #                                'INFO: p2p_test_01 joined the chat.')))

        with TestTimeout(10):
            _ = [logger.info('p2p_test_02: %s', line) for line in wait_for_string(
                p2p_containers['p2p_test_02'],
                'INFO: p2p_test_01 joined the chat.').split('\n')]

    def test02_send_message(self):
        """
        Tests connecting two chat application clients and sending messages
        from each client to the other.
        """
        p2p_containers = {
            'p2p_test_01': P2PContainer(self.client, 'p2p_test_01', 'p2p_test_01'),
            'p2p_test_02': P2PContainer(self.client, 'p2p_test_02', 'p2p_test_02'),
        }

        for container in p2p_containers.values():
            container.start()

        p2p_containers['p2p_test_01'].p2p_connect(
            p2p_containers['p2p_test_02'].get_container_ip())

        time.sleep(1)
        p2p_containers['p2p_test_01'].p2p_send_message('Hello, World!')

        with TestTimeout(10):
            self.assertTrue(any('p2p_test_01: Hello, World!' in line for line in \
                       wait_for_string(p2p_containers['p2p_test_02'],
                                       'p2p_test_01: Hello, World!')))

        time.sleep(1)
        p2p_containers['p2p_test_02'].p2p_send_message('Hello!')

        with TestTimeout(10):
            self.assertTrue(any('p2p_test_02: Hello!' in line for line in \
                       wait_for_string(p2p_containers['p2p_test_01'],
                                       'p2p_test_02: Hello!')))

    def test03_connect_three(self):
        """
        Tests connecting three p2p chat application clients in the following order:
          client01 -> client02
          client03 -> client01

        In the end, all three clients should be connected to eachother.
        """
        p2p_containers = {
            'p2p_test_01': P2PContainer(self.client, 'p2p_test_01', 'p2p_test_01'),
            'p2p_test_02': P2PContainer(self.client, 'p2p_test_02', 'p2p_test_02'),
            'p2p_test_03': P2PContainer(self.client, 'p2p_test_03', 'p2p_test_03'),
        }

        for container in p2p_containers.values():
            container.start()

        p2p_containers['p2p_test_01'].p2p_connect(
            p2p_containers['p2p_test_02'].get_container_ip())

        p2p_containers['p2p_test_02'].p2p_connect(
            p2p_containers['p2p_test_01'].get_container_ip())

        p2p_containers['p2p_test_03'].p2p_connect(
            p2p_containers['p2p_test_01'].get_container_ip())

        # with TestTimeout(10):
        #     self.assertTrue(any('INFO: p2p_test_02 joined the chat.' in line for line in \
        #                wait_for_string(p2p_containers['p2p_test_01'],
        #                                'INFO: p2p_test_02 joined the chat.')))

        # with TestTimeout(10):
        #     self.assertTrue(any('INFO: p2p_test_01 joined the chat.' in line for line in \
        #                wait_for_string(p2p_containers['p2p_test_02'],
        #                                'INFO: p2p_test_01 joined the chat.')))

        # with TestTimeout(10):
        #     self.assertTrue(any('INFO: p2p_test_01 joined the chat.' in line for line in \
        #                wait_for_string(p2p_containers['p2p_test_03'],
        #                                'INFO: p2p_test_01 joined the chat.')))

        # # with TestTimeout(10):
        # #     self.assertTrue(any('INFO: p2p_test_02 joined the chat.' in line for line in \
        # #                wait_for_string(p2p_containers['p2p_test_03'],
        # #                                'INFO: p2p_test_02 joined the chat.')))

        # with TestTimeout(10):
        #     self.assertTrue(any('INFO: p2p_test_03 joined the chat.' in line for line in \
        #                wait_for_string(p2p_containers['p2p_test_01'],
        #                                'INFO: p2p_test_03 joined the chat.')))

        # with TestTimeout(10):
        #     self.assertTrue(any('INFO: p2p_test_03 joined the chat.' in line for line in \
        #                wait_for_string(p2p_containers['p2p_test_02'],
        #                                'INFO: p2p_test_03 joined the chat.')))

        p2p_test_01_stdout = ''

        p2p_containers['p2p_test_01'].p2p_list()
        with TestTimeout(10):
            p2p_test_01_stdout += wait_for_string(p2p_containers['p2p_test_01'], 'current peers:')
            # self.assertTrue(any('current peers:' in line for line in \
            #            wait_for_string(p2p_containers['p2p_test_01'], 'current peers:')))

        with TestTimeout(10):
            if 'p2p_test_02' not in p2p_test_01_stdout:
                self.assertTrue(any('p2p_test_02' in line for line in \
                           wait_for_string(p2p_containers['p2p_test_01'], 'p2p_test_02')))

        with TestTimeout(10):
            if 'p2p_test_03' not in p2p_test_01_stdout:
                self.assertTrue(any('p2p_test_03' in line for line in \
                           wait_for_string(p2p_containers['p2p_test_01'], 'p2p_test_03')))

def main():
    """
    Main method.
    """
    logging.basicConfig(level=logging.INFO)
    unittest.main()

if __name__ == '__main__':
    main()
