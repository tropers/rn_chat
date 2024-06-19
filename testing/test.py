#!/usr/bin/env python
"""
Main entrypoint.
"""

import time
import sys
import logging
import re
from typing import List, Dict
import unittest

import docker

from p2pcontainer import P2PContainer
from test_timeout import TestTimeout, TestTimeoutException

READ_BYTES = 255

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)

class P2PTest(unittest.TestCase):
    """
    P2PTest implements test cases testing the p2p chat application by spawning
    docker containers and then interacting with the applications through
    stdin / stdout.
    """
    client = docker.from_env()

    def __wait_for_string_in_container_stdout(self,
                                              container: P2PContainer,
                                              regex: str) -> str:
        """
        Read from container socket until search string ('string' parameter) is found
        in the stdout of the container.
        WARNING: Blocks until string is found.
        """
        while not re.search(regex, container.get_stdout_utf8()):
            try:
                buffer = container.read_from_container(READ_BYTES)
                for line in buffer.decode('utf-8').split('\n'):
                    logger.info('%s: %s', container.container_name, line)
            except BlockingIOError:
                time.sleep(1)

    def __check_container_stdout_contains(self, container: P2PContainer, regex: str):
        """
        Check if the search string ('string' parameter) is found in the stdout of the
        container. If not, try to read more from the stdout of the container for a specified
        amount of time.
        If the string is not found in the stdout of the container within a defined timeout,
        the test fails.
        """
        if not re.search(regex, container.get_stdout_utf8()):
            try:
                with TestTimeout(10):
                    self.__wait_for_string_in_container_stdout(container, regex)
                    # _ = [logger.info('%s: %s', container.container_name, line) \
                    #     for line in container.get_stdout_utf8().split('\n')]
            except TestTimeoutException as te:
                logger.info('%s: %s', container.container_name, te)
                self.fail()

    def __check_container_stdout_does_not_contain(self, container: P2PContainer, string: str):
        if string in container.get_stdout_utf8():
            self.fail()
        else:
            # with self.assertRaises(TestTimeoutException):
            try:
                with TestTimeout(10):
                    self.__wait_for_string_in_container_stdout(container, string)
                    _ = [logger.info('%s: %s', container.container_name, line) \
                        for line in container.get_stdout_utf8().split('\n')]
            except TestTimeoutException as te:
                logger.info('%s: %s', container.container_name, te)

    def __init_containers(self, container_and_chat_names: Dict[str, str]) \
        -> Dict[str, P2PContainer]:
        """
        Creates a dict of P2PContainers.

        Args:
          container_and_chat_names: Dict containing the container names and chat client names
                                    ((key) container name: (value) chat client name)
        """
        containers = {container_name: P2PContainer(self.client, container_name, name) for \
            container_name, name in container_and_chat_names.items()}

        for container in containers.values():
            container.start()

        return containers

    def test01_two_clients_connect(self):
        """
        Test connecting two p2p chat applications.
        """
        p2p_containers = self.__init_containers({
            'p2p_test_01': 'p2p_test_01',
            'p2p_test_02': 'p2p_test_02'
        })

        p2p_containers['p2p_test_01'].p2p_connect(
            p2p_containers['p2p_test_02'].get_container_ip())

        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'INFO: p2p_test_02 joined the chat.')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_02'],
            'INFO: p2p_test_01 joined the chat.')

        # TODO: Fix failing correctly
        # self.__check_container_stdout_does_not_contain(p2p_containers['p2p_test_01'],
        #     'INFO: p2p_test_02 joined the chat.')

        for container in p2p_containers.values():
            container.p2p_quit()

    def test02_send_message(self):
        """
        Test connecting two chat application clients and sending messages
        from each client to the other.
        """
        p2p_containers = self.__init_containers({
            'p2p_test_01': 'p2p_test_01',
            'p2p_test_02': 'p2p_test_02'
        })

        p2p_containers['p2p_test_01'].p2p_connect(
            p2p_containers['p2p_test_02'].get_container_ip())

        time.sleep(1)
        p2p_containers['p2p_test_01'].p2p_send_message('Hello, World!')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_02'],
            'p2p_test_01: Hello, World!')

        time.sleep(1)
        p2p_containers['p2p_test_02'].p2p_send_message('Hello!')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'p2p_test_02: Hello!')

        for container in p2p_containers.values():
            container.p2p_quit()

    def test03_connect_three(self):
        """
        Test connecting three p2p chat application clients in the following order:
          client01 -> client02
          client03 -> client01

        In the end, all three clients should be connected to eachother.
        """
        p2p_containers = self.__init_containers({
            'p2p_test_01': 'p2p_test_01',
            'p2p_test_02': 'p2p_test_02',
            'p2p_test_03': 'p2p_test_03'
        })

        p2p_containers['p2p_test_01'].p2p_connect(
            p2p_containers['p2p_test_02'].get_container_ip())

        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'INFO: p2p_test_02 joined the chat.')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_02'],
            'INFO: p2p_test_01 joined the chat.')

        p2p_containers['p2p_test_03'].p2p_connect(
            p2p_containers['p2p_test_01'].get_container_ip())

        self.__check_container_stdout_contains(p2p_containers['p2p_test_03'],
            'INFO: p2p_test_01 joined the chat.')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_03'],
            'INFO: p2p_test_02 joined the chat.')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'INFO: p2p_test_03 joined the chat.')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_02'],
            'INFO: p2p_test_03 joined the chat.')

        for container in p2p_containers.values():
            container.p2p_quit()

    def test04_connect_multiple(self):
        p2p_containers = self.__init_containers({
            'p2p_test_01': 'p2p_test_01',
            'p2p_test_02': 'p2p_test_02',
            'p2p_test_03': 'p2p_test_03',
            'p2p_test_04': 'p2p_test_04',
            'p2p_test_05': 'p2p_test_05',
            'p2p_test_06': 'p2p_test_06',
            'p2p_test_07': 'p2p_test_07',
            'p2p_test_08': 'p2p_test_08'
        })

        # Connect 1, 2 and 3
        p2p_containers['p2p_test_01'].p2p_connect(
            p2p_containers['p2p_test_02'].get_container_ip())

        p2p_containers['p2p_test_03'].p2p_connect(
            p2p_containers['p2p_test_01'].get_container_ip())

        # Connect 4, 5 and 6
        p2p_containers['p2p_test_04'].p2p_connect(
            p2p_containers['p2p_test_05'].get_container_ip())

        p2p_containers['p2p_test_06'].p2p_connect(
            p2p_containers['p2p_test_04'].get_container_ip())

        p2p_containers['p2p_test_07'].p2p_connect(
            p2p_containers['p2p_test_08'].get_container_ip())

        time.sleep(1)
        # Connect all clients
        p2p_containers['p2p_test_06'].p2p_connect(
            p2p_containers['p2p_test_01'].get_container_ip())

        p2p_containers['p2p_test_07'].p2p_connect(
            p2p_containers['p2p_test_04'].get_container_ip())

        self.__check_container_stdout_contains(p2p_containers['p2p_test_06'],
            'INFO: p2p_test_01 joined the chat.')

        # Check p2p_test_01 connections
        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'INFO: p2p_test_04 joined the chat.')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'INFO: p2p_test_05 joined the chat.')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'INFO: p2p_test_06 joined the chat.')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'INFO: p2p_test_02 joined the chat.')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'INFO: p2p_test_03 joined the chat.')

        time.sleep(1)
        # Send test message to all clients to see if everyone is connected
        p2p_containers['p2p_test_04'].p2p_send_message('Hello, everyone!')
        self.__check_container_stdout_contains(p2p_containers['p2p_test_04'],
            'Hello, everyone!')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_06'],
            'p2p_test_04: Hello, everyone!')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'p2p_test_04: Hello, everyone!')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_02'],
            'p2p_test_04: Hello, everyone!')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_03'],
            'p2p_test_04: Hello, everyone!')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_04'],
            'p2p_test_04: Hello, everyone!')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_05'],
            'p2p_test_04: Hello, everyone!')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_07'],
            'p2p_test_04: Hello, everyone!')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_08'],
            'p2p_test_04: Hello, everyone!')

        '''TODO: Check if all clients are actually connected
              (is message receiving enough? 
               Otherwise check peer lists of each client aswell).'''

        for container in p2p_containers.values():
            container.p2p_quit()

    def test05_name_taken_two_clients(self):
        """
        Test connecting two p2p chat applications.
        """
        p2p_containers = self.__init_containers({
            'p2p_test_01': 'p2p_test_01',
            'p2p_test_02': 'p2p_test_01'
        })

        p2p_containers['p2p_test_01'].p2p_connect(
            p2p_containers['p2p_test_02'].get_container_ip())

        self.__check_container_stdout_contains(p2p_containers['p2p_test_02'],
            'INFO: Name "p2p_test_01" taken!')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'INFO: Failed received with code: 1')

        for container in p2p_containers.values():
            container.p2p_quit()

    def test06_connection_loss(self):
        """
        Test connection loss between two p2p chat applications.
        """

        p2p_containers = self.__init_containers({
            'p2p_test_01': 'p2p_test_01',
            'p2p_test_02': 'p2p_test_02'
        })

        time.sleep(1)
        p2p_containers['p2p_test_01'].p2p_connect(
            p2p_containers['p2p_test_02'].get_container_ip())

        p2p_containers['p2p_test_02'].stop()

        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'INFO: Socket.*hung up.')

        for container in p2p_containers.values():
            container.p2p_quit()

    def test07_connection_loss_three(self):
        """
        Test connection loss between three p2p chat application clients.
        """
        p2p_containers = self.__init_containers({
            'p2p_test_01': 'p2p_test_01',
            'p2p_test_02': 'p2p_test_02',
            'p2p_test_03': 'p2p_test_03'
        })

        p2p_containers['p2p_test_01'].p2p_connect(
            p2p_containers['p2p_test_02'].get_container_ip())

        p2p_containers['p2p_test_03'].p2p_connect(
            p2p_containers['p2p_test_01'].get_container_ip())

        p2p_containers['p2p_test_02'].stop()

        self.__check_container_stdout_contains(p2p_containers['p2p_test_01'],
            'INFO: Socket.*hung up.')

        self.__check_container_stdout_contains(p2p_containers['p2p_test_03'],
            'INFO: Socket.*hung up.')

        for container in p2p_containers.values():
            container.p2p_quit()

def main():
    """
    Main method.
    """
    logging.basicConfig(level=logging.INFO)
    unittest.main()

if __name__ == '__main__':
    main()
