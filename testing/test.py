#!/usr/bin/env python
"""
Main entrypoint.
"""

import time
import sys
import logging
import re
from typing import Dict
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

    client = docker.from_env().api

    def __read_and_log_container_output(self, container: P2PContainer):
        buffer = container.read_from_container(READ_BYTES)
        for line in buffer.decode("utf-8").split("\n"):
            logger.info("%s: %s", container.container_name, line)

    def __wait_for_regex_in_container_stdout(
        self, container: P2PContainer, regex: str
    ):
        """
        Read from container socket until it matches the regular expression ('regex' parameter).
        WARNING: Blocks until string is found.
        """
        while not re.search(regex, container.get_stdout_utf8()):
            try:
                self.__read_and_log_container_output(container)
            except BlockingIOError:
                time.sleep(1)

    def __dump_container_output(self, container: P2PContainer):
        blocking_error_count = 0

        # Try to read from container two times, then quit reading,
        # all data must be read.
        while blocking_error_count < 2:
            try:
                self.__read_and_log_container_output(container)
            except BlockingIOError:
                blocking_error_count += 1

    def __check_container_stdout_contains(
        self, containers: Dict[str, P2PContainer], container_name: str, regex: str
    ):
        """
        Check if the stdout of the container matches a regular expression ('regex' parameter).
        If not, try to read more from the stdout of the container for a specified
        amount of time.
        If the stdout does not match the regular expression within a defined timeout,
        the test fails.
        """
        if not re.search(regex, containers[container_name].get_stdout_utf8()):
            try:
                with TestTimeout(10):
                    self.__wait_for_regex_in_container_stdout(
                        containers[container_name], regex
                    )
                logger.info(
                    '[OKAY] %s: Regex "%s" found in output of container %s.',
                    container_name,
                    regex,
                    container_name,
                )
            except TestTimeoutException as te:
                logger.info("[FAIL] %s: %s", container_name, te)

                # If test fails, dump all output from all containers:
                for name, container in containers.items():
                    if name != container_name:
                        self.__dump_container_output(container)
                self.fail()

    def __check_container_stdout_does_not_contain(
        self, containers: Dict[str, P2PContainer], container_name: str, regex: str
    ):
        if re.search(regex, containers[container_name].get_stdout_utf8()):
            logger.info(
                '[FAIL] Regex "%s" found in output of container %s!',
                regex,
                container_name,
            )

            # If test fails, dump all output from all containers:
            for name, container in containers.items():
                if name != container_name:
                    self.__dump_container_output(container)

            self.fail()

        else:
            try:
                with TestTimeout(10):
                    self.__wait_for_regex_in_container_stdout(
                        containers[container_name], regex
                    )
            except TestTimeoutException:
                logger.info(
                    '[OKAY] Regex "%s" not found in output of container %s.',
                    regex,
                    container_name,
                )

    def __init_containers(
        self, container_and_chat_names: Dict[str, str]
    ) -> Dict[str, P2PContainer]:
        """
        Creates a dict of P2PContainers.

        Args:
          container_and_chat_names: Dict containing the container names and chat client names
                                    ((key) container name: (value) chat client name)
        """
        containers = {
            container_name: P2PContainer(self.client, container_name, name)
            for container_name, name in container_and_chat_names.items()
        }

        for container in containers.values():
            container.start()

        return containers

    def test01_two_clients_connect(self):
        """
        Test connecting two p2p chat applications.
        """
        p2p_containers = self.__init_containers(
            {"p2p_test_01": "p2p_test_01", "p2p_test_02": "p2p_test_02"}
        )

        p2p_containers["p2p_test_01"].p2p_connect(
            p2p_containers["p2p_test_02"].get_container_ip()
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_01", "INFO: p2p_test_02 joined the chat."
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_02", "INFO: p2p_test_01 joined the chat."
        )

        for container in p2p_containers.values():
            container.p2p_quit()

    def test02_send_message(self):
        """
        Test connecting two chat application clients and sending messages
        from each client to the other.
        """
        p2p_containers = self.__init_containers(
            {"p2p_test_01": "p2p_test_01", "p2p_test_02": "p2p_test_02"}
        )

        p2p_containers["p2p_test_01"].p2p_connect(
            p2p_containers["p2p_test_02"].get_container_ip()
        )

        time.sleep(1)
        p2p_containers["p2p_test_01"].p2p_send_message("Hello, World!")

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_02", "p2p_test_01: Hello, World!"
        )

        time.sleep(1)
        p2p_containers["p2p_test_02"].p2p_send_message("Hello!")

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_01", "p2p_test_02: Hello!"
        )

        for container in p2p_containers.values():
            container.p2p_quit()

    def test03_connect_three(self):
        """
        Test connecting three p2p chat application clients in the following order:
          p2p_test_01 -> p2p_test_02
          p2p_test_03 -> p2p_test_01

        In the end, all three clients should be connected to eachother.
        """
        p2p_containers = self.__init_containers(
            {
                "p2p_test_01": "p2p_test_01",
                "p2p_test_02": "p2p_test_02",
                "p2p_test_03": "p2p_test_03",
            }
        )

        p2p_containers["p2p_test_01"].p2p_connect(
            p2p_containers["p2p_test_02"].get_container_ip()
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_01", "INFO: p2p_test_02 joined the chat."
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_02", "INFO: p2p_test_01 joined the chat."
        )

        p2p_containers["p2p_test_03"].p2p_connect(
            p2p_containers["p2p_test_01"].get_container_ip()
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_03", "INFO: p2p_test_01 joined the chat."
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_03", "INFO: p2p_test_02 joined the chat."
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_01", "INFO: p2p_test_03 joined the chat."
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_02", "INFO: p2p_test_03 joined the chat."
        )

        for container in p2p_containers.values():
            container.p2p_quit()

    def test04_connect_multiple(self):
        """
        Test connecting multiple clients through different configurations.

        Create one cluster of three clients:
        p2p_test_01 -> p2p_test02
        p2p_test_03 -> p2p_test01

        Create another cluster of three clients:
        p2p_test_04 -> p2p_test_05
        p2p_test_06 -> p2p_test_04

        Create a cluster of two clients:
        p2p_test_07 -> p2p_test_08

        Connect cluster one and two:
        p2p_test_06 -> p2p_test_01

        Connect all clusters:
        p2p_test_07 -> p2p_test_04

        p2p_test_04 sends a "Hello, everyone!" to see if all clients are connected
        to each other.
        """
        p2p_containers = self.__init_containers(
            {
                "p2p_test_01": "p2p_test_01",
                "p2p_test_02": "p2p_test_02",
                "p2p_test_03": "p2p_test_03",
                "p2p_test_04": "p2p_test_04",
                "p2p_test_05": "p2p_test_05",
                "p2p_test_06": "p2p_test_06",
                "p2p_test_07": "p2p_test_07",
                "p2p_test_08": "p2p_test_08",
            }
        )

        # Connect 1, 2 and 3 (cluster 1)
        p2p_containers["p2p_test_01"].p2p_connect(
            p2p_containers["p2p_test_02"].get_container_ip()
        )

        p2p_containers["p2p_test_03"].p2p_connect(
            p2p_containers["p2p_test_01"].get_container_ip()
        )

        # Connect 4, 5 and 6 (cluster 2)
        p2p_containers["p2p_test_04"].p2p_connect(
            p2p_containers["p2p_test_05"].get_container_ip()
        )

        p2p_containers["p2p_test_06"].p2p_connect(
            p2p_containers["p2p_test_04"].get_container_ip()
        )

        # Connect 7 and 8 (cluster 3)
        p2p_containers["p2p_test_07"].p2p_connect(
            p2p_containers["p2p_test_08"].get_container_ip()
        )

        time.sleep(5)
        # Connect all clients
        p2p_containers["p2p_test_06"].p2p_connect(
            p2p_containers["p2p_test_01"].get_container_ip()
        )

        p2p_containers["p2p_test_07"].p2p_connect(
            p2p_containers["p2p_test_04"].get_container_ip()
        )

        time.sleep(1)
        # Send test message to all clients to see if everyone is connected
        p2p_containers["p2p_test_04"].p2p_send_message("Hello, everyone!")
        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_04", "Hello, everyone!"
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_06", "p2p_test_04: Hello, everyone!"
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_01", "p2p_test_04: Hello, everyone!"
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_02", "p2p_test_04: Hello, everyone!"
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_03", "p2p_test_04: Hello, everyone!"
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_04", "p2p_test_04: Hello, everyone!"
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_05", "p2p_test_04: Hello, everyone!"
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_07", "p2p_test_04: Hello, everyone!"
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_08", "p2p_test_04: Hello, everyone!"
        )

        for container in p2p_containers.values():
            container.p2p_quit()

    def test05_name_taken_two_clients(self):
        """
        Test connecting two p2p chat applications.
        """
        p2p_containers = self.__init_containers(
            {"p2p_test_01": "p2p_test_01", "p2p_test_02": "p2p_test_01"}
        )

        p2p_containers["p2p_test_01"].p2p_connect(
            p2p_containers["p2p_test_02"].get_container_ip()
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_02", 'INFO: Name "p2p_test_01" taken!'
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_01", "INFO: Failed received with code: 1"
        )

        for container in p2p_containers.values():
            container.p2p_quit()

    def test06_connection_loss(self):
        """
        Test connection loss between two p2p chat applications.
        """

        p2p_containers = self.__init_containers(
            {"p2p_test_01": "p2p_test_01", "p2p_test_02": "p2p_test_02"}
        )

        time.sleep(1)
        p2p_containers["p2p_test_01"].p2p_connect(
            p2p_containers["p2p_test_02"].get_container_ip()
        )

        p2p_containers["p2p_test_02"].stop()

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_01", "INFO: Socket.*hung up."
        )

        for container in p2p_containers.values():
            container.p2p_quit()

    def test07_connection_loss_three(self):
        """
        Test connection loss between three p2p chat application clients.
        """
        p2p_containers = self.__init_containers(
            {
                "p2p_test_01": "p2p_test_01",
                "p2p_test_02": "p2p_test_02",
                "p2p_test_03": "p2p_test_03",
            }
        )

        p2p_containers["p2p_test_01"].p2p_connect(
            p2p_containers["p2p_test_02"].get_container_ip()
        )

        p2p_containers["p2p_test_03"].p2p_connect(
            p2p_containers["p2p_test_01"].get_container_ip()
        )

        p2p_containers["p2p_test_02"].stop()

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_01", "INFO: Socket.*hung up."
        )

        self.__check_container_stdout_contains(
            p2p_containers, "p2p_test_03", "INFO: Socket.*hung up."
        )

        for container in p2p_containers.values():
            container.p2p_quit()


def main():
    """
    Main method.
    """
    logging.basicConfig(level=logging.INFO)
    unittest.main()


if __name__ == "__main__":
    main()
