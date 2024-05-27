import os

import docker

DOCKER_IMAGE = 'p2pchat_test:latest'

class P2PContainer():
    '''
    P2PContainer contains all informatio needed for a chat application testing container
    '''
    def __init__(self, client: docker.Client, container_name: str, chat_name: str):
        self.__client = client
        self.container_name = container_name
        self.__container = self.__client.create_container(
            DOCKER_IMAGE,
            name=self.container_name,
            stdin_open=True,
            tty=True)

        # Create socket to interact with testing container
        self.__socket = self.__client.attach_socket(self.__container,
            {'stdin': 1, 'stdout': 1, 'stderr': 1, 'stream':1})
        self.__socket._sock.setblocking(False)

        self.__chat_name = chat_name

    def __del__(self):
        self.__client.stop(self.__container)
        self.__client.wait(self.__container)
        self.__client.remove_container(self.__container)

    def convert_to_message(self, message_string) -> bytes:
        return bytes(message_string, 'utf-8')

    def send_to_container(self, msg: str):
        os.write(self.__socket.fileno(), self.convert_to_message(msg))

    def read_from_container(self, read_bytes: int) -> bytes:
        return os.read(self.__socket.fileno(), read_bytes)

    def get_container_id(self) -> str:
        return self.__container['Id']

    def get_container_ip(self) -> str:
        return self.__client.containers(filters={'id': self.get_container_id()})[0] \
                ['NetworkSettings']['Networks']['bridge']['IPAddress']

    def start(self):
        self.__client.start(self.__container)
        # Sending chat name and local ip address to container to start the chat application
        self.send_to_container(f'{self.__chat_name}\n')
        self.send_to_container(f'{self.get_container_ip()}\n')

    def stop(self):
        self.__client.stop(self.__container)

    # Chat commands
    def p2p_connect(self, ip_address: str):
        self.send_to_container(f'/connect {ip_address} 6969\n')

    def p2p_list(self):
        self.send_to_container('/list\n')

    def p2p_send_message(self, msg: str):
        self.send_to_container(f'{msg}\n')

    def p2p_quit(self):
        self.send_to_container('/quit\n')
