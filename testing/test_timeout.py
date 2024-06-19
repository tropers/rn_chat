import signal

class TestTimeoutException(Exception):
    """
    Gets raised by TestTimeout when the timeout occurs.
    """

class TestTimeout:
    """
    Implements a simple timeout mechanism for testing purposes.
    """
    def __init__(self, seconds, error_message=None):
        if error_message is None:
            error_message = f'Test timed out after {seconds}s.'

        self.seconds = seconds
        self.error_message = error_message

    def __handle_timeout(self, signum, frame):
        raise TestTimeoutException(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.__handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)
