import logging
import logging.handlers
import logging.config
import pickle
import select
import socketserver
import struct
from contextlib import contextmanager
from threading import Thread
from typing import Generator


LOGGER = logging.getLogger(__name__)


class LogRecordStreamHandler(socketserver.StreamRequestHandler):
    """Handler for a streaming logging request.

    This basically logs the record using whatever logging policy is
    configured locally.
    """

    def handle(self):
        """
        Handle multiple requests - each expected to be a 4-byte length,
        followed by the LogRecord in pickle format. Logs the record
        according to whatever policy is configured locally.
        """

        while True:
            chunk = self.connection.recv(4)
            if len(chunk) < 4:
                break
            slen = struct.unpack('>L', chunk)[0]
            chunk = self.connection.recv(slen)
            while len(chunk) < slen:
                chunk = chunk + self.connection.recv(slen - len(chunk))
            obj = pickle.loads(chunk)
            record = logging.makeLogRecord(obj)
            record.msg = f'[ {self.connection.getpeername()[0]} ] {record.msg}'
            LOGGER.handle(record)


class LogRecordSocketReceiver(socketserver.ThreadingTCPServer):
    """
    Simple TCP socket-based logging receiver suitable for testing.
    """

    allow_reuse_address = True

    def __init__(self,
                 host: str = 'localhost',
                 port: int = logging.handlers.DEFAULT_TCP_LOGGING_PORT,
                 handler=LogRecordStreamHandler):
        socketserver.ThreadingTCPServer.__init__(self, (host, port), handler)
        self.abort: int = 0
        self.timeout: int = 1
        self.logname = None

    def stop(self) -> None:
        self.abort = 1

    def serve_until_stopped(self) -> None:
        abort = 0
        while not abort:
            rd, wr, ex = select.select([self.socket.fileno()],
                                       [], [],
                                       self.timeout)
            if rd:
                self.handle_request()
            abort = self.abort


@contextmanager
def run_logger_server(server_ip: str, port: int) -> Generator:
    server = LogRecordSocketReceiver(server_ip, port)
    try:
        LOGGER.info(f'About to start TCP LOG server on {server_ip}:{port}...')
        server_thread = Thread(target=server.serve_until_stopped)
        server_thread.start()
        yield
    finally:
        LOGGER.info(f'About to stop TCP LOG server on {server_ip}:{port}...')
        server.stop()
        LOGGER.info(f'Trigered shutdown for LOG server on {server_ip}:{port}')
        server_thread.join()
        LOGGER.info('Done')