""" This script has to be compatible with python 3.6 """
import logging
import logging.handlers
import sys
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from logging import Logger


def add_socket_handler(
        logger: 'Logger',
        host: Optional[str],
        port: Optional[int] = logging.handlers.DEFAULT_TCP_LOGGING_PORT
        ) -> None:
    if not (host and port):
        logger.warning("Host or port not defined for logger socket handler!"
                       " Probably it should be specified for remote services.")
        return

    if is_any_socket_handler(logger):
        # return if there is socket handler already
        return
    socket_handler_remote = logging.handlers.SocketHandler(
        host, port)
    logger.addHandler(socket_handler_remote)
    sys.stdout.write = logger.debug  # type: ignore
    sys.stderr.write = logger.debug  # type: ignore
    return


def is_any_socket_handler(logger: 'Logger') -> bool:
    for handler in logger.handlers:
        if isinstance(handler, logging.handlers.SocketHandler):
            return True
    return False


def get_log_handler_host(logger: 'Logger') -> Optional[str]:
    for handler in logger.handlers:
        if isinstance(handler, logging.handlers.SocketHandler):
            return handler.host
    return None


def get_log_handler_port(logger) -> Optional[int]:
    for handler in logger.handlers:
        if isinstance(handler, logging.handlers.SocketHandler):
            return handler.port
    return None


def remove_socket_handlers(logger: 'Logger') -> None:
    for handler in logger.handlers:
        if isinstance(handler, logging.handlers.SocketHandler):
            logger.removeHandler(handler)