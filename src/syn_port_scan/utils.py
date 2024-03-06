import socket
from contextlib import closing


def get_free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", 0))
        return s.getsockname()[1]


def get_local_ip() -> str:
    # UDP-сокеты побыстрее соединяются, потому что 4 рукопожатия не нужно
    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
        s.connect(("8.8.8.8", 53))
        return s.getsockname()[0]
