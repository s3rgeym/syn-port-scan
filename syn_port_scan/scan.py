# Использованные примеры:
# https://www.binarytides.com/python-syn-flood-program-raw-sockets-linux/
# https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
import dataclasses
import itertools
import random
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing
from dataclasses import dataclass, field
from typing import TextIO

from .log import logger
from .tcpip import Packet
from .utils import get_local_ip


@dataclass
class PortScanner:
    output: TextIO = sys.stdout
    _: dataclasses.KW_ONLY
    max_workers: int = 10
    socket_timeout: float = 15.0

    local_ip: str | None = field(
        init=False, repr=False, default_factory=get_local_ip
    )

    def get_socket(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.settimeout(self.socket_timeout)
        return s

    def check_port(self, host: str, port: int):
        dest_ip = socket.gethostbyname(host)
        syn = Packet.make_syn(
            src_addr=self.local_ip,
            src_port=random.randint(20000, 30000),
            dest_addr=dest_ip,
            dst_port=port,
        )
        logger.debug(syn)
        packet = syn.pack()
        with closing(self.get_socket()) as sock:
            sock.sendto(packet, (dest_ip, 0))
            logger.debug("sent: %s", packet.hex(" ", 1))
            data = sock.recv(4096)
            logger.debug("recieve: %s", data.hex(" ", 1))
            ans = Packet.unpack(data)
            logger.debug(ans)
            self.output.write(f"{host}:{port}\n")

    def scan(self, addresses: list[str], ports: list[int]) -> None:
        with ThreadPoolExecutor(self.max_workers) as pool:
            futs = [
                pool.submit(self.check_port, addr, port)
                for addr, port in itertools.product(addresses, ports)
            ]

        for fut in as_completed(futs):
            try:
                fut.result()
            except Exception as ex:
                logger.exception(ex)

        logger.info("Finished!")
