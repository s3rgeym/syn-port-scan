# Использованные примеры:
# https://www.binarytides.com/python-syn-flood-program-raw-sockets-linux/
# https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
import dataclasses
import itertools
import random
import socket
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator, TextIO

from .log import logger
from .packet import IpHeader, TcpHeader, TcpPacket
from .utils import get_free_port, get_local_ip


@dataclass
class PortScanner:
    output: TextIO = sys.stdout
    _: dataclasses.KW_ONLY
    max_workers: int = 10
    socket_timeout: float = 15.0

    local_ip: str | None = field(
        init=False, repr=False, default_factory=get_local_ip
    )

    @contextmanager
    def get_socket(self) -> Iterator[socket.socket]:
        try:
            with socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            ) as sock:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # sock.settimeout(self.socket_timeout)
                yield sock
        except PermissionError as ex:
            raise RuntimeError(
                "Root privileges are required to create the socket."
            ) from ex

    def check_port(self, host: str, port: int):
        resolved_ip = socket.gethostbyname(host)
        # src_port = get_free_port()
        syn = TcpPacket.make_syn(
            src_addr=self.local_ip,
            src_port=random.randint(30000, 32000),
            src_mac=uuid.getnode(),
            dst_addr=resolved_ip,
            dst_port=port,
            dst_mac=0,
        )
        logger.debug("crafted packet: %s", syn)
        with self.get_socket() as sock:
            raw = syn.pack()[14:]
            logger.debug(raw.hex(" "))
            sock.sendto(syn.pack()[14:], (resolved_ip, 0))
            while True:
                data = sock.recv(65535)
                # logger.debug("recieve data: %s", data.hex(" ", 1))
                iph = IpHeader.unpack(data)
                tcph = TcpHeader.unpack(data[20:])

                if tcph.flags == (TcpHeader.Flags.SYN | TcpHeader.Flags.ACK):

                    logger.debug(iph)
                    logger.debug(tcph)

                # ans = TcpPacket.unpack(data)
                # logger.debug("answer: %s", ans)
                # self.output.write(f"{host}:{port}\n")

    def scan(self, addresses: list[str], ports: list[int]) -> None:
        dt = -time.monotonic()
        with ThreadPoolExecutor(self.max_workers) as pool:
            futs = [
                pool.submit(self.check_port, addr, port)
                for addr, port in itertools.product(addresses, ports)
            ]

        for fut in as_completed(futs):
            try:
                fut.result()
            except (socket.timeout, socket.error) as ex:
                logger.warning("socket error: %s", ex)

        dt += time.monotonic()
        logger.info("finished at %.3fs", dt)
