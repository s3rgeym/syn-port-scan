import argparse
import logging
import sys
from typing import Sequence, TextIO

from .log import logger
from .scan import PortScanner


class NameSpace(argparse.Namespace):
    addresses: list[str]
    debug: bool
    input: TextIO
    output: TextIO
    ports: list[int | list[int]]
    timeout: float
    workers: int


def parse_port(value: str) -> int | list[int]:
    try:
        first, last = value.split("-")
        return list(range(int(first), int(last) + 1))
    except ValueError:
        return int(value)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-a",
        "--address",
        "--addr",
        dest="addresses",
        nargs="*",
        default=[],
        help="one or more addresses to scan",
    )

    parser.add_argument(
        "-i",
        "--input",
        type=argparse.FileType(),
        default="-",
        help="list addresses to scan",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=argparse.FileType("w+"),
        default="-",
        help="output file",
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="ports",
        nargs="+",
        type=parse_port,
        help="port",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="socket timeout",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=50,
        help="maximum number of workers",
    )
    parser.add_argument(
        "-d",
        "--debug",
        default=False,
        action="store_true",
    )
    args = parser.parse_args(argv, NameSpace())

    addresses = list(args.addresses)

    if not args.input.isatty():
        addresses.extend(filter(None, map(str.strip, args.input)))

    if not addresses:
        parser.error("nothing to scan")

    ports = []

    for item in args.ports:
        if isinstance(item, Sequence):
            ports.extend(item)
        else:
            ports.append(item)

    if not ports:
        parser.error("please specify at least one port with --port")

    if args.debug:
        logger.setLevel(logging.DEBUG)

    scanner = PortScanner(
        args.output,
        max_workers=args.workers,
        socket_timeout=args.timeout,
    )

    try:
        scanner.scan(addresses, ports)
    except BaseException as ex:
        logger.critical(ex, exc_info=True)
        sys.exit(1)
