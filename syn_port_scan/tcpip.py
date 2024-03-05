# Частичная реализация протокола TCP/IP

# Описание протокола:
# https://datatracker.ietf.org/doc/html/rfc791
from __future__ import annotations

import ipaddress
import logging
import secrets
import socket
from abc import ABC, abstractclassmethod, abstractmethod
from dataclasses import dataclass
from enum import IntFlag, auto
from struct import Struct
from typing import ClassVar, Type, TypeVar

from .log import logger

T = TypeVar("T")


class Base(ABC):
    @abstractclassmethod
    def unpack(cls: Type[T], data: bytes) -> T:
        raise NotImplementedError

    @abstractmethod
    def pack(self) -> bytes:
        raise NotImplementedError


class Header(Base):
    @property
    @abstractmethod
    def struct(self) -> Struct:
        raise NotImplementedError

    @classmethod
    def to_tuple(cls: Type[T], data: bytes) -> tuple[int, ...]:
        return cls.struct.unpack(data[: cls.struct.size])


# https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
@dataclass
class TCPHeader(Header):
    class Flags(IntFlag):
        FIN = 1
        SYN = auto()
        RST = auto()
        PSH = auto()
        ACK = auto()
        URG = auto()
        ECE = auto()
        CWR = auto()

    # 2H
    src_port: int  # 2 bytes
    dst_port: int  # 2 bytes

    # 2L
    seq_num: int  # 4 bytes
    ack_num: int  # 4 bytes

    # 2B

    # Размер заголовка в 32-битных словах (4 байта).
    # Минимальный - 20 байт (4 x 5)
    data_offset: int  # 4 bits
    reserved: int  # 4 bits
    flags: Flags  # 8 bits

    # 3H
    window_size: int  # 2 bytes
    csum: int  # 2 bytes
    urgent_ptr: int  # 2 bytes
    # опции не нужны

    # в интернете есть только big-endian
    struct: ClassVar = Struct("!HHIIBB3H")

    def pack(self) -> bytes:
        return self.struct.pack(
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            ((self.data_offset & 0xF) << 4) | 0,  # (self.reserved & 0xF),
            self.flags,
            self.window_size,
            self.csum,
            self.urgent_ptr,
        )

    @classmethod
    def unpack(cls: Type[TCPHeader], data: bytes) -> TCPHeader:
        values = cls.to_tuple(data)
        return cls(
            src_port=values[0],
            dst_port=values[1],
            seq_num=values[2],
            ack_num=values[3],
            data_offset=(values[4] >> 4) & 0b1111,
            reserved=values[4] & 0b1111,
            flags=cls.Flags(values[5]),
            window_size=values[6],
            csum=values[7],
            urgent_ptr=values[8],
        )


# https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header
@dataclass
class IPHeader(Header):
    #   Various Control Flags.

    #     Bit 0: reserved, must be zero
    #     Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
    #     Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.
    class Flags(IntFlag):
        R = 0
        DF = 1
        MF = 2

    # B
    version: int  # version. ip v4 = 4. 4 bits
    ihl: int  # internet header length in 32 bits words (total bytes / 4). 4 bit

    # B
    dscp: int  # Differentiated Services Code Point or ToS (Type of Service) = 6 bits
    ecn: int  # 2 bits

    # H
    total_length: int  # 2 bytes. packet size in bytes

    # H
    id: int  #  2 bytes. must be 0

    # H
    flags: Flags  # 3 bits
    fragment_offset: int  # 13 bits

    # B
    ttl: int  # 1 byte. time to live in seconds. 1 секунды хватит всем

    # B
    protocol: int  # 1byte

    # H
    csum: int  # 2 bytes. header csum sum

    # L
    src_addr: str  # 4 bytes

    # L
    dest_addr: str  # 4 bytes

    # options if ihl > 5 (20 bytes)

    struct: ClassVar = Struct("!BB3HBBHLL")

    def pack(self) -> bytes:
        return self.struct.pack(
            ((self.version & 0b1111) << 4) | (self.ihl & 0b1111),
            ((self.dscp & 0b111111) << 2) | (self.ecn & 0b11),
            self.total_length,
            self.id,
            # 16 bits = 3 bits flags + 13 bits fragment offset
            ((self.flags & 0b111) << 13)
            | (self.fragment_offset & 0b1111111111111),
            self.ttl,
            self.protocol,
            self.csum,
            int(ipaddress.ip_address(self.src_addr)),
            int(ipaddress.ip_address(self.dest_addr)),
        )

    @classmethod
    def unpack(cls: Type[IPHeader], data: bytes) -> IPHeader:
        values = cls.to_tuple(data)
        return cls(
            version=(values[0] >> 4) & 0b1111,
            ihl=values[0] & 0b1111,
            # each 4 bits, total: 1 byte
            dscp=(values[1] >> 2) & 0b111111,  # 6 bits
            ecn=values[1] & 0b11,  # 2 bits
            # total: 8 bits = 1 byte
            total_length=values[2],
            id=values[3],
            flags=cls.Flags((values[4] >> 13) & 0b111),
            fragment_offset=values[4] & 0b1111111111111,
            ttl=values[5],
            protocol=values[6],
            csum=values[7],
            src_addr=str(ipaddress.ip_address(values[8])),
            dest_addr=str(ipaddress.ip_address(values[9])),
        )


# https://stackoverflow.com/a/8845286/2240578
def cheksum(data: bytes) -> int:
    rv = 0
    for i in range(0, len(data), 2):
        rv += (data[i] << 8) + data[i + 1]
    rv = (rv >> 16) + (rv & 0xFFFF)
    # rv += rv >> 16
    return ~rv & 0xFFFF


@dataclass
class Packet(Base):
    ip_header: IPHeader
    tcp_header: TCPHeader

    @classmethod
    def unpack(cls: Type[Packet], data: bytes) -> Packet:
        # Это неправильно
        return cls(IPHeader.unpack(data), TCPHeader.unpack(data[20:]))

    def pack(self) -> bytes:
        return self.ip_header.pack() + self.tcp_header.pack()

    @classmethod
    def make_syn(
        cls: Type[Packet],
        src_addr: str,
        src_port: int,
        dest_addr: str,
        dst_port: int,
    ) -> bytes:
        iph = IPHeader(
            ihl=5,
            version=4,
            dscp=0,
            ecn=0,
            total_length=IPHeader.struct.size + TCPHeader.struct.size,
            id=0,
            flags=0,
            fragment_offset=0,
            ttl=255,
            protocol=socket.IPPROTO_TCP,
            csum=0,
            src_addr=src_addr,
            dest_addr=dest_addr,
        )

        iph.csum = cheksum(iph.pack())

        tcph = TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=secrets.randbits(32),
            ack_num=0,
            data_offset=IPHeader.struct.size // 4,
            reserved=0,
            flags=TCPHeader.Flags.SYN,
            window_size=65535,
            csum=0,
            urgent_ptr=0,
        )

        tcph.csum = cheksum(tcph.pack())

        return cls(iph, tcph)
