# Частичная реализация протокола TCP/IP

# Описание протокола:
# https://datatracker.ietf.org/doc/html/rfc791
from __future__ import annotations

import ipaddress
import secrets
import socket
from abc import ABC, abstractclassmethod, abstractmethod
from dataclasses import dataclass
from enum import IntEnum, IntFlag, auto
from struct import Struct
from typing import Any, ClassVar, Type, TypeVar

from .log import logger

T = TypeVar("T")


class _Base(ABC):
    @abstractclassmethod
    def unpack(cls: Type[T], data: bytes) -> T:
        raise NotImplementedError

    @abstractmethod
    def pack(self) -> bytes:
        raise NotImplementedError


class _BaseStruct(_Base):
    @property
    @abstractmethod
    def struct(self) -> Struct:
        raise NotImplementedError

    @classmethod
    def to_tuple(cls: Type[T], data: bytes) -> tuple[int, ...]:
        return cls.struct.unpack(data[: cls.struct.size])


# https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
@dataclass
class TcpHeader(_BaseStruct):
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
    def unpack(cls: Type[TcpHeader], data: bytes) -> TcpHeader:
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
class IpHeader(_BaseStruct):
    #   Various Control Flags.

    #     Bit 0: reserved, must be zero
    #     Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
    #     Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.
    class Flags(IntEnum):
        R = 0
        DF = 1
        MF = 2

    # B
    version: int  # version. ip v4 = 4. 4 bits
    ihl: int  # internet Header length in 32 bits words (total bytes / 4). 4 bit

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
    csum: int  # 2 bytes. Header csum sum

    # L
    src_addr: str  # 4 bytes

    # L
    dst_addr: str  # 4 bytes

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
            int(ipaddress.ip_address(self.dst_addr)),
        )

    @classmethod
    def unpack(cls: Type[IpHeader], data: bytes) -> IpHeader:
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
            dst_addr=str(ipaddress.ip_address(values[9])),
        )


# https://stackoverflow.com/a/8845286/2240578
def cheksum(msg: bytes) -> int:
    s = 0
    for i in range(0, len(msg), 2):
        s += (msg[i] << 8) + msg[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s = ~s & 0xFFFF
    return s


class MacAddress(int):
    def __str__(self) -> str:
        return self.to_bytes(6).hex(":")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self}>"


@dataclass
class EthernetHeader(_Base):

    # https://en.wikipedia.org/wiki/EtherType#Values
    class EtherType(IntEnum):
        IPV4 = 0x800
        IPV6 = 0x86DD

    # cat /proc/net/arp
    # IP address       HW type     Flags       HW address            Mask     Device
    # 192.168.0.1      0x1         0x2         01:02:03:04:05:06     *        enp4s0
    dst_mac: MacAddress
    # текущий - uuid.getnode()
    src_mac: MacAddress
    type: EtherType

    def __post_init__(self) -> None:
        self.dst_mac = MacAddress(self.dst_mac)
        self.src_mac = MacAddress(self.src_mac)

    def pack(self) -> bytes:
        return (
            self.dst_mac.to_bytes(6)
            + self.src_mac.to_bytes(6)
            + int.to_bytes(self.type, 2)
        )

    @classmethod
    def unpack(cls: Type[EthernetHeader], data: bytes) -> EthernetHeader:
        return cls(
            MacAddress.from_bytes(data[:6]),
            MacAddress.from_bytes(data[6:12]),
            cls.EtherType(int.from_bytes(data[12:14])),
        )


@dataclass
class TcpPacket(_Base):
    eth: EthernetHeader
    iph: IpHeader
    tcph: TcpHeader

    @classmethod
    def unpack(cls: Type[TcpPacket], data: bytes) -> TcpPacket:
        return cls(
            EthernetHeader.unpack(data[:14]),
            IpHeader.unpack(data[14:]),
            TcpHeader.unpack(data[14 + IpHeader.struct.size :]),
        )

    def pack(self) -> bytes:
        return self.eth.pack() + self.iph.pack() + self.tcph.pack()

    @classmethod
    def make_syn(
        cls: Type[TcpPacket],
        src_addr: str,
        src_port: int,
        src_mac: str,
        dst_addr: str,
        dst_port: int,
        dst_mac: str,
    ) -> bytes:
        # src_mac = uuid.getnode()
        eth = EthernetHeader(dst_mac, src_mac, EthernetHeader.EtherType.IPV4)

        iph = IpHeader(
            ihl=5,
            version=4,
            dscp=0,
            ecn=0,
            total_length=IpHeader.struct.size + TcpHeader.struct.size,
            id=0,
            flags=IpHeader.Flags(0x2),
            fragment_offset=0,
            ttl=64,
            protocol=socket.IPPROTO_TCP,
            csum=0,  # если оставить пустым, то ядро самостоятельно расчитает сумму
            src_addr=src_addr,
            dst_addr=dst_addr,
        )

        tcph = TcpHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=secrets.randbits(32),
            ack_num=0,
            data_offset=IpHeader.struct.size // 4,
            reserved=0,
            flags=TcpHeader.Flags.SYN,
            window_size=32120,
            csum=0,
            urgent_ptr=0,
        )

        # суммы можно не считать
        tcph.csum = cheksum(iph.pack() + tcph.pack())
        return cls(eth, iph, tcph)
