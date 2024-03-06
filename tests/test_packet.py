import dataclasses
import typing
import unittest

from syn_port_scan.packet import (
    EthernetHeader,
    IpHeader,
    TcpHeader,
    TcpPacket,
    cheksum,
)


class TestWireshark(unittest.TestCase):
    def setUp(self) -> None:
        # WireShark
        # Первые 12-байт отредактированы
        self.data = bytes.fromhex(
            "01020304050606050403020108004500003ca5f6400040069ddac0a800685db8d822c18a01bb38abdb5900000000a0027d78f7190000020405b40402080a260d69e40000000001030307"
        )
        self.packet = TcpPacket.unpack(self.data)

    def test_attrs(self) -> None:
        # TcpPacket(eth=EthernetHeader(dst_mac=<MacAddress: 01:02:03:04:05:06>, src_mac=<MacAddress: 06:05:04:03:02:01>, type=<EtherType.IPV4: 2048>), iph=IpHeader(version=4, ihl=5, dscp=0, ecn=0, total_length=60, id=42486, flags=<Flags.MF: 2>, fragment_offset=0, ttl=64, protocol=6, csum=40410, src_addr='192.168.0.104', dst_addr='93.184.216.34'), tcph=TcpHeader(src_port=49546, dst_port=443, seq_num=950786905, ack_num=0, data_offset=10, reserved=0, flags=<Flags.SYN: 2>, window_size=32120, csum=63257, urgent_ptr=0))
        print(self.packet)

        self.assertEqual(str(self.packet.eth.dst_mac), "01:02:03:04:05:06")
        self.assertEqual(str(self.packet.eth.src_mac), "06:05:04:03:02:01")
        self.assertEqual(self.packet.eth.type, EthernetHeader.EtherType.IPV4)

        self.assertEqual(self.packet.iph.version, 4)
        self.assertEqual(self.packet.iph.ihl, 5)

        self.assertEqual(self.packet.iph.src_addr, "192.168.0.104")
        self.assertEqual(self.packet.tcph.src_port, 49546)

        self.assertEqual(self.packet.iph.dst_addr, "93.184.216.34")
        self.assertEqual(self.packet.tcph.dst_port, 443)

        self.assertEqual(self.packet.iph.ttl, 64)

        self.assertEqual(self.packet.tcph.seq_num, 950786905)
        self.assertEqual(self.packet.tcph.flags, TcpHeader.Flags.SYN)
        self.assertEqual(self.packet.tcph.window_size, 32120)

        self.assertEqual(self.packet.iph.csum, 0x9DDA)
        self.assertEqual(self.packet.tcph.csum, 0xF719)

    def test_checksum(self) -> None:
        iph = dataclasses.replace(self.packet.iph, csum=0)
        self.assertEqual(self.packet.iph.csum, cheksum(iph.pack()))
        # TODO: посчитать контрольную сумму всего пакета

    def test_pack(self) -> None:
        # пробуем упаковать заголовки и проверяем чтобы они соотв входным данным

        data = self.data[14:]
        self.assertEqual(self.packet.iph.pack(), data[:20])

        # парсинг опций и тела пакета не реализован, поэтому сравнивает только 20 байт
        self.assertEqual(self.packet.tcph.pack(), data[20:40])
