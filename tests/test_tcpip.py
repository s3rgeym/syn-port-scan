from syn_port_scan.tcpip import IPHeader, TCPHeader


def test_pack_unpack_ip_header() -> None:
    h1 = IPHeader(
        version=4,
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=40,
        id=30964,
        flags=IPHeader.Flags.R,
        fragment_offset=0,
        ttl=64,
        protocol=6,
        checksum=9693,
        src_addr="192.168.0.101",
        dest_addr="10.0.0.1",
    )

    print(h1)
    data = h1.pack()

    h2 = IPHeader.unpack(data)
    print(h2)

    assert h1 == h2


def test_pack_unpack_tcp_header() -> None:
    h1 = TCPHeader(
        src_port=47960,
        dst_port=80,
        seq_num=3731055133,
        ack_num=0,
        data_offset=10,
        reserved=0,
        flags=TCPHeader.Flags.SYN,
        window_size=32120,
        checksum=56365,
        urgent_ptr=0,
    )

    print(h1)

    data = h1.pack()

    h2 = TCPHeader.unpack(data)

    print(h2)

    assert h1 == h2
