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


# (ip.src == 93.184.216.34 or ip.dst == 93.184.216.34) and (tcp.flags.syn == 1 or (tcp.flags.syn==1 and tcp.flags.ack==1))

# SYN

# Internet Protocol Version 4, Src: 192.168.0.104, Dst: 93.184.216.34
#     0100 .... = Version: 4
#     .... 0101 = Header Length: 20 bytes (5)
#     Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
#     Total Length: 60
#     Identification: 0xc6b0 (50864)
#     010. .... = Flags: 0x2, Don't fragment
#     ...0 0000 0000 0000 = Fragment Offset: 0
#     Time to Live: 64
#     Protocol: TCP (6)
#     Header Checksum: 0x7d20 [validation disabled]
#     [Header checksum status: Unverified]
#     Source Address: 192.168.0.104
#     Destination Address: 93.184.216.34
# Transmission Control Protocol, Src Port: 40506, Dst Port: 443, Seq: 0, Len: 0
#     Source Port: 40506
#     Destination Port: 443
#     [Stream index: 2287]
#     [Conversation completeness: Incomplete, DATA (15)]
#     [TCP Segment Len: 0]
#     Sequence Number: 0    (relative sequence number)
#     Sequence Number (raw): 8006911
#     [Next Sequence Number: 1    (relative sequence number)]
#     Acknowledgment Number: 0
#     Acknowledgment number (raw): 0
#     1010 .... = Header Length: 40 bytes (10)
#     Flags: 0x002 (SYN)
#     Window: 32120
#     [Calculated window size: 32120]
#     Checksum: 0xf719 [unverified]
#     [Checksum Status: Unverified]
#     Urgent Pointer: 0
#     Options: (20 bytes), Maximum segment size, SACK permitted, Timestamps, No-Operation (NOP), Window scale
#         TCP Option - Maximum segment size: 1460 bytes
#         TCP Option - SACK permitted
#         TCP Option - Timestamps: TSval 177389898, TSecr 0
#         TCP Option - No-Operation (NOP)
#         TCP Option - Window scale: 7 (multiply by 128)
#             Kind: Window Scale (3)
#             Length: 3
#             Shift count: 7
#             [Multiplier: 128]
#     [Timestamps]
#         [Time since first frame in this TCP stream: 0.000000000 seconds]
#         [Time since previous frame in this TCP stream: 0.000000000 seconds]

# SYN-ACK

# 340804c2cf2a74563c2f84ac08004500003cc6b0400040067d20c0a800685db8d8229e3a01bb007a2cff00000000a0027d78f7190000020405b40402080a0a92c14a0000000001030307

# Internet Protocol Version 4, Src: 192.168.0.104, Dst: 93.184.216.34
#     0100 .... = Version: 4
#     .... 0101 = Header Length: 20 bytes (5)
#     Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
#     Total Length: 60
#     Identification: 0xc6b0 (50864)
#     010. .... = Flags: 0x2, Don't fragment
#     ...0 0000 0000 0000 = Fragment Offset: 0
#     Time to Live: 64
#     Protocol: TCP (6)
#     Header Checksum: 0x7d20 [validation disabled]
#     [Header checksum status: Unverified]
#     Source Address: 192.168.0.104
#     Destination Address: 93.184.216.34
# Transmission Control Protocol, Src Port: 40506, Dst Port: 443, Seq: 0, Len: 0
#     Source Port: 40506
#     Destination Port: 443
#     [Stream index: 2287]
#     [Conversation completeness: Complete, WITH_DATA (31)]
#     [TCP Segment Len: 0]
#     Sequence Number: 0    (relative sequence number)
#     Sequence Number (raw): 8006911
#     [Next Sequence Number: 1    (relative sequence number)]
#     Acknowledgment Number: 0
#     Acknowledgment number (raw): 0
#     1010 .... = Header Length: 40 bytes (10)
#     Flags: 0x002 (SYN)
#     Window: 32120
#     [Calculated window size: 32120]
#     Checksum: 0xf719 [unverified]
#     [Checksum Status: Unverified]
#     Urgent Pointer: 0
#     Options: (20 bytes), Maximum segment size, SACK permitted, Timestamps, No-Operation (NOP), Window scale
#         TCP Option - Maximum segment size: 1460 bytes
#         TCP Option - SACK permitted
#         TCP Option - Timestamps: TSval 177389898, TSecr 0
#         TCP Option - No-Operation (NOP)
#         TCP Option - Window scale: 7 (multiply by 128)
#             Kind: Window Scale (3)
#             Length: 3
#             Shift count: 7
#             [Multiplier: 128]
#     [Timestamps]
#         [Time since first frame in this TCP stream: 0.000000000 seconds]
#         [Time since previous frame in this TCP stream: 0.000000000 seconds]


# 74563c2f84ac340804c2cf2a08004500003c0000400036064dd15db8d822c0a8006801bb9e3a777dd219007a2d00a012ffff21010000020405b40402080a526afab30a92c14a01030309
