from dataclasses import dataclass

@dataclass
class NetflowV5Header:
    version: int
    count: int
    sys_uptime: int
    unix_secs: int
    unix_nsecs: int
    flow_sequence: int
    engine_type: int
    engine_id: int
    sampling_interval: int


@dataclass
class NetflowV5Record:
    src_addr: str
    dst_addr: str
    next_hop: str
    input_iface: int
    output_iface: int
    packets: int
    octets: int
    first_time: int
    last_time: int
    src_port: int
    dst_port: int
    pad1: int
    tcp_flags: int
    protocol: int
    tos: int
    src_as: int
    dst_as: int
    src_mask: int
    dst_mask: int
    pad2: int