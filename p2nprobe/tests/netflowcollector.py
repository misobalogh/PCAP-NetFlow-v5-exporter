from netflowV5format import NetflowV5Header, NetflowV5Record


import socket
import struct
from typing import Dict, List, Tuple


class NetflowCollector:
    def __init__(self, host: str = "localhost", port: int = 9995):
        self.host = host
        self.port = port
        self.flows: Dict[Tuple[str, int, str, int], List[NetflowV5Record]] = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))

    def parse_header(self, data: bytes) -> NetflowV5Header:
        return NetflowV5Header(
            version=struct.unpack('!H', data[0:2])[0],
            count=struct.unpack('!H', data[2:4])[0],
            sys_uptime=struct.unpack('!I', data[4:8])[0],
            unix_secs=struct.unpack('!I', data[8:12])[0],
            unix_nsecs=struct.unpack('!I', data[12:16])[0],
            flow_sequence=struct.unpack('!I', data[16:20])[0],
            engine_type=data[20],
            engine_id=data[21],
            sampling_interval=struct.unpack('!H', data[22:24])[0]
        )

    def parse_record(self, data: bytes) -> NetflowV5Record:
        src_addr = socket.inet_ntoa(data[0:4])
        dst_addr = socket.inet_ntoa(data[4:8])
        return NetflowV5Record(
            src_addr=src_addr,
            dst_addr=dst_addr,
            next_hop=socket.inet_ntoa(data[8:12]),
            input_iface=struct.unpack('!H', data[12:14])[0],
            output_iface=struct.unpack('!H', data[14:16])[0],
            packets=struct.unpack('!I', data[16:20])[0],
            octets=struct.unpack('!I', data[20:24])[0],
            first_time=struct.unpack('!I', data[24:28])[0],
            last_time=struct.unpack('!I', data[28:32])[0],
            src_port=struct.unpack('!H', data[32:34])[0],
            dst_port=struct.unpack('!H', data[34:36])[0],
            pad1=data[36],
            tcp_flags=data[37],
            protocol=data[38],
            tos=data[39],
            src_as=struct.unpack('!H', data[40:42])[0],
            dst_as=struct.unpack('!H', data[42:44])[0],
            src_mask=data[44],
            dst_mask=data[45],
            pad2=struct.unpack('!H', data[46:48])[0]
        )

    def collect_flows(self, timeout: int = 5) -> None:
        self.sock.settimeout(timeout)
        try:
            while True:
                data, addr = self.sock.recvfrom(1500)
                header = self.parse_header(data)

                if header.version != 5:
                    print(f"Warning: Received non-NetFlow v5 packet {header}")
                    continue

                offset = 24  # Header size
                for _ in range(header.count):
                    record = self.parse_record(data[offset:offset + 48])
                    if record.protocol == 6:  # TCP only
                        flow_key = (record.src_addr, record.src_port,
                                  record.dst_addr, record.dst_port)
                        if flow_key not in self.flows:
                            self.flows[flow_key] = []
                        self.flows[flow_key].append(record)
                    offset += 48 # Record size

        except socket.timeout:
            print("Collection finished")
            print(f"Total flows: {len(self.flows)}")
        finally:
            self.sock.close()