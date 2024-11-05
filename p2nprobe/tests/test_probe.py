#!/usr/bin/env python3

import subprocess
import sys
import time
from typing import Dict, Optional

from netflowcollector import NetflowCollector

P2NPROBE_PATH = "../p2nprobe"

GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'


def color_by_result(val_1, val_2):
    if val_1 == val_2:
        return GREEN
    return RED


def run_probe(p2nprobe_path: str, pcap_file: str, collector_port: int, active_timeout: int = 60,
              inactive_timeout: int = 60) -> Optional[subprocess.Popen]:
    try:
        print("Running p2nprobe...")
        print("ARGS:", p2nprobe_path, f"localhost:{collector_port}", pcap_file, "-a", f"{active_timeout}", "-i",
              f"{inactive_timeout}")
        return subprocess.Popen(
            [p2nprobe_path, f"localhost:{collector_port}", pcap_file,
             "-a", f"{active_timeout}", "-i", f"{inactive_timeout}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except subprocess.SubprocessError as e:
        print(f"Error running p2nprobe: {e}")
        return None


def run_softflowd(pcap_file: str, collector_port: int, expint: int = 60, maxlife: int = 60) -> Optional[subprocess.Popen]:
    try:
        print("Running softflowd...")
        return subprocess.Popen(
            ["softflowd",
                "-r", pcap_file,
                "-n", f"localhost:{collector_port}",
                "-t", f"expint={expint}",
                "-t", f"maxlife={maxlife}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except subprocess.SubprocessError as e:
        print(f"Error running softflowd: {e}")
        return None


def compare_flows(collected: Dict, reference: Dict) -> None:
    print("\nFlow Comparison Results:")
    print("------------------------")

    total_flows = len(reference)
    matching_flows = 0
    total_packets = 0
    total_octets = 0
    ref_packets = 0
    ref_octets = 0

    for flow_key, ref_records in reference.items():
        if flow_key in collected:
            matching_flows += 1
            for rec, ref_rec in zip(collected[flow_key], ref_records):
                total_packets += rec.packets
                total_octets += rec.octets
                ref_packets += ref_rec.packets
                ref_octets += ref_rec.octets

                time_diff = abs((rec.last_time - rec.first_time) -
                                (ref_rec.last_time - ref_rec.first_time))

                if rec.packets != ref_rec.packets or rec.octets != ref_rec.octets or time_diff != 0:
                    print(f"\nDiscrepancy in flow {flow_key}:{RESET}")
                    print(
                        f"{color_by_result(rec.packets, ref_rec.packets)}Collected: {rec.packets} packets | Reference: {ref_rec.packets} packets{RESET}")
                    print(
                        f"{color_by_result(rec.octets, ref_rec.octets)}Collected: {rec.octets} octets | Reference: {ref_rec.octets} octets{RESET}")
                    print(
                        f"{color_by_result(time_diff, 0)}Time difference: {time_diff}ms{RESET}")
                else:
                    print(f"\n{GREEN}Flow {flow_key} matched!{RESET}")
                    print(f"{GREEN}Time difference: {time_diff}ms{RESET}")

        else:
            print(f"\n{RED}Missing flow: {flow_key}{RESET}")

    print(f"\nMatched flows: {matching_flows}/{total_flows}")
    print(f"Total packets: {total_packets} (Reference: {ref_packets})")
    print(f"Total octets: {total_octets} (Reference: {ref_octets})")


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: ./test_probe.py <pcap_file> [collector_port] [active_timeout] [inactive_timeout]")
        sys.exit(1)

    pcap_file = sys.argv[1]
    collector_port = int(sys.argv[2]) if len(sys.argv) > 2 else 9995
    active_timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 60
    inactive_timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 60

    collector_p2nprobe = NetflowCollector(port=collector_port)

    probe_process = run_probe(p2nprobe_path=P2NPROBE_PATH, pcap_file=pcap_file,
                              collector_port=collector_port, active_timeout=active_timeout, inactive_timeout=inactive_timeout)
    if not probe_process:
        sys.exit(1)

    collector_p2nprobe.collect_flows()

    _, stderr = probe_process.communicate()
    if probe_process.returncode != 0:
        print(f"STDERR: {stderr.decode()}")
        sys.exit(1)

    count = 0
    for flow_key, records in collector_p2nprobe.flows.items():
        print(f"Flow: {flow_key}")
        count += 1
    print(f"Total flows: {count}")

    # collector_softflowd = NetflowCollector(port=collector_port+1)

    # softflowd_process = run_softflowd(
    #     pcap_file, collector_port+1, active_timeout, inactive_timeout)
    # if not softflowd_process:
    #     sys.exit(1)

    # collector_softflowd.collect_flows()

    # _, stderr = softflowd_process.communicate()
    # if softflowd_process.returncode != 0:
    #     print(f"STDERR: {stderr.decode()}")
    #     sys.exit(1)

    # print("\nComparing p2nprobe flows with softflowd flows:")
    # compare_flows(collector_p2nprobe.flows, collector_softflowd.flows)


if __name__ == "__main__":
    main()
