import subprocess
import sys
from typing import List, Tuple
from itertools import permutations

SUCCESS = 0
ERROR = 1

EXISTING_PCAP_FILE = "pcaps/tcp.pcap"
NONEXISTING_PCAP_FILE = "does_not_exist.pcap"


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'


def run_test(args: List[str]) -> Tuple[int, str, str]:
    try:
        args_without_spaces = [item for arg in args for item in arg.split(" ")]

        process = subprocess.run(['./p2nprobe'] + args_without_spaces,
                                 capture_output=True,
                                 text=True)
        return process.returncode, process.stdout, process.stderr
    except FileNotFoundError:
        print("Error: p2nprobe executable not found")
        sys.exit(1)


def run_test_with_permutations(args: List[str], expected_code: int) -> Tuple[bool, int, List[str]]:
    all_passed = True
    failed_args = []
    total_runs = 0

    # Generate all possible permutations of the arguments
    for perm in permutations(args):
        actual_code, _, _ = run_test(list(perm))
        total_runs += 1
        passed = (expected_code == actual_code) or (
            expected_code == ERROR and actual_code != SUCCESS)
        if not passed:
            print(f"Failed: {actual_code}, {expected_code}")
            all_passed = False
            failed_args.append(list(perm))

    return all_passed, total_runs, failed_args


def print_result(test_name: str, expected_code: int, actual_code: int, args: List[str]):
    passed = (expected_code == actual_code) or (
        expected_code == ERROR and actual_code != SUCCESS)
    color = Colors.GREEN if passed else Colors.RED
    status = "PASS" if passed else "FAIL"
    print(f"{color}[{status}]{Colors.RESET} {test_name}")
    if not passed:
        print(f"  Arguments: {' '.join(args)}")
        print(f"  Expected exit code: {expected_code}")
        print(f"  Actual exit code: {actual_code}")


def print_permutation_result(test_name: str, passed: bool, total_runs: int, failed_args: List[List[str]]):
    color = Colors.GREEN if passed else Colors.RED
    status = "PASS" if passed else "FAIL"
    print(f"{color}[{status}]{Colors.RESET} {test_name}")
    print(f"  Total permutations tested: {total_runs}")
    if not passed:
        print("  Failed permutations:")
        for args in failed_args:
            print(f"    {' '.join(args)}")


def main():
    # Test cases: (test_name, arguments, expected outcome)
    tests = [
        ("Valid arguments", ["localhost:2055", EXISTING_PCAP_FILE], SUCCESS),
        ("Help message", ["-h"], SUCCESS),
        ("Help message 2", ["localhost:9555", "-h"], SUCCESS),
        ("Help message 3", [NONEXISTING_PCAP_FILE, "localhost:9555", "-h"], SUCCESS),
        ("Help message 3", ["localhost:9555", "-h"], SUCCESS),
        ("Missing arguments", [], ERROR),
        ("Invalid port", ["localhost:99999", EXISTING_PCAP_FILE], ERROR),
        ("Invalid active timeout", ["localhost:2055", EXISTING_PCAP_FILE, "-a", "abc"], ERROR),
        ("Invalid inactive timeout", ["localhost:2055", EXISTING_PCAP_FILE, "-i", "-1"], ERROR),
        ("Missing port", ["localhost", EXISTING_PCAP_FILE], ERROR),
        ("Invalid port format", ["localhost:", EXISTING_PCAP_FILE], ERROR),
        ("Valid timeouts", ["localhost:2055", EXISTING_PCAP_FILE, "-a 30", "-i 60"], SUCCESS),
        ("Extra arguments", ["localhost:2055", EXISTING_PCAP_FILE, "extra"], ERROR),
    ]

    print("Running p2nprobe argument tests with permutations...\n")

    passed_tests = 0
    total_tests = len(tests)
    total_permutations = 0

    for test_name, args, expected_code in tests:
        passed, runs, failed = run_test_with_permutations(args, expected_code)
        print_permutation_result(test_name, passed, runs, failed)
        if passed:
            passed_tests += 1
        total_permutations += runs

    print(f"\nSummary: {passed_tests}/{total_tests} tests passed")
    print(f"Total permutations tested: {total_permutations}")

    sys.exit(0 if passed_tests == total_tests else 1)


if __name__ == "__main__":
    main()
