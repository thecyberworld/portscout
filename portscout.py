#!/bin/python3
import os
import sys
import socket
import argparse
import concurrent.futures
from termcolor import colored
from datetime import datetime as dt

# Define the list of the top 100 commonly used ports
TOP_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 110, 111, 115, 123,
    135, 137, 138, 139, 143, 161, 162, 179, 194, 213, 443, 465, 514,
    515, 520, 530, 531, 532, 540, 554, 587, 601, 631, 636, 646, 660,
    669, 674, 688, 691, 694, 700, 707, 750, 751, 760, 761, 762, 780,
    800, 808, 843, 873, 902, 989, 990, 991, 992, 993, 994, 995, 1080,
    1194, 1723, 3306, 3389, 5432, 5900, 6000, 6379, 6466, 8080, 8443,
    8888, 9000, 9090, 9200, 9300, 9418
]


def exit_program() -> None:
    """Exit the program."""
    sys.exit()


def get_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Get arguments for port scanner")
    parser.add_argument('-H', '--host', dest='HOST', help="IP address of host machine", required=True)
    parser.add_argument('-o', '--output', dest='OUTPUT', help="Write the output into a file")
    parser.add_argument('-p', '--port', dest='PORTS', help="Ports to scan, input in the form <start>-<end>")
    parser.add_argument('-v', '--verbose', action='store_true', help="Increase output verbosity")
    return parser.parse_args()


def check_port(port: int) -> bool:
    """Check if a port is open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        socket.setdefaulttimeout(0.5)  # Timeout of 0.5 seconds for quicker response
        result = sock.connect_ex((target, port))
    return result == 0


def display_conf_data() -> None:
    """Display configuration data for the scan."""
    print(colored("-" * 50, 'cyan'))
    print(colored("Scanning Configuration", 'cyan'))
    print(colored("-" * 50, 'cyan'))
    print(f"Target Host: {target}")

    # Indicate if the top ports are being used
    if port_start == 1 and port_end == 65535:
        print(f"Ports Range: Top 100 Ports ({min(TOP_PORTS)} - {max(TOP_PORTS)})")
    else:
        print(f"Ports Range: {port_start} - {port_end}")

    print(f"Output File: {output_file if output_file else 'Not specified'}")
    print(colored("-" * 50, 'cyan'))


def find_open_ports():
    """Find open ports using multithreading."""
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
            futures = {executor.submit(check_port, port): port for port in range(port_start, port_end + 1)}

            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                if future.result():
                    if store_open_ports:
                        store_open_ports.write(f"{target}:{port} => OPEN\n")
                    print(colored(f"{target}:{port} => OPEN", 'green'))
                    open_ports.append(port)
                elif args.verbose:  # Print closed ports if verbosity is enabled
                    print(colored(f"{target}:{port} => CLOSED", 'yellow'))

        print(colored(f"\n{"-" * 50}\nScan Summary\n{"-" * 50}\n", 'magenta'))
        print(colored(f"Total Open Ports: {len(open_ports)}", 'cyan'))
        print(colored(f"Open Ports: {open_ports if open_ports else 'None found'}", 'cyan'))

    except KeyboardInterrupt:
        print(colored("\n <- Keyboard Interruption - Terminating scan ->", "red"))
        exit_program()
    except socket.gaierror:
        print(colored(" ! Host name could not be resolved! ", "red"))
        exit_program()
    except socket.error as e:
        print(colored(f" ! Could not connect to host/ip {target}: {e}", "red"))
        exit_program()


if __name__ == '__main__':
    start_time = dt.now()
    print(colored("Time started: " + str(start_time), 'blue'))

    args = get_arguments()
    target = args.HOST

    # Set default port range to top 100 ports
    if args.PORTS:
        ports = args.PORTS
        if "-" in ports:
            port_start, port_end = map(int, ports.split("-"))
        else:
            port_start = int(ports)
            port_end = port_start
    else:
        port_start, port_end = min(TOP_PORTS), max(TOP_PORTS)  # Default to top ports

    # Check the start and end port values
    if port_start > port_end:
        port_start, port_end = port_end, port_start

    # Debugging outputs for the port range
    print(colored(f"Scanning ports from {port_start} to {port_end}", 'yellow'))

    # Handle output file
    output_file = args.OUTPUT
    store_open_ports = open(f"{output_file}", "a") if output_file else None

    display_conf_data()
    open_ports = []

    find_open_ports()

    if store_open_ports:
        store_open_ports.close()  # Close the output file if it was opened

    end_time = dt.now()
    total_time = end_time - start_time
    print(colored(f"\nScanning completed in {total_time}", 'blue'))
    print(colored("=" * 35, 'blue'))
    exit_program()
