#!/usr/bin/env python3
import concurrent
import subprocess
import ipaddress
import argparse
import re
from itertools import chain
from concurrent.futures import ThreadPoolExecutor
import json
import xml.etree.ElementTree as ET
from threading import Lock
import os

# Scan options
SCAN_TYPES = {
    "default": "-sV -p- -T4",
    "OS": "-sV -p- -O -T4",
    "stealth": "-p- -sS -Pn -T2",
    "balanced": "-p- -sV -T3",
    "aggressive": "-p- -A -T4",
    "quick": "-sV --top-ports 1000 -T4",
    "custom": None  # User will provide the complete Nmap command
}

def process_scan_results(result):
    scan_data = {
        "open_ports": [],
        "service_versions": [],
        "os_detection": None,
        "notes": []
    }

    # Parsing Open Ports and Services
    open_ports = re.findall(r'(\d+/tcp)\s+open\s+([\w-]+)', result)
    for port, service in open_ports:
        scan_data["open_ports"].append({"port": port, "service": service, "status": "Open"})

    # Parsing Service Versions (if available)
    service_versions = re.findall(r'(\d+/tcp)\s+open\s+[\w-]+\s+(.+)', result)
    for port, version in service_versions:
        scan_data["service_versions"].append({"port": port, "version": version})

    # Parsing OS Detection (if available)
    os_detection = re.search(r'OS details: (.+)', result)
    if os_detection:
        scan_data["os_detection"] = os_detection.group(1)

    # Adding Notes
    scan_data["notes"].append("An open port indicates a network service running on the machine, which could be a point of interest for further analysis.")
    scan_data["notes"].append("Nmap version detection is not always accurate.")
    scan_data["notes"].append("Nmap OS detection is not always accurate.")

    return scan_data

def format_json(scan_data):
    return json.dumps(scan_data, indent=4)

def format_xml(scan_data):
    root = ET.Element("ScanResults")

    def add_elements(parent, elements, tag_name):
        for element in elements:
            child = ET.SubElement(parent, tag_name)
            for key, value in element.items():
                child.set(key, value)

    if scan_data["open_ports"]:
        add_elements(root, scan_data["open_ports"], "OpenPort")

    if scan_data["service_versions"]:
        add_elements(root, scan_data["service_versions"], "ServiceVersion")

    if scan_data["os_detection"]:
        os_det = ET.SubElement(root, "OSDetection")
        os_det.text = scan_data["os_detection"]

    if scan_data["notes"]:
        notes = ET.SubElement(root, "Notes")
        for note in scan_data["notes"]:
            note_elem = ET.SubElement(notes, "Note")
            note_elem.text = note

    return ET.tostring(root, encoding='unicode', method='xml')

def validate_ip(ip):
    try:
        return list(ipaddress.ip_network(ip, strict=False).hosts())
    except ValueError:
        return []

def validate_ports(ports_str):
    ports = ports_str.split(',')
    for port in ports:
        if not port.isdigit() or not 0 < int(port) <= 65535:
            return False
    return True

def positive_int(value):
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(f"{value} is an invalid positive int value")
    return ivalue

def save_quick_scan_command(command):
    with open("quick_scan_command.txt", "w") as file:
        file.write(command)

def load_quick_scan_command():
    if os.path.exists("quick_scan_command.txt"):
        with open("quick_scan_command.txt", "r") as file:
            return file.read().strip()
    else:
        return None

def read_ips_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def format_output(result):
    formatted_result = []
    open_ports_detected = False
    service_versions_detected = False
    os_detection_detected = False

    # Headers and Separators
    sep = "--------------------------------------------------------------------------------"
    header_open_ports = "Open Ports and Services:"
    header_service_versions = "Service Versions:"
    header_os_detection = "Operating System Detection:"
    header_notes = "Notes:"

    # Parsing Open Ports and Services
    open_ports = re.findall(r'(\d+/tcp)\s+open\s+([\w-]+)', result)
    if open_ports:
        open_ports_detected = True
        open_ports_info = ["  Port     Service       Status"]
        for port, service in open_ports:
            open_ports_info.append(f"  {port:<8} {service:<12} Open")
        formatted_result.append(sep)
        formatted_result.append(header_open_ports)
        formatted_result.append(sep)
        formatted_result.extend(open_ports_info)

    # Parsing Service Versions (if available)
    service_versions = re.findall(r'(\d+/tcp)\s+open\s+[\w-]+\s+(.+)', result)
    if service_versions:
        service_versions_detected = True
        service_versions_info = ["  Port     Service Version"]
        for port, version in service_versions:
            service_versions_info.append(f"  {port:<8} {version}")
        formatted_result.append(sep)
        formatted_result.append(header_service_versions)
        formatted_result.append(sep)
        formatted_result.extend(service_versions_info)

    # Parsing OS Detection (if available)
    os_detection = re.search(r'OS details: (.+)', result)
    if os_detection:
        os_detection_detected = True
        formatted_result.append(sep)
        formatted_result.append(header_os_detection)
        formatted_result.append(sep)
        formatted_result.append(f"  OS Details: {os_detection.group(1)}")

    # Adding Notes
    formatted_result.append(sep)
    formatted_result.append(header_notes)
    formatted_result.append(sep)
    if open_ports_detected:
        formatted_result.append("An open port indicates a network service running on the machine, which could be a point of interest for further analysis.")
    if service_versions_detected:
        formatted_result.append("Nmap was able to detect a service. Nmap version detection is not always accurate.")
    if os_detection_detected:
        formatted_result.append("Nmap was able to detect an operating system. Nmap OS detection is not always accurate.")

    return '\n'.join(formatted_result) if formatted_result else "No significant findings or Nmap output was not in a recognized format."

def scan_ip(ip, options, output_file_handles, lock, ports=None, debug_mode=False, timeout=12000):
    print(f"Scanning {ip} with options: {options}")
    ip_str = str(ip)
    command = ["nmap"] + options.split()
    if ports:
        command += ['-p', ports]
    command += [ip_str]

    print("Executing command:", ' '.join(command))

    try:
        adjusted_timeout = timeout if '-A' not in options else max(timeout, 24000)  # Increase timeout for aggressive scan
        result = subprocess.check_output(command, timeout=adjusted_timeout).decode()

        if debug_mode:
            print("Raw Nmap Output:\n", result)

        scan_data = process_scan_results(result)
        console_output = format_output(result)
        print(console_output)

        if output_file_handles:
            with lock:
                for fmt in output_file_handles.keys():
                    if fmt == 'json':
                        formatted_result = format_json(scan_data)
                    elif fmt == 'xml':
                        formatted_result = format_xml(scan_data)
                    else:
                        formatted_result = console_output

                    output_file_handles[fmt].write(formatted_result + "\n")
                    output_file_handles[fmt].flush()

    except subprocess.CalledProcessError as e:
        print(f"Nmap scan failed for {ip}. Error: {e}")
    except subprocess.TimeoutExpired:
        print(f"Scan for {ip} timed out after {adjusted_timeout} seconds. Consider scanning fewer ports or increasing the timeout.")
    except Exception as e:
        print(f"An unexpected error occurred while scanning {ip}: {e}")

def interactive_mode():
    global SCAN_TYPES
    ip_input = input("Enter IP/CIDR to scan: ")
    ips = validate_ip(ip_input)
    if not ips:
        print("Invalid IP address or CIDR notation.")
        return

    custom_ports_choice = input("Would you like to enter custom ports to scan? (Y/N): ").lower()
    ports = None
    if custom_ports_choice == 'y':
        ports = input("Enter custom ports to scan (comma-separated): ")
        if not validate_ports(ports):
            print("Invalid ports format. Ports must be a comma-separated list of numbers.")
            return
        for key in SCAN_TYPES:
            if SCAN_TYPES[key]:
                SCAN_TYPES[key] = SCAN_TYPES[key].replace("-p- ", "")

    timeout = 12000
    custom_timeout_choice = input(f"Would you like to enter a custom timeout value default={timeout}? (Y/N): ").lower()
    if custom_timeout_choice == 'y':
        timeout_input = input("Enter custom timeout value in seconds: ")
        if timeout_input.isdigit():
            timeout = int(timeout_input)

    save_output = input("Would you like to save the output to a file? (Y/N): ").lower()
    output_file = None
    output_format = "text"
    if save_output == 'y':
        output_file = input("Enter output file name (without extension): ")
        print("Choose output format:")
        print("1. Text")
        print("2. JSON")
        print("3. XML")
        print("4. All formats")
        format_choice = input("Choice (1-4): ")
        format_options = {"1": "text", "2": "json", "3": "xml", "4": "all"}
        output_format = format_options.get(format_choice, "text")

    print("Select scan type")
    for i, (scan_type, options) in enumerate(SCAN_TYPES.items(), start=1):
        print(f"{i}. {scan_type.title()} (nmap {options} <target>)")

    choice = int(input(f"Choice (1-{len(SCAN_TYPES)}): "))
    if choice not in range(1, len(SCAN_TYPES) + 1):
        print(f"Invalid choice. Please select a number between 1 and {len(SCAN_TYPES)}.")
        return
    scan_type = list(SCAN_TYPES.keys())[choice - 1]

    thread_count = input("Enter number of threads (optional, default=1, max=10): ")
    if thread_count.strip().isdigit():
        thread_count = int(thread_count)
        if not 1 <= thread_count <= 10:
            print("Invalid thread count. Please enter a number between 1 and 10.")
            return
    else:
        thread_count = 1

    string_ips = [str(ip) for ip in ips]
    run_nmap_scan(string_ips, SCAN_TYPES[scan_type], output_file, thread_count, ports, output_format, timeout)

def display_help():
    print("=========================================================================================")
    print("                                     SweetScan                                          ")
    print("=========================================================================================")
    print()
    print("Usage:")
    print("  python3 SweetScan.py [options]")
    print()
    print("Options:")
    print("  -i, --interactive           Interactive mode")
    print("  -m [IP/CIDR]                IP address(es) or CIDR(s) to scan")
    print("  -t, --type [SCAN_TYPE]      Type of scan to perform (default, OS, stealth, balanced, aggressive, quick, custom)")
    print("  -o, --output [FILE]         Output file to save scan results")
    print("  -h, --help                  Show this help message and exit")
    print("  -p, --ports [PORTS]         Specify custom ports (comma-separated, no spaces) e.g., 80,443,8080")
    print("  -threads [THREADS]          Number of parallel scan threads (default: 1, max: 10)")
    print("  -timeout [SECONDS]          Custom timeout in seconds (default: 12000)")
    print("  -ipf, --ipfile [FILE]       File containing IP addresses or CIDR blocks to scan")
    print("  -q, --quick [COMMAND]       Quick scan with saved command")
    print()
    print("Examples:")
    print("  Interactive mode:")
    print("    python3 SweetScan.py -i")
    print()
    print("  Scan a single IP with default options:")
    print("    python3 SweetScan.py -m 192.168.1.1 -t default -o scan_results.txt")
    print()
    print("  Quick scan with a saved command:")
    print("    python3 SweetScan.py -q 192.168.1.1")
    print("=========================================================================================")

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()

def run_nmap_scan(ips, options, output_file, threads, ports=None, output_format="text", timeout=12000):
    output_file_handles = {}
    file_write_lock = Lock()
    if output_file:
        if output_format == "all":
            formats = ["text", "json", "xml"]
        else:
            formats = [output_format]

        for fmt in formats:
            file_extension = ".txt" if fmt == 'text' else ".json" if fmt == 'json' else ".xml"
            output_file_handles[fmt] = open(f"{output_file}{file_extension}", "w")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_ip, ip, options, output_file_handles, file_write_lock, ports, timeout=timeout): ip for ip in ips}
        try:
            for future in concurrent.futures.as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            print("\nScan interrupted. Terminating running scans...")
            executor.shutdown(wait=False)
            raise

    for f in output_file_handles.values():
        f.close()

def is_nmap_installed():
    try:
        subprocess.check_output(["nmap", "-v"])
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def main():
    try:
        parser = argparse.ArgumentParser(description='SweetScan: A user-friendly network scanning tool.', add_help=False)
        parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
        parser.add_argument('-m', nargs='*', help='IP address(es) or CIDR(s) to scan', default=None)
        parser.add_argument('-t', '--type', choices=SCAN_TYPES.keys(), default='default', help='Type of scan to perform')
        parser.add_argument('-o', '--output', help='Output file to save scan results')
        parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit.')
        parser.add_argument('-p', '--ports', help='Specify custom ports (comma-separated, no spaces) e.g., 80,443,8080')
        parser.add_argument('-threads', '--threads', type=int, default=1, help='Number of parallel scan threads')
        parser.add_argument('-timeout', '--timeout', type=int, default=12000, help='Custom timeout in seconds')
        parser.add_argument('-ipf', '--ipfile', help='File containing IP addresses or CIDR blocks to scan')
        parser.add_argument('-q', '--quick', nargs='*', help='Quick scan with saved command')

        args = parser.parse_args()

        if not is_nmap_installed():
            print("Nmap is not installed or not found in PATH.")
            return

        if args.quick:
            if args.quick[0] == "set":
                save_quick_scan_command(' '.join(args.quick[1:]))
                print("Custom command saved for quick scans.")
                return
            else:
                quick_command = load_quick_scan_command()
                if quick_command:
                    ips = []
                    if args.ipfile:
                        ips_from_file = read_ips_from_file(args.ipfile)
                        for ip in ips_from_file:
                            validated_ips = validate_ip(ip)
                            if validated_ips:
                                run_nmap_scan(validated_ips, SCAN_TYPES[args.type], args.output, args.threads,
                                              args.ports, "text", args.timeout)
                            else:
                                print(f"Invalid IP address or CIDR: {ip}")
                        print("Scanning of all IPs from file completed.")
                        return
                    elif args.quick:
                        ips = validate_ip(' '.join(args.quick))
                        if not ips:
                            print("Invalid IP address or CIDR for quick scan.")
                            return

                    if not ips:
                        print("No targets specified for quick scan. Use an IP/CIDR or -ipf with a file.")
                        return
                    else:
                        run_nmap_scan(ips, quick_command, args.output, args.threads, None, "text", args.timeout)
                else:
                    print("No custom command saved for quick scans.")
                return

        if args.interactive:
            interactive_mode()
            return

        if args.help:
            display_help()
            return

        ips = []
        if args.ipfile:
            ips = read_ips_from_file(args.ipfile)
        if args.m:
            ips.extend(validate_ip(' '.join(args.m)))

        if not ips:
            print("No valid targets were specified, so 0 hosts scanned.")
            return

        if args.type == 'custom':
            custom_options = "-p " + args.ports if args.ports else input("Enter custom Nmap switches: ")
            run_nmap_scan(ips, custom_options, args.output, args.threads, args.timeout)
        else:
            run_nmap_scan(ips, SCAN_TYPES[args.type], args.output, args.threads, args.timeout)

    except KeyboardInterrupt:
        print("\nExecution interrupted by the user. Exiting. Good Bye.")

if __name__ == "__main__":
    main()
