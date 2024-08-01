# SweetScan

SweetScan is a user-friendly network scanning tool that leverages the power of `nmap` to perform detailed network scans. It aims to simplify the use of `nmap` by providing a set of predefined scan types, multi-threaded scanning, and options for output formatting.

## Features

- **Predefined Scan Types**: Choose from several predefined scan options or provide custom `nmap` commands.
- **Multi-threaded Scanning**: Perform concurrent scans to improve efficiency.
- **Output Formats**: Export scan results in JSON, XML, or human-readable text.
- **Interactive Mode**: Guided setup for users unfamiliar with command-line arguments.
- **Quick Scan Commands**: Save and reuse custom scan commands.

## Prereq

- Python 3.x
- nmap

## Setup and Usage

1. **Clone the repository:**
    ```sh
    git clone https://github.com/dkhan25/SweetScan.git
    cd SweetScan
    ```

2. **Install dependencies:**

    SweetScan does not require external Python libraries beyond the standard library and `nmap` installation. Ensure Python and nmap are installed.

3. **Run the Application**

    ### Interactive Mode
    ```sh
    python3 SweetScan.py -i
    ```

    ### Command-Line Arguments

    Use various command-line arguments to specify scan options:
    ```sh
    python3 SweetScan.py -m <IP_ADDRESS> -t <SCAN_TYPE> -o <OUTPUT_FILE>
    ```

    #### Example:
    ```sh
    python3 SweetScan.py -m 192.168.1.1 -t default -o scan_results.txt
    ```

    ### Quick Scan

    Save a custom quick scan command:
    ```sh
    python3 SweetScan.py -q set <NMAP_COMMAND>
    ```

    Use the saved quick scan command:
    ```sh
    python3 SweetScan.py -q <IP_ADDRESS>
    ```

4. **Help Command**

    Use the help command to see all options:
    ```sh
    python3 SweetScan.py -h
    ```

## Scan Types

The following scan types are available:

- **default**: `-sV -p- -T4`
- **OS**: `-sV -p- -O -T4`
- **stealth**: `-p- -sS -Pn -T2`
- **balanced**: `-p- -sV -T3`
- **aggressive**: `-p- -A -T4`
- **quick**: `-sV --top-ports 1000 -T4`
- **custom**: User-provided `nmap` command

## Developed By

- **Developer**: dkhan25 (GitHub)
- **Contact**: [GitHub Profile](https://github.com/dkhan25)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
