# Intrusion Detection System (IDS)

## Overview

This Intrusion Detection System (IDS) script is designed to capture and analyze network traffic using Tshark. It serves as a security monitoring tool to detect suspicious activity and potential threats on a network.

## Requirements

- Linux operating system
- Bash shell
- Tshark (Wireshark command-line utility)
- Go programming language (for certain features)
- VirusTotal CLI (vt-cli) for file analysis (optional)

## Usage

1. **Download the Script**: Clone or download the IDS script to your local machine.

2. **Navigate to the Directory**: Open a terminal window and navigate to the directory containing the IDS script.

3. **Make the Script Executable**: If necessary, make the script executable by running the following command:
   ```bash
   chmod +x IDS.sh

Run the Script: Execute the script by running the following command:

./IDS.sh


Description

The IDS script performs the following tasks:

Installs necessary dependencies such as Tshark, Go, and VirusTotal CLI.
Creates a main directory named "IDS" for storing captured data and analysis results.
Downloads an IP list from a specified URL and configures Tshark to capture network traffic based on the IP addresses in the list.
Captures network traffic to a log file named "Log.pcap" and an alerts file named "Alerts.txt".
Extracts files from the captured network traffic for further analysis.
Conducts file analysis using the VirusTotal CLI if available, and logs the results in a file named "log_file.txt".
Note
This script must be run without using sudo privileges. Running it with sudo may cause issues with file permissions and execution.
Ensure that the necessary dependencies are installed and configured properly before running the script.



