# SSCAMIKO - SSH Security Scanner

![SSCAMIKO](https://github.com/user-attachments/assets/91d3ded0-c82b-4fbe-becd-48f2f4819310)

## Overview
SSCAMIKO is a professional and user-friendly tool designed for cybersecurity specialists to analyze and secure SSH services. This tool provides advanced capabilities such as:

- IP reachability checks via ICMP packets.
- Port scanning with SYN packets.
- Sending RST packets to close specific ports.
- SSH brute-force attacks.
- Multi-threaded port scanning for enhanced efficiency.
- Detailed logging for tracking actions and analyzing results.

The program is fully compatible with **Kali Linux**.

## Features
- **ICMP Ping**: Verify if a target IP is reachable.
- **Port Scanning**: Check if specific ports are open or closed.
- **Close Ports**: Send RST packets to terminate open connections.
- **SSH Brute Force**: Test credentials to evaluate SSH security.
- **Threading**: Multi-threaded port scanning for faster results.
- **Logging**: Records all actions and results in `sscamiko.log`.

## Installation
To install and run SSCAMIKO on Kali Linux, follow these steps:

1. **Update the system and install Python3**:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip -y
   ```

2. **Install required Python libraries**:
   ```bash
   pip3 install scapy paramiko termcolor
   ```

3. **Download SSCAMIKO**:
   Clone the repository:
   ```bash
   git clone https://github.com/Skinnygoat/SScamiko.git
   cd SScamiko
   ```

4. **Run SSCAMIKO**:
   Execute the program with root privileges:
   ```bash
   sudo python3 main.py
   ```

## Usage
1. **Start the program**:
   ```
   ==============================================
   SSCAMIKO - SSH Security Scanner
   ==============================================
   Compatible with Kali Linux.
   ```

2. **Check IP availability**:
   ```
   Enter target IP address: 192.168.1.1
   [+] Target 192.168.1.1 is reachable.
   ```

3. **Scan ports**:
   ```
   Enter starting port: 20
   Enter ending port: 25
   [+] Port 22 is open.
   [-] Port 21 is closed.
   ```

4. **Actions Menu**:
   - Close a port:
     ```
     Choose an action:
     1. Close a port
     2. Brute-force SSH
     3. Exit
     > 1
     Enter port to close: 22
     [+] Port 22 successfully closed.
     ```
   - Brute-force SSH:
     ```
     Choose an action:
     1. Close a port
     2. Brute-force SSH
     3. Exit
     > 2
     Enter SSH username: admin
     Enter SSH password: admin123
     [-] Authentication failed for admin:admin123
     ```

5. **Exit**:
   ```
   Choose an action:
   1. Close a port
   2. Brute-force SSH
   3. Exit
   > 3
   Exiting SSCAMIKO.
   ```

## Requirements
- **Operating System**: Kali Linux
- **Python Version**: Python 3.6+
- **Dependencies**:
  - `scapy`: For network packet manipulation.
  - `paramiko`: For SSH brute-force operations.
  - `termcolor`: For colored console output.

## Logging
All actions and errors are logged in `sscamiko.log`. Logs include timestamps, action types, and results for later analysis.

## Disclaimer
SSCAMIKO is intended for educational and ethical penetration testing purposes only. The author is not responsible for any misuse or illegal activities conducted using this tool.

## Contribution
Feel free to contribute to this project by creating pull requests or submitting issues via the [GitHub repository](https://github.com/Skinnygoat/SScamiko).
