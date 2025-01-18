# SSCAMIKO - SSH Security Scanner

## Overview
SSCAMIKO is a versatile tool designed for cybersecurity specialists. It provides advanced capabilities to analyze and secure SSH services. The tool is fully compatible with **Kali Linux** and offers functionalities such as:

- IP reachability check via ICMP packets
- Port scanning with SYN packets
- SSH brute-force attacks
- Detailed logging for analysis and debugging

## Features
- **ICMP Ping**: Check if a target IP address is reachable.
- **Port Scanning**: Identify open and closed ports using SYN packets.
- **SSH Brute Force**: Test credentials to assess SSH security.
- **Cross-platform Support**: Fully optimized for Kali Linux environments.

## Installation
To install and run SSCAMIKO, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/Skinnygoat/SScamiko.git
   cd SScamiko
   ```
2. Install dependencies:
   ```bash
   sudo apt update && sudo apt install python3-pip
   pip3 install -r requirements.txt
   ```
3. Run the tool:
   ```bash
   python3 main.py
   ```

## Usage
### 1. Check Target IP Reachability
```bash
Enter target IP address: 192.168.1.1
[+] Target 192.168.1.1 is reachable.
```

### 2. Scan for Open Ports
```bash
Enter port to scan (default SSH port is 22): 22
[+] Port 22 is open.
```

### 3. Perform SSH Brute Force
```bash
Enter SSH username: admin
Enter SSH password: admin123
[-] Authentication failed for admin:admin123
```

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer
**SSCAMIKO** is intended for educational and ethical penetration testing purposes only. The author is not responsible for any misuse or illegal activities conducted with this tool.

## Future Enhancements
- Multi-threaded brute force capabilities
- Integration with advanced logging systems
- Support for additional SSH protocols

For contributions and feedback, please create an issue or submit a pull request via the [GitHub repository](https://github.com/Skinnygoat/SScamiko).
