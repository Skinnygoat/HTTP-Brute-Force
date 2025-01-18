# Libraries
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
import paramiko
import time
import logging
from threading import Thread
from termcolor import colored

# Configure logging
logging.basicConfig(
    filename='sscamiko.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Function to check IP reachability
def check_ip(ip):
    """Check if the target IP address is reachable via ICMP."""
    try:
        conf.verb = 0
        icmp_pkt = IP(dst=ip) / ICMP()
        response = sr1(icmp_pkt, timeout=1, verbose=0)
        if response:
            logging.info(f"Target {ip} is reachable.")
            print(colored(f"[+] Target {ip} is reachable.", 'green'))
            return True
        else:
            logging.warning(f"Target {ip} is unreachable.")
            print(colored(f"[-] Target {ip} is unreachable.", 'yellow'))
            return False
    except Exception as e:
        logging.error(f"Error checking IP {ip}: {e}")
        print(colored(f"[!] Error checking IP {ip}: {e}", 'red'))
        return False

# Function to scan a specific port
def scan_port(ip, port):
    """Scan a specific port on the target IP using SYN packets."""
    try:
        src_port = RandShort()
        conf.verb = 0
        syn_pkt = sr1(IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S"), timeout=1, verbose=0)
        if syn_pkt and syn_pkt.haslayer(TCP) and syn_pkt.getlayer(TCP).flags == 0x12:
            logging.info(f"Port {port} is open on {ip}.")
            print(colored(f"[+] Port {port} is open.", 'green'))
            return True
        else:
            logging.warning(f"Port {port} is closed on {ip}.")
            print(colored(f"[-] Port {port} is closed.", 'yellow'))
            return False
    except Exception as e:
        logging.error(f"Error scanning port {port} on {ip}: {e}")
        print(colored(f"[!] Error scanning port {port} on {ip}: {e}", 'red'))
        return False

# Function to send RST packet to close a port
def close_port(ip, port):
    """Send RST packet to close a specific port."""
    try:
        src_port = RandShort()
        conf.verb = 0
        rst_pkt = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="R")
        send(rst_pkt, verbose=0)
        logging.info(f"RST packet sent to close port {port} on {ip}.")
        print(colored(f"[+] Port {port} successfully closed.", 'green'))
        return True
    except Exception as e:
        logging.error(f"Error closing port {port} on {ip}: {e}")
        print(colored(f"[!] Error closing port {port} on {ip}: {e}", 'red'))
        return False

# Function for SSH brute force
def brute_force_ssh(ip, port, username, password):
    """Attempt to brute-force SSH credentials on the target."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=port, username=username, password=password, timeout=5)
        logging.info(f"Success: Username: {username}, Password: {password}")
        print(colored(f"[+] Success: Username: {username}, Password: {password}", 'green', attrs=['bold']))
        client.close()
        return True
    except paramiko.AuthenticationException:
        logging.warning(f"Authentication failed for {username}:{password}")
        print(colored(f"[-] Authentication failed for {username}:{password}", 'yellow'))
        return False
    except Exception as e:
        logging.error(f"Error during SSH brute force: {e}")
        print(colored(f"[!] Error during SSH brute force: {e}", 'red'))
        return False

# Function to handle multi-threaded port scanning
def threaded_port_scan(ip, ports):
    """Scan ports using multiple threads."""
    def worker(port):
        scan_port(ip, port)

    threads = []
    for port in ports:
        thread = Thread(target=worker, args=(port,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

# Main function
def main():
    print(colored("""
    ==============================================
    SSCAMIKO - SSH Security Scanner
    ==============================================
    Compatible with Kali Linux.
    """, 'cyan', attrs=['bold']))

    target_ip = input(colored("Enter target IP address: ", 'blue'))
    if not check_ip(target_ip):
        return

    min_port = int(input(colored("Enter starting port: ", 'blue')))
    max_port = int(input(colored("Enter ending port: ", 'blue')))
    ports = range(min_port, max_port + 1)

    threaded_port_scan(target_ip, ports)

    while True:
        action = input(colored("\nChoose an action:\n1. Close a port\n2. Brute-force SSH\n3. Exit\n> ", 'blue'))
        if action == "1":
            port_to_close = int(input(colored("Enter port to close: ", 'blue')))
            close_port(target_ip, port_to_close)
        elif action == "2":
            username = input(colored("Enter SSH username: ", 'blue'))
            password = input(colored("Enter SSH password: ", 'blue'))
            brute_force_ssh(target_ip, 22, username, password)
        elif action == "3":
            print(colored("Exiting SSCAMIKO.", 'cyan', attrs=['bold']))
            break
        else:
            print(colored("Invalid choice. Please try again.", 'red'))

if __name__ == "__main__":
    main()
