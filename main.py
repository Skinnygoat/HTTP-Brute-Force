# Libraries.
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
import paramiko
import time


# Definitions. Check if Target is available.
def check_ip(ip):
    # Check that the Target is reachable.
    try:
        # Verbose configuration.
        conf.verb = 0
        # ICMP packet. Ping.
        icmp_pkt = IP(dst=ip) / ICMP()
        # Ping.
        if icmp_pkt is not None:
            # Print result.
            print(f"\n[+] Target {ip} is available.")
            # Send ICMP packet.
            print(f"[+] Sending ICMP packet to {ip}...\n"
                  f"{print(send(icmp_pkt, verbose=0))}")
            # Check if packet was sent successfully and received.
            icmp_result = icmp_pkt.show()
            # Print result.
            print("[+] ICMP result:"
                  f"\n{icmp_result}")
            # Return value.
            return True
    # Error handling.
    except Exception as error:
        # Print error.
        print(f"\n[-] Target {ip} is unreachable."
              f"\n[-] Error: {error}")
        # Return value.
        return False


# Definitions. Scan port with SYN/ACK packets.
def scan_port(port):
    # Source port. Generate random port from 1 to 65535.
    src_port = RandShort()
    # Verbose configuration.
    conf.verb = 0
    # Packets.
    syn_pkt = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S"), timeout=0.5)
    # Scan for open ports. Check all possible ports, flags and layers.
    if syn_pkt is not None:
        # Print results.
        print(f"[+] Port {port} is open.")
        # Check if packet in open port has TCP layers.
        if syn_pkt.haslayer(TCP):
            # Print results.
            print(f"[+] Port {port} has TCP layer.")
            # Check if TCP layer has SYN flag.
            if syn_pkt.getlayer(TCP).flags == "SA":
                # Print results.
                print(f"[+] Port {port} has 'SA' flag.")
                # Check all possible .flags values.
                if syn_pkt.getlayer(TCP).flags == 0x2:
                    # Print results.
                    print(f"[+] Port {port} has SYN flag.\n")
                    # Return value.
                    return True
                elif syn_pkt.getlayer(TCP).flags == 0x10:
                    # Print results.
                    print(f"[+] Port {port} has ACK flag.\n")
                    # Return value.
                    return True
                elif syn_pkt.getlayer(TCP).flags == 0x12:
                    # Print results.
                    print(f"[+] Port {port} has SYN/ACK flag.\n")
                    # Return value.
                    return True
                else:
                    # Print results.
                    print(f"[-] Port {port} does not have SYN, ACK or SYN/ACK flag.\n")
                    # Return value.
                    return False
            else:
                # Print results.
                print(f"[-] Port {port} does not have 'SA' flag.\n")
                # Return value.
                return False
        else:
            # Print results.
            print(f"[-] Port {port} does not have TCP layer.\n")
            # Return value.
            return False
    else:
        # Print results.
        print(f"[-] Port {port} is closed.\n")
        # Return value.
        return False


# Definitions. Close connection with RST packet.
def close_port(port):
    # Source port. Generate random port from 1 to 65535.
    src_port = RandShort()
    # Verbose configuration.
    conf.verb = 0
    # Packets.
    syn_pkt = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S"), timeout=0.5)
    # Scan for open ports. Check all possible ports, flags and layers.
    if syn_pkt is not None:
        # Print results.
        print(f"[+] Port {port} is open.")
        # Check if packet in open port has TCP layers.
        if syn_pkt.haslayer(TCP):
            # Print results.
            print(f"[+] Port {port} has TCP layer.")
            # Check if TCP layer has SYN flag.
            if syn_pkt.getlayer(TCP).flags == "SA":
                # Print results.
                print(f"[+] Port {port} has 'SA' flag.")
                # Check all possible .flags values.
                if syn_pkt.getlayer(TCP).flags == 0x2:
                    # Print results.
                    print(f"[+] Port {port} has SYN flag.")
                    # RST packet.
                    rst_pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="R")
                    # Send RST packet to close port.
                    send(rst_pkt, verbose=0)
                    # Print results.
                    print(f"[+] Port {port} successfully closed.\n")
                    # Return value.
                    return True
                elif syn_pkt.getlayer(TCP).flags == 0x10:
                    # Print results.
                    print(f"[+] Port {port} has ACK flag.")
                    # RST packet.
                    rst_pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="R")
                    # Send RST packet to close port.
                    send(rst_pkt, verbose=0)
                    # Print results.
                    print(f"[+] Port {port} successfully closed.\n")
                    # Return value.
                    return True
                elif syn_pkt.getlayer(TCP).flags == 0x12:
                    # Print results.
                    print(f"[+] Port {port} has SYN/ACK flag.")
                    # RST packet.
                    rst_pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="R")
                    # Send RST packet to close port.
                    send(rst_pkt, verbose=0)
                    # Print results.
                    print(f"[+] Port {port} successfully closed.\n")
                    # Return value.
                    return True
                else:
                    # Print results.
                    print(f"[-] Port {port} does not have SYN, ACK or SYN/ACK flag.\n")
                    # Return value.
                    return False
            else:
                # Print results.
                print(f"[-] Port {port} does not have 'SA' flag.\n")
                # Return value.
                return False
        else:
            # Print results.
            print(f"[-] Port {port} does not have TCP layer.\n")
            # Return value.
            return False
    else:
        # Print results.
        print(f"[-] Port {port} is closed.\n")
        # Return value.
        return False


# Definitions. Brute force function.
def brute_force():



# Call Main Function.
if __name__ == "__main__":
    # Print welcome message and additional information.
    print("\n=================================================="
          "\nFINAL PROJECT"
          "\n=================================================="
          "\nInformation:"
          "\n=> For the sake of the project choose port range from 1-1023!"
          "\n==================================================")
    # Inputs.
    target_ip = input("\nEnter Target IP address: ")
    min_port = int(input("\nEnter min port: "))
    max_port = int(input("\nEnter max port: "))
    # Verbose configuration.
    conf.verb = 0
    # Variables.
    reg_ports = range(min_port, max_port + 1)
    open_ports = []
    close_ports = []
    # Print all values.
    print(f"\nTarget IP address: {target_ip}"
          f"\nMin port: {min_port}"
          f"\nMax port: {max_port}")
    # While loop.
    while True:
        # First Menu.
        first_menu = input("\n=================================================="
                           "\nMain Menu:"
                           "\n[1] Check Target availability and send ICMP packet."
                           "\n[2] Quit."
                           "\nEnter your choice: ")
        print("==================================================")
        # Choice 1.
        if first_menu == "1":
            # Call check_ip function.
            if check_ip(target_ip):
                # While loop.
                while True:
                    # Second Menu.
                    second_menu = input("\n=================================================="
                                        "\nMain Menu:"
                                        "\n[1] Scan the Target."
                                        "\n[2] Quit."
                                        "\nEnter your choice: ")
                    print("==================================================")
                    # Choice 1.
                    if second_menu == "1":
                        # For in statements. Checking all ports.
                        for port in reg_ports:
                            # Call scan_port function.
                            if scan_port(port):
                                # Add port to list.
                                open_ports.append(port)
                            else:
                                # Add port to list.
                                close_ports.append(port)
                        # Print results.
                        print("All open ports:"
                              f"\n{open_ports}")
                        print("\nAll close ports:"
                              f"\n{close_ports}")
                        # While loop.
                        while True:
                            # Third Menu.
                            third_menu = input("\n=================================================="
                                               "\nMain Menu:"
                                               "\n[1] Scan and send RST packet to the Target."
                                               "\n[2] Brute force the Target."
                                               "\n[3] Quit."
                                               "\nEnter your choice: ")
                            print("==================================================")
                            # Verbose configuration.
                            conf.verb = 0
                            # Variables.
                            closed_ports = []
                            closed_ports_by_rst_pkt = []
                            # Choice 1.
                            if third_menu == "1":
                                # For in statements. Closing active connection.
                                for port in reg_ports:
                                    # Call close_port function.
                                    if close_port(port):
                                        # Add port to list.
                                        closed_ports_by_rst_pkt.append(port)
                                    else:
                                        # Add port to list.
                                        closed_ports.append(port)
                                # Print results.
                                print("Closed ports without sending a packet:"
                                      f"\n{closed_ports}")
                                print("\nClosed ports by RST packet:"
                                      f"\n{closed_ports_by_rst_pkt}")
                            # Choice 3.
                            elif third_menu == "3":
                                # Print results.
                                print("\n[+] Quitting...")
                                # Break loop.
                                break
                            # Error handling.
                            else:
                                # Print error message.
                                print("\n[-] Invalid choice!")
                                continue
                            # Break loop.
                            break
                    # Choice 2.
                    elif second_menu == "2":
                        # Print results.
                        print("\n[+] Quitting...")
                        break
                    # Error handling.
                    else:
                        # Print error message.
                        print("\n[-] Invalid choice!")
                        continue
                    # Break loop.
                    break
            # Error handling.
            else:
                # Print error message.
                print("\n[-] Something went wrong! Invalid IP address or Target is not available.")
                continue
        # Choice 2.
        elif first_menu == "2":
            # Print results
            print("\n[+] Quitting...")
            break
        # Error handling.
        else:
            # Print error message.
            print("\n[-] Invalid choice!")
            continue
