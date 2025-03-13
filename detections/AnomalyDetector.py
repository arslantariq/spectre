import re
import requests
import argparse
import json
import dns.resolver
import socket
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import numpy as np
from prettytable import PrettyTable
from collections import Counter
from collections import defaultdict
from colorama import Fore, Style
from typing import List, Dict
from tabulate import tabulate
from PIL import Image
from io import BytesIO
import dns.reversename
import dns.resolver
import math
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

""" Following statements are required to add parent path to import parent folders"""
from inspect import getsourcefile
import os.path
import sys
current_path = os.path.abspath(getsourcefile(lambda:0))
current_dir = os.path.dirname(current_path)
parent_dir = current_dir[:current_dir.rfind(os.path.sep)]
sys.path.insert(0, parent_dir)
sys.path.insert(0, parent_dir + os.path.sep + "json")
from JsonModule import *

# ANSI escape sequences for colors
RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"

# Namespace: Detections
class Detections:
    # Parent Class
    class IPDetectionModule:
        """
        IPDetectionModule serves as the parent class responsible for coordinating
        detection of malicious IP addresses by utilizing methods from MaliciousIPDetector.
        """

        @staticmethod
        def detect_malicious_ips(ip_addresses, vt_api_key, compromisedIPs=set(), safeIPs=set(), whois_api_key=None, verbose=False, skip_plot=False):
            """
            Detects malicious IPs from a list of IP addresses.
            Calls VirusTotal and Spamhaus checks for each IP, and if an IP is found
            to be malicious, it performs a WHOIS lookup if the API key is provided.

            Args:
                ip_addresses (list): List of IP addresses to check.
                vt_api_key (str): VirusTotal API key.
                compromisedIPs(set, optional): Compromised IP addresses set.
                safeIPs(set, optional) : Safe IP addresses set
                whois_api_key (str, optional): WHOIS lookup API key. Defaults to None.
                verbose (bool, optional): If True, prints detailed WHOIS data. Defaults to False.
                skip_plot(bool, optional): If True, matplot is skipped, by default it is displayed.
            """
            # Initialize counter for benign and malicious IPs
            count = Counter({"benign": 0, "malicious": 0}) 
            
            vt_benign = set()
            vt_malicious = set()
            results = {}

            # Iterate over each IP in the provided list
            for ip in ip_addresses:
                
                if ip in compromisedIPs:
                    if verbose:
                        print(ip + " is compromised")
                    results[ip] = 'compromised'
                    continue
                    
                if ip in safeIPs:
                    if verbose:
                        print(ip + " is safe")
                    results[ip] = 'safe'
                    continue
                    
                # Call VirusTotal API to check the IP
                vt_result = Detections.MaliciousIPDetector.check_virustotal(ip.strip(), vt_api_key)
                # Check if IP is blacklisted in Spamhaus
                spamhaus_result = Detections.MaliciousIPDetector.check_spamhaus(ip.strip())

                # Display results for VirusTotal and Spamhaus checks
                result = Detections.MaliciousIPDetector.display_results(ip.strip(), vt_result, spamhaus_result)
                if verbose:
                    print("VT Result : " + str(result))
                
                results[ip] = str(result['malicious_indicators']) + ":" + str(result['total_indicators'])
                
                # If the IP is flagged as malicious by VirusTotal
                if vt_result.get('malicious', 0) > 0:
                    count["malicious"] += 1
                    vt_malicious.add(ip)
                    # Perform WHOIS lookup if the API key is provided
                    if whois_api_key:
                        domain = Detections.MaliciousIPDetector.ip_to_domain(ip.strip())
                        if domain:
                            Detections.MaliciousIPDetector.perform_whois_lookup(domain, whois_api_key, verbose)
                        else:
                            print(f"No domain found for IP: {ip.strip()}")
                    ip_info=Detections.MaliciousIPDetector.get_ip_info(ip)
                    # Print the output in a readable format
                    print("\nIP GetLocation Information:")
                    for key, value in ip_info.items():
                        print(f"{key}: {value}")
                
                else:
                    # Count as benign if no malicious activity is detected
                    count["benign"] += 1
                    vt_benign.add(ip)

            if not skip_plot:
                # Plot results for benign vs malicious IPs
                Detections.MaliciousIPDetector.plot_results(count)
            
            if verbose:
                print("Malicous IPs as per VirusTotal : " + str(vt_malicious))
                print("Non-malicous IPs as per VirusTotal : " + str(vt_benign))
                print(results)
                
            return results

    # Child Class
    class MaliciousIPDetector:
        """
        MaliciousIPDetector contains methods for checking an IP address for
        malicious activity using VirusTotal and Spamhaus, performing WHOIS lookups, 
        and displaying the results.
        """

        @staticmethod
        def check_virustotal(ip_address, api_key):
            """
            Checks the specified IP address against VirusTotal's database.

            Args:
                ip_address (str): The IP address to check.
                api_key (str): VirusTotal API key.

            Returns:
                dict: A dictionary containing the analysis results, including 
                the number of malicious reports and a permalink to the VirusTotal report.
            """
            # VirusTotal API URL for IP address information
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
            headers = {'x-apikey': api_key}

            try:
                # Send request to VirusTotal
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()

                # Parse response data to extract analysis statistics
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})

                return {
                    'malicious': last_analysis_stats.get('malicious', 0),
                    'total': last_analysis_stats.get('malicious', 0) + 
                             last_analysis_stats.get('harmless', 0) + 
                             last_analysis_stats.get('undetected', 0) + 
                             last_analysis_stats.get('suspicious', 0),
                    'permalink': data['data'].get('links', {}).get('self', ''),
                    'detected_sources': [
                        source for source, result in attributes.get('last_analysis', {}).items() if result.get('result')
                    ]
                }

            except requests.RequestException as e:
                return {"error": f"Error occurred while checking VirusTotal: {e}"}

        @staticmethod
        def check_spamhaus(ip_address):
            """
            Checks if the given IP address is blacklisted in Spamhaus.

            Args:
                ip_address (str): The IP address to check.

            Returns:
                dict: A dictionary with a blacklisted status or error message.
            """
            # Reverse IP address for DNS lookup with Spamhaus
            reversed_ip = '.'.join(reversed(ip_address.split('.')))
            query = f"{reversed_ip}.zen.spamhaus.org"

            try:
                # Perform DNS query
                answers = dns.resolver.resolve(query, 'A')
                if answers:
                    return {"blacklisted": True}
            except dns.resolver.NoAnswer:
                return {"blacklisted": False}
            except dns.resolver.NXDOMAIN:
                return {"blacklisted": False}
            except Exception as e:
                return {"error": f"Error occurred while checking Spamhaus: {e}"}

            return {"blacklisted": False}

        @staticmethod
        def ip_to_domain_socketbased(ip_address):
            """
            Converts an IP address to a domain name via reverse DNS lookup.

            Args:
                ip_address (str): The IP address to resolve.

            Returns:
                str: The domain name or None if resolution fails.
            """
            try:
                domain_name = socket.gethostbyaddr(ip_address)[0]
                return domain_name
            except socket.herror:
                return None
        
        @staticmethod        
        def ip_to_domain(ip_address):
            try:
                rev_name = dns.reversename.from_address(ip_address)
                domain_name = str(dns.resolver.resolve(rev_name, 'PTR')[0])
                return domain_name
            except Exception:
                return None

        @staticmethod
        def perform_whois_lookup(domain, api_key, verbose=False):
            """
            Performs WHOIS lookup on a domain using ip2whois API.

            Args:
                domain (str): The domain to lookup.
                api_key (str): ip2whois API key.
                verbose (bool): If True, displays full WHOIS data. Defaults to False.
            """
            url = f"https://api.ip2whois.com/v2?key={api_key}&domain={domain}"

            try:
                # Request WHOIS data
                response = requests.get(url)
                response.raise_for_status()
                whois_info = response.json()

                # Print summary or full WHOIS info based on verbosity
                print("\n--- WHOIS Lookup Summary ---")
                print(f"Domain: {whois_info.get('domain')}")
                print(f"Registrar: {whois_info['registrar']['name'] if 'registrar' in whois_info else 'N/A'}")
                print(f"Creation Date: {whois_info.get('create_date', 'N/A')}")
                print(f"Expiration Date: {whois_info.get('expire_date', 'N/A')}")

                if verbose:
                    print("\n--- Full WHOIS Information ---")
                    print(json.dumps(whois_info, indent=4))

            except requests.exceptions.RequestException as e:
                print(f"{domain} is not avaiable in ip2whois.com")

        @staticmethod
        # Function to get IP information from ipinfo.io
        def get_ip_info(ip_address):
            try:
                # ipinfo API endpoint for IP address lookup
                url = f"https://ipinfo.io/{ip_address}/json"
                
                # Make a GET request to the API
                response = requests.get(url)
                
                # If the request is successful (HTTP 200 OK)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extracting relevant information
                    ip_info = {
                        "IP Address": data.get('ip', 'N/A'),
                        "Hostname": data.get('hostname', 'N/A'),
                        "City": data.get('city', 'N/A'),
                        "Region": data.get('region', 'N/A'),
                        "Country": data.get('country', 'N/A'),
                        "Location": data.get('loc', 'N/A'),
                        "Organization": data.get('org', 'N/A'),
                        "Postal": data.get('postal', 'N/A'),
                        "Timezone": data.get('timezone', 'N/A')
                    }
                    return ip_info
                else:
                    return {"error": f"Failed to retrieve data for {ip_address}. HTTP Status code: {response.status_code}"}
            
            except Exception as e:
                return {"error": f"An error occurred: {str(e)}"}
        
        @staticmethod
        def display_results(ip, vt_result, spamhaus_result):
            """
            Displays the results of VirusTotal and Spamhaus checks in a formatted table.

            Args:
                ip (str): The IP address being checked.
                vt_result (dict): Result from VirusTotal check.
                spamhaus_result (dict): Result from Spamhaus check.
            """
            table = PrettyTable()
            table.title = f"Report for IP: {ip}"
            table.field_names = ["Check", "Result"]
            table.align = "l"
            result={}

            # VirusTotal result display
            if 'error' in vt_result:
                table.add_row(["VirusTotal", vt_result['error']])
            else:
                malicious_summary = f"{vt_result['malicious']} out of {vt_result['total']}"
                result['malicious_indicators'] = int(vt_result['malicious'])
                result['total_indicators'] = int(vt_result['total'])
                # Color malicious activity count
                if vt_result['malicious'] > 0:
                    malicious_summary = f"{Fore.RED}{malicious_summary}{Style.RESET_ALL}"
                else:
                    malicious_summary = f"{Fore.GREEN}{malicious_summary}{Style.RESET_ALL}"
                table.add_row(["VirusTotal Malicious Activity", malicious_summary])
                table.add_row(["VirusTotal Report Link", vt_result['permalink']])

            # Spamhaus result display
            if 'error' in spamhaus_result:
                table.add_row(["Spamhaus", spamhaus_result['error']])
            else:
                table.add_row(["Spamhaus Blacklisted", f"{Fore.RED}Yes{Style.RESET_ALL}" if spamhaus_result['blacklisted'] else f"{Fore.GREEN}No{Style.RESET_ALL}"])

            print(table)
            return result

        @staticmethod
        def plot_results(count):
            """
            Plots a bar chart of benign and malicious IP counts.

            Args:
                count (Counter): Counter object containing benign and malicious counts.
            """ 
            plt.bar(count.keys(), count.values(), color=['#ccffcc', '#ffcccc'])
            plt.title("Benign vs Malicious IPs")
            plt.xlabel("IP Type")
            plt.ylabel("Count")
            plt.show()
    
    class MaliciousRunDLLProcess:
        def __init__(self, process_list: List['MemoryForensicsNamespace.ProcessTree'], network_connections: List['NetworkConnection'], verbose: bool = False):
            self.process_list = process_list
            self.network_connections = network_connections
            self.verbose = verbose
            self.malicious_info = []
            self.non_malicious_info = []
            self.low_risk_info = []
            self.table_data = []

        def detect_malicious_rundll32(self):
            """Detect potentially malicious rundll32.exe processes with network connections."""
            def process_rundll32(process):
                if process.image_file_name.lower() == "rundll32.exe":
                    if not process.cmd or process.cmd.strip() == "" or process.cmd.strip()=="rundll32.exe":
                        related_connections = [conn for conn in self.network_connections if conn.pid == process.pid]
                        if len(related_connections) > 0:
                            alert_message = f"{RED}[Alert] Suspicious rundll32.exe process without arguments and connections: PID {process.pid}{RESET}"
                            self.malicious_info.append(process)
                            if self.verbose:
                                print(alert_message)
                            for conn in related_connections:
                                self.table_data.append([process.pid, process.image_file_name, conn.local_addr, conn.local_port, conn.foreign_addr, conn.foreign_port])
                        elif len(process.children) > 0:
                            alert_message = f"{RED}[Alert] Suspicious rundll32.exe process without arguments and with children: PID {process.pid}{RESET}"
                            self.malicious_info.append(process)
                            if self.verbose:
                                print(alert_message)
                        else:
                            info_message = f"{BLUE}[INFO] Likely legitimate rundll32.exe process with arguments: PID {process.pid}{RESET}"
                            if self.verbose:
                                print(info_message)
                            self.low_risk_info.append(process)
                    else:
                        self.non_malicious_info.append(process)
                
                # Recursively process child processes
                for child in process.children:
                    process_rundll32(child)

            for process in self.process_list:
                process_rundll32(process)

            # Display non-malicious info if verbose
            if self.verbose:
                for process in self.non_malicious_info:
                    print(f"{GREEN}[Verbose Info] Legitimate rundll32.exe process with arguments: PID {process.pid}, Command: {process.cmd}{RESET}")

            # Display table for malicious processes
            if self.table_data and self.verbose:
                print("\nMalicious Process Connections:")
                print(tabulate(self.table_data, headers=["PID", "ImageFileName", "Local Address", "Local Port", "Foreign Address", "Foreign Port"], tablefmt="fancy_grid").encode('utf-8', 'ignore').decode('utf-8'))

            return self.malicious_info, self.non_malicious_info, self.low_risk_info

        def plot_results(self, axis=None):
            """
            Plot the detection summary for rundll32.exe processes.

            Parameters:
                axis (matplotlib.axes._axes.Axes, optional): 
                    An axis object to plot on. If None, a new figure is created.
            """
            labels = ['Malicious', 'Low Risk', 'Non-Malicious']
            sizes = [len(self.malicious_info), len(self.low_risk_info), len(self.non_malicious_info)]
            colors = ['#FF9999', '#FFB266', '#4caf50']
            
            # If no axis is provided, create a new figure and axis
            if axis is None:
                plt.figure(figsize=(8, 5))
                plt.bar(labels, sizes, color=colors)
                plt.title('Rundll32.exe Process Analysis')
                plt.xlabel('Process Type')
                plt.ylabel('Count')

                # Set the figure window title if supported
                fig_manager = plt.get_current_fig_manager()
                if fig_manager is not None:
                    fig_manager.set_window_title('Rundll32.exe Process Analysis')
                
                plt.show()
            else:
                # Use the provided axis to create the plot
                axis.barh(labels, sizes, color=colors)
                axis.set_title('Rundll32.exe Process Analysis')
                axis.set_xlabel('')
                axis.set_ylabel('')   
       
    class CredentialDumpDetector:
        """A class to detect credential dumping activity in process trees."""

        def __init__(self, processes_list: List[MemoryForensicsNamespace.ProcessTree], verbose: bool = False):
            self.processes_list = processes_list
            self.verbose = verbose
            self.procdump_pattern = re.compile(r'procdump(?:\.exe)? -ma lsass\.exe', re.IGNORECASE)
            self.rundll32_pattern = re.compile(r"rundll32\.exe .*comsvcs\.dll MiniDump .* full", re.IGNORECASE)

        def detect_credential_dumping(self) -> List[Dict[str, str]]:
            """
            Detects potential credential dumping activity based on process command line patterns,
            including recursively checking child processes.
            
            :return: A list of dictionaries with details of detected credential dumping activities.
            """
            def recursive_detection(process) -> None:
                """
                Helper recursive function to detect credential dumping in a process and its children.
                
                :param process: A process object containing command details and potentially children.
                """
                if process.cmd is not None:
                    # Check for ProcDump pattern
                    if self.procdump_pattern.search(process.cmd):
                        if self.verbose:
                            print(f"{RED}[Alert] Detected ProcDump credential dumping: PID {process.pid}, Command: {process.cmd}{RESET}")
                        detections[process.pid] = {'pid': process.pid, 'method': 'ProcDump', 'command': process.cmd}

                    # Check for rundll32 pattern
                    elif self.rundll32_pattern.search(process.cmd):
                        if self.verbose:
                            print(f"{RED}[Alert] Detected rundll32 credential dumping: PID {process.pid}, Command: {process.cmd}{RESET}")
                        detections[process.pid] = {'pid': process.pid, 'method': 'rundll32 with comsvcs.dll', 'command': process.cmd}

                    # No dumping detected, marked as benign
                    else:
                        if self.verbose:
                            print(f"{GREEN}[Info] No credential dumping detected for: PID {process.pid}, Command: {process.cmd}{RESET}")
                        detections[process.pid] = {'pid': process.pid, 'method': 'Benign', 'command': process.cmd}
                        #print(process.pid, process.cmd)
                else:
                    detections[process.pid] = {'pid': process.pid, 'method': 'Null CMD', 'command': ''}
                    
                # Recursively check child processes if they exist
                for child in process.children:               
                    recursive_detection(child)

            # Initialize detections list and start recursive detection from each top-level process
            detections = {}
            null_command_count = 0
            for process in self.processes_list:
                recursive_detection(process)

            return detections

        @staticmethod
        def plot_detection_summary(detections: List[Dict[str, str]], axis=None):
            """
            Generates a bar chart showing the frequency of each detected credential dumping method.

            Parameters:
                detections (List[Dict[str, str]]): 
                    A list of dictionaries, each containing details of a detected credential dumping activity.
                axis (matplotlib.axes._axes.Axes, optional): 
                    An axis object to plot on. If None, a new figure is created.
            """
            # Count occurrences of each detection method
            method_counts = {}
            for detection in detections:
                method = detection['method']
                method_counts[method] = method_counts.get(method, 0) + 1

            # Define methods and corresponding counts
            methods = [
                'ProcDump',
                'rundll32 with comsvcs.dll',
                'Benign',
                'Null CMD'
            ]
            counts = [
                method_counts.get('ProcDump', 0),
                method_counts.get('rundll32 with comsvcs.dll', 0),
                method_counts.get('Benign', 0),
                method_counts.get('Null CMD', 0)
            ]

            if axis is None:
                # Create a new figure and plot
                plt.figure(figsize=(10, 6))
                plt.bar(methods, counts, color=['#FF6666', '#FFB266', '#4caf50', '#4c50af'])
                plt.title('Credential Dumping Detection Summary')
                plt.xlabel('Credential Dumping Method')
                plt.ylabel('Number of Detections')

                # Set the figure window title if supported
                fig_manager = plt.get_current_fig_manager()
                if fig_manager is not None:
                    fig_manager.set_window_title('Credential Dump Detection')
                
                plt.show()
            else:
                # Use the provided axis to create the plot
                axis.barh(methods, counts, color=["#ffb3e6", "#ff9999", '#D3F2A6', "#ccff99"])
                axis.set_title('Credential Dumping Detection')
                axis.set_xlabel('')
                axis.set_ylabel('')

        @staticmethod
        def display_detections(detections: List[Dict[str, str]]):
            """
            Displays detected credential dumping activities in a tabular format.

            :param detections: List of detected credential dumping activities.
            """
            if detections:
                table_data = [[detection['pid'], detection['method'], detection['command']] for detection in detections]
                print("\nCredential Dumping Activities Detected:")
                print(tabulate(table_data, headers=["PID", "Method", "Command"], tablefmt="fancy_grid"))
            else:
                print("\nNo credential dumping activities detected.")

    # List of safe executable extensions
    SAFE_EXTENSIONS = [
        "bat", "bin", "cmd", "com", "cpl", "exe", "gadget", "inf1", "ins", "inx", "isu", "job", "jse", "lnk", 
        "msc", "msi", "msp", "mst", "paf", "pif", "ps1", "reg", "rgs", "scr", "sct", "shb", "shs", "u3p", 
        "vb", "vbe", "vbs", "vbscript", "ws", "wsf", "wsh", "dll"
    ]
    
    class ProcessExtensionAnalyzer:
        # Function to check if an extension is safe
        @staticmethod
        def is_safe_extension(file_path):
            if file_path:
                tokens = file_path.lower().split('.')
                if len(tokens) < 2:
                    return False
                extension = tokens[-1]  # Get the extension after the last '.'
                return extension in Detections.SAFE_EXTENSIONS
            return True

        # Recursive function to detect unsafe extensions, including __children
        @staticmethod
        def detect_unsafe_extensions_recursive(process, details, extensions_count):
            audit = process.audit
            cmd = process.cmd
            path = process.path
            file_name = process.image_file_name
            
            source = cmd
            if source is None:
                source = path
            
            if source is not None:
                tokens = source.split(file_name)
                if len(tokens) >= 2:
                    if (file_name + tokens[1]) in source:
                        file_name = file_name + tokens[1].split(' ')[0].split('"')[0]                       
            # Check if any field contains a file with a non-safe extension
            if (not Detections.ProcessExtensionAnalyzer.is_safe_extension(file_name)):
                details[process.pid] = {
                    "PID": process.pid,
                    "Audit": audit,
                    "Cmd": cmd,
                    "Path": path,
                    "Name": file_name,
                    "Warning": "Unsafe extension detected"
                }
                tokens = file_name.split('.')
                if len(tokens) >= 2:
                    extensions_count[tokens[-1].lower()]+=1
                else:
                    extensions_count['NO_EXTENSION']+=1
            
            # Recursively check the __children
            for child in process.children:
                Detections.ProcessExtensionAnalyzer.detect_unsafe_extensions_recursive(child, details, extensions_count)

        # Function to detect unsafe extensions in the JSON data
        @staticmethod
        def detect_unsafe_extensions(processes_list):
            
            details = {}
            # Initialize a defaultdict to count the extensions
            extensions_count: defaultdict[str, int] = defaultdict(int)

            # Check each process in the JSON recursively
            for process in processes_list:
                Detections.ProcessExtensionAnalyzer.detect_unsafe_extensions_recursive(process, details, extensions_count)

            return details,extensions_count
    
    class ConnectionDetector:
        """Detects and plots network connection types and country flags for IPs in a connections JSON file."""
        
        def __init__(self, connections_file):
            self.connections_file = connections_file
            self.connection_data = self.load_connections()

        def load_connections(self):
            """Load network connections from a JSON file."""
            with open(self.connections_file, 'r') as file:
                return json.load(file)
        
        def get_geo_from_ip(self, ip):
            """Get country and country code from an IP address."""
            try:
                response = requests.get(f'http://ip-api.com/json/{ip}')
                data = response.json()
                if data['status'] == 'success':
                    return data['country'], data['countryCode']
                else:
                    return None, None
            except Exception as e:
                print(f"Error retrieving data for IP {ip}: {e}")
                return None, None

        def fetch_country_flag(self, country_code):
            """Fetch flag image from country code."""
            try:
                flag_url = f"https://flagcdn.com/w320/{country_code.lower()}.png"
                response = requests.get(flag_url)
                return Image.open(BytesIO(response.content))
            except Exception as e:
                print(f"Could not load flag for country code {country_code}: {e}")
                return None

        def plot_connection_types(self):
            """Plot connection types (TCPv4, TCPv6, UDPv4, UDPv6) as a bar chart."""
            protocol_counts = {'TCPv4': 0, 'TCPv6': 0, 'UDPv4': 0, 'UDPv6': 0}
            for entry in self.connection_data:
                protocol = entry.get('Proto')
                if protocol in protocol_counts:
                    protocol_counts[protocol] += 1

            plt.figure(figsize=(8, 5))
            plt.bar(protocol_counts.keys(), protocol_counts.values(), color=['blue', 'green', 'orange', 'red'])
            plt.title("Connection Types")
            plt.xlabel("Protocol")
            plt.ylabel("Count")
            
            # Set the figure window title if supported
            fig_manager = plt.get_current_fig_manager()
            if fig_manager is not None:
                fig_manager.set_window_title('Connection Types')
            plt.show()

        def fetch_country_flag(self, country_code):
            """Fetch flag image from country code."""
            try:
                flag_url = f"https://flagcdn.com/w320/{country_code.lower()}.png"
                response = requests.get(flag_url)
                return Image.open(BytesIO(response.content))
            except Exception as e:
                print(f"Could not load flag for country code {country_code}: {e}")
                return None

        def plot_country_flags(self, display_flags=False):
            """Plot flags of countries associated with foreign IP addresses and a histogram of connection counts by country."""
            connection_count = {}
            flags = {}
            
            # Populate connection counts and flags
            for entry in self.connection_data:
                ip = entry.get("ForeignAddr")
                if ip and ip not in connection_count:
                    country, country_code = self.get_geo_from_ip(ip)
                    if country and country_code:
                        flag_img = self.fetch_country_flag(country_code)
                        if flag_img:
                            flags[country] = flag_img
                            connection_count[country] = connection_count.get(country, 0) + 1

            # Plot flag grid if display_flags is True
            if display_flags:
                num_countries = len(flags)
                cols = min(5, num_countries)
                rows = math.ceil(num_countries / cols)
                fig, axes = plt.subplots(rows + 1, cols, figsize=(cols * 3, (rows + 1) * 2.5))
                axes = axes.flatten()

                # Display country flags with connection counts
                for i, (country, flag_img) in enumerate(flags.items()):
                    axes[i].imshow(flag_img)
                    axes[i].axis('off')
                    axes[i].set_title(f"{country} ({connection_count[country]})")

                for i in range(len(flags), len(axes)):
                    axes[i].axis('off')
            else:
                # If only histogram is required, set up a single plot
                fig, ax = plt.subplots(figsize=(10, 6))

            # Plot histogram of connections by country
            plt.subplot()
            plt.bar(connection_count.keys(), connection_count.values(), color='skyblue')
            plt.xticks(rotation=45, ha='right')
            plt.title("Histogram of Connections by Country")
            plt.xlabel("Country")
            plt.ylabel("Connection Count")

            plt.tight_layout()
            
            # Set the figure window title if supported
            fig_manager = plt.get_current_fig_manager()
            if fig_manager is not None:
                fig_manager.set_window_title('Countries Histogram')
            
            plt.show()
            
        def display_countries(self, axis=None):
            """
            Plots a histogram of connections by country.

            Parameters:
                axis (matplotlib.axes._axes.Axes, optional): 
                    An axis object to plot on. If None, a new figure is created.
            """
            """Plot flags of countries associated with foreign IP addresses and a histogram of connection counts by country."""
            connection_count = {}
            flags = {}
            
            # Populate connection counts and flags
            for entry in self.connection_data:
                ip = entry.get("ForeignAddr")
                if ip and ip not in connection_count:
                    country, country_code = self.get_geo_from_ip(ip)
                    if country and country_code:
                        flag_img = self.fetch_country_flag(country_code)
                        if flag_img:
                            flags[country] = flag_img
                            connection_count[country] = connection_count.get(country, 0) + 1
            
            if axis is None:
                # Create a new figure and plot
                plt.figure(figsize=(10, 6))
                plt.bar(connection_count.keys(), connection_count.values(), color='skyblue')
                plt.xticks(rotation=45, ha='right')
                plt.title("Histogram of Connections by Country")
                plt.xlabel("Country")
                plt.ylabel("Connection Count")
                plt.tight_layout()

                # Set the figure window title if supported
                fig_manager = plt.get_current_fig_manager()
                if fig_manager is not None:
                    fig_manager.set_window_title('Countries Histogram')

                plt.show()
            else:
                # Use the provided axis to create the plot
                axis.barh(list(connection_count.keys()), list(connection_count.values()), color='skyblue')
                axis.set_title("Connections by Country")
                axis.set_xlabel("")
                axis.set_ylabel("")
        
        def parse_time(self, connection):
            """Parse the Created time from a connection and return as datetime object, rounded to the nearest minute."""
            try:
                timestamp = connection.get("Created")
                parsed_time = datetime.fromisoformat(timestamp)
                return parsed_time.replace(second=0, microsecond=0)  # Round to minute
            except Exception as e:
                print(f"Error parsing time for connection: {e}")
                return None

        def count_connections_by_minute(self):
            """Count the number of connections per minute."""
            time_stamps = [self.parse_time(conn) for conn in self.connection_data if self.parse_time(conn)]
            return Counter(time_stamps)

        def plot_connections_by_minute(self):
            """Plot the number of connections over time by minute."""
            connections_by_minute = self.count_connections_by_minute()
            times = sorted(connections_by_minute.keys())
            counts = [connections_by_minute[time] for time in times]

            plt.figure(figsize=(10, 5))
            plt.plot(times, counts, marker='o', linestyle='-', color='b')
            plt.xlabel('Time (by minute)')
            plt.ylabel('Number of Connections')
            plt.title('Connections over Time (Per Minute)')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            plt.grid(True)

            # Set the figure window title if supported
            fig_manager = plt.get_current_fig_manager()
            if fig_manager is not None:
                fig_manager.set_window_title('Connections Timeline')
            
            plt.show()

        def get_geo_from_ip(self, ip):
            """Get country and country code from an IP address."""
            try:
                response = requests.get(f'http://ip-api.com/json/{ip}')
                data = response.json()
                if data['status'] == 'success':
                    return data['country'], data['countryCode']
                else:
                    return None, None
            except Exception as e:
                print(f"Error retrieving data for IP {ip}: {e}")
                return None, None
                
    class MaliciousRundll32Child:
        """
        Class to detect and visualize suspicious process lineages involving 'rundll32.exe' and other processes.
        """

        # Define the list of potentially suspicious parent processes
        SUSPICIOUS_PARENTS = [
            "winword.exe", "excel.exe", "msaccess.exe", "lsass.exe", "taskeng.exe",
            "winlogon.exe", "schtask.exe", "regsvr32.exe", "wmiprvse.exe", "wsmprovhost.exe"
        ]

        def __init__(self, verbose=False):
            self.verbose = verbose
            self.malicious = []
            self.non_malicious = []
            self.graph = nx.DiGraph()  # Directed graph to represent process lineage

        def detect_lineage(self, process_list):
            """
            Detects suspicious process lineage and adds nodes and edges to the graph.

            Parameters:
                process_list (list): A list of process objects to analyze.
            """
            for process in process_list:
                parent_node = f"{process.image_file_name} (PID: {process.pid})"
                for child in process.children:
                    child_node = f"{child.image_file_name} (PID: {child.pid})"

                    # Check for suspicious lineage
                    if process.image_file_name in self.SUSPICIOUS_PARENTS and child.image_file_name == "rundll32.exe":
                        print(f"{RED}Alert: Suspicious process lineage detected! Parent: {parent_node} -> Child: {child_node}{RESET}")
                        self._add_edge_to_graph(parent_node, child_node, "#ff9999")

                        if process.pid not in self.malicious:
                            self.malicious.append(process.pid)
                        self.malicious.append(child.pid)

                        if process.pid in self.non_malicious:
                            self.non_malicious.remove(process.pid)
                    else:
                        if self.verbose:
                            print(f"{GREEN}Info: Non-malicious lineage. Parent: {parent_node} -> Child: {child_node}{RESET}")
                        self._add_edge_to_graph(parent_node, child_node, "green")

                        if process.pid not in self.malicious:
                            self.non_malicious.append(process.pid)
                        self.non_malicious.append(child.pid)

                # Recursively check child processes
                self.detect_lineage(process.children)

        def _add_edge_to_graph(self, parent, child, color):
            """
            Adds a parent-child relationship as nodes and edges to the graph.

            Parameters:
                parent (str): Parent process identifier.
                child (str): Child process identifier.
                color (str): Color of the edge to represent type of relationship.
            """
            self.graph.add_node(parent, color="#ccff99" if color == "green" else "#ff9999")
            self.graph.add_node(child, color="#ccff99" if color == "green" else "#ff9999")
            self.graph.add_edge(parent, child, color=color)

        def plot_process_lineage(self, axis=None):
            """
            Plots the process lineage graph while ensuring minimal overlap between nodes and edges.

            Parameters:
                axis (matplotlib.axes.Axes, optional): The axis to plot the graph on.
                                                       If None, a new plot will be created.
            """
            pos = nx.spring_layout(self.graph, k=0.5, iterations=50)  # Layout with better spacing
            edge_colors = [self.graph.edges[edge].get('color', 'black') for edge in self.graph.edges]
            node_colors = [self.graph.nodes[node].get('color', 'green') for node in self.graph.nodes]

            if axis is None:
                # Create a new figure for the plot
                plt.figure(figsize=(14, 10))
                nx.draw(
                    self.graph,
                    pos,
                    with_labels=True,
                    node_color=node_colors,
                    edge_color=edge_colors,
                    node_size=300,
                    font_size=10,
                    font_color='black',
                    linewidths=1.5,
                    arrows=True,
                    arrowstyle='-|>',
                    arrowsize=20
                )
                plt.title("Process Lineage Graph", fontsize=16)
                plt.tight_layout()
                plt.show()
            else:
                # Use the provided axis for the plot
                nx.draw(
                    self.graph,
                    pos,
                    ax=axis,  # Use the provided axis
                    with_labels=False,
                    node_color=node_colors,
                    edge_color=edge_colors,
                    node_size=50,
                    font_size=10,
                    font_color='black',
                    linewidths=1.5,
                    arrows=True,
                    arrowstyle='-|>',
                    arrowsize=5
                )
                axis.set_title("Process Lineage Graph", fontsize=16)
                plt.tight_layout()

        def plot_process_lineage_with_hover(self, fig=None, axis=None):
            """
            Plots the process lineage graph where node labels are visible only on hover.

            Parameters:
                fig (matplotlib.figure.Figure, optional): The figure to plot the graph on. If None, a new figure will be created.
                axis (matplotlib.axes.Axes, optional): The axis to plot the graph on. If None, a new axis will be created.
            """
            # Create fig and axis if not provided
            plot = False
            if fig is None or axis is None:
                plot = True
                fig, axis = plt.subplots(figsize=(14, 10))

            # Create positions for the nodes
            pos = nx.spring_layout(self.graph, k=0.5, iterations=50)
            edge_colors = [self.graph.edges[edge].get('color', 'black') for edge in self.graph.edges]
            node_colors = [self.graph.nodes[node].get('color', 'green') for node in self.graph.nodes]

            # Plot without labels initially
            nx.draw(
                self.graph,
                pos,
                ax=axis,  # Use the provided axis
                with_labels=False,  # Hide labels initially
                node_color=node_colors,
                edge_color=edge_colors,
                node_size=200 if plot else 100,
                linewidths=1.5,
                arrows=True,
                arrowstyle='-|>',
                arrowsize=10,
            )
            axis.set_title("Malicious Process Lineage Graph")

            # Draw hidden labels
            annotations = {}
            for node, (x, y) in pos.items():
                annotation = axis.annotate(
                    node,  # Use node name as label
                    xy=(x, y),
                    xytext=(5, 5),
                    textcoords="offset points",
                    fontsize=10,
                    color="black",
                    alpha=0,  # Start hidden
                )
                annotations[node] = annotation

            # Define hover event
            def on_hover(event):
                visibility_changed = False
                for node, (x, y) in pos.items():
                    # Transform node position to display coordinates
                    display_coords = axis.transData.transform((x, y))
                    # Check if the cursor is near the node
                    if (abs(display_coords[0] - event.x) < 10) and (abs(display_coords[1] - event.y) < 10):
                        annotations[node].set_alpha(1)  # Show label
                        visibility_changed = True
                    else:
                        annotations[node].set_alpha(0)  # Hide label
                if visibility_changed:
                    fig.canvas.draw_idle()

            # Connect the hover event
            fig.canvas.mpl_connect("motion_notify_event", on_hover)

            if plot:
                plt.tight_layout()
                plt.show()  

        def plot_process_histogram(self, axis=None):
                """
                Plots a histogram comparing counts of malicious and non-malicious processes.

                Parameters:
                    axis (matplotlib.axes.Axes, optional): The axis to plot the histogram on. 
                                                           If None, a new plot will be created.
                """
                categories = ['Malicious', 'Non-Malicious']
                counts = [len(self.malicious), len(self.non_malicious)]
                colors = ["#ff9999", "#ccff99"]

                if axis is None:
                    # Create a new plot
                    plt.figure(figsize=(10, 6))
                    plt.bar(categories, counts, color=colors)
                    plt.title("Malicious vs Non-Malicious Processes", fontsize=12)
                    plt.xlabel("Process Type", fontsize=10)
                    plt.ylabel("Count", fontsize=10)
                    plt.xticks(fontsize=10)
                    plt.yticks(fontsize=10)
                    plt.tight_layout()
                    plt.show()
                else:
                    # Use the provided axis
                    axis.barh(categories, counts, color=colors)
                    axis.set_title("RunDll32 Child Analysis", fontsize=12)
                    axis.set_xlabel("", fontsize=10)
                    axis.set_ylabel("Process Type", fontsize=10)
                    axis.tick_params(axis='x', labelsize=10)
                    axis.tick_params(axis='y', labelsize=10)
                    
    class IPCategorytDetector:
        def __init__(self, blacklist_file, whitelist_file, pstree_file, connections_file):
            self.blacklist_ips = Detections.IPCategorytDetector.load_ip_list(blacklist_file)
            self.whitelist_ips = Detections.IPCategorytDetector.load_ip_list(whitelist_file)
            self.process_data = self.load_json_file(pstree_file)
            self.connection_data = self.load_json_file(connections_file)
            self.other_ips = set()
            self.blacklist_counts = {}
        
        @staticmethod
        def load_ip_list(filename):
            with open(filename, 'r') as file:
                return set(file.read().splitlines())
        
        def load_json_file(self, filename):
            with open(filename, 'r') as file:
                return json.load(file)
        
        def categorize_ips(self, axis=None):
            """
            Categorize each foreign IP in connection_data as blacklisted, whitelisted, or other.

            Parameters:
                axis (matplotlib.axes.Axes, optional): The axis to plot the graph on. If None, a new plot is created.
            """
            # Initialize counters for IP categories
            self.foreign_ip_counts = {'blacklist': 0, 'whitelist': 0, 'other': 0}

            for connection in self.connection_data:
                ip = connection['ForeignAddr']
                if ip in self.blacklist_ips:
                    self.foreign_ip_counts['blacklist'] += 1
                    #print('Malicious Process : ' + str(connection['PID']) + " " + ip)
                    if self.blacklist_counts.get(connection['PID'], 0) == 0:
                        self.blacklist_counts[connection['PID']] = 1
                    else:
                        self.blacklist_counts[connection['PID']] += 1
                elif ip in self.whitelist_ips:
                    self.foreign_ip_counts['whitelist'] += 1
                else:
                    self.foreign_ip_counts['other'] += 1
                    self.other_ips.add(ip)

            # Colors for the bar chart
            colors = ['#ffcccc', '#cce5ff', '#ccffcc']  # Light colors for categories

            # If axis is None, create a new figure and axis
            if axis is None:
                fig, axis = plt.subplots(figsize=(8, 6))
                show_plot = True  # Indicate that we should call plt.show() later
            else:
                show_plot = False  # Caller will handle plt.show()

            # Plot the data
            axis.bar(self.foreign_ip_counts.keys(), self.foreign_ip_counts.values(), color=colors)

            # Set labels and title
            axis.set_xlabel("IP Category")
            axis.set_ylabel("Number of IPs")
            axis.set_title("Categorization of Connected IPs")

            # Adjust layout and display the plot if created locally
            if show_plot:
                plt.tight_layout()
                plt.show()

        def search_cmd_ips(self, process, blacklist_counts):
            """Search Cmd entries for full IP addresses and categorize them as blacklisted, whitelisted, or other."""
            
            # Regular expression for matching a full IPv4 address
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            
            # Queue for breadth-first search to handle recursive __children entries
            queue = [process]

            while queue:
                current_process = queue.pop(0)
                
                # Check if Cmd is present and contains an IP address
                cmd = current_process.get('Cmd', '')
                if cmd:
                    # Find all unique IP addresses in the Cmd string
                    ips_in_cmd = set(ip_pattern.findall(cmd))
                    
                    for ip in ips_in_cmd:
                        if ip in self.blacklist_ips:
                            blacklist_counts['blacklist'] += 1
                            blacklist_counts[current_process['PID']] += 1
                        elif ip in self.whitelist_ips:
                            blacklist_counts['whitelist'] += 1
                        else:
                            blacklist_counts['other'] += 1
                            self.other_ips.add(ip)

                # Add child processes to the queue for BFS
                queue.extend(current_process.get('__children', []))
        
        def process_cmd_ip_analysis(self):
            """Analyze Cmd entries in processes for blacklisted, whitelisted, and other IPs and plot results with light colors."""
            blacklist_counts = defaultdict(int)
            
            # Recursively search and count IP occurrences in Cmd fields
            for process in self.process_data:
                self.search_cmd_ips(process, blacklist_counts)
            
            # Define categories and their counts
            categories = ['blacklist', 'whitelist', 'other']
            values = [blacklist_counts.get(cat, 0) for cat in categories]
            
            # Define a light color palette for each category
            light_colors = ['#ffcccc', '#cce5ff', '#ccffcc']  # Light pastel colors for each category
            
            # Plot CMD IP categorization with light colors
            plt.figure(figsize=(10, 6))
            plt.bar(categories, values, color=light_colors)
            plt.xlabel("CMD IP Category")
            plt.ylabel("Number of CMD IPs")
            plt.title("Categorization of CMD IPs in Processes")
            plt.tight_layout()
            plt.show()
            
            # Update global blacklist counts with new counts from CMD analysis
            for key, count in blacklist_counts.items():
                self.blacklist_counts[key] = self.blacklist_counts.get(key, 0) + count

        def plot_blacklist_connections_by_process(self, axis=None): 
            """
            Plot number of blacklisted connections by process, arranged from highest to lowest with light colors.

            Parameters:
                axis (matplotlib.axes.Axes, optional): The axis to plot the graph on. If None, a new plot is created.
            """
            # Create a dictionary of process names and PIDs mapped to their blacklist counts
            #print(self.blacklist_counts)
            #print(self.process_data)
            process_blacklist_counts = {
                f"{process['ImageFileName']}\n(PID: {process['PID']}": self.blacklist_counts[process['PID']]
                for process in self.process_data
                if process['PID'] in self.blacklist_counts
            }
            #print(process_blacklist_counts)

            # Check if there are any blacklisted connections
            if not process_blacklist_counts:
                print("No blacklisted connections found for any processes.")
                return

            # Sort the dictionary by blacklist counts in descending order
            sorted_process_counts = dict(sorted(process_blacklist_counts.items(), key=lambda item: item[1], reverse=True))

            # Use a light color gradient from a colormap
            colors = cm.Pastel1(np.linspace(0.2, 1, len(sorted_process_counts)))  # Light pastel colors

            # If axis is None, create a new figure and axis
            show_plot = True
            if axis is None:
                fig, axis = plt.subplots(figsize=(12, 8))
            else:
                show_plot = False
                # Caller will handle plt.show()

            # Plot the data
            axis.bar(sorted_process_counts.keys(), sorted_process_counts.values(), color=colors)

            # Set labels and title
            axis.set_xlabel("Process Name and PID")
            axis.set_ylabel("")
            axis.set_title("Processes with Blacklisted Connections")
            axis.tick_params(axis='x', rotation=45)
            axis.set_xticks(axis.get_xticks(), rotation=45, ha='right')

            # Adjust layout if we created a new figure
            if show_plot:
                plt.tight_layout()
                plt.show()