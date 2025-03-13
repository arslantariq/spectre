import json
import random
import matplotlib.pyplot as plt
from faker import Faker
from collections import defaultdict
from typing import List, Dict
from datetime import datetime
import numpy as np
import os
fake = Faker()

""" Following statements are required to add parent path to import parent folders"""
from inspect import getsourcefile
import os.path
import sys
current_path = os.path.abspath(getsourcefile(lambda:0))
current_dir = os.path.dirname(current_path)
parent_dir = current_dir[:current_dir.rfind(os.path.sep)]
sys.path.insert(0, parent_dir)
sys.path.insert(0, parent_dir + os.path.sep + "detections")
from AnomalyDetector import *

sys.path.insert(0, parent_dir + os.path.sep + "visualization")
from VisualizationModule import VisualizationModule

class MemoryDump:   
    
    def loadFiles(self, processes_file, connections_file, users_file, modules_file, dlls_file, registries_file):

        # Load data from the provided files
        self.processes = self.load_json(processes_file)
        self.connections = self.load_json(connections_file)
        self.users = self.load_json(users_file)
        self.modules = self.load_json(modules_file)
        self.dlls = self.load_json(dlls_file)
        self.registries = self.load_json(registries_file)

        # extract IPs from connections
        self.ips = [conn['ForeignAddr'] for conn in self.connections]
        
        self.connections_file = connections_file
        self.pstree_file = processes_file
    
    def loadDirectory(self, directory):
        
        self.connections_file = os.path.join(directory, "netstat.json")
        self.pstree_file = os.path.join(directory, "pstree.json")
        
        # Load data from the provided directory
        self.processes = self.load_json(self.pstree_file)
        self.connections = self.load_json(self.connections_file)
        self.users = self.load_json(os.path.join(directory, "hashdump.json"))
        self.modules = self.load_json(os.path.join(directory, "ldrmodules.json"))
        #self.dlls = self.load_json(os.path.join(directory, "dlllist.json"))
        self.registries = self.load_json(os.path.join(directory, "printkey.json"))

        # extract IPs from connections
        self.ips = [conn['ForeignAddr'] for conn in self.connections]
    
    def load_json(self, file_path):
        with open(file_path, 'r') as f:
            return json.load(f)
   
    def read_dump(self, file_path: str) -> None:
        """Read and initialize data from a JSON dump file."""
        with open(file_path, 'r') as file:
            data = json.load(file)
            self.processes = data.get("processes", [])
            self.connections = data.get("connections", [])
            self.users = data.get("users", [])
            self.modules = data.get("modules", [])
            self.registries = data.get("registries", [])
            
            # Extract IPs from connections
            self.ips = list({conn['ForeignAddr'] for conn in self.connections})
            
            # Extract commands by traversing processes
            self.commands = self._extract_commands(self.processes)
    
    def save_json(self, output_path: str) -> None:
        """Save the current data to a JSON file."""
        data = {
            "processes": self.processes,
            "connections": self.connections,
            "users": self.users,
            "modules": self.modules,
            "ips": self.ips,
            "registries": self.registries,
            "commands": self.commands
        }
        with open(output_path, 'w') as file:
            json.dump(data, file, indent=4)
    
    def _extract_commands(self, processes: List[Dict]) -> Dict:
        """Recursively traverse processes to extract commands."""
        commands = {}
        for process in processes:
            if process.get('Cmd'):
                commands[process['PID']] = process['Cmd']
            # Traverse __children recursively
            if '__children' in process:
                commands.update(self._extract_commands(process['__children']))
        return commands
    
    def getProcesses(self) -> List[Dict]:
        return self.processes

    def getConnections(self) -> List[Dict]:
        return self.connections

    def getUsers(self) -> List[Dict]:
        return self.users

    def getModules(self) -> List[Dict]:
        return self.modules

    def getIPAddresses(self) -> List[str]:
        return self.ips

    def getRegistries(self) -> List[Dict]:
        return self.registries

    def getCommands(self) -> Dict:
        return self.commands

    def addProcesses(self, newProcesses: List[Dict]) -> None:
        self.processes.extend(newProcesses)

    def addConnections(self, newConnections: List[Dict]) -> None:
        self.connections.extend(newConnections)
        self.ips.extend(list({conn['ForeignAddr'] for conn in self.connections}))

    def addUsers(self, newUsers: List[Dict]) -> None:
        self.users.extend(newUsers)

    def addModules(self, newModules: List[Dict]) -> None:
        self.modules.extend(newModules)

    def addIPAddresses(self, newIPAddresses: List[str]) -> None:
        self.ips.extend(newIPAddresses)

    def addRegistries(self, newRegistries: List[Dict]) -> None:
        self.registries.extend(newRegistries)

    def addCommands(self, newCommands: Dict) -> None:
        self.commands.update(newCommands)
    
    def plot_statistics(self) -> None:
        """Generate a plot displaying statistics for each JSON category."""
        categories = ['Processes', 'Connections', 'Users', 'Modules', 'IPs', 'Registries', 'Commands']
        values = [
            len(self.processes),
            len(self.connections),
            len(self.users),
            len(self.modules),
            len(self.ips),
            len(self.registries),
            len(self.commands)
        ]

        plt.figure(figsize=(12, 6))
        plt.barh(categories, values, color=['#cce5ff', '#ffcccc', '#ccffcc', '#ffd9b3', '#ffffcc', '#d9b3ff', '#ffb3e6'])
        plt.xlabel('Count')
        plt.title('Memory Dump Statistics')
        plt.tight_layout()
        plt.show()

    # Fake data generation methods
    def generate_fake_processes(self, num_entries):
        processes = []
        for _ in range(num_entries):
            has_children = random.choice([True, False])
            process = {
                "PID": fake.random_int(min=1000, max=9999),
                "PPID": fake.random_int(min=100, max=999) if has_children else None,
                "Cmd": fake.sentence() if has_children else None,
                "ImageFileName": fake.file_name(extension="exe"),
                "CreateTime": fake.date_time_this_year().isoformat(),
                "ExitTime": fake.date_time_this_year().isoformat() if random.choice([True, False]) else None,
                "Threads": fake.random_int(min=0, max=20),
                "__children": [] if not has_children else [fake.sentence() for _ in range(2)]
            }
            processes.append(process)
        return processes

    def generate_fake_connections(self, num_entries):
        connections = []
        for _ in range(num_entries):
            state = random.choice(["Listening", "Established", "Closed"])
            proto = random.choice(["TCPv4", "TCPv6", "UDPv4", "UDPv6"])
            connections.append({
                "PID": fake.random_int(min=1000, max=9999),
                "LocalAddr": fake.ipv4(),
                "ForeignAddr": fake.ipv4_public() if random.choice([True, False]) else fake.ipv4_private(),
                "Proto": proto,
                "State": state,
                "Owner": fake.user_name()
            })
        return connections

    def generate_fake_users(self, num_entries):
        return [{"User": fake.user_name(), "lmhash": fake.md5(), "nthash": fake.md5(), "rid": fake.random_int()} for _ in range(num_entries)]

    def generate_fake_modules(self, num_entries):
        return [{"Base": fake.random_int(), "Pid": fake.random_int(min=1000, max=9999), "MappedPath": fake.file_path()} for _ in range(num_entries)]

    def generate_fake_registries(self, num_entries):
        return [{"Key": fake.file_path(), "Name": fake.word(), "Type": "REG_SZ", "Data": fake.sentence()} for _ in range(num_entries)]
    
    def generate_fake_dlls(self, num_entries):
        # Generate fake DLLs data
        dlls = []
        for _ in range(num_entries):
            dll = {
                "Base": random.randint(140000000000000, 150000000000000),
                "File output": random.choice(["Enabled", "Disabled"]),
                "LoadTime": fake.iso8601(),
                "Name": fake.word() + ".dll",
                "PID": random.randint(1000, 2000),
                "Path": "\\SystemRoot\\System32\\" + fake.word() + ".dll",
                "Process": fake.word(),
                "Size": random.randint(10000, 1000000),
                "__children": []
            }
            dlls.append(dll)
        
        return dlls
    
    # Save data to JSON file
    def save_json(self):
        data = {
            "processes": self.processes,
            "connections": self.connections,
            "users": self.users,
            "modules": self.modules,
            "registries": self.registries,
            "commands": self.commands
        }
        with open(self.file_path, 'w') as f:
            json.dump(data, f, indent=4)

class MemoryAnalysis:

    @staticmethod
    def plot_detailed_statistics(memoryDump):
        fig, axs = plt.subplots(3, 3, figsize=(20, 16))
        
        # Set the figure window title if supported
        fig_manager = plt.get_current_fig_manager()
        if fig_manager is not None:
            fig_manager.set_window_title('Memory Dump Detailed Statistics')

        # 1. Processes: Parent vs Child (Pie Chart)
        parent_count = sum(1 for p in memoryDump.processes if p['__children'])
        child_count = len(memoryDump.processes) - parent_count
        wedges, texts = axs[0, 0].pie([parent_count, child_count], labels=["Parents", "Children"], 
                                      colors=["#66b3ff", "#ffb3e6"])
        axs[0, 0].set_title("Processes: Parent vs Child")
        for i, wedge in enumerate(wedges):
            # Calculate angle for placing text
            angle = (wedge.theta2 + wedge.theta1) / 2
            x = 0.7 * np.cos(np.radians(angle))
            y = 0.7 * np.sin(np.radians(angle))
            axs[0, 0].text(x, y, f'{[parent_count, child_count][i]}', color="black", fontsize=14, ha="center", va="center")

        # 2. Processes: Running vs Closed (Pie Chart)
        closed_count = sum(1 for p in memoryDump.processes if p["ExitTime"])
        running_count = len(memoryDump.processes) - closed_count
        wedges, texts = axs[0, 1].pie([running_count, closed_count], labels=["Running", "Closed"], 
                                      colors=["#99ff99", "#ffcc99"])
        axs[0, 1].set_title("Processes: Running vs Closed")
        for i, wedge in enumerate(wedges):
            # Calculate angle for placing text
            angle = (wedge.theta2 + wedge.theta1) / 2
            x = 0.7 * np.cos(np.radians(angle))
            y = 0.7 * np.sin(np.radians(angle))
            axs[0, 1].text(x, y, f'{[running_count, closed_count][i]}', color="black", fontsize=14, ha="center", va="center")

        # 3. Connections: Internal vs External (Pie Chart)
        internal_connections = sum(1 for c in memoryDump.connections if c["ForeignAddr"].startswith("192.168") or c["ForeignAddr"].startswith("10."))
        external_connections = len(memoryDump.connections) - internal_connections
        wedges, texts = axs[0, 2].pie([internal_connections, external_connections], labels=["Internal", "External"], 
                                      colors=["#ffcc99", "#66ff99"])
        axs[0, 2].set_title("Connections: Internal vs External")
        for i, wedge in enumerate(wedges):
            # Calculate angle for placing text
            angle = (wedge.theta2 + wedge.theta1) / 2
            x = 0.7 * np.cos(np.radians(angle))
            y = 0.7 * np.sin(np.radians(angle))
            axs[0, 2].text(x, y, f'{[internal_connections, external_connections][i]}', color="black", fontsize=14, ha="center", va="center")

        # 4. Connections: Connection States (Horizontal Bar Chart)
        state_counts = defaultdict(int)
        for conn in memoryDump.connections:
            state_counts[conn["State"]] += 1

        # Sorting states by count in descending order for better presentation
        sorted_states = sorted(state_counts.items(), key=lambda x: x[1], reverse=True)
        states = [state for state, count in sorted_states]
        counts = [count for state, count in sorted_states]

        # Creating a horizontal bar chart
        axs[1, 0].barh(states, counts, color=["#ffb3e6", "#ff9999", "#ccff99"])

        # Adding counts as labels on the bars
        for i, (state, count) in enumerate(zip(states, counts)):
            axs[1, 0].text(count + 0.1, i, str(count), va='center', color="black", fontsize=14)

        # Setting title and labels
        axs[1, 0].set_title("Connections: State Counts")
        axs[1, 0].set_xlabel("")
        axs[1, 0].set_ylabel("State")

        # 5. Connections: Protocol Types (Pie Chart)
        proto_counts = defaultdict(int)
        for conn in memoryDump.connections:
            proto_counts[conn["Proto"]] += 1
        wedges, texts = axs[1, 1].pie(proto_counts.values(), labels=proto_counts.keys(), 
                                      colors=["#66ffcc", "#99ffcc", "#ffccff", "#b3b3ff"])
        axs[1, 1].set_title("Connections: Protocol Counts")
        for i, wedge in enumerate(wedges):
            # Calculate angle for placing text
            angle = (wedge.theta2 + wedge.theta1) / 2
            x = 0.7 * np.cos(np.radians(angle))
            y = 0.7 * np.sin(np.radians(angle))
            axs[1, 1].text(x, y, f'{list(proto_counts.values())[i]}', color="black", fontsize=14, ha="center", va="center")

        # 6. Top 3 Processes with Most DLLs (Pie Chart)
        pid_dll_count = defaultdict(int)
        for dll in memoryDump.modules:
            pid_dll_count[dll["Pid"]] += 1
        sorted_pid_dlls = sorted(pid_dll_count.items(), key=lambda x: x[1], reverse=True)[:3]
        top_3_pid_dlls = [pid for pid, count in sorted_pid_dlls]
        top_3_counts_dlls = [count for pid, count in sorted_pid_dlls]
        top_3_labels_dlls = [f"PID {pid}" for pid in top_3_pid_dlls]
        wedges, texts = axs[2, 1].pie(top_3_counts_dlls, labels=top_3_labels_dlls, 
                                      colors=random.sample(plt.cm.Paired.colors, len(top_3_counts_dlls)))
        axs[2, 1].set_title("Top 3 Processes with Most DLLs")
        for i, wedge in enumerate(wedges):
            # Calculate angle for placing text
            angle = (wedge.theta2 + wedge.theta1) / 2
            x = 0.7 * np.cos(np.radians(angle))
            y = 0.7 * np.sin(np.radians(angle))
            axs[2, 1].text(x, y, f'{top_3_counts_dlls[i]}', color="black", fontsize=14, ha="center", va="center")

       # 7. Connections: Horizontal Bar Chart of Protocol by PID (Updated)
        pid_proto_count = defaultdict(lambda: defaultdict(int))
        for conn in memoryDump.connections:
            pid_proto_count[conn['PID']][conn['Proto']] += 1
        
        # Identify the PID with the most connections
        pid_connection_count = defaultdict(int)
        for conn in memoryDump.connections:
            pid_connection_count[conn['PID']] += 1
        most_connected_pid = max(pid_connection_count, key=pid_connection_count.get)
        
        # Get protocol counts for the PID with the most connections
        proto_counts_for_pid = pid_proto_count[most_connected_pid]
        
        # Create horizontal bar chart for protocol counts
        proto_types = ["TCPv4", "TCPv6", "UDPv4", "UDPv6"]
        counts = [proto_counts_for_pid.get(proto, 0) for proto in proto_types]
        
        axs[1, 2].barh(proto_types, counts, color='#66b3ff')
        axs[1, 2].set_title(f"Protocols for PID {most_connected_pid} (Most Connections)")
        axs[1, 2].set_xlabel("")
        axs[1, 2].set_ylabel("Protocol Type")

        # 8. Top 3 Processes with Most Threads (Pie Chart)
        pid_thread_count = defaultdict(int)
        for process in memoryDump.processes:
            pid_thread_count[process['PID']] += process['Threads']
        sorted_pid_threads = sorted(pid_thread_count.items(), key=lambda x: x[1], reverse=True)[:3]
        top_3_pid_threads = [pid for pid, count in sorted_pid_threads]
        top_3_counts_threads = [count for pid, count in sorted_pid_threads]
        top_3_labels_threads = [f"PID {pid}" for pid in top_3_pid_threads]
        wedges, texts = axs[2, 0].pie(top_3_counts_threads, labels=top_3_labels_threads, 
                                      colors=random.sample(plt.cm.Paired.colors, len(top_3_counts_threads)))
        axs[2, 0].set_title("Top 3 Processes\nwith Most Threads", loc='left', x=-1, y=0.1)

        for i, wedge in enumerate(wedges):
            # Calculate angle for placing text
            angle = (wedge.theta2 + wedge.theta1) / 2
            x = 0.7 * np.cos(np.radians(angle))
            y = 0.7 * np.sin(np.radians(angle))
            axs[2, 0].text(x, y, f'{top_3_counts_threads[i]}', color="black", fontsize=14, ha="center", va="center")

        # 9. Connections: Top 3 Processes with Most Connections (Pie Chart)
        pid_connection_count = defaultdict(int)
        for conn in memoryDump.connections:
            pid_connection_count[conn['PID']] += 1
        sorted_pid_connections = sorted(pid_connection_count.items(), key=lambda x: x[1], reverse=True)[:3]
        top_3_pid_connections = [pid for pid, count in sorted_pid_connections]
        top_3_counts_connections = [count for pid, count in sorted_pid_connections]
        top_3_labels_connections = [f"PID {pid}" for pid in top_3_pid_connections]
        wedges, texts = axs[2, 2].pie(top_3_counts_connections, labels=top_3_labels_connections, 
                                      colors=random.sample(plt.cm.Paired.colors, len(top_3_counts_connections)))
        axs[2, 2].set_title("Top 3 Processes\nwith Most\nConnections", loc='left', x=-0.85, y=0.1)
        for i, wedge in enumerate(wedges):
            # Calculate angle for placing text
            angle = (wedge.theta2 + wedge.theta1) / 2
            x = 0.7 * np.cos(np.radians(angle))
            y = 0.7 * np.sin(np.radians(angle))
            axs[2, 2].text(x, y, f'{top_3_counts_connections[i]}', color="black", fontsize=14, ha="center", va="center")

        # Adjust layout to prevent overlapping
        plt.tight_layout(pad=3.0, h_pad=3.0, w_pad=3.0)
        plt.subplots_adjust(top=0.92)  # Adjust the space at the top to fit the main title
        plt.show(block=True)
    
    @staticmethod
    def plot_additional_statistics(memoryDump, whitelist_ips, blacklist_ips, vt_key):
        fig, axs = plt.subplots(3, 3, figsize=(15, 9))
        #fig.suptitle("Additional Forensic Analysis Charts", fontsize=18, fontweight="bold")
        
        # Set the figure window title if supported
        fig_manager = plt.get_current_fig_manager()
        if fig_manager is not None:
            fig_manager.set_window_title('Anomaly Analysis')
        
        processes_list = parse_audit_entry_list(json.dumps(memoryDump.processes))
        data = json.loads(json.dumps(memoryDump.connections))
        network_connections = [NetworkConnection.from_dict(conn) for conn in data]

        # 1. Unsafe extensions
        session_id_counts = defaultdict(int)
        
        # Detect unsafe extensions
        unsafe_extension_pids, extensions_count = Detections.ProcessExtensionAnalyzer.detect_unsafe_extensions(processes_list)
        #print('Unsafe extensions')
        #print(unsafe_extension_pids.keys())

        # Call the visualization function to display the extensions chart
        VisualizationModule.displayExtensions(extensions_count, axs[0, 0])
        
        # Malicious rundll32 parent process Analysis
        detector = Detections.MaliciousRunDLLProcess(processes_list, network_connections, False)
        malicious_info, non_malicious_info, low_risk_info = detector.detect_malicious_rundll32()
        detector.plot_results(axs[0,1])
        malicious_rundll32_process = [process.pid for process in malicious_info]
        #print('rundll32 process')
        #print(malicious_rundll32_process)
        
        # Credential Dump Detector Analysis
        detector = Detections.CredentialDumpDetector(processes_list, False)
        # Run detection and display results
        credential_dump_detections = detector.detect_credential_dumping()
        Detections.CredentialDumpDetector.plot_detection_summary(credential_dump_detections.values(), axs[0,2])
        #print('credential dumping')
        #print([detection for detection in credential_dump_detections.values() if (detection['method'] in ['ProcDump', 'rundll32 with comsvcs.dll'])])
        
        # Connection Detection Analysis
        # Instantiate and use ConnectionDetector
        detector = Detections.ConnectionDetector(memoryDump.connections_file)
        detector.display_countries(axs[1,0])
        
        # RunDll32 malicious child analysis
        detector = Detections.MaliciousRundll32Child() 
        detector.detect_lineage(processes_list)
        # Plot the lineage graph if not skipped
        detector.plot_process_lineage_with_hover(fig, axs[2,0])
        detector.plot_process_histogram(axs[1,1])
        #print('rundll32 child')
        #print(detector.malicious)
        rundll32_malicious_hierarchy = detector.malicious
        
        # Blacklisted ip analysis
        # Initialize the detector with file paths and call methods to perform analysis and plotting.
        detector = Detections.IPCategorytDetector(
            blacklist_file=blacklist_ips,
            whitelist_file=whitelist_ips,
            pstree_file=memoryDump.pstree_file,
            connections_file=memoryDump.connections_file
        )
        detector.categorize_ips(axs[2,2]) # Categorize foreign IPs and plot
        blacklist_pid_connection_counts = detector.blacklist_counts
        #detector.process_cmd_ip_analysis()        # Analyze CMD IPs and plot
        detector.plot_blacklist_connections_by_process(axs[2,1])  # #Plot blacklisted connections by process

        #print("processes with blacklisted connections")
        #print(detector.blacklist_counts)

        # Top 3 Foreign IPs with most connections
        ip_connection_count = defaultdict(int)
        pid_connection_count = defaultdict(int)
        for conn in memoryDump.connections:
            if conn['ForeignAddr'] in ['::', '*', '0.0.0.0']:
                continue
            else:
                ip_connection_count[conn['ForeignAddr']] += 1
            
            pid_connection_count[conn['PID']] +=1
        
        sorted_ip_connections = sorted(ip_connection_count.items(), key=lambda x: x[1], reverse=True)[:3]
        top_3_ip_connections = [ip for ip, count in sorted_ip_connections]
        top_3_counts_connections = [count for ip, count in sorted_ip_connections]
        top_3_labels_connections = [f"{ip}" for ip in top_3_ip_connections]

        axs[1, 2].set_title("Top 3 IPs with most connections")

        # Horizontal bar chart for top 3 IPs with most connections
        axs[1, 2].barh(top_3_labels_connections, top_3_counts_connections, 
                       color=["#ffb3e6", "#ff9999", "#ccff99"])

        # Set title
        axs[1, 2].set_title("Top 3 IPs with most Connections")
       
        # Adjust layout for readability
        plt.tight_layout(pad=3.0, h_pad=3.0, w_pad=3.0)
        plt.subplots_adjust(top=0.93)
        plt.show(block=True)
        
        # Get virus total results for all the ips and associate with corresponding processes.
        compromisedIPs = Detections.IPCategorytDetector.load_ip_list(blacklist_ips)
        safeIPs = Detections.IPCategorytDetector.load_ip_list(whitelist_ips)
        
        checked = {}
        vt_pids = defaultdict(list)
        
        for conn in network_connections:
        
            if conn.foreign_addr not in checked:
                result = Detections.IPDetectionModule.detect_malicious_ips([conn.foreign_addr], vt_key, compromisedIPs, safeIPs, None, False, True)
                #print(result)
                vt_pids[conn.pid].append(result)
                checked.update(result)
            else:
                #print(conn.foreign_addr + ' is already checked')
                vt_pids[conn.pid].append({conn.foreign_addr:checked[conn.foreign_addr]})
        
        #print('Checked : ' + str(checked))
        #print('VT Malicious PIDS : ' + str(vt_pids))
        
        # Processes Dictionary
        processes_dictionary = get_process_dictionary(processes_list)
        
        # Plot the process scatter visualization.
        process_data = []

        for pid,values in processes_dictionary.items():
            
            malicious_indicators = []
            is_malicious = False
            
            if pid in unsafe_extension_pids:
                is_malicious = True
                malicious_indicators.append('Malicious Extension')            
            
            if pid in credential_dump_detections and credential_dump_detections[pid]['method'] not in ['Benign', 'Null CMD']:
                malicious_indicators.append(credential_dump_detections[pid]['method'])
                is_malicious = True
                
            if pid in blacklist_pid_connection_counts:
                malicious_indicators.append('Blacklisted Connections. Total Connections : ' + str(blacklist_pid_connection_counts[pid]))
                is_malicious = True
            
            if pid in rundll32_malicious_hierarchy:
                malicious_indicators.append('Malicious rundll32 process hierarchy')
                is_malicious = True
                
            if pid in malicious_rundll32_process:
                malicious_indicators.append('No argument rundll32 process with connections')
                is_malicious = True
            
            if pid in vt_pids:
                for indicator in vt_pids[pid]:
                    ip, value = next(iter(indicator.items()))
                    tokens = value.split(':')
                    #print(pid, tokens)
                    if len(tokens) > 1 and int(tokens[0]) > 0: 
                        malicious_indicators.append('Connected with ' + ip + ' indicated by Virus Total as malicious. ' + tokens[0] + ' malicious indicators out of ' + tokens[1] + ' total indicators.')
                        is_malicious = True
            
            # String to convert
            date_string = values['CreateTime']

            # Replace the colon in the timezone offset to make it compatible
            date_string_fixed = date_string.split("+")[0]

            # Convert to datetime
            dt_object = datetime.strptime(date_string_fixed, "%Y-%m-%dT%H:%M:%S")
            
            process = {
                "name": values['ImageFileName'],
                "PID": pid,
                "connections": pid_connection_count[pid],
                "is_malicious": is_malicious,
                "creation_time": dt_object,
                "malicious_indicators": malicious_indicators
            }
            process_data.append(process)
        
        plotter = VisualizationModule.ScatterPlotter(process_data)
        plotter.plot(True)
       
