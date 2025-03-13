import json
import random
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import numpy as np
from collections import Counter, defaultdict
import os
import random
import re
from typing import List, Tuple, Dict, Any
from operator import itemgetter
from colorama import Fore, Style

""" Following statements are required to add parent paths to import JsonModule"""
from inspect import getsourcefile
import os.path
import sys
current_path = os.path.abspath(getsourcefile(lambda:0))
current_dir = os.path.dirname(current_path)
parent_dir = current_dir[:current_dir.rfind(os.path.sep)]
sys.path.insert(0, parent_dir + os.path.sep + "json")

from JsonModule import *

class TimelinePlotter:
    """Plots timelines for both network connections and process creations from JSON files."""
    
    def __init__(self, pstree_file=None, connections_file=None):
        self.pstree_file = pstree_file
        self.connections_file = connections_file
        self.process_data = self.load_process_data()
        self.connection_data = self.load_connection_data()
        self.pid_to_name = self.map_pid_to_name()

    def load_process_data(self):
        """Load process creation data from a JSON file or generate random data if no file is provided."""
        if self.pstree_file:
            with open(self.pstree_file, 'r') as file:
                return json.load(file)
        else:
            return self.generate_random_process_data()

    def generate_random_process_data(self):
        """Generate random process data with potential child processes over a 30-minute period."""
        base_time = datetime.now()
        
        def create_random_process(level=0):
            """Recursively create random process data with a chance for children."""
            process = {
                "CreateTime": (base_time + timedelta(minutes=random.randint(0, 29), seconds=random.randint(0, 59))).isoformat(),
                "__children": [create_random_process(level + 1) for _ in range(random.randint(0, 2))] if level < 2 else []
            }
            return process

        return [create_random_process() for _ in range(20)]

    def load_connection_data(self):
        """Load network connection data from a JSON file or generate random data if no file is provided."""
        if self.connections_file:
            with open(self.connections_file, 'r') as file:
                return json.load(file)
        else:
            return self.generate_random_connection_data()

    def generate_random_connection_data(self):
        """Generate random network connections over a 1-hour period."""
        base_time = datetime.now()
        connections = []
        for _ in range(40):
            connection = {
                "Created": (base_time + timedelta(minutes=random.randint(0, 59), seconds=random.randint(0, 59))).isoformat(),
            }
            connections.append(connection)
        return connections

    def parse_creation_times(self, process, times):
        """Recursively parse creation times from a process and its children, storing each time in a list."""
        try:

            timestamp = process.get("CreateTime")
            creation_time = datetime.fromisoformat(timestamp)
            times.append(creation_time)
        except Exception as e:
            #print(f"CreateTime for process {process.get('PID')} is invalid: {e}. Ignoring this entry")
            pass

        # Recur for each child process
        for child in process.get("__children", []):
            self.parse_creation_times(child, times)

    def get_process_creation_times(self):
        """Get all process creation times, including children processes."""
        creation_times = []
        for process in self.process_data:
            self.parse_creation_times(process, creation_times)
        return creation_times

    def get_connection_creation_times(self):
        """Get creation times from all network connections."""
        connection_times = []
        for connection in self.connection_data:
            try:
                timestamp = connection.get("Created")
                connection_time = datetime.fromisoformat(timestamp)
                connection_times.append(connection_time)
            except Exception as e:
                print(f"Error parsing creation time for connection: {e}")
        return connection_times

    def plot_timelines(self, block=True):
        """Plot timelines for process creations and network connections on the same graph."""
        # Get creation times
        process_times = self.get_process_creation_times()
        connection_times = self.get_connection_creation_times()
        
        if not process_times and not connection_times:
            print("No valid data found for processes or connections.")
            return

        # Prepare data for plotting
        process_counts_by_time = self.aggregate_counts_by_minute(process_times)
        connection_counts_by_time = self.aggregate_counts_by_minute(connection_times)

        # Combine time series for a unified x-axis
        all_times = sorted(set(process_counts_by_time.keys()).union(connection_counts_by_time.keys()))
        process_counts = [process_counts_by_time.get(time, 0) for time in all_times]
        connection_counts = [connection_counts_by_time.get(time, 0) for time in all_times]

        # Plotting
        plt.figure(figsize=(12, 6))
        plt.plot(all_times, process_counts, label='Process Creations', color='purple', marker='o')
        plt.plot(all_times, connection_counts, label='Network Connections', color='blue', marker='x')
        plt.xlabel("Time (by minute)")
        plt.ylabel("Number of Events")
        plt.title("Process Creation and Network Connection Timeline")
        plt.xticks(rotation=45, ha='right')
        plt.legend()
        plt.tight_layout()
        plt.grid(True)

        # Set the figure window title if supported
        fig_manager = plt.get_current_fig_manager()
        if fig_manager is not None:
            fig_manager.set_window_title('Process and Connection Timeline')

        plt.show(block=block)
        
    def aggregate_counts_by_minute(self, times):
        """Aggregate event counts by minute."""
        counts_by_time = {}
        for time in times:
            minute = time.replace(second=0, microsecond=0)  # Group by minute
            counts_by_time[minute] = counts_by_time.get(minute, 0) + 1
        return counts_by_time

    def plot_top_processes_by_connections(self, top_n=10, block=True):
        """Plot the top N processes with the most connections, including process name (ImageFileName) and PID."""       
        
        # Recursive function to flatten pstree data and get PID to process name mapping
        def get_pid_to_name(data, pid_to_name):
            pid_to_name[data["PID"]] = data["ImageFileName"]
            for child in data.get("__children", []):
                get_pid_to_name(child, pid_to_name)

        pid_to_name = {}
        for process in self.process_data:
            get_pid_to_name(process, pid_to_name)

        # Initialize dictionaries to hold counts per protocol per PID
        protocol_counts_by_pid = {
            'TCPv4': Counter(),
            'TCPv6': Counter(),
            'UDPv4': Counter(),
            'UDPv6': Counter()
        }
        
        # Populate the protocol counts by PID
        for connection in self.connection_data:
            pid = connection.get("PID")
            protocol = connection.get("Proto")
            if pid and protocol in protocol_counts_by_pid:
                protocol_counts_by_pid[protocol][pid] += 1
        
        # Get the total connection count for each PID and select the top N PIDs
        total_counts = Counter()
        for protocol, counts in protocol_counts_by_pid.items():
            total_counts.update(counts)
        top_pids = [pid for pid, _ in total_counts.most_common(top_n)]
        
        if not top_pids:
            print(f"No processes found to plot for top {top_n} connections.")
            return

        # Prepare data for stacked bar plot
        protocols = ['TCPv4', 'TCPv6', 'UDPv4', 'UDPv6']
        pid_labels = [
            f"{pid_to_name.get(pid, 'Unknown')}\n(PID: {pid})"
            for pid in top_pids
        ]
        protocol_data = [
            [protocol_counts_by_pid[protocol][pid] for pid in top_pids]
            for protocol in protocols
        ]

        # Plotting stacked bar chart
        fig, ax = plt.subplots(figsize=(12, 8))
        colors = ['lightsteelblue', 'lightcoral', 'lightgreen', 'lightpink']
        
        bottom = np.zeros(len(top_pids))
        for data, color, protocol in zip(protocol_data, colors, protocols):
            ax.bar(pid_labels, data, label=protocol, bottom=bottom, color=color)
            bottom += data

        # Labels and legend
        ax.set_xlabel("Process Name and PID")
        ax.set_ylabel("Number of Connections")
        ax.set_title(f"Top {top_n} Processes by Connection Count (Stacked by Protocol)")
        ax.legend(title="Protocol")
        
        # Show plot
        #plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show(block=block)

    def map_pid_to_name(self):
        """Map PIDs to process names from pstree data recursively."""
        pid_to_name = {}
        
        def get_pid_to_name(data):
            pid_to_name[data["PID"]] = data["ImageFileName"]
            for child in data.get("__children", []):
                get_pid_to_name(child)
                
        for process in self.process_data:
            get_pid_to_name(process)
        
        return pid_to_name

    def get_connection_counts(self):
        """Get connection and process counts by minute and identify top processes."""
        connection_counts_by_time = Counter()
        process_counts_by_time = defaultdict(Counter)

        for entry in self.connection_data:
            created_time = datetime.fromisoformat(entry["Created"])
            pid = entry["PID"]
            minute_time = created_time.replace(second=0, microsecond=0)
            connection_counts_by_time[minute_time] += 1
            process_counts_by_time[minute_time][pid] += 1

        return connection_counts_by_time, process_counts_by_time

    def plot_combined_timelines(self, block=True):
        """Plot connections/process timeline and top processes per timeslot in vertically arranged plots."""
        connection_counts_by_time, process_counts_by_time = self.get_connection_counts()

        # Sort the timeslots
        all_times = sorted(set(connection_counts_by_time.keys()).union(process_counts_by_time.keys()))

        # Extract connection counts for each time slot
        connections_per_minute = [connection_counts_by_time.get(time, 0) for time in all_times]
        
        # Prepare data for top processes plot
        top_processes_per_timeslot = []
        for time in all_times:
            # Identify the top 3 processes with the most connections at each timeslot
            top_processes = process_counts_by_time[time].most_common(3)
            top_processes_per_timeslot.append({
                "time": time,
                "processes": [(self.pid_to_name.get(pid, f"PID: {pid}"), count) for pid, count in top_processes]
            })

        # Plot the timelines
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 14), gridspec_kw={'height_ratios': [3, 4]}, facecolor="#f8f9fa")

        # Plot connections and process timeline
        ax1.plot(all_times, connections_per_minute, label="Connections", color="skyblue", marker="o", linestyle='-', markerfacecolor='white')
        ax1.set_xlabel("Time", color="gray")
        ax1.set_ylabel("Number of Connections", color="gray")
        ax1.set_title("Connections Over Time", color="dimgray")
        ax1.grid(True, color="lightgray")
        ax1.tick_params(axis='x', colors="gray")
        ax1.tick_params(axis='y', colors="gray")

        # Plot top 3 processes for each timeslot
        for entry in top_processes_per_timeslot:
            time = entry["time"]
            processes = entry["processes"]

            # Process data for stacked bar plot
            x_pos = all_times.index(time)  # Position on the x-axis
            heights = [count for _, count in processes]
            labels = [f"{name}" for name, _ in processes]

            # Stacked bar chart for top processes
            bottom = 0
            for height, label in zip(heights, labels):
                ax2.bar(x_pos, height, bottom=bottom, label=label, alpha=0.7)
                bottom += height

        ax2.set_xticks(range(len(all_times)))
        ax2.set_xticklabels([time.strftime("%H:%M") for time in all_times], rotation=45, ha='right', color="gray")
        ax2.set_xlabel("", color="gray")
        ax2.set_ylabel("Number of Connections", color="gray")
        fig.text(0.5, 0.02, "Top Processes by Connection Count", ha='center', va='center', fontsize=12, color="dimgray")
        ax2.legend(loc="upper left", title="Processes", bbox_to_anchor=(1.05, 1), frameon=False)
        ax2.grid(True, color="lightgray")
        ax2.tick_params(axis='x', colors="gray")
        ax2.tick_params(axis='y', colors="gray")

        plt.tight_layout()
        plt.show(block=block)
        
class ProcessTimeLineAnalysis:
    def __init__(self, file_list: List[str]):
        self.file_list = file_list  # List of file paths
        self.diffs = []  # Store differences for plotting

    @staticmethod
    def read_json_from_file(filename: str) -> str:
        with open(filename, 'r') as file:
            return file.read()

    def compute_differences(self, tree1: List[MemoryForensicsNamespace.ProcessTree], tree2: List[MemoryForensicsNamespace.ProcessTree]):
        diffs = []

        def process_node(node1, node2, relationship="Parent"):
            if node1 and not node2:
                diffs.append((node1.pid, relationship, "Removed", node1.image_file_name, node1.cmd))
            elif node2 and not node1:
                diffs.append((node2.pid, relationship, "New", node2.image_file_name, node2.cmd))
                if node2.exit_time:
                    diffs.append((node2.pid, relationship, "Removed", node2.image_file_name, node2.cmd))
            else:
                
                old_exit_time = node1.exit_time.isoformat() if node1.exit_time else None
                new_exit_time = node2.exit_time.isoformat() if node2.exit_time else None
                if old_exit_time != new_exit_time:
                    diffs.append((node2.pid, relationship, "Removed", node2.image_file_name, node2.cmd))
                else:
                    updates = []
                    keys_to_check = [
                        "Audit", "ImageFileName", "Cmd", "PPID", "CreateTime", "Handles",
                        "Offset(V)", "Path", "SessionId", "Threads", "Wow64"
                    ]
                    for key in keys_to_check:
                        old_value = getattr(node1, key.lower(), None)
                        new_value = getattr(node2, key.lower(), None)
                        if old_value != new_value:
                            updates.append((key, old_value, new_value))

                    if updates:
                        for key, old_value, new_value in updates:
                            diffs.append((node1.pid, relationship, "Updated", f"{key}: {old_value}", f"{key}: {new_value}"))
                    else:
                        diffs.append((node1.pid, relationship, "Consistent", node1.image_file_name, node1.cmd))

            children1 = {child.pid: child for child in node1.children} if node1 else {}
            children2 = {child.pid: child for child in node2.children} if node2 else {}
            all_pids = set(children1.keys()).union(children2.keys())
            for pid in all_pids:
                process_node(children1.get(pid), children2.get(pid), "Child")

        tree1_map = {node.pid: node for node in tree1}
        tree2_map = {node.pid: node for node in tree2}
        all_pids = set(tree1_map.keys()).union(tree2_map.keys())
        for pid in all_pids:
            process_node(tree1_map.get(pid), tree2_map.get(pid))

        added = [p for p in diffs if p[2] == "New"]
        removed = [p for p in diffs if p[2] == "Removed"]
        updated = [p for p in diffs if p[2] == "Updated"]
        consistent = [p for p in diffs if p[2] == "Consistent"]
        
        return added, removed, updated, consistent

    def plot_comparison_results(self, axis=None):
        comparisons = [f"T{i+2}" for i in range(len(self.diffs))]

        added_lengths = [len(diff['added']) for diff in self.diffs]
        removed_lengths = [len(diff['removed']) for diff in self.diffs]
        updated_lengths = [len(diff['updated']) for diff in self.diffs]
        consistent_lengths = [len(diff['consistent']) for diff in self.diffs]

        if axis is None:
            # Create a new figure and axes
            fig, axs = plt.subplots(2, 2, figsize=(10, 8))
            axs = axs.ravel()  # Flatten the 2D array to 1D for easier indexing
        else:
            # Use the provided axis, assumed to be a 1D array-like of axes
            axs = axis

        # Plot data in each subplot
        axs[0].plot(comparisons, added_lengths, label="Added", color="blue", marker="o")
        axs[0].set_title("Added Processes")
        axs[0].set_ylabel("Count")

        axs[1].plot(comparisons, removed_lengths, label="Removed", color="red", marker="o")
        axs[1].set_title("Removed Processes")
        axs[1].set_ylabel("Count")

        axs[2].plot(comparisons, updated_lengths, label="Updated", color="orange", marker="o")
        axs[2].set_title("Updated Processes")
        axs[2].set_ylabel("Count")

        axs[3].plot(comparisons, consistent_lengths, label="Consistent", color="green", marker="o")
        axs[3].set_title("Consistent Processes")
        axs[3].set_ylabel("Count")

        # Adjust layout only if creating a new figure
        if axis is None:
            plt.tight_layout()
            plt.show()


    def compare_files(self):
        file_list_sorted = sorted(self.file_list, key=lambda f: int(re.search(r'(\d+)', f).group()))

        for i in range(len(file_list_sorted) - 1):
            old_file = file_list_sorted[i]
            new_file = file_list_sorted[i + 1]

            old_json = self.read_json_from_file(old_file)
            new_json = self.read_json_from_file(new_file)
            old_entries = parse_audit_entry_list(old_json)
            new_entries = parse_audit_entry_list(new_json)

            added, removed, updated, consistent = self.compute_differences(old_entries, new_entries)

            self.diffs.append({
                'added': added,
                'removed': removed,
                'updated': updated,
                'consistent': consistent
            })

        self.plot_comparison_results()

class ModulesTimeLineAnalysis:
    def __init__(self, file_list: List[str]):
        """
        Initialize the analysis with a list of files.
        """
        self.file_list = file_list  # List of JSON files
        self.diffs = []  # To store differences for plotting

    def compute_differences(self, old_modules, new_modules) -> Tuple[List[Any], List[Any], List[Tuple[Any, List[Tuple[str, Any, Any]]]], List[Any]]:
        """
        Compute differences between old and new module lists.
        Returns:
            - added: List of modules added in the new list.
            - removed: List of modules removed in the new list.
            - updated: List of tuples (module, changes).
            - consistent: List of modules that remained consistent.
        """
        old_set = {(mod.Pid, mod.MappedPath): mod for mod in old_modules}
        new_set = {(mod.Pid, mod.MappedPath): mod for mod in new_modules}

        added = [new_set[key] for key in new_set if key not in old_set]
        removed = [old_set[key] for key in old_set if key not in new_set]
        updated = []
        consistent = []

        monitored_keys = ["Base", "InInit", "InLoad", "InMem", "Process"]

        for key in old_set:
            if key in new_set:
                old_mod = old_set[key]
                new_mod = new_set[key]
                changes = []
                for field in monitored_keys:
                    old_value = getattr(old_mod, field, None)
                    new_value = getattr(new_mod, field, None)
                    if old_value != new_value:
                        changes.append((field, old_value, new_value))
                if changes:
                    updated.append((new_mod, changes))
                else:
                    consistent.append(new_mod)

        return added, removed, updated, consistent

    def plot_comparison_results(self):
        """
        Plot the comparison results for added, removed, updated, and consistent modules.
        """
        comparisons = [f"T{i+2}" for i in range(len(self.diffs))]

        added_lengths = [len(diff['added']) for diff in self.diffs]
        removed_lengths = [len(diff['removed']) for diff in self.diffs]
        updated_lengths = [len(diff['updated']) for diff in self.diffs]
        consistent_lengths = [len(diff['consistent']) for diff in self.diffs]

        plt.figure(figsize=(10, 8))

        # Subplot 1: Added
        plt.subplot(2, 2, 1)
        plt.plot(comparisons, added_lengths, label='Added', color='blue')
        plt.title('Added Modules')
        plt.xlabel('Comparison')
        plt.ylabel('Count')

        # Subplot 2: Removed
        plt.subplot(2, 2, 2)
        plt.plot(comparisons, removed_lengths, label='Removed', color='red')
        plt.title('Removed Modules')
        plt.xlabel('Comparison')
        plt.ylabel('Count')

        # Subplot 3: Updated
        plt.subplot(2, 2, 3)
        plt.plot(comparisons, updated_lengths, label='Updated', color='orange')
        plt.title('Updated Modules')
        plt.xlabel('Comparison')
        plt.ylabel('Count')

        # Subplot 4: Consistent
        plt.subplot(2, 2, 4)
        plt.plot(comparisons, consistent_lengths, label='Consistent', color='green')
        plt.title('Consistent Modules')
        plt.xlabel('Comparison')
        plt.ylabel('Count')

        plt.tight_layout()
        plt.show()

    def compare_files(self):
        """
        Compare module lists across files and visualize the results.
        """
        file_list_sorted = sorted(self.file_list, key=lambda f: int(re.search(r'(\d+)', f).group()))
        
        for i in range(len(file_list_sorted) - 1):
            # Load JSON from two consecutive files
            with open(file_list_sorted[i], 'r') as file1, open(file_list_sorted[i + 1], 'r') as file2:
                json_data1 = file1.read()
                json_data2 = file2.read()

            # Parse JSON into LdrModule objects
            old_module_list = parse_module_json(json_data1)
            new_module_list = parse_module_json(json_data2)

            # Compute differences
            added, removed, updated, consistent = self.compute_differences(old_module_list, new_module_list)

            # Store the differences
            self.diffs.append({
                'added': added,
                'removed': removed,
                'updated': updated,
                'consistent': consistent
            })

        # Plot the results
        self.plot_comparison_results()

# Define the ConnectionTimeLineAnalysis class
class ConnectionTimeLineAnalysis:
    def __init__(self, file_list: List[str]):
        self.file_list = file_list  # List of files to compare
        self.connection_diffs = []  # Store differences

    # Function to compute differences between connection lists
    def compute_connection_differences(self, old_connections, new_connections):
        old_set = {f"{proc.owner} ({proc.pid}) {proc.foreign_addr}:{proc.foreign_port} {proc.local_addr}:{proc.local_port}": proc for proc in old_connections}
        new_set = {f"{proc.owner} ({proc.pid}) {proc.foreign_addr}:{proc.foreign_port} {proc.local_addr}:{proc.local_port}": proc for proc in new_connections}

        added = [new_set[key] for key in new_set if key not in old_set]
        removed = [old_set[key] for key in old_set if key not in new_set]
        updated = []
        consistent = []

        # Keys to monitor for changes
        monitored_keys = ["Created", "ForeignAddr", "ForeignPort", "LocalAddr", "LocalPort", "Offset", "Owner", "PID", "Proto", "State"]

        # Check for any updated fields between old and new process data
        for key in old_set:
            if key in new_set:
                old_proc = old_set[key]
                new_proc = new_set[key]
                changes = []
                for field in monitored_keys:
                    old_value = getattr(old_proc, field.lower(), None)
                    new_value = getattr(new_proc, field.lower(), None)
                    if old_value != new_value:
                        changes.append((field, old_value, new_value))
                if changes:
                    updated.append((new_proc, changes))
                else:
                    consistent.append(new_proc)  # Track consistent connections

        return added, removed, updated, consistent

    # Function to plot the comparison results for added, removed, updated, and consistent lengths
    def plot_comparison_results(self):
        comparisons = [f"T{i+2}" for i in range(len(self.connection_diffs))]

        added_lengths = [len(diff['added']) for diff in self.connection_diffs]
        removed_lengths = [len(diff['removed']) for diff in self.connection_diffs]
        updated_lengths = [len(diff['updated']) for diff in self.connection_diffs]
        consistent_lengths = [len(diff['consistent']) for diff in self.connection_diffs]

        plt.figure(figsize=(10, 8))

        # Subplot 1: Added
        plt.subplot(2, 2, 1)
        plt.plot(comparisons, added_lengths, label='Added', color='blue', marker='o')
        plt.title('Added Connections')
        plt.ylabel('Count')
        plt.xticks(rotation=45)

        # Subplot 2: Removed
        plt.subplot(2, 2, 2)
        plt.plot(comparisons, removed_lengths, label='Removed', color='red', marker='o')
        plt.title('Removed Connections')
        plt.ylabel('Count')
        plt.xticks(rotation=45)

        # Subplot 3: Updated
        plt.subplot(2, 2, 3)
        plt.plot(comparisons, updated_lengths, label='Updated', color='orange', marker='o')
        plt.title('Updated Connections')
        plt.ylabel('Count')
        plt.xticks(rotation=45)

        # Subplot 4: Consistent
        plt.subplot(2, 2, 4)
        plt.plot(comparisons, consistent_lengths, label='Consistent', color='green', marker='o')
        plt.title('Consistent Connections')
        plt.ylabel('Count')
        plt.xticks(rotation=45)

        plt.tight_layout()
        plt.show()

    # Main function to compare files
    def compare_connection_files(self):
    
        # Sort files based on sequence number in the filename
        file_list_sorted = sorted(self.file_list, key=lambda f: int(re.search(r'(\d+)', f).group()))

        for i in range(len(file_list_sorted) - 1):
            # Load JSON from two consecutive files
            with open(file_list_sorted[i], 'r') as file1, open(file_list_sorted[i+1], 'r') as file2:
                json_data1 = file1.read()
                json_data2 = file2.read()

            # Parse JSON into NetworkConnection objects
            old_connection_list = parse_connection_json(json_data1)
            new_connection_list = parse_connection_json(json_data2)

            # Compute differences between the two consecutive JSON files
            added, removed, updated, consistent = self.compute_connection_differences(old_connection_list, new_connection_list)

            # Store the lengths of the differences for plotting later
            self.connection_diffs.append({
                'added': added,
                'removed': removed,
                'updated': updated,
                'consistent': consistent
            })

        # Plot the results of comparisons
        self.plot_comparison_results()


class RegistryTimelineAnalysis:
    def __init__(self, file_list: List[str]):
        """
        Initialize with a list of JSON files to analyze.
        """
        self.file_list = file_list  # List of file paths
        self.diffs = []  # Store the comparison results

    @staticmethod
    def parse_json(json_string: str) -> List[Dict[str, Any]]:
        """
        Parse a JSON string into a list of dictionary entries.
        """
        return json.loads(json_string)

    @staticmethod
    def read_json_from_file(filename: str) -> str:
        """
        Read JSON data from a file.
        """
        with open(filename, 'r') as file:
            return file.read()

    def compute_differences(self, old_entries: List[Dict[str, Any]], new_entries: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Tuple[Dict[str, Any], List[Tuple[str, Any, Any]]]], List[Dict[str, Any]]]:
        """
        Compute differences between old and new registry entries.
        Returns:
            - added: List of new entries not in the old set.
            - removed: List of old entries not in the new set.
            - updated: List of tuples containing entry and changes.
            - consistent: List of unchanged entries.
        """
        old_set = {entry["Name"]: entry for entry in old_entries}
        new_set = {entry["Name"]: entry for entry in new_entries}

        added = [new_set[key] for key in new_set if key not in old_set]
        removed = [old_set[key] for key in old_set if key not in new_set]
        updated = []
        consistent = []

        monitored_keys = ["Data", "Hive Offset", "Key", "Last Write Time", "Name", "Type", "Volatile"]

        for key in old_set:
            if key in new_set:
                old_entry = old_set[key]
                new_entry = new_set[key]
                changes = []
                for field in monitored_keys:
                    old_value = old_entry.get(field)
                    new_value = new_entry.get(field)
                    if old_value != new_value:
                        changes.append((field, old_value, new_value))
                if changes:
                    updated.append((new_entry, changes))
                else:
                    consistent.append(new_entry)

        return added, removed, updated, consistent

    def plot_comparison_results(self):
        """
        Plot the comparison results stored in `self.diffs`.
        """
        comparisons = [f"T{i+2}" for i in range(len(self.diffs))]

        added_lengths = [len(diff['added']) for diff in self.diffs]
        removed_lengths = [len(diff['removed']) for diff in self.diffs]
        updated_lengths = [len(diff['updated']) for diff in self.diffs]
        consistent_lengths = [len(diff['consistent']) for diff in self.diffs]

        plt.figure(figsize=(10, 8))

        # Subplot 1: Added
        plt.subplot(2, 2, 1)
        plt.plot(comparisons, added_lengths, label='Added', color='blue', marker='o')
        plt.title('Added Keys')
        plt.ylabel('Count')
        plt.xticks(rotation=45)

        # Subplot 2: Removed
        plt.subplot(2, 2, 2)
        plt.plot(comparisons, removed_lengths, label='Removed', color='red', marker='o')
        plt.title('Removed Keys')
        plt.ylabel('Count')
        plt.xticks(rotation=45)

        # Subplot 3: Updated
        plt.subplot(2, 2, 3)
        plt.plot(comparisons, updated_lengths, label='Updated', color='orange', marker='o')
        plt.title('Updated Keys')
        plt.ylabel('Count')
        plt.xticks(rotation=45)

        # Subplot 4: Consistent
        plt.subplot(2, 2, 4)
        plt.plot(comparisons, consistent_lengths, label='Consistent', color='green', marker='o')
        plt.title('Consistent Keys')
        plt.ylabel('Count')
        plt.xticks(rotation=45)

        plt.tight_layout()
        plt.show()

    def compare_files(self):
        """
        Compare registry entries across JSON files in sequence and visualize the results.
        """
        # Sort files by sequence number in filenames
        file_list_sorted = sorted(self.file_list, key=lambda f: int(re.search(r'(\d+)', f).group()))

        for i in range(len(file_list_sorted) - 1):
            old_file = file_list_sorted[i]
            new_file = file_list_sorted[i + 1]

            # Read and parse JSON data
            old_json = self.read_json_from_file(old_file)
            new_json = self.read_json_from_file(new_file)
            old_entries = self.parse_json(old_json)
            new_entries = self.parse_json(new_json)

            # Compute differences
            added, removed, updated, consistent = self.compute_differences(old_entries, new_entries)

            # Store the differences for plotting
            self.diffs.append({
                'added': added,
                'removed': removed,
                'updated': updated,
                'consistent': consistent
            })

        # Plot the comparison results
        self.plot_comparison_results()
