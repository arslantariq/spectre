import json
from collections import defaultdict
from collections import Counter
import matplotlib.pyplot as plt
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

class MemoryDiff:
    def __init__(self):
        self.connection_updates = {}
        self.process_updates = {}
        self.registry_updates = {}
        self.modules_updates = {}
        self.user_updates = {}
        self.top_connections = {'old':{'PID':None, 'count':None}, 'new':{'PID':None, 'count':None}}

    def compare_dumps(self, dump1, dump2):
        self.diffConnections(dump1.connections, dump2.connections)
        self.diffProcesses(dump1.processes, dump2.processes)
        self.diffRegistries(dump1.registries, dump2.registries)
        self.diffModules(dump1.modules, dump2.modules)
        self.diffUsers(dump1.users, dump2.users)
        
        return {
            'connection_updates': self.connection_updates,
            'process_updates': self.process_updates,
            'registry_updates': self.registry_updates,
            'modules_updates': self.modules_updates,
            'user_updates': self.user_updates
        }
        
        #return self.generate_delta_report()

    def generate_delta_report(self):
        report = {
            'connection_updates': self.connection_updates,
            'process_updates': self.process_updates,
            'registry_updates': self.registry_updates,
            'modules_updates': self.modules_updates,
            'user_updates': self.user_updates
        }
        with open("delta_report.html", "w") as file:
            file.write("<html><head><title>Delta Report</title></head><body><h1>Delta Report</h1><pre>")
            file.write(json.dumps(report, indent=4))
            file.write("</pre></body></html>")
        return report

    def diffConnections(self, old_connections, new_connections):
        old_set = {f"{conn['Owner']} ({conn['PID']}) {conn['ForeignAddr']}:{conn['ForeignPort']} {conn['LocalAddr']}:{conn['LocalPort']}": conn for conn in old_connections}
        new_set = {f"{conn['Owner']} ({conn['PID']}) {conn['ForeignAddr']}:{conn['ForeignPort']} {conn['LocalAddr']}:{conn['LocalPort']}": conn for conn in new_connections}

        added = [new_set[key] for key in new_set if key not in old_set]
        removed = [old_set[key] for key in old_set if key not in new_set]
        updated = []
        consistent = []

        monitored_keys = ["Created", "ForeignAddr", "ForeignPort", "LocalAddr", "LocalPort", "Offset", "Owner", "PID", "Proto", "State"]

        for key in old_set:
            if key in new_set:
                old_conn = old_set[key]
                new_conn = new_set[key]
                changes = []
                for field in monitored_keys:
                    old_value = old_conn.get(field)
                    new_value = new_conn.get(field)
                    if old_value != new_value:
                        changes.append((field, old_value, new_value))
                if changes:
                    updated.append((new_conn, changes))
                else:
                    consistent.append(new_conn)
        
        # Get process with most connection 
        old_counter= Counter([conn['PID'] for conn in old_connections])
        old_common = old_counter.most_common(1)
        if old_common:
            process, count = old_common[0]
            self.top_connections['old']={'PID':process, 'count':count}
        
        # Get process with most connection 
        new_counter= Counter([conn['PID'] for conn in new_connections])
        new_common = new_counter.most_common(1)
        if new_common:
            process, count = new_common[0]
            self.top_connections['new']={'PID':process, 'count':count}
        
        self.connection_updates = {'added': added, 'removed': removed, 'updated': updated, 'consistent': consistent}
        
        self.conn_added = len(self.connection_updates['added'])
        self.conn_removed = len(self.connection_updates['removed'])
        self.conn_updated = len(self.connection_updates['updated'])
        self.conn_consistent = len(self.connection_updates['consistent'])
        
        return self.connection_updates

    def diffProcesses(self, tree1, tree2):
        diffs = []
        # Parse the JSON data
        tree1 = parse_ProcessTree_json(tree1)
        tree2 = parse_ProcessTree_json(tree2)

        def process_node(node1, node2, relationship='Parent'):
            if node1 and not node2:
                diffs.append((node1.pid, relationship, "Removed", node1.image_file_name, node1.cmd))
            elif node2 and not node1:
                diffs.append((node2.pid, relationship, "New", node2.image_file_name, node2.cmd))
                if node2.exit_time != None:
                    diffs.append((node2.pid, relationship, "Removed", node2.image_file_name, node2.cmd))
            else:
                
                # Check specifically for ExitTime where one might be None
                old_exit_time = node1.exit_time.isoformat() if node1.exit_time else None
                new_exit_time = node2.exit_time.isoformat() if node2.exit_time else None
                if old_exit_time != new_exit_time:
                    diffs.append((node2.pid, relationship, "Removed", node2.image_file_name, node2.cmd))                
                else:                               
                    # Check for updates
                    updates = []
                    keys_to_check = ["Audit", "ImageFileName", "Cmd", "PPID", "CreateTime", "Handles", "Offset(V)", "Path", "SessionId", "Threads", "Wow64"]
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

            # Check children recursively
            children1 = {child.pid: child for child in node1.children} if node1 else {}
            children2 = {child.pid: child for child in node2.children} if node2 else {}

            # Iterate over all unique PIDs from both nodes
            all_pids = set(children1.keys()).union(children2.keys())
            for pid in all_pids:
                process_node(children1.get(pid), children2.get(pid), 'Child')

        # Match roots
        tree1_map = {node.pid: node for node in tree1}
        tree2_map = {node.pid: node for node in tree2}
        
        all_pids = set(tree1_map.keys()).union(tree2_map.keys())
        for pid in all_pids:
            process_node(tree1_map.get(pid), tree2_map.get(pid))
        
        self.process_updates = diffs
        self.proc_added = len([p for p in self.process_updates if p[2] == "New"])
        self.proc_removed = len([p for p in self.process_updates if p[2] == "Removed"])
        self.proc_updated = len([p for p in self.process_updates if p[2] == "Updated"])
        self.proc_consistent = len([p for p in self.process_updates if p[2] == "Consistent"])

        return diffs

    def diffRegistries(self, old_registries, new_registries):
        
        old_set = {entry["Name"]: entry for entry in old_registries}
        new_set = {entry["Name"]: entry for entry in new_registries}

        added = [new_set[key] for key in new_set if key not in old_set]
        removed = [old_set[key] for key in old_set if key not in new_set]
        updated = []
        consistent = []

        monitored_keys = ["Data", "Hive Offset", "Key", "Last Write Time", "Name", "Type", "Volatile"]

        # Check for changes between old and new entries
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
       
        self.registry_updates = {'added': added, 'removed': removed, 'updated': updated, 'consistent': consistent}
        
        self.reg_added = len(self.registry_updates['added'])
        self.reg_removed = len(self.registry_updates['removed'])
        self.reg_updated = len(self.registry_updates['updated'])
        self.reg_consistent = len(self.registry_updates['consistent'])
        
        return self.registry_updates

    def diffModules(self, old_modules, new_modules):    
        old_modules = [LdrModule.from_dict(item) for item in old_modules]
        new_modules = [LdrModule.from_dict(item) for item in new_modules]

        old_set = {(mod.Pid, mod.MappedPath): mod for mod in old_modules}
        new_set = {(mod.Pid, mod.MappedPath): mod for mod in new_modules}

        added = [new_set[key] for key in new_set if key not in old_set]
        removed = [old_set[key] for key in old_set if key not in new_set]
        updated = []
        consistent = []

        # Keys to monitor for changes (no need to convert to lowercase)
        monitored_keys = ["Base", "InInit", "InLoad", "InMem", "Process"]

        # Check for any updated fields between old and new module data
        for key in old_set:
            if key in new_set:
                old_mod = old_set[key]
                new_mod = new_set[key]
                changes = []
                for field in monitored_keys:
                    # Use the correct field name without modifying case
                    old_value = getattr(old_mod, field, None)
                    new_value = getattr(new_mod, field, None)
                    if old_value != new_value:
                        changes.append((field, old_value, new_value))
                if changes:
                    updated.append((new_mod, changes))
                else:
                    consistent.append(new_mod)  # Track consistent modules
        self.modules_updates = {'added': added, 'removed' : removed, 'updated': updated, 'consistent' : consistent}
        
        self.mod_added = len(self.modules_updates['added'])
        self.mod_removed = len(self.modules_updates['removed'])
        self.mod_updated = len(self.modules_updates['updated'])
        self.mod_consistent = len(self.modules_updates['consistent'])
        
        return self.modules_updates

    def diffUsers(self, old_users, new_users):
        
        old_users = {entry["User"]: entry for entry in old_users}
        new_users = {entry["User"]: entry for entry in new_users}        
        added = {user: new_users[user] for user in new_users if user not in old_users}
        removed = {user: old_users[user] for user in old_users if user not in new_users}
        updated = {user: (old_users[user], new_users[user]) for user in old_users if user in new_users and old_users[user] != new_users[user]}
        consistent = {user: (old_users[user], new_users[user]) for user in old_users if user in new_users}
        
        self.user_updates = {'added': added, 'removed' : removed, 'updated': updated, 'consistent' : consistent}
        
        self.usr_added = len(self.user_updates['added'])
        self.usr_removed = len(self.user_updates['removed'])
        self.usr_updated = len(self.user_updates['updated'])
        self.usr_consistent = len(self.user_updates['consistent'])
        
        return self.user_updates

class DeltaAnalysis:
    def __init__(self, memoryDiff):
        self.memoryDiff = memoryDiff
        
    def plotConnectionUpdates(self):
        added = len(self.memoryDiff.connection_updates['added'])
        removed = len(self.memoryDiff.connection_updates['removed'])
        updated = len(self.memoryDiff.connection_updates['updated'])
        consistent = len(self.memoryDiff.connection_updates['consistent'])

        labels = ['New Connections', 'Removed Connections', 'Updated Connections', 'Consistent Connections']
        counts = [added, removed, updated, consistent]
        colors = ['#76c7c0', '#ff6f61', '#ffcc5c', '#4caf50']

        plt.figure(figsize=(10, 6))
        plt.bar(labels, counts, color=colors)
        plt.title('Process Connections Comparison')
        plt.xlabel('Connection Type')
        plt.ylabel('Count')
        plt.show()

    def plotProcessUpdates(self):
        added = len([p for p in self.memoryDiff.process_updates if p[2] == "New"])
        removed = len([p for p in self.memoryDiff.process_updates if p[2] == "Removed"])
        updated = len([p for p in self.memoryDiff.process_updates if p[2] == "Updated"])
        consistent = len([p for p in self.memoryDiff.process_updates if p[2] == "Consistent"])

        labels = ['New Processes', 'Removed Processes', 'Updated Processes', 'Consistent Processes']
        counts = [added, removed, updated, consistent]
        colors = ['#76c7c0', '#ff6f61', '#ffcc5c', '#4caf50']

        plt.figure(figsize=(10, 6))
        plt.bar(labels, counts, color=colors)
        plt.title('Process Updates Comparison')
        plt.xlabel('Process Type')
        plt.ylabel('Count')
        plt.show()

    def plotCombinedUpdates(self):
        # Prepare data for plots
        # Process Updates
        proc_labels = ['New', 'Removed', 'Updated', 'Consistent']
        proc_counts = [self.memoryDiff.proc_added, self.memoryDiff.proc_removed, self.memoryDiff.proc_updated, self.memoryDiff.proc_consistent]
        proc_colors = ['#b3e5fc', '#ffcccb', '#fff9c4', '#c8e6c9']  # Light colors

        # Connection Updates
        conn_labels = ['New', 'Removed', 'Updated', 'Consistent']
        conn_counts = [self.memoryDiff.conn_added, self.memoryDiff.conn_removed, self.memoryDiff.conn_updated, self.memoryDiff.conn_consistent]
        conn_colors = ['#c5cae9', '#f8bbd0', '#ffe0b2', '#dcedc8']  # Light colors
        
        # Top Connection Processes
        categories = ['Old', 'New']
        counts = [self.memoryDiff.top_connections['old']['count'], self.memoryDiff.top_connections['new']['count']]
        pids = [self.memoryDiff.top_connections['old']['PID'], self.memoryDiff.top_connections['new']['PID']]       

        # Module Updates
        mod_labels = ['New', 'Removed', 'Updated', 'Consistent']
        mod_counts = [self.memoryDiff.mod_added, self.memoryDiff.mod_removed, self.memoryDiff.mod_updated, self.memoryDiff.mod_consistent]
        mod_colors = ['#bbdefb', '#ffccbc', '#fff8e1', '#d1c4e9']  # Light colors

        # Registry Updates
        reg_labels = ['New', 'Removed', 'Updated', 'Consistent']
        reg_counts = [self.memoryDiff.reg_added, self.memoryDiff.reg_removed, self.memoryDiff.reg_updated, self.memoryDiff.reg_consistent]
        reg_colors = ['#e1bee7', '#c8e6c9', '#ffecb3', '#b2ebf2']  # Light colors

        # User Updates
        usr_labels = ['New', 'Removed', 'Updated', 'Consistent']
        usr_counts = [self.memoryDiff.usr_added, self.memoryDiff.usr_removed, self.memoryDiff.usr_updated, self.memoryDiff.usr_consistent]
        usr_colors = ['#ffe0b2', '#d1c4e9', '#c5e1a5', '#f8bbd0']  # Light colors

        # Create 2x3 grid for subplots
        fig, axs = plt.subplots(2, 3, figsize=(15, 9))
        #fig.suptitle('Dumps Delta', fontsize=18, fontweight='bold')
        # Set the figure window title if supported
        fig_manager = plt.get_current_fig_manager()
        if fig_manager is not None:
            fig_manager.set_window_title('Delta Analysis')

        # Bar charts
        # Process Updates
        axs[0, 0].bar(proc_labels, proc_counts, color=proc_colors)
        axs[0, 0].set_title('Process Updates')
        axs[0, 0].set_ylabel('Count')

        # Connection Updates
        axs[0, 1].bar(conn_labels, conn_counts, color=conn_colors)
        axs[0, 1].set_title('Connection Updates')
        axs[0, 1].set_ylabel('Count')
        
        # Top Connections
        bars = axs[0, 2].barh(categories, counts, color=["#76c7c0", "#ff6f61"], height=0.5)

        # Adding process IDs inside the bars
        for bar, pid in zip(bars, pids):
            width = bar.get_width()
            axs[0, 2].text(width / 2, bar.get_y() + bar.get_height() / 2, f"PID: {pid}", 
                    ha='center', va='center', color="white", weight='bold')

        axs[0, 2].set_title("Process with most connections")
        axs[0, 2].set_ylabel("Process Type")

        # Module Updates
        axs[1, 0].barh(mod_labels, mod_counts, color=mod_colors)
        axs[1, 0].set_ylabel('Count')
        axs[1, 0].set_xlabel("")
        axs[1, 0].set_title("Module Updates", loc='left', y=0.9)

        # Registry Updates
        axs[1, 1].barh(reg_labels, reg_counts, color=reg_colors)
        #axs[1, 1].set_ylabel('Count')
        axs[1, 1].set_xlabel("")
        axs[1, 1].set_title("Registry Updates", loc='left', y=0.9)

        # User Updates
        axs[1, 2].barh(usr_labels, usr_counts, color=usr_colors)
        #axs[1, 2].set_ylabel('Count')
        axs[1, 2].set_title("User Updates", loc='left', y=0.9)
        axs[1, 2].set_xlabel("")


        # Adjust layout
        plt.tight_layout(rect=[0, 0, 1, 0.95])
        plt.show(block=True)

    def plotAdditionalDeltas(self):
        categories = ['Processes', 'Connections', 'Keys', """'Modules',""" 'Users']
        # Total number of changes for each category (added + removed + updated)
        total_changes = {
            'Processes': self.memoryDiff.proc_added + self.memoryDiff.proc_removed + self.memoryDiff.proc_updated,
            'Connections': self.memoryDiff.conn_added + self.memoryDiff.conn_removed + self.memoryDiff.conn_updated,
            'Keys': self.memoryDiff.reg_added + self.memoryDiff.reg_removed + self.memoryDiff.reg_updated,
            #'Modules': self.memoryDiff.mod_added + self.memoryDiff.mod_removed + self.memoryDiff.mod_updated,
            'Users': self.memoryDiff.usr_added + self.memoryDiff.usr_removed + self.memoryDiff.usr_updated
        }

        # Prepare data for pie chart
        category_names = list(total_changes.keys())
        category_values = list(total_changes.values())

        # Create grid for subplots
        fig, axs = plt.subplots(2, 3, figsize=(15, 9))
        # Set the figure window title if supported
        fig_manager = plt.get_current_fig_manager()
        if fig_manager is not None:
            fig_manager.set_window_title('Delta Analysis')

        # Create pie chart
        #axs[0, 0].pie(category_values, labels=category_names, autopct='%1.1f%%', startangle=140, colors=['skyblue', 'lightgreen', 'orange', 'gold', 'lightcoral'])
        axs[0, 0].barh(category_names, category_values, color=['gold', 'lightgreen', 'orange', 'skyblue'])

        # Add title
        axs[0, 0].set_title('Total Changes by Category\n(Added, Removed, Updated)', fontsize=14)

        # Equal aspect ratio ensures that pie chart is drawn as a circle
        #axs[0, 0].axis('equal')

        # Display the plot
        plt.show()
        
    def plotModulesUpdates(self):
        # Set up counters for each type of change
        labels = ['New Modules', 'Removed Modules', 'Updated Modules', 'Consistent Modules']
        counts = [len(self.memoryDiff.modules_updates['added']), len(self.memoryDiff.modules_updates['removed']), len(self.memoryDiff.modules_updates['updated']), len(self.memoryDiff.modules_updates['consistent'])]
        colors = ['#76c7c0', '#ff6f61', '#ffcc5c', '#4caf50']

        # Create the plot
        plt.figure(figsize=(10, 6))
        plt.bar(labels, counts, color=colors)
        plt.title('LDR Modules Comparison')
        plt.xlabel('Module Type')
        plt.ylabel('Count')
        plt.show()

    def plotRegistriesUpdates(self):
        
        added = len(self.memoryDiff.registry_updates['added'])
        removed = len(self.memoryDiff.registry_updates['removed'])
        updated = len(self.memoryDiff.registry_updates['updated'])
        consistent = len(self.memoryDiff.registry_updates['consistent'])
        
        labels = ['New Entries', 'Removed Entries', 'Updated Entries', 'Consistent Entries']
        counts = [added, removed, updated, consistent]
        colors = ['#76c7c0', '#ff6f61', '#ffcc5c', '#4caf50']

        plt.figure(figsize=(10, 6))
        plt.bar(labels, counts, color=colors)
        plt.title('Registry Entries Comparison')
        plt.xlabel('Entry Type')
        plt.ylabel('Count')
        plt.show()

    def plotUserUpdates(self):
        
        added = len(self.memoryDiff.user_updates['added'])
        removed = len(self.memoryDiff.user_updates['removed'])
        updated = len(self.memoryDiff.user_updates['updated'])
        consistent = len(self.memoryDiff.user_updates['consistent'])
        
        labels = ['New Users', 'Removed Users', 'Updated Users', 'Consistent Users']
        counts = [added, removed, updated, consistent]
        colors = ['#76c7c0', '#ff6f61', '#ffcc5c', '#4caf50']

        plt.figure(figsize=(10, 6))
        plt.bar(labels, counts, color=colors)
        plt.title('Users Comparison')
        plt.xlabel('Entry Type')
        plt.ylabel('Count')
        plt.show()

