# Namespace: EmulationModule
import json
import random
import string
import numpy as np
import hashlib
from colorama import Fore, Style
from datetime import datetime
from typing import List, Dict
import math
from faker import Faker
# Initialize Faker object
fake = Faker()

# ANSI escape sequences for colors
RED = "\033[91m"  # Red for alerts and potential threats
GREEN = "\033[92m"  # Green for info
BLUE = "\033[94m"
RESET = "\033[0m"  # Reset to default color

class EmulationModule:
    # Parent Class: TestDataEmulator
    
    class TestDataEmulator:
        """
        TestDataEmulator is the primary class for data generation,
        supporting the creation of process trees and IP-based command emulation.
        This class utilizes its child classes for process generation and IP command creation.
        """

        @staticmethod
        def create_process_tree(total_processes, max_depth, max_children, extensions, parent_ids, exclude_pids, commandList=None):
            """
            Generate a list of root processes with a hierarchical tree structure,
            using the ProcessTreeEmulator for process tree creation.

            Args:
                total_processes (int): Total number of processes.
                max_depth (int): Maximum depth of the tree.
                max_children (int): Maximum children per node.
                extensions (list): List of file extensions for process names.
                parent_ids (list): List of parent PIDs for root processes.
                exclude_pids (set): Set of PIDs to exclude from generation.

            Returns:
                list: List of root processes with full tree structures.
            """
            return EmulationModule.ProcessTreeEmulator.generate_process_tree(
                total_processes, max_depth, max_children, extensions, parent_ids, exclude_pids, commandList
            )

        @staticmethod
        def generate_commands_with_ips(benign_ips, malicious_ips, benign_ratio, malicious_ratio, count):
            """
            Generate command strings using benign and malicious IP addresses
            based on specified ratios, utilizing IPCliEmulator for command structure.

            Args:
                benign_ips (list): List of benign IP addresses.
                malicious_ips (list): List of malicious IP addresses.
                benign_ratio (float): Ratio of benign IPs to total IPs.
                malicious_ratio (float): Ratio of malicious IPs to total IPs.
                count (int): Number of commands to generate.
            """
            
            commands = {'benign': [], 'malicious': []}
            for _ in range(count):
                is_benign = random.choices([True, False], weights=[benign_ratio, malicious_ratio])[0]
                ip_list = benign_ips if is_benign else malicious_ips
                ip = random.choice(ip_list)

                command = EmulationModule.IPCliEmulator.generate_command(ip, is_benign)
                
                if is_benign:
                    commands['benign'].append(command)
                else:
                    commands['malicious'].append(command)

            return commands

        @staticmethod
        def write_json_output(filename, process_list):
            """
            Writes the generated process tree to a specified JSON file.

            Args:
                filename (str): Path to the output file.
                process_list (list): List of root processes to serialize and save.
            """
            with open(filename, 'w') as f:
                # Collect all process dictionaries into a list
                process_dicts = [process.to_dict() for process in process_list]
                
                # Write the list of dictionaries as a JSON array
                json.dump(process_dicts, f, indent=4)
                    
    class ProcessTree:
        """Represents a single process with potential child processes."""
        def __init__(self, cmd, create_time, exit_time, image_file_name, pid, ppid, session_id, threads, wow64, children, audit=None, handles=None, offset=None, path=None):
            self.cmd = cmd
            self.create_time = create_time
            self.exit_time = exit_time
            self.image_file_name = image_file_name
            self.pid = pid
            self.ppid = ppid
            self.session_id = session_id
            self.threads = threads
            self.wow64 = wow64
            self.children = children
            self.audit = audit
            self.handles = handles
            self.offset = offset
            self.path = path

        def to_dict(self):
            """Convert the process object to a dictionary."""
            return {
                "Audit": self.audit,
                "Cmd": self.cmd,
                "CreateTime": self.create_time,
                "ExitTime": self.exit_time,
                "Handles": self.handles,
                "ImageFileName": self.image_file_name,
                "Offset(V)": self.offset,
                "PID": self.pid,
                "PPID": self.ppid,
                "Path": self.path,
                "SessionId": self.session_id,
                "Threads": self.threads,
                "Wow64": self.wow64,
                "__children": [child.to_dict() for child in self.children]
            }

    # Child Class: ProcessTreeEmulator
    class ProcessTreeEmulator:
        """
        Generates a hierarchical process tree for a given total number of processes,
        structured by depth and child constraints.
        """
        
        @staticmethod
        def generate_random_arguments():
            
            # Generate a random number of arguments (1 to 10)
            num_args = random.randint(1, 10)
            
            # Generate random command-line arguments
            arguments = []
            for _ in range(num_args):
                arg_type = random.choice(["flag", "key_value", "value"])
                if arg_type == "flag":
                    # Boolean flag arguments like `--help` or `-v`
                    arguments.append(f"--{fake.word()}")
                elif arg_type == "key_value":
                    # Key-value pairs like `--config=config.yaml`
                    key = fake.word()
                    value = fake.word() if random.choice([True, False]) else fake.file_path()
                    arguments.append(f"--{key}={value}")
                elif arg_type == "value":
                    # Standalone values like `input.txt` or `123`
                    arguments.append(fake.file_path() if random.choice([True, False]) else str(random.randint(1, 1000)))
    
            return arguments

        @staticmethod
        def generate_random_directory_path():
            # Randomly choose a drive letter from a list of possible drives
            drive_letter = random.choice(['C', 'D', 'E', 'F'])

            # Simulate directory structure
            directories = ["Program Files", "Users", "Windows", "Documents", "Downloads", "System32", "Temp", "AppData", "Music", "Pictures"]
            
            # Generate a random directory path
            path = drive_letter + ":\\"
            path += '\\'.join([random.choice(directories) for _ in range(random.randint(2, 4))]) + "\\"

            # Ensure double backslashes for Windows path format
            
            return path

        @staticmethod
        def generate_fake_process(pid_pool, ppid, extensions, exclude_pids, commandList=None):
            """
            Creates a single process node with random attributes.

            Args:
                pid_pool (set): Set of available PIDs.
                ppid (int): Parent PID for the new process.
                extensions (list): List of file extensions for process name.
                exclude_pids (set): Set of PIDs to exclude from generation.
                commandList (list): Processes names and cmd will be randomly picked from this.

            Returns:
                ProcessTree: New process object.
            """
            if commandList != None and len(commandList) > 0:
                # Randomly select an index
                random_index = random.randint(0, len(commandList) - 1)

                # Capture the command at that index
                cmd = commandList[random_index]

                # Remove the element from the list
                commandList.pop(random_index)
                
                if len(extensions) > 0:                
                    # Assign the file name as well.
                    image_file_name=cmd.split(' ')[0].split('.')[0] + "-" + str(fake.random_int(min=1000, max=9999)) + random.choice(extensions)
                    
                    # Reset the cmd as per file name
                    cmd = image_file_name + ' ' + ' '.join(cmd.split(' ')[1:])
                else:
                    image_file_name=cmd.split(' ')[0]
                
                path = EmulationModule.ProcessTreeEmulator.generate_random_directory_path() + image_file_name
                
            else:
                image_file_name=fake.word() + "-" + str(fake.random_int(min=1000, max=9999)) + random.choice(extensions)
                
                path = EmulationModule.ProcessTreeEmulator.generate_random_directory_path() + image_file_name
                cmd = path + " " + " ".join(EmulationModule.ProcessTreeEmulator.generate_random_arguments())
            
            pid = random.choice(list(pid_pool - exclude_pids))
            process = EmulationModule.ProcessTree(
                cmd=cmd,
                create_time=fake.date_time_between(start_date='-30d', end_date='now').isoformat() + "+00:00",
                exit_time=None,
                image_file_name=image_file_name,
                pid=pid,
                ppid=ppid,
                path=path,
                session_id=random.randint(0, 10),
                threads=random.randint(1, 20),
                wow64=fake.boolean(),
                children=[]
            )
            return process

        @staticmethod
        def distribute_processes_across_depths(root, total_processes, max_depth, max_children, pid_pool, extensions, exclude_pids, commandList=None):
            """
            Assign child processes to nodes, creating a tree-like structure.

            Args:
                root (ProcessTree): Root process of the tree.
                total_processes (int): Total processes in the tree.
                max_depth (int): Maximum depth of the tree.
                max_children (int): Max children per node.
                pid_pool (set): Available PIDs.
                extensions (list): List of file extensions for process name.
                exclude_pids (set): PIDs to exclude.
            """
            remaining_processes = total_processes - 1
            current_generation = [root]
            current_depth = 0

            while remaining_processes > 0 and current_generation and current_depth < max_depth:
                next_generation = []
                for parent_process in current_generation:
                    if remaining_processes <= 0:
                        break

                    for _ in range(max_children):
                        if remaining_processes <= 0:
                            break
                        child_process = EmulationModule.ProcessTreeEmulator.generate_fake_process(pid_pool, parent_process.pid, extensions, exclude_pids, commandList)
                        parent_process.children.append(child_process)
                        next_generation.append(child_process)
                        pid_pool.remove(child_process.pid)
                        remaining_processes -= 1
                current_generation = next_generation
                current_depth += 1
        
        @staticmethod
        def total_in_single_tree(N, K):
            # Special case: when N is 1
            if N == 1:
                return K + 1
            # General case: when N is not 1
            return (N**(K+1) - 1) // (N - 1)
            
        @staticmethod
        def generate_process_tree(total_processes, max_depth, max_children, extensions, parent_ids, exclude_pids, commandList=None):
            """
            Create a complete process tree structure with the specified parameters.

            Args:
                total_processes (int): Total processes in the tree.
                max_depth (int): Maximum depth of the tree.
                max_children (int): Max children per node.
                extensions (list): File extensions for process name.
                parent_ids (list): Parent IDs for root processes.
                exclude_pids (set): PIDs to exclude from creation.

            Returns:
                list: List of root processes with full tree structures.
            """
            processes = []
            pid_pool = set(range(1000, 65000)) - exclude_pids
            num_roots = math.ceil(total_processes/ EmulationModule.ProcessTreeEmulator.total_in_single_tree(max_children, max_depth))
            
            print(EmulationModule.ProcessTreeEmulator.total_in_single_tree(max_children, max_depth), total_processes, num_roots)

            for _ in range(num_roots):
                root_process = EmulationModule.ProcessTreeEmulator.generate_fake_process(pid_pool, random.choice(parent_ids), extensions, exclude_pids, commandList)
                processes.append(root_process)
                pid_pool.remove(root_process.pid)

            total_created = 0
            for root in processes:
                remaining_count = total_processes - total_created
                max_per_parent = min(EmulationModule.ProcessTreeEmulator.total_in_single_tree(max_children, max_depth), remaining_count)
                EmulationModule.ProcessTreeEmulator.distribute_processes_across_depths(root, max_per_parent, max_depth, max_children, pid_pool, extensions, exclude_pids, commandList)
                total_created += max_per_parent

            return processes
        
        @staticmethod
        def createTree(processes, exclude_pids):
            """
            Create a process tree with a simple hierarchy as defined by the `processes` list.
            
            Args:
                processes (list): List of process names in hierarchical order.
                exclude_pids (set): Set of PIDs to exclude from generation.
                
            Returns:
                list: Root process with child hierarchy as defined by `processes`.
            """
            if not processes:
                return []

            pid_pool = set(range(1000, 65000)) - exclude_pids
            root_process = EmulationModule.ProcessTreeEmulator.generate_fake_process(pid_pool, ppid=0, extensions=[], exclude_pids=exclude_pids, commandList=[processes[0]])
            current_process = root_process
            pid_pool.remove(root_process.pid)

            for process_name in processes[1:]:
                child_process = EmulationModule.ProcessTreeEmulator.generate_fake_process(pid_pool, ppid=current_process.pid, extensions=[], exclude_pids=exclude_pids, commandList=[process_name])
                current_process.children.append(child_process)
                current_process = child_process  # Move down the hierarchy
                pid_pool.remove(current_process.pid)

            return root_process

    class IPCliEmulator:
        """
        Emulates command-line behavior by generating commands with IP addresses and arguments.
        """

        @staticmethod
        def load_ips(filename):
            """
            Load IPs from a file.

            Args:
                filename (str): Path to file containing IPs.

            Returns:
                list: List of IP addresses.
            """
            try:
                with open(filename, 'r') as file:
                    return [line.strip() for line in file.readlines() if line.strip()]
            except FileNotFoundError:
                print(f"Error: File '{filename}' not found.")
                exit(1)

        @staticmethod
        def parse_ratio(ratio_arg):
            """
            Parse benign-to-malicious IP ratio.

            Args:
                ratio_arg (str): Ratio in "benign:malicious" format.

            Returns:
                tuple: Benign and malicious ratios as floats.
            """
            benign_ratio, malicious_ratio = map(int, ratio_arg.split(":"))
            total = benign_ratio + malicious_ratio
            return benign_ratio / total, malicious_ratio / total

        @staticmethod
        def generate_command(ip, is_benign):
            """
            Create a command string with IP and command-line options.

            Args:
                ip (str): IP to include in command.
                is_benign (bool): Whether IP is benign or malicious.

            Returns:
                str: Command string.
            """
            command_base = fake.file_name(extension="exe")
            ip_option = random.choice(["-i", "-ip", "--ipaddress"]) if random.choice([True, False]) else ""
            extra_args = [
                f"-user {fake.user_name()}",
                f"-port {random.randint(1024, 65535)}",
                f"-config {fake.file_path(extension='conf')}",
                "--verbose",
                f"--timeout {random.randint(1, 60)}",
                fake.domain_name()
            ]
            random.shuffle(extra_args)
            extra_args_str = " ".join(extra_args[:random.randint(1, 3)])

            if ip_option:
                return f"{command_base} {ip_option} {ip} {extra_args_str}"
            else:
                return f"{command_base} {ip} {extra_args_str}"
       
    # Class for generating benign and malicious rundll32 command executions
    class RunDLL32MaliciousParent:
        """
        RunDLL32MaliciousParent generates fake rundll32 commands with
        benign or malicious parent processes to simulate suspicious process lineage detection.
        """
        
        # List of common suspicious parent processes
        SUSPICIOUS_PARENTS = [
            "winword.exe", "excel.exe", "msaccess.exe", "lsass.exe", "taskeng.exe",
            "winlogon.exe", "schtask.exe", "regsvr32.exe", "wmiprvse.exe", "wsmprovhost.exe"
        ]

        @staticmethod
        def parse_ratio(ratio_arg):
            """
            Parse the benign:malicious ratio argument.

            Args:
                ratio_arg (str): Ratio in the form "benign:malicious".

            Returns:
                tuple: (benign_ratio, malicious_ratio) as floats.
            """
            try:
                benign_ratio, malicious_ratio = map(int, ratio_arg.split(":"))
                total = benign_ratio + malicious_ratio
                return benign_ratio / total, malicious_ratio / total
            except ValueError:
                print("Error: Invalid ratio format. Use 'benign:malicious' format (e.g., 9:1).")
                exit(1)

        @staticmethod
        def generate_command_chain(is_benign, depth):
            """
            Generate a command chain for rundll32.exe with specified depth, starting with either
            a benign or suspicious parent process.

            Args:
                is_benign (bool): If True, generate a chain starting with a benign process; if False, with a suspicious one.
                depth (int): Number of processes in the command chain.

            Returns:
                str: Formatted command chain string.
            """
            # Initialize the chain with the first parent process
            chain = []
            parent_process = fake.file_name(extension="exe") if is_benign else random.choice(EmulationModule.RunDLL32MaliciousParent.SUSPICIOUS_PARENTS)
            chain.append(parent_process)
            
            # Add intermediate processes
            for _ in range(depth - 1):
                process_name = "rundll32.exe" if _ == depth - 2 else fake.file_name(extension="exe")
                command = f"{process_name} {fake.file_path(extension='dll')}, {fake.word()}"
                chain.append(command)

            # Join the process chain with '->' to show hierarchy
            return " -> ".join(chain)

        @staticmethod
        def generate_commands(benign_ratio, malicious_ratio, count, depth):
            """
            Generate a set of commands based on the provided benign-to-malicious ratio.

            Args:
                benign_ratio (float): Proportion of benign commands to total commands.
                malicious_ratio (float): Proportion of malicious commands to total commands.
                count (int): Total number of commands to generate.
                depth (int): Depth of the process chain for each command.

            Returns:
                dict: Dictionary with keys 'benign' and 'malicious' containing lists of commands.
            """
            commands = {'benign': [], 'malicious': []}
            
            for _ in range(count):
                is_benign = random.choices([True, False], weights=[benign_ratio, malicious_ratio])[0]
                command_chain = EmulationModule.RunDLL32MaliciousParent.generate_command_chain(is_benign, depth)
                if is_benign:
                    commands['benign'].append(command_chain)
                else:
                    commands['malicious'].append(command_chain)
                    
            return commands

    class ConnectionGenerator:
        """Generates network connections in JSON format with specified parameters."""
        
        def __init__(self, n, benign_ips, malicious_ips, benign_ratio, malicious_ratio, exclude_pids, processes):
            self.n = n
            self.benign_ips = benign_ips
            self.malicious_ips = malicious_ips
            self.benign_ratio = benign_ratio
            self.malicious_ratio = malicious_ratio
            self.exclude_pids = exclude_pids
            self.processes = [proc for proc in processes if proc['PID'] not in exclude_pids]
            self.used_ports = set()

        @staticmethod
        def load_ips(filename):
            """Load IP addresses from a file."""
            try:
                with open(filename, 'r') as file:
                    return [line.strip() for line in file if line.strip()]
            except FileNotFoundError:
                print(f"Error: File '{filename}' not found.")
                exit(1)

        @staticmethod
        def parse_ratio(ratio_arg):
            """Parse benign-to-malicious ratio."""
            benign_ratio, malicious_ratio = map(int, ratio_arg.split(":"))
            total = benign_ratio + malicious_ratio
            return benign_ratio / total, malicious_ratio / total

        @staticmethod
        def load_process_tree(filename):
            """Load process data from JSON file."""
            try:
                with open(filename, 'r') as file:
                    return json.load(file)
            except FileNotFoundError:
                print(f"Error: pstree file '{filename}' not found.")
                exit(1)

        def generate_single_connection(self, newProcess=None):
            """Generate a single connection entry."""
            # Choose benign or malicious foreign IP based on ratio
            is_benign = random.choices([True, False], weights=[self.benign_ratio, self.malicious_ratio])[0]
            foreign_addr = random.choice(self.benign_ips if is_benign else self.malicious_ips)
            foreign_port = random.randint(1024, 65535)
            
            # Ensure unique local ports
            local_port = random.randint(1024, 65535)
            while local_port in self.used_ports:
                local_port = random.randint(1024, 65535)
            self.used_ports.add(local_port)

            # Randomly select process details from loaded process tree
            process = random.choice(self.processes) if not newProcess else newProcess
            owner = process['ImageFileName']
            pid = process['PID']

            # Generate other connection fields
            proto = random.choice(["TCPv4", "TCPv6", "UDPv4", "UDPv6"])
            state = random.choice(["ESTABLISHED", "LISTENING"]) if proto.startswith("TCP") else ""
            offset = random.randint(1, 999999999999999)  # Random offset value
            created_time = datetime.utcnow().isoformat() + "+00:00"

            # Create the connection entry dictionary
            return {
                "Created": created_time,
                "ForeignAddr": foreign_addr,
                "ForeignPort": foreign_port,
                "LocalAddr": "10.0.2.15",  # Fake local address
                "LocalPort": local_port,
                "Offset": offset,
                "Owner": owner,
                "PID": pid,
                "Proto": proto,
                "State": state,
                "__children": []
            }

        def generate_connections(self):
            """Generate multiple connections."""
            return [self.generate_single_connection() for _ in range(self.n)]
        
        def generate_connections_for_process(self, process):
            """Generate a list of connections for a single process."""
            connections = []
            for _ in range(2):
                connection = self.generate_single_connection(process)
                connections.append(connection)
            return connections

        def generate_connections_for_all_processes(self):
            """Generate connections for all processes in self.processes."""
            all_connections = []
            for process in self.processes:
                all_connections.extend(self.generate_connections_for_process(process))
            return all_connections
            
    class CredentialDumpGenerator:
        def __init__(self, count: int, ratio: str = "9:1"):
            self.count = count
            self.benign_commands = []
            self.malicious_commands = []

            # Parse the benign-to-malicious ratio
            benign_ratio, malicious_ratio = map(int, ratio.split(":"))
            total_ratio = benign_ratio + malicious_ratio
            self.benign_prob = benign_ratio / total_ratio
            self.malicious_prob = malicious_ratio / total_ratio

        def generate_commands(self) -> Dict[str, List[str]]:
            """
            Generate benign and malicious commands.
            """
            for _ in range(self.count):
                if random.random() < self.malicious_prob:
                    command = self.generate_malicious_command()
                    self.malicious_commands.append(command)
                else:
                    command = self.generate_benign_command()
                    self.benign_commands.append(command)

            return {"benign": self.benign_commands, "malicious": self.malicious_commands}

        def generate_benign_command(self) -> str:
            """
            Generate a benign command with random parameters and filenames.
            """
            filename = fake.file_name(extension="exe")
            params = " ".join(fake.words(random.randint(1, 3)))
            command = f"{filename} -param1 {params} -config {random.randint(1000, 9999)}"
            return command

        def generate_malicious_command(self) -> str:
            """
            Generate a malicious credential dumping command with double backslashes in paths.
            """
            if random.choice([True, False]):
                # ProcDump command with random path for the output file
                fake_path = fake.file_path(depth=2).replace("/", "\\")
                command = f"procdump.exe -ma lsass.exe -o {fake_path}\\lsass_dump.dmp"
            else:
                # rundll32 command with comsvcs.dll
                pid = random.randint(1000, 9999)
                fake_path = fake.file_path(depth=2).replace("/", "\\")
                command = f"rundll32.exe {fake_path}\\comsvcs.dll MiniDump {pid} lsass.dmp full"
            return command
            
    class LDRModulesEmulator:
        def __init__(self, pid_process_map):
            """
            Initialize the emulator with a dictionary of Pid and Process mappings.
            :param pid_process_map: Dictionary where keys are Pid and values are Process names.
            """
            self.pid_process_map = pid_process_map
            self.faker = Faker()

        def generate_module_entry(self, pid, process):
            """
            Generate a single module entry.
            :param pid: Process ID.
            :param process: Process name.
            :return: A dictionary representing a single module entry.
            """
            return {
                "Base": random.randint(1000000000, 4000000000),
                "InInit": random.choice([True, False]),
                "InLoad": random.choice([True, False]),
                "InMem": random.choice([True, False]),
                "MappedPath": random.choice(['\\Windows\\System32\\','\\Windows\\SysWOW64\\']) + self.faker.file_name(extension='dll'),
                "Pid": pid,
                "Process": process,
                "__children": []
            }

        def generate_modules(self, count_per_process=5):
            """
            Generate a list of module entries for all processes.
            :param count_per_process: Number of modules to generate per process.
            :return: List of all module entries.
            """
            modules = []
            for pid, values in self.pid_process_map.items():
                for _ in range(count_per_process):
                    modules.append(self.generate_module_entry(pid,values['ImageFileName']))
            return modules

        def save_to_file(self, filename, modules):
            """
            Save the generated modules to a JSON file.
            :param filename: Name of the file to save the data.
            :param modules: List of module entries.
            """
            with open(filename, 'w') as file:
                json.dump(modules, file, indent=4)

    class KeysEmulator:
        def __init__(self, num_entries):
            self.num_entries = num_entries
            self.fake = Faker()
            self.generated_data = []

        def generate_entry(self, name):
            entry = {
                "Data": "",
                "Hive Offset": random.randint(100000000000000, 999999999999999),
                "Key": self.fake.file_path(depth=random.randint(1, 3)),
                "Last Write Time": self.fake.date_time_this_decade().isoformat() + "+00:00",
                "Name": name,
                "Type": random.choice(["Key", "User", "REG_SZ", "REG_DWORD"]),
                "Volatile": random.choice([True, False]),
                "__children": []
            }
            return entry
        
        def unique_name(self, existing_names, length=8):
            while True:
                name = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
                if name not in existing_names:
                    existing_names.add(name)
                    return name

        def generate_data(self):
            used_names = set()
            for _ in range(self.num_entries):
                name = self.unique_name(used_names)
                self.generated_data.append(self.generate_entry(name))
                used_names.add(name)

        def save_to_file(self, file_name):
            with open(file_name, "w") as file:
                json.dump(self.generated_data, file, indent=4)

    class UserEmulator:
        def __init__(self, num_users):
            self.num_users = num_users
            self.fake = Faker()
            self.generated_data = []

        def generate_unique_hash(self):
            """Generate a unique hash using random bytes."""
            random_bytes = random.getrandbits(128).to_bytes(16, 'big')
            return hashlib.md5(random_bytes).hexdigest()

        def generate_entry(self, rid):
            """Generate a single JSON object for a user."""
            entry = {
                "User": self.fake.first_name(),
                "__children": [],
                "lmhash": self.generate_unique_hash(),
                "nthash": self.generate_unique_hash(),
                "rid": rid
            }
            return entry

        def generate_data(self):
            """Generate unique user entries."""
            used_rids = set()
            for _ in range(self.num_users):
                rid = random.randint(100, 1000000)
                while rid in used_rids:  # Ensure unique RIDs
                    rid = random.randint(100, 1000000)
                used_rids.add(rid)
                self.generated_data.append(self.generate_entry(rid))

        def save_to_file(self, file_name):
            """Save generated data to a JSON file."""
            with open(file_name, "w") as file:
                json.dump(self.generated_data, file, indent=4)

    class RunDllGenerator:
        def __init__(self, ratio="8:1:1", verbose=False):
            self.verbose = verbose
            self.benign_ratio, self.low_risk_ratio, self.malicious_ratio = map(int, ratio.split(':'))
            self.network_connections = []  # Placeholder for network connection objects
            self.table_data = []           # Placeholder for table of malicious process connections
            self.process_list = []         # Placeholder for process list

        def generate_benign_command(self):
            """Generate a benign command with plausible arguments using Faker."""
            file_name = fake.file_name(extension="dll")
            func_name = fake.word()
            log_path = fake.file_path(depth=2, extension="log")
            return f"rundll32.exe {file_name},{func_name} --log={log_path}"

        def generate_low_risk_command(self):
            """Generate a low-risk command."""

            return "rundll32.exe"

        def generate_malicious_command(self):
            """Generate a suspicious rundll32.exe command without arguments."""
            return "rundll32.exe" + ("" if random.choice([True, False]) else "->" + fake.file_name())  # Malicious command without arguments with or without child

        def generate_commands(self):
            """Generates benign, low-risk, and malicious rundll32 commands."""
            categorized = {'benign': [], 'low_risk': [], 'malicious': []}
            for _ in range(self.benign_ratio):
                categorized['benign'].append(self.generate_benign_command())
            for _ in range(self.low_risk_ratio):    
                categorized['low_risk'].append(self.generate_low_risk_command())
            for _ in range(self.malicious_ratio):
                categorized['malicious'].append(self.generate_malicious_command())
            
            return categorized