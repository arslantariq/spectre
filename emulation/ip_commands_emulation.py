import argparse
import random
from faker import Faker
from colorama import Fore, Style
from TestDataEmulator import EmulationModule

# Main function for command-line interaction
def main():
    # Set up argument parser for command-line arguments
    parser = argparse.ArgumentParser(description="Generate command-line arguments with benign and malicious IPs.")
    parser.add_argument("--benign", required=True, help="Path to the benign IPs file")
    parser.add_argument("--malicious", required=True, help="Path to the malicious IPs file")
    parser.add_argument("--ratio", default="90:10", help="Ratio of benign to malicious IPs, format benign:malicious (default 90:10)")
    parser.add_argument("--count", type=int, default=10, help="Number of commands to generate (default 10)")

    # Parse command-line arguments
    args = parser.parse_args()

    # Load IPs from files using IPCliEmulator
    benign_ips = EmulationModule.IPCliEmulator.load_ips(args.benign)
    malicious_ips = EmulationModule.IPCliEmulator.load_ips(args.malicious)

    # Parse the benign to malicious ratio
    benign_ratio, malicious_ratio = EmulationModule.IPCliEmulator.parse_ratio(args.ratio)

    # Generate commands using the TestDataEmulator class
    command_dict = EmulationModule.TestDataEmulator.generate_commands_with_ips(benign_ips, malicious_ips, benign_ratio, malicious_ratio, args.count)
       
    # Display commands with color coding
    print("Benign Ips:")
    for command in command_dict['benign']:
        #processes.append(command)
        print(f"{Fore.GREEN}{command}{Style.RESET_ALL}")
    
    print("\nMalicious Malicious:")
    for command in command_dict['malicious']:
        #processes.append(command)
        print(f"{Fore.RED}{command}{Style.RESET_ALL}")

    exclude_pids = set()
        
    # Generate the process tree using ProcessTreeEmulator
    process_list = EmulationModule.TestDataEmulator.create_process_tree(
        total_processes=len(command_dict['malicious']) + len(command_dict['benign']),
        max_depth=0,
        max_children=1,
        extensions=[],
        parent_ids=[0],
        exclude_pids=exclude_pids, commandList=command_dict['malicious'] + command_dict['benign'])

    EmulationModule.TestDataEmulator.write_json_output('ip_commands_pstree.json', process_list)
    
    print('Processes generated in file ip_commands_pstree.json' )

# Entry point for script execution
if __name__ == "__main__":
    main()
