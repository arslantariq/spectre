import argparse
import random
from faker import Faker
from colorama import Fore, Style
from TestDataEmulator import EmulationModule 

# Main function to handle command-line argument parsing and command generation
def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Generate command-line rundll32.exe executions with benign and malicious parent processes.")
    parser.add_argument("--ratio", default="9:1", help="Ratio of benign to malicious commands, format benign:malicious (default 90:10)")
    parser.add_argument("--count", type=int, default=10, help="Number of commands to generate (default 10)")
    parser.add_argument("--depth", type=int, default=2, help="Depth of the process chain in each command (minimum 2)")
    
    # Parse command-line arguments
    args = parser.parse_args()

    # Ensure minimum depth is 2
    if args.depth < 2:
        print("Error: Depth must be at least 2.")
        exit(1)

    # Parse the benign:malicious ratio
    benign_ratio, malicious_ratio = EmulationModule.RunDLL32MaliciousParent.parse_ratio(args.ratio)
    
    # Generate commands
    command_dict = EmulationModule.RunDLL32MaliciousParent.generate_commands(benign_ratio, malicious_ratio, args.count, args.depth)
    
    processes = []
    
    # Display commands with color coding
    print("Benign Commands:")
    for command in command_dict['benign']:
        hierchy = [i.strip() for i in command.split('->')]
        processes.append(hierchy)
        print(f"{Fore.GREEN}{command}{Style.RESET_ALL}")
    
    print("\nMalicious Commands:")
    for command in command_dict['malicious']:
        hierchy = [i.strip() for i in command.split('->')]
        processes.append(hierchy)
        print(f"{Fore.RED}{command}{Style.RESET_ALL}")

    exclude_pids = set()
        
    # Generate the process list
    process_list = []
    for process in processes:
        process_list.append(EmulationModule.ProcessTreeEmulator.createTree(process, exclude_pids))

    EmulationModule.TestDataEmulator.write_json_output('rundll32_parent_pstree.json', process_list)
    
    print('Processes generated in file rundll32_parent_pstree.json')
    
if __name__ == "__main__":
    main()
