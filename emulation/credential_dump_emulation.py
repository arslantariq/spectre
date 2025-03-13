import json
import argparse
from colorama import Fore, Style
from TestDataEmulator import EmulationModule

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate benign and malicious credential dumping commands.")
    parser.add_argument("--count", type=int, default=10, help="Total number of commands to generate.")
    parser.add_argument("--ratio", type=str, default="9:1", help="Benign-to-malicious ratio (e.g., '9:1').")
    args = parser.parse_args()

    generator = EmulationModule.CredentialDumpGenerator(count=args.count, ratio=args.ratio)
    command_dict = generator.generate_commands()
    
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

    EmulationModule.TestDataEmulator.write_json_output('credentials_pstree.json', process_list)
    
    print('Processes generated in file credentials_pstree.json')

