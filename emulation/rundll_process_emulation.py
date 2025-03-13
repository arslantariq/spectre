import random
import argparse
from TestDataEmulator import *
import tracemalloc

# Main execution
def main():
    parser = argparse.ArgumentParser(description="Generate rundll32 commands with various risk levels.")
    parser.add_argument("-r", "--ratio", type=str, default="8:1:1", help="Ratio of benign:low_risk:malicious commands")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for generated commands")
    parser.add_argument("--benign_list", required=True, help="File containing list of benign IP addresses")
    parser.add_argument("--malicious_list", required=True, help="File containing list of malicious IP addresses")
    args = parser.parse_args()

    generator = EmulationModule.RunDllGenerator(ratio=args.ratio, verbose=args.verbose)
    categorized_commands = generator.generate_commands()

    if args.verbose:
        print("\nGenerated Commands by Category:")
        for category, commands in categorized_commands.items():
            print(f"{category.capitalize()} Commands ({len(commands)}):")
            for command in commands:
                print(f"  {command}")
            
    exclude_pids = set()
        
    # Generate the process tree using ProcessTreeEmulator
    process_list = EmulationModule.TestDataEmulator.create_process_tree(
        total_processes=len(categorized_commands['benign'] + categorized_commands['low_risk']),
        max_depth=0,
        max_children=1,
        extensions=[],
        parent_ids=[0],
        exclude_pids=exclude_pids, commandList=categorized_commands['benign'] + categorized_commands['low_risk'])

    malicious_list = []
    # Generate malicious process list
    for process in categorized_commands['malicious']:
        if "rundll32.exe->" in process:
            malicious_list.append(EmulationModule.ProcessTreeEmulator.createTree(process.split('->'), exclude_pids))
        else:
            malicious_list.extend(EmulationModule.TestDataEmulator.create_process_tree(
        total_processes=1,
        max_depth=0,
        max_children=1,
        extensions=[],
        parent_ids=[0],
        exclude_pids=exclude_pids, commandList=[process]))
    
    process_list.extend(malicious_list)
    EmulationModule.TestDataEmulator.write_json_output('pstree.json', process_list)
    
    print('Processes generated in file pstree.json' )
    
    # Load benign and malicious IPs
    benign_ips = EmulationModule.ConnectionGenerator.load_ips(args.benign_list)
    malicious_ips = EmulationModule.ConnectionGenerator.load_ips(args.malicious_list)
    
    # Initialize EmulationModule.ConnectionGenerator
    generator = EmulationModule.ConnectionGenerator(
        n=len(malicious_list),
        benign_ips=benign_ips,
        malicious_ips=malicious_ips,
        benign_ratio=1,
        malicious_ratio=1,
        exclude_pids=exclude_pids,
        processes=[process.to_dict() for process in malicious_list]
    )

    # Generate connections
    connections = generator.generate_connections_for_all_processes()

    # Write connections to JSON file
    with open("netstat.json", "w") as file:
        json.dump(connections, file, indent=4)

    print(f"Generated connections in 'netstat.json'.")
    

if __name__ == "__main__":
    
    # Start tracing memory allocation
    tracemalloc.start()
    
    main()
    
    # Get peak memory usage
    current, peak = tracemalloc.get_traced_memory()
    print(f"Current memory usage: {current / 10**6} MB")
    print(f"Peak memory usage: {peak / 10**6} MB")

    # Stop tracing
    tracemalloc.stop()