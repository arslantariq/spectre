import argparse
import json
import random
from TestDataEmulator import EmulationModule

def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Generate connection records in JSON format.")
    parser.add_argument("--n", type=int, required=True, help="Number of connections to generate")
    parser.add_argument("--benign_list", required=True, help="File containing list of benign IP addresses")
    parser.add_argument("--malicious_list", required=True, help="File containing list of malicious IP addresses")
    parser.add_argument("--ratio", default="9:1", help="Ratio of benign to malicious connections (default 9:1)")
    parser.add_argument("--exclude_pids", nargs='+', type=int, default=[], help="List of PIDs to exclude from process selection")
    parser.add_argument("--pstree_file", required=True, help="File containing process tree data in JSON format")
    
    # Parse command-line arguments
    args = parser.parse_args()

    # Load benign and malicious IPs
    benign_ips = EmulationModule.ConnectionGenerator.load_ips(args.benign_list)
    malicious_ips = EmulationModule.ConnectionGenerator.load_ips(args.malicious_list)

    # Parse ratio for benign-to-malicious selection
    benign_ratio, malicious_ratio = EmulationModule.ConnectionGenerator.parse_ratio(args.ratio)

    # Load process data
    processes = EmulationModule.ConnectionGenerator.load_process_tree(args.pstree_file)

    # Initialize EmulationModule.ConnectionGenerator
    generator = EmulationModule.ConnectionGenerator(
        n=args.n,
        benign_ips=benign_ips,
        malicious_ips=malicious_ips,
        benign_ratio=benign_ratio,
        malicious_ratio=malicious_ratio,
        exclude_pids=args.exclude_pids,
        processes=processes
    )

    # Generate connections
    connections = generator.generate_connections()

    # Write connections to JSON file
    with open("netstat.json", "w") as file:
        json.dump(connections, file, indent=4)

    print(f"Generated {args.n} connections in 'netstat.json'.")

if __name__ == "__main__":
    main()
