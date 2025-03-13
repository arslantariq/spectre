import json
import argparse
from AnomalyDetector import *

# Main execution
def main():
    parser = argparse.ArgumentParser(description='Detect malicious rundll32.exe processes.')
    parser.add_argument('-s', '--skip-plot', action='store_true', help='Skip plotting the results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Display non-malicious information')
    parser.add_argument("--pstree", type=str, required=True, help="Path to the JSON file containing the process tree.")
    parser.add_argument("--netstat", type=str, required=True, help="Path to the JSON file containing the network connections.")
    args = parser.parse_args()

    # Read JSON data from file
    try:
        with open(args.pstree, 'r') as file:
            processes_list = json.load(file)
        with open(args.netstat, 'r') as file:
            network_connections = json.load(file)
    except FileNotFoundError:
        print("Error: The specified pstree file was not found.")
        return
    except json.JSONDecodeError:
        print("Error: Failed to parse the JSON file.")
        return

    # Parse JSON objects
    processes_list = parse_audit_entry_list(json.dumps(processes_list))
    data = json.loads(json.dumps(network_connections))
    network_connections = [NetworkConnection.from_dict(conn) for conn in data]

    # Run detection and analysis
    detector = Detections.MaliciousRunDLLProcess(processes_list, network_connections, args.verbose)
    malicious_info, non_malicious_info, low_risk_info = detector.detect_malicious_rundll32()

    # Plot results if not skipped
    if not args.skip_plot:
        detector.plot_results()

if __name__ == "__main__":
    main()