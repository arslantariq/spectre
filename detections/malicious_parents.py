import json
import dateutil.parser
import matplotlib.pyplot as plt
import argparse
from AnomalyDetector import *

# ANSI escape codes for colors
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Detect credential dumping activity.")
    parser.add_argument("-s", "--skip-plot", action="store_true", help="Skip the plotting of detection summary.")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Enable verbose output for detection.")
    parser.add_argument("--pstree", type=str, required=True, help="Path to the JSON file containing the process tree.")
    args = parser.parse_args()

    # Read JSON data from file
    try:
        with open(args.pstree, 'r') as file:
            processes_list = json.load(file)
    except FileNotFoundError:
        print("Error: The specified pstree file was not found.")
        return
    except json.JSONDecodeError:
        print("Error: Failed to parse the JSON file.")
        return

    # Parse the JSON string
    audit_entries = parse_audit_entry_list(json.dumps(processes_list))
    malicious = []
    non_malicious = []

    # Detect lineages
    detector = Detections.MaliciousRundll32Child(verbose=args.verbose) 
    detector.detect_lineage(audit_entries)
    # Plot the lineage graph if not skipped
    if not args.skip_plot:
        #detector.plot_process_lineage()
        detector.plot_process_histogram()
        detector.plot_process_lineage_with_hover();

# Main execution
if __name__ == "__main__":
    main()