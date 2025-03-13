import json
import argparse
from AnomalyDetector import *

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

    # Parse JSON and create a detector instance
    processes_list = parse_audit_entry_list(json.dumps(processes_list))   
    detector = Detections.CredentialDumpDetector(processes_list, args.verbose)

    # Run detection and display results
    detections = detector.detect_credential_dumping()
    if args.verbose:
        detector.display_detections(detections.values())

    # Plot the detection summary if not skipped
    if detections and not args.skip_plot:
        Detections.CredentialDumpDetector.plot_detection_summary(detections.values())

if __name__ == "__main__":
    main()