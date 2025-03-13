import json
import argparse
from AnomalyDetector import *

""" Following statements are required to add parent path to import memmodule"""
from inspect import getsourcefile
import os.path
import sys
current_path = os.path.abspath(getsourcefile(lambda:0))
current_dir = os.path.dirname(current_path)
parent_dir = current_dir[:current_dir.rfind(os.path.sep)]
sys.path.insert(0, parent_dir + os.path.sep + "visualization")
from VisualizationModule import VisualizationModule

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Detect usafe extensions.")
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
        
    processes_list = parse_audit_entry_list(json.dumps(processes_list))
    
    # Detect unsafe extensions
    unsafe_entries, extensions_count = Detections.ProcessExtensionAnalyzer.detect_unsafe_extensions(processes_list)

    # Output the results
    print("Unsafe Extensions Summary: " + str(extensions_count))
    print(json.dumps(unsafe_entries, indent=4))
    
    # Call the visualization function to display the extensions chart
    VisualizationModule.displayExtensions(extensions_count)


if __name__ == "__main__":
    main();