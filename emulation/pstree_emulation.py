# Import necessary libraries
import json
import argparse
from tabulate import tabulate
import sys
import io
from TestDataEmulator import EmulationModule

# Configure output to support UTF-8 encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def write_json_output(filename, process_list):
    """
    Write process tree to a JSON file.

    Args:
        filename (str): Path to the output file.
        process_list (list): List of root processes to serialize and save.
    """
    EmulationModule.TestDataEmulator.write_json_output(filename, process_list)

def extract_process_data(process, depth=0, data=None):
    """
    Recursively extract process data with indentation according to depth.

    Args:
        process (ProcessTree): The root process node to start extraction.
        depth (int): The depth of the current process in the tree.
        data (list): Accumulator for extracted data.

    Returns:
        list: Accumulated process data.
    """
    if data is None:
        data = []

    data.append((depth, process.image_file_name, process.pid, process.ppid))

    for child in process.children:
        extract_process_data(child, depth + 1, data)

    return data

def display_colored_table(data):
    """
    Displays a table from the given data with color-coded process names based on the first tuple value.

    Args:
        data (list of tuples): Each tuple contains (color_key, process_name, process_id, parent_process_id).
    """
    print("\nEMULATED PROCESSES")
    # Define colors for each possible value of the first entry
    colors = {
        0: "\033[34m",  # Blue
        1: "\033[32m",  # Green
        2: "\033[33m",  # Yellow
        3: "\033[35m",  # Magenta
        4: "\033[36m"   # Cyan
    }
    reset_color = "\033[0m"

    # Prepare table data
    table_data = []
    for serial, (color_key, process_name, process_id, parent_process_id) in enumerate(data, start=1):
        color = colors.get(color_key, "\033[0m")  # Default to no color if key not found
        colored_process_name = f"{color}{process_name}{reset_color}"
        table_data.append([serial, colored_process_name, process_id, parent_process_id])

    # Print the table
    headers = ["Serial No", "Process Name", "Process ID", "Parent Process ID"]
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid").encode('utf-8', 'ignore').decode('utf-8'))

def main():
    # Command line arguments
    parser = argparse.ArgumentParser(description="Generate fake Volatility pstree JSON data.")
    parser.add_argument("-n", "--num_processes", type=int, default=10, help="Total number of processes (including children)")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Maximum depth of child processes")
    parser.add_argument("-m", "--max_children", type=int, default=10, help="Maximum immediate children at each level")
    parser.add_argument("-e", "--extensions", type=str, help="Comma-separated list of additional file extensions")
    parser.add_argument("--parent_ids", type=int, nargs='+', default=[0], help="List of parent IDs for root processes")
    parser.add_argument("--exclude_pids", type=int, nargs='+', default=[], help="List of PIDs to exclude from creation")
    parser.add_argument("--skip_plot", action="store_true", help="Skip displaying the process table")
    args = parser.parse_args()

    default_extensions = ['.exe', '.bat', '.bin']
    extensions = default_extensions + ["." + ext.strip() for ext in args.extensions.split(',')] if args.extensions else default_extensions

    exclude_pids = set(args.exclude_pids)

    # Generate the process tree using ProcessTreeEmulator
    process_list = EmulationModule.TestDataEmulator.create_process_tree(
        total_processes=args.num_processes,
        max_depth=args.depth,
        max_children=args.max_children,
        extensions=extensions,
        parent_ids=args.parent_ids,
        exclude_pids=exclude_pids, commandList=None
    )

    output_file = "pstree.json"
    write_json_output(output_file, process_list)
    print(f"Generated Volatility pstree JSON data and saved to {output_file}.")

    # Extract and print process data if skip_plot is not set
    if not args.skip_plot:
        process_data = []
        for root in process_list:
            process_data.extend(extract_process_data(root))

        display_colored_table(process_data)

if __name__ == "__main__":
    main()
