import argparse
import tracemalloc
from MemoryModule import *

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Analyze memory dump data and generate statistics plots.")
    
    # Add arguments for the required files
    parser.add_argument('-input', '--input_directory', type=str, help="Path to the folder containing all JSON files, if this option is used, other file options are not required")
    parser.add_argument('-p', '--processes', type=str, help="Path to the processes JSON file")
    parser.add_argument('-c', '--connections', type=str, help="Path to the connections JSON file")
    parser.add_argument('-u', '--users', type=str, help="Path to the users JSON file")
    parser.add_argument('-m', '--modules', type=str, help="Path to the modules JSON file")
    parser.add_argument('-d', '--dlls', type=str, help="Path to the DLLs JSON file")
    parser.add_argument('-r', '--registries', type=str, help="Path to the registries JSON file")
    parser.add_argument("--blacklist-ips", required=True, help="File containing blacklisted IP addresses.")
    parser.add_argument("--whitelist-ips", required=True, help="File containing whitelisted IP addresses.")
    parser.add_argument("-k", "--api-key", required=True, help="API key for VirusTotal.")
    
    # Parse arguments
    args = parser.parse_args()
    dump = MemoryDump()
    # Create an instance of the MemoryDump class
    if args.input_directory:
        dump.loadDirectory(args.input_directory)
    else:
        dump.loadFiles(processes_file=args.processes, 
            connections_file=args.connections, 
            users_file=args.users,
            modules_file=args.modules,
            dlls_file=args.dlls,
            registries_file=args.registries
        )
    
    # Plot the statistics
    MemoryAnalysis.plot_detailed_statistics(dump)
    MemoryAnalysis.plot_additional_statistics(dump,args.whitelist_ips, args.blacklist_ips, args.api_key)
    
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
        