import argparse
import tracemalloc
from TestDataEmulator import EmulationModule

""" Following statements are required to add parent path to import memmodule"""
from inspect import getsourcefile
import os.path
import sys
current_path = os.path.abspath(getsourcefile(lambda:0))
current_dir = os.path.dirname(current_path)
parent_dir = current_dir[:current_dir.rfind(os.path.sep)]
sys.path.insert(0, parent_dir + os.path.sep + "json")
from JsonModule import *

def main():    
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Modules, Users and registries generator")
    parser.add_argument('-c', '--count', type=int, help="Count of each entry to be emulated")
    parser.add_argument('-p', '--processes', type=str, help="Path to the processes JSON file")
    
    # Parse arguments
    args = parser.parse_args()
    with open(args.processes, 'r') as f:
        process_list =  json.load(f)
    
    processes_list = parse_audit_entry_list(json.dumps(process_list))
    processes_dictionary = get_process_dictionary(processes_list)

    # Create an instance of LDRModulesEmulator
    emulator = EmulationModule.LDRModulesEmulator(processes_dictionary)

    # Generate the modules
    modules = emulator.generate_modules(count_per_process=1)

    # Save to ldrmodules.json
    emulator.save_to_file("ldrmodules.json", modules)

    print("ldrmodules.json has been generated.")
    
    # Generate and save registry data
    emulator = EmulationModule.KeysEmulator(args.count)
    emulator.generate_data()
    output_file = "printkey.json"
    emulator.save_to_file(output_file)
    print("printkey.json has been generated.")
    
    # Generate and save user data
    output_file = "hashdump.json"
    emulator = EmulationModule.UserEmulator(args.count)
    emulator.generate_data()
    emulator.save_to_file(output_file)
    print("hashdump.json has been generated.")
    
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
        