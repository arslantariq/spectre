import argparse
import json
import os
import sys
import copy
from memory.MemoryModule import *
from delta.DeltaModule import *
from utils.VolatilityWrapper import VolatilityWrapper
from utils.OutputHandler import OutputHandler
from osmodule.OSModule import *
from timeline.TimeLineAnalysis import *

class Main:
    """Main class that integrates memory forensics and output handling."""

    def __init__(self, memDumpFile, output, volatility):
        self.volatility_wrapper = VolatilityWrapper(memDumpFile, volatility)
        self.output_handler = OutputHandler(output)

    def run(self):
        """Main method to execute all commands and handle the output."""
        print("Executing Volatility commands...")

        windowsInterface = WindowsInterface(self.volatility_wrapper, self.output_handler)
        windowsInterface.extractProcesses()
        windowsInterface.extractConnections()
        windowsInterface.extractModules()
        windowsInterface.extractRegistries()
        windowsInterface.extractUsers()
        
        dump = MemoryDump()
        dump.loadDirectory(self.output_handler.output_folder)
        MemoryAnalysis.plot_detailed_statistics(dump)
        
        # Plot processes and connections using TimelinePlotter. 
        plotter = TimelinePlotter(dump.pstree_file, dump.connections_file)
        plotter.plot_timelines()
        plotter.plot_top_processes_by_connections(top_n=10)
        plotter.plot_combined_timelines()
        '''
        Uncomment this section to test DeltaAnalysis on the memory dump with embedded updates.
        # Add some changes and plot delta.
        processes = [{
                        "Audit": "\\Device\\HarddiskVolume3\\Program Files\\OSForensics\\osf64.exe",
                        "Cmd": "\"C:\\Program Files\\OSForensics\\osf64.exe\" ",
                        "CreateTime": "2025-1-1T23:16:46+00:00",
                        "ExitTime": "2025-1-1T23:18:46+00:00",
                        "Handles": 0,
                        "ImageFileName": "osf64.exe",
                        "Offset(V)": 244696837902464,
                        "PID": 5281,
                        "PPID": 996,
                        "Path": "C:\\Program Files\\OSForensics\\osf64.exe",
                        "SessionId": 1,
                        "Threads": 23,
                        "Wow64": False,
                        "__children": []
                    }]

        connections = [{
                        "Created": "2022-07-18T23:25:43+00:00",
                        "ForeignAddr": "203.213.73.18",
                        "ForeignPort": 443,
                        "LocalAddr": "10.0.2.15",
                        "LocalPort": 49873,
                        "Offset": 244696831412896,
                        "Owner": "msedge.exe",
                        "PID": 5280,
                        "Proto": "TCPv4",
                        "State": "ESTABLISHED",
                        "__children": []
                     }]

        users = [{
                    "User": "tempUser",
                    "__children": [],
                    "lmhash": "aad3b435b51404eeaad3b435b51505ee",
                    "nthash": "31d6cfe0d16ae931b73c59d7e0c079c0",
                    "rid": 500
                }]

        # Create another memory dump and add differences.
        dump2 = copy.deepcopy(dump)
        dump2.addProcesses(processes)
        dump2.addConnections(connections)
        dump2.addUsers(users)
        
        # Perform delta analysis
        diff = MemoryDiff()
        delta_report = diff.compare_dumps(dump, dump2)
        analysis = DeltaAnalysis(diff)
        analysis.plotCombinedUpdates()'''
                    
if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Run Volatility commands and save JSON output.")
    p.add_argument('-f', '--memdump', help='Path to memory dump file', required=True)
    p.add_argument('-o', '--output', default="./output", help='Path to the folder where output JSON files will be created', required=True)
    p.add_argument('-V', '--volatility', default=None, help='Path to the vol.py file in Volatility3 folder', required=True)

    args = p.parse_args()

    # Initialize and run the Main class
    main = Main(args.memdump, args.output, args.volatility)
    main.run()