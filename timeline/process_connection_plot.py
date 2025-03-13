import argparse
from TimeLineAnalysis import *
import tracemalloc

def main():         
    # Command-line usage
    parser = argparse.ArgumentParser(description="Plot timelines for process creations and network connections.")
    parser.add_argument("--pstree-file", type=str, help="Path to the process tree JSON file")
    parser.add_argument("--connections-file", type=str, help="Path to the network connections JSON file")
    args = parser.parse_args()

    plotter = TimelinePlotter(args.pstree_file, args.connections_file)
    plotter.plot_timelines()
    plotter.plot_top_processes_by_connections(top_n=10)
    plotter.plot_combined_timelines()

if __name__ == "__main__":
    
    # Start tracing memory allocation
    tracemalloc.start()
    
    main()
    
    # Get peak memory usage
    current, peak = tracemalloc.get_traced_memory()
    #print(f"Current memory usage: {current / 10**6} MB")
    print(f"Peak memory usage: {peak / 10**6} MB")

    # Stop tracing
    tracemalloc.stop()