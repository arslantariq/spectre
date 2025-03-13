import argparse
from DeltaModule import *
import tracemalloc

from memory.MemoryModule import MemoryDump

def main():
    parser = argparse.ArgumentParser(description="Delta Analysis between two memory dumps.")
    parser.add_argument("-d1", "--dump1", required=True, help="Path to first memory dump JSON files directory")
    parser.add_argument("-d2", "--dump2", required=True, help="Path to second memory dump JSON files directory")
    args = parser.parse_args()

    # Load memory dumps
    dump1 = MemoryDump()
    dump1.loadDirectory(args.dump1)
    dump2 = MemoryDump()
    dump2.loadDirectory(args.dump2)

    # Perform delta analysis
    diff = MemoryDiff()
    delta_report = diff.compare_dumps(dump1, dump2)
    analysis = DeltaAnalysis(diff)
    
    # Output JSON report to console
    #print("Delta Report:", delta_report)

    # Generate plots
    #analysis.plotConnectionUpdates()
    #analysis.plotProcessUpdates()
    analysis.plotCombinedUpdates()
    #analysis.plotAdditionalDeltas()
    #analysis.plotModulesUpdates()
    #analysis.plotRegistriesUpdates()
    #analysis.plotUserUpdates()
    
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