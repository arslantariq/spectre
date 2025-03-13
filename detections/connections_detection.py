import argparse
import json
from AnomalyDetector import Detections
           
# Command-line usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect and plot connection types and flags from connections file.")
    parser.add_argument("--connections-file", type=str, required=True, help="Path to the connections JSON file")
    args = parser.parse_args()

    # Instantiate and use ConnectionDetector
    detector = Detections.ConnectionDetector(args.connections_file)
    detector.plot_connection_types()
    detector.plot_country_flags(display_flags=True)
    #detector.display_countries()
    
    # Connection fluctuation plot
    #detector.plot_connections_by_minute()
