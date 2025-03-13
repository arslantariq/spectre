import argparse
from AnomalyDetector import *

def main():
    parser = argparse.ArgumentParser(description="Analyze IP connections and process data for blacklist/whitelist categorization.")
    parser.add_argument("--blacklist-ips", required=True, help="File containing blacklisted IP addresses.")
    parser.add_argument("--whitelist-ips", required=True, help="File containing whitelisted IP addresses.")
    parser.add_argument("--pstree-file", required=True, help="JSON file containing process tree data.")
    parser.add_argument("--connections-file", required=True, help="JSON file containing connection data.")

    args = parser.parse_args()

    # Initialize the detector with file paths and call methods to perform analysis and plotting.
    detector = Detections.IPCategorytDetector(
        blacklist_file=args.blacklist_ips,
        whitelist_file=args.whitelist_ips,
        pstree_file=args.pstree_file,
        connections_file=args.connections_file
    )
    detector.categorize_ips() # Categorize foreign IPs and plot
    detector.process_cmd_ip_analysis()        # Analyze CMD IPs and plot
    detector.plot_blacklist_connections_by_process()  # Plot blacklisted connections by process

if __name__ == "__main__":
    main()
