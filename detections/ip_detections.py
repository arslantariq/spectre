import argparse
from AnomalyDetector import *

# Main function
def main():
    parser = argparse.ArgumentParser(description="Check IP addresses for malicious activity and WHOIS info.")
    parser.add_argument("-i", "--ip-addresses", required=True, help="Comma-separated list of IP addresses to check.")
    parser.add_argument("-k", "--api-key", required=True, help="API key for VirusTotal.")
    parser.add_argument("--whois-api-key", help="API key for ip2whois for WHOIS lookup.")
    parser.add_argument("--unsafe-ips", required=True, help="File containing compromised IP addresses.")
    parser.add_argument("--safe-ips", required=True, help="File containing safe IP addresses.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display full verbose WHOIS output.")
    args = parser.parse_args()
    
    compromisedIPs = Detections.IPCategorytDetector.load_ip_list(args.unsafe_ips)
    safeIPs = Detections.IPCategorytDetector.load_ip_list(args.safe_ips)
    
    # Convert comma-separated string to list of IP addresses
    ip_addresses = args.ip_addresses.split(",")
    # Use IPDetectionModule to detect malicious IPs
    Detections.IPDetectionModule.detect_malicious_ips(ip_addresses, args.api_key,compromisedIPs, safeIPs, args.whois_api_key, args.verbose)

if __name__ == "__main__":
    main()
