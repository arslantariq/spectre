import argparse
import json
import random
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from collections import Counter

def load_connections(file_name=None):
    """Load connections from a JSON file or generate random data."""
    if file_name:
        with open(file_name, 'r') as file:
            return json.load(file)
    else:
        # Generate random connection data over a 1-hour period
        base_time = datetime.now()
        return [
            {
                "Created": (base_time + timedelta(minutes=random.randint(0, 59), seconds=random.randint(0, 59))).isoformat(),
                "ForeignAddr": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "ForeignPort": random.randint(1024, 65535),
                "LocalAddr": "10.0.2.15",
                "LocalPort": random.randint(1024, 65535),
                "Offset": random.randint(1000000, 9999999),
                "Owner": random.choice(["rundll32.exe", "svchost.exe", "chrome.exe"]),
                "PID": random.randint(1000, 60000),
                "Proto": random.choice(["TCPv4", "TCPv6", "UDPv4", "UDPv6"]),
                "State": "ESTABLISHED",
                "__children": []
            }
            for _ in range(100)
        ]

def parse_time(connection):
    """Parse the Created time from a connection and return as datetime object, rounded to the nearest minute."""
    try:
        timestamp = connection.get("Created")
        parsed_time = datetime.fromisoformat(timestamp)
        return parsed_time.replace(second=0, microsecond=0)  # Round to minute
    except Exception as e:
        print(f"Error parsing time for connection: {e}")
        return None

def count_connections_by_minute(connections):
    """Count the number of connections per minute."""
    time_stamps = [parse_time(conn) for conn in connections if parse_time(conn)]
    return Counter(time_stamps)

def plot_connections_by_minute(connections_by_minute):
    """Plot the number of connections over time by minute."""
    times = sorted(connections_by_minute.keys())
    counts = [connections_by_minute[time] for time in times]

    plt.figure(figsize=(10, 5))
    plt.plot(times, counts, marker='o', linestyle='-', color='b')
    plt.xlabel('Time (by minute)')
    plt.ylabel('Number of Connections')
    plt.title('Connections over Time (Per Minute)')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.grid(True)
    plt.show()

def main(file_name):
    connections = load_connections(file_name)
    connections_by_minute = count_connections_by_minute(connections)
    plot_connections_by_minute(connections_by_minute)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot connections over time by minute from JSON connection data.")
    parser.add_argument("--connections-file", type=str, help="Path to the JSON file with connection data")
    args = parser.parse_args()

    main(args.connections_file)
