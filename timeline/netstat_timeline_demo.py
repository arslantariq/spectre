import argparse
from TimeLineAnalysis import *

# Function to generate random JSON files for testing
def generate_random_json_files(num_files=10):
    os.makedirs('test_files', exist_ok=True)
    processes = ['smss.exe', 'csrss.exe', 'explorer.exe', 'cmd.exe', 'chrome.exe']
    states = ['LISTENING', 'ESTABLISHED', 'CLOSE_WAIT', 'TIME_WAIT']
    protos = ['TCPv4', 'TCPv6', 'UDP']

    for i in range(1, num_files + 1):
        json_data = []
        for _ in range(random.randint(1, 5)):  # Random number of entries per file
            process_name = random.choice(processes)
            pid = random.randint(100, 5000)
            created_time = datetime.utcnow() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23), minutes=random.randint(0, 59))
            connection = {
                "Created": created_time.isoformat() + "+00:00",  # ISO format with timezone offset
                "ForeignAddr": f"192.168.1.{random.randint(1, 255)}",
                "ForeignPort": random.randint(1024, 65535),
                "LocalAddr": f"10.0.2.{random.randint(1, 255)}",
                "LocalPort": random.randint(1024, 65535),
                "Offset": random.randint(100000000000000, 999999999999999),
                "Owner": process_name,
                "PID": pid,
                "Proto": random.choice(protos),
                "State": random.choice(states),
                "__children": []  # Empty list for children
            }
            json_data.append(connection)
        
        file_name = f'test_files/netstat_{i}.json'
        with open(file_name, 'w') as f:
            json.dump(json_data, f, indent=4)
        print(f"Generated file: {file_name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare consecutive network connection JSON files.")
    parser.add_argument('-files', '--file_list', help="Comma-separated list of JSON files for comparison.")
    parser.add_argument('-g', '--generate', action='store_true', help="Generate random JSON files for testing purposes")
    args = parser.parse_args()

    if args.generate:
        generate_random_json_files()
    else:
        file_list = [file.strip() for file in args.file_list.split(',')]
        analysisObject = ConnectionTimeLineAnalysis(file_list)
        analysisObject.compare_connection_files()
