import argparse

from TimeLineAnalysis import *

# Function to generate random JSON files for testing
def generate_random_json_files(num_files=10):
    os.makedirs('test_files', exist_ok=True)
    names = ['A', 'B', 'C', 'D', 'E']
    
    for i in range(1, num_files + 1):
        json_data = []
        for _ in range(random.randint(1, 5)):  # Random number of entries per file
            name = random.choice(names)
            entry = {
                "Data": f"Value{random.randint(1, 100)}",
                "Hive Offset": random.randint(100000000000000, 999999999999999),
                "Key": f"Subkey{random.randint(1, 10)}",
                "Last Write Time": (datetime.utcnow() - timedelta(days=random.randint(0, 30))).isoformat() + "+00:00",
                "Name": name,
                "Type": random.choice(["Key", "Value"]),
                "Volatile": random.choice([True, False]),
                "__children": []
            }
            json_data.append(entry)
        
        file_name = f'test_files/printkey_{i}.json'
        with open(file_name, 'w') as f:
            json.dump(json_data, f, indent=4)
        print(f"Generated file: {file_name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare consecutive JSON files for registry entries.")
    parser.add_argument('-files', '--file_list', help="Comma-separated list of JSON files for comparison.")
    parser.add_argument('-g', '--generate', action='store_true', help="Generate random JSON files for testing purposes.")
    args = parser.parse_args()

    if args.generate:
        generate_random_json_files()
    else:
        file_list = [file.strip() for file in args.file_list.split(',')]
        analysisObject = RegistryTimelineAnalysis(file_list)
        analysisObject.compare_files()
