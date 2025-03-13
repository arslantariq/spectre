import argparse
import random
from TimeLineAnalysis import *

# Function to generate random JSON files for testing
def generate_random_json_files(num_files=10):
    os.makedirs('test_files', exist_ok=True)
    processes = ['smss.exe', 'csrss.exe', 'explorer.exe', 'cmd.exe', 'chrome.exe']

    for i in range(1, num_files + 1):
        json_data = []
        for _ in range(random.randint(1, 5)):  # Random number of entries per file
            process_name = random.choice(processes)
            pid = random.randint(100, 5000)
            module = {
                "Base": random.randint(1000000, 9999999),
                "InInit": bool(random.getrandbits(1)),
                "InLoad": bool(random.getrandbits(1)),
                "InMem": bool(random.getrandbits(1)),
                "MappedPath": f"\\\\Windows\\\\System32\\\\{process_name}",
                "Pid": pid,
                "Process": process_name
            }
            json_data.append(module)
        
        file_name = f'test_files/ldrmodules_{i}.json'
        with open(file_name, 'w') as f:
            json.dump(json_data, f, indent=4)
        print(f"Generated file: {file_name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare consecutive LDR module JSON files.")
    parser.add_argument('-files', '--file_list', help="Comma-separated list of JSON files for comparison.")
    parser.add_argument('-g', '--generate', action='store_true', help="Generate random JSON files for testing purposes")
    args = parser.parse_args()

    if args.generate:
        generate_random_json_files()
    else:
        file_list = [file.strip() for file in args.file_list.split(',')]
        analysisObject = ModulesTimeLineAnalysis(file_list)
        analysisObject.compare_files()
