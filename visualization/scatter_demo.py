from faker import Faker
import random
from datetime import datetime, timedelta
from VisualizationModule import VisualizationModule

# Example usage
faker = Faker()
malicious_indicators = [
    "Malicious rundll32 child process",
    "Malicious rundll32 parent process",
    "Credential Dumping detected",
    "Malicious extension detected",
    "Blacklisted IP used in command line",
    "Remote connection with blacklisted IP",
    "Remote connection with IP detected as malicious by Virus Total"
]

# Generate fake data for processes
process_data = []
num_processes = 100
start_time = datetime.now()
end_time = start_time + timedelta(days=4)

for _ in range(num_processes):
    is_malicious = random.choices([True, False], weights=[1, 10])[0]
    process = {
        "name": faker.file_name(extension="exe"),
        "PID": random.randint(1000, 9999),
        "connections": random.randint(10, 20),
        "is_malicious": is_malicious,
        "creation_time": start_time + (end_time - start_time) * random.random(),
        "malicious_indicators": random.sample(malicious_indicators, random.randint(2, 3)) if is_malicious else []
    }
    process_data.append(process)

# Create instance and plot
plotter = VisualizationModule.ScatterPlotter(process_data)
plotter.plot()
