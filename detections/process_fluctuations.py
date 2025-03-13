import argparse
import json
import random
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

class ProcessCreationPlotter:
    """Plots process creation times from a JSON file containing recursive process data with children processes."""
    
    def __init__(self, pstree_file=None):
        self.pstree_file = pstree_file
        self.process_data = self.load_process_data()

    def load_process_data(self):
        """Load process creation data from a JSON file or generate random data if no file is provided."""
        if self.pstree_file:
            with open(self.pstree_file, 'r') as file:
                return json.load(file)
        else:
            return self.generate_random_process_data()

    def generate_random_process_data(self):
        """Generate a random set of process data with potential child processes over a 30-minute period."""
        base_time = datetime.now()
        
        def create_random_process(level=0):
            """Recursively create random process data with a chance for children."""
            process = {
                "Audit": None,
                "Cmd": f"process{random.randint(1, 100)}.exe",
                "CreateTime": (base_time + timedelta(minutes=random.randint(0, 29), seconds=random.randint(0, 59))).isoformat(),
                "ExitTime": None,
                "Handles": random.randint(50, 500),
                "ImageFileName": f"process{random.randint(1, 100)}.exe",
                "Offset(V)": None,
                "PID": random.randint(1000, 60000),
                "PPID": random.randint(0, 1000),
                "Path": f"C:\\Program Files\\process{random.randint(1, 100)}.exe",
                "SessionId": random.randint(1, 10),
                "Threads": random.randint(1, 20),
                "Wow64": bool(random.getrandbits(1)),
                "__children": [create_random_process(level + 1) for _ in range(random.randint(0, 2))] if level < 2 else []
            }
            return process

        # Create a base list of processes
        return [create_random_process() for _ in range(20)]

    def parse_creation_times(self, process, times):
        """Recursively parse creation times from a process and its children, storing each time in a list."""
        try:
            if not process.get("CreateTime"):
                return None
                
            timestamp = process.get("CreateTime")
            creation_time = datetime.fromisoformat(timestamp)
            times.append(creation_time)
        except Exception as e:
            print(f"Error parsing creation time for process: {e}")

        # Recur for each child process
        for child in process.get("__children", []):
            self.parse_creation_times(child, times)

    def plot_process_creations(self):
        """Plot the number of processes created over time, including children processes."""
        creation_times = []
        
        # Extract all creation times recursively from the data
        for process in self.process_data:
            self.parse_creation_times(process, creation_times)
        
        if not creation_times:
            print("No valid process creation times found.")
            return

        # Sort times and count the number of processes per minute
        creation_times.sort()
        counts_by_time = {}
        for time in creation_times:
            minute = time.replace(second=0, microsecond=0)  # Group by minute
            counts_by_time[minute] = counts_by_time.get(minute, 0) + 1

        # Extract times and counts for plotting
        times = list(counts_by_time.keys())
        counts = list(counts_by_time.values())

        # Plotting
        plt.figure(figsize=(10, 5))
        plt.scatter(times, counts, color='purple', s=50, alpha=0.6)
        plt.plot(times, counts, linestyle='-', color='purple', alpha=0.7)
        plt.xlabel("Time (by minute)")
        plt.ylabel("Number of Processes Created")
        plt.title("Process Creation Over Time")
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.grid(True)

        # Set the figure window title if supported
        fig_manager = plt.get_current_fig_manager()
        if fig_manager is not None:
            fig_manager.set_window_title('Process Creation Timeline')
        
        plt.show()

# Command-line usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot process creation times from a process tree JSON file.")
    parser.add_argument("--pstree-file", type=str, help="Path to the process tree JSON file")
    args = parser.parse_args()

    plotter = ProcessCreationPlotter(args.pstree_file)
    plotter.plot_process_creations()
