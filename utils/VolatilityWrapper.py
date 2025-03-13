import subprocess

class VolatilityWrapper:
    """Handles memory forensics operations by executing Volatility commands."""
    
    def __init__(self, memDumpFile, volatility):
        self.memDumpFile = memDumpFile
        self.volatility = volatility

    def run_command(self, command):
        """Executes the given Volatility command and returns the raw output."""
        full_command = ['python', self.volatility, '-f', self.memDumpFile, '-r=json', command]
        result = subprocess.run(full_command, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Error executing {command}: {result.stderr}")
        return result.stdout
