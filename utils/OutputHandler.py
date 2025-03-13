import json
import os

class OutputHandler:
    """Handles memory dump JSON operations"""

    def __init__(self, output_folder):
        self.output_folder = output_folder
        # Ensure the output directory exists
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

    def clean_json_output(self, raw_json):
        """Clean the raw JSON output by removing escape characters and newlines."""
        try:
            parsed_json = json.loads(raw_json)
            return json.dumps(parsed_json, indent=4)  # Reformat the JSON for readability
        except json.JSONDecodeError:
            raise Exception("Failed to parse JSON output")

    def save_output(self, command, output_data):
        """Saves the cleaned JSON output to a file in the specified output directory."""
        file_path = os.path.join(self.output_folder, f"{command}.json")
        with open(file_path, 'w') as f:
            f.write(output_data)
        # print(f"Output saved to {file_path}")

    def write_json_output(self, command, json_output):
        """Write process tree to JSON file."""
        file_path = os.path.join(self.output_folder, f"{command}.json")
        
        # Step 2: Write the Python object to a file
        with open(file_path, "w") as file:
            json.dump(json_output, file, indent=4)  # Indent for readability

