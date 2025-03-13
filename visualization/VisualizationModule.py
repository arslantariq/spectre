import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
from collections import defaultdict

class VisualizationModule:
    @staticmethod
    def displayExtensions(extension_counts: defaultdict, axis=None):
        """
        Displays a horizontal bar chart of file extensions and their counts.
        
        Parameters:
            extension_counts (defaultdict): A dictionary-like object where keys are file extensions (str) 
                                            and values are their counts (int).
            axis (matplotlib.axes._axes.Axes, optional): An axis object for plotting. If None, a new plot is created.
                                                         Defaults to None.

        Example input:
            defaultdict(<class 'int'>, {'bmp': 4, 'jpg': 2, 'png': 3})
        """
        # Extract extensions and their counts from the defaultdict
        extensions = list(extension_counts.keys())  # Get a list of extension names
        counts = list(extension_counts.values())    # Get the corresponding list of counts

        if axis is None:
            # Configure the plot's figure size for better readability
            plt.figure(figsize=(8, 5))

            # Create the horizontal bar chart
            plt.barh(
                extensions,    # Extensions on the y-axis
                counts,        # Counts on the x-axis
                color=['skyblue', "#FFB266", "#ff9999", "#ccff99"]  # Light colors for the bars
                #edgecolor='black'   # Add black edges for better visibility
            )

            # Add chart title and labels for the axes
            plt.title("File Extension Counts", fontsize=14)    # Title of the chart
            plt.xlabel("Count", fontsize=12)                   # Label for the x-axis
            plt.ylabel("Unsafe Extensions", fontsize=12)         # Label for the y-axis

            # Add a grid for better readability
            plt.grid(axis='x', linestyle='--', alpha=0.7)      # Add dashed grid lines on the x-axis

            # Ensure the layout fits well within the display area
            plt.tight_layout()

            # Display the chart
            plt.show()
        else:
            # Use the provided axis to create the plot
            axis.barh(
                extensions,    # Extensions on the y-axis
                counts,        # Counts on the x-axis
                color=['skyblue', "#FFB266", "#ff9999", "#ccff99"]  # Light colors for the bars
                #edgecolor='black'   # Add black edges for better visibility
            )

            # Add chart title and labels for the axes
            axis.set_title("Unsafe Extension Counts", fontsize=14)  # Title of the chart
            #axis.set_xlabel("Count", fontsize=9)                 # Label for the x-axis
            #axis.set_ylabel("Unsafe Extensions", fontsize=12)       # Label for the y-axis

            # Add a grid for better readability
            axis.grid(axis='x', linestyle='--', alpha=0.7)        # Add dashed grid lines on the x-axis

    class ScatterPlotter:
        """
        A class to generate scatter plots for processes over a timeline.

        Attributes:
            process_data (list): List of dictionaries representing process details.
        """

        def __init__(self, process_data):
            """
            Initializes the ScatterPlotter class with process data.

            Args:
                process_data (list): List of dictionaries with the following keys:
                    - 'name': str, Process name
                    - 'PID': int, Process ID
                    - 'connections': int, Number of connections
                    - 'is_malicious': bool, Malicious or benign process
                    - 'creation_time': datetime, Process creation time
                    - 'malicious_indicators': list, List of malicious indicators
            """
            self.process_data = process_data
                    
        def plot(self, block=True):
            """
            Generates a scatter plot for the processes over a timeline.
            """
            # Separate data for plotting
            x = [p["creation_time"] for p in self.process_data]  # Use the generated timestamps
            y = [p["connections"] for p in self.process_data]  # Y-axis now corresponds to the number of connections
            sizes = [100] * len(self.process_data)  # Fixed size for simplicity
            classes = [1 if p["is_malicious"] else 2 for p in self.process_data]  # 1 for Malicious, 2 for Non-Malicious
            pids = [p["PID"] for p in self.process_data]  # PIDs for hover text
            names = [p["name"] for p in self.process_data]  # Process names for hover text

            # Scatter plot
            fig, ax = plt.subplots(figsize=(12, 6))

            scatter = ax.scatter(
                x, y, c=classes, s=sizes, alpha=0.7, cmap="Set1", edgecolors="black", linewidths=0.5
            )

            # Determine dynamic tick interval
            x_min, x_max = min(x), max(x)
            x_range = (x_max - x_min).total_seconds()
            max_ticks = 10  # Limit the number of ticks to a maximum of 10

            if x_range <= 600:  # If range is less than or equal to 10 minutes
                tick_interval = 1  # Tick every minute
            else:
                tick_interval = max(1, int(x_range // max_ticks // 60))  # Dynamic interval in minutes

            # Format x-axis as timeline
            ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=tick_interval))  # Dynamic interval
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))  # Format as HH:MM:SS
            plt.xticks(rotation=45)  # Rotate for better readability
            ax.set_xticklabels([])  # Hide x-axis labels

            # Add legends for classes
            legend_labels = ["Malicious", "Non-Malicious"]
            handles, _ = scatter.legend_elements()

            legend1 = ax.legend(
                handles, 
                legend_labels,
                loc="lower right",  
                title="Classes"
            )
            ax.add_artist(legend1)

            # Labels and title
            ax.set_title("Processes Over Timeline", fontsize=14)
            ax.set_xlabel("Timeline (HH:MM:SS)", fontsize=12)
            ax.set_ylabel("Number of Connections", fontsize=12)

            # Add hover functionality with comment box
            annotations = {}
            comment_boxes = {}  # Dictionary to store comment boxes

            for i, (xi, yi) in enumerate(zip(x, y)):
                # Default tooltip text with process name, PID, and connections
                tooltip_text = f"Name: {names[i]}\nPID: {pids[i]}\nConnections: {y[i]}\nCreation Time: {x[i]}"
                
                # Add malicious indicators for malicious processes
                if classes[i] == 1:  # Malicious process
                    indicators = "\n".join(self.process_data[i]["malicious_indicators"])
                    tooltip_text += "\nMalicious Indicators:\n" + indicators

                annotation = ax.annotate(
                    tooltip_text,
                    xy=(xi, yi),
                    xytext=(5, 5),
                    textcoords="offset points",
                    fontsize=9,
                    color="black",
                    visible=False,  # Start hidden
                )
                annotations[i] = annotation
                
                # Create a comment box with yellow background
                bboxprops = dict(boxstyle="round,pad=0.3", facecolor="#FFFFC5", edgecolor="black", linewidth=1)
                comment_box = ax.text(
                    xi, yi, tooltip_text, 
                    fontsize=9, color="black", 
                    bbox=bboxprops, 
                    visible=False  # Initially hidden
                )
                comment_boxes[i] = comment_box

            def on_hover(event):
                visibility_changed = False
                for i, (xi, yi) in enumerate(zip(x, y)):
                    if event.inaxes == ax:
                        # Calculate the distance between the cursor and the center of the node
                        display_coords = ax.transData.transform((mdates.date2num(xi), yi))
                        distance = np.sqrt((display_coords[0] - event.x) ** 2 + (display_coords[1] - event.y) ** 2)
                        
                        # Check if the distance is less than or equal to the radius of the node
                        radius = np.sqrt(sizes[i] / np.pi)  # Calculate radius from the area (sizes[i] = pi * radius^2)
                        if distance <= radius:
                            # Show both the annotation and the comment box
                            annotations[i].set_visible(True)
                            comment_boxes[i].set_visible(True)
                            visibility_changed = True
                        else:
                            # Hide both the annotation and the comment box
                            annotations[i].set_visible(False)
                            comment_boxes[i].set_visible(False)
                
                if visibility_changed:
                    fig.canvas.draw_idle()

            # Connect hover event to the figure
            fig.canvas.mpl_connect("motion_notify_event", on_hover)

            plt.tight_layout()
            
            # Set the figure window title if supported
            fig_manager = plt.get_current_fig_manager()
            if fig_manager is not None:
                fig_manager.set_window_title('Process Scatter Plot')

            plt.show(block=block)

# Example usage:
if __name__ == "__main__":
    # Example defaultdict containing file extensions and their counts
    example_counts = defaultdict(int, {'bmp': 4, 'jpg': 2, 'png': 3})

    # Call the static function to display the chart
    VisualizationModule.displayExtensions(example_counts)
