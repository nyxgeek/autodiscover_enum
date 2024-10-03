import re
import numpy as np
import argparse
import matplotlib.pyplot as plt
from jenkspy import JenksNaturalBreaks
import signal
import sys

# Function to handle SIGINT properly
def signal_handler(sig, frame):
    print("\nProcess interrupted. Exiting gracefully.")
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

# Function to read data from file and filter relevant values
def read_data_from_file(filename):
    values = []
    with open(filename, 'r') as file:
        for line in file:
            if line.lstrip().startswith("VALID") or line.lstrip().startswith("INVALID"):
                parts = re.split(r'\s+', line.strip())
                value = parts[3]
                values.append(3.0 if value == "XXX" else float(value))
    return np.array(values)

# Set up argument parser
parser = argparse.ArgumentParser(description='Process a text file, classify, and update VALID/INVALID labels.')
parser.add_argument('-f', '--file', type=str, required=True, help='Path to the file containing the data')
parser.add_argument('--graph', action='store_true', help='Plot the histogram with the upper break overlay')
parser.add_argument('--max-value', type=float, help='Maximum value to include in the graph')
args = parser.parse_args()

# Read data from the specified file
data = read_data_from_file(args.file)

# Sort data
data = np.sort(data)

# Step 3: Perform Jenks natural breaks calculation to determine the major clusters
jenks = JenksNaturalBreaks(n_classes=3)  # Increase number of classes to get better separation of bulk data
jenks.fit(data)
breaks = jenks.breaks_

# Identify the highest Jenks break point (excluding the maximum value)
max_jenks_break = max(breaks[:-1])

# Find differences between consecutive data points (gaps)
diffs = np.diff(data)

# Identify the two largest gaps
largest_gaps_indices = np.argsort(diffs)[-2:]

# Find the midpoint of the largest gap (upper break value for classification)
# Make sure this midpoint is less than the highest Jenks break point
upper_break = None
upper_break_upper_boundary = None
upper_break_lower_boudary = None

for idx in reversed(largest_gaps_indices):
    midpoint = (data[idx] + data[idx + 1]) / 2
    if midpoint < max_jenks_break:
        upper_break = midpoint
        break
    left_value = data[idx]
    right_value = data[idx + 1]

for idx in reversed(largest_gaps_indices):
    left_value = data[idx]
    right_value = data[idx + 1]
    #point_99_percent = left_value + 0.99 * (right_value - left_value)
    #if point_99_percent < max_jenks_break:
    #    upper_break = point_99_percent
    #    break
    if right_value < max_jenks_break:
        upper_break_upper_boundary = right_value
        #break
    if left_value < max_jenks_break:
        upper_break_lower_boundary = left_value

# Fallback if no suitable midpoint was found (use max_jenks_break as the threshold)
if upper_break is None:
    upper_break = max_jenks_break

# Print the upper break value for reference
print("Upper break value (threshold between VALID and INVALID):", upper_break)
print(f"Upper: {upper_break_upper_boundary}")

# Step 4: Process lines in the original file
output_lines = []

with open(args.file, 'r') as file:
    for line in file:
        original_line = line.rstrip()  # Preserve leading whitespace, remove trailing newline
        leading_whitespace = len(line) - len(line.lstrip())  # Calculate leading whitespace

        if line.lstrip().startswith("VALID") or line.lstrip().startswith("INVALID"):
            parts = re.split(r'\s+', original_line.strip())
            value = parts[3]
            value = 3.0 if value == "XXX" else float(value)

            # Update the first part based on the value compared to the upper break
            if value > upper_break:
                parts[0] = "INVALID"
            else:
                parts[0] = "VALID"

            updated_line = " " * leading_whitespace + " ".join(parts)
            output_lines.append(updated_line)
        else:
            output_lines.append(line.rstrip())

# Step 5: Output the updated lines
output_filename = args.file + ".reclassified.txt"
with open(output_filename, "w") as file:
    for line in output_lines:
        file.write(line + "\n")

print(f"Processing complete. Output saved to '{output_filename}'.")

# Step 6: Plotting the histogram if --graph flag is provided
if args.graph:
    try:
        # If --max-value is provided, filter data accordingly
        if args.max_value is not None:
            filtered_data = data[data <= args.max_value]
        else:
            filtered_data = data

        plt.hist(filtered_data, bins=20, color='blue', edgecolor='black')

        plt.axvline(upper_break, color='red', linestyle='dashed', linewidth=2)
        
        # Adding the upper break label with a background and offset to the right
        plt.text(upper_break + 0.01, plt.ylim()[1] * 0.9, f'{upper_break:.2f}', color='red',
                 fontsize=14, fontweight='bold', ha='left',
                 bbox=dict(facecolor='#ccc', alpha=0.5, edgecolor='none'))

        plt.axvline(upper_break_upper_boundary, color='red', linestyle='dashed', linewidth=2)
        
        # Adding the upper break label with a background and offset to the right
        plt.text(upper_break_upper_boundary + 0.05, plt.ylim()[1] * 0.7, f'{upper_break_upper_boundary:.2f}', color='red',
                 fontsize=14, fontweight='bold', ha='left',
                 bbox=dict(facecolor='#ccc', alpha=0.5, edgecolor='none'))

        plt.axvline(upper_break_lower_boundary, color='red', linestyle='dashed', linewidth=2)
        
        # Adding the upper break label with a background and offset to the right
        plt.text(upper_break_lower_boundary - 0.15, plt.ylim()[1] * 0.7, f'{upper_break_lower_boundary:.2f}', color='red',
                 fontsize=14, fontweight='bold', ha='left',
                 bbox=dict(facecolor='#ccc', alpha=0.5, edgecolor='none'))

        plt.title('Upper Break Value Overlay')
        plt.xlabel('Values')
        plt.ylabel('Frequency')
        plt.show()

    except KeyboardInterrupt:
        print("\nPlotting interrupted. Exiting gracefully.")

print("Done.")

