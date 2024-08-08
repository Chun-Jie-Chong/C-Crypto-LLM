#!/bin/bash

# Directory to change into
target_directory="../src"

# Change to the target directory
cd "$target_directory" || { echo "Failed to change directory to $target_directory"; exit 1; }

# Specify the output file
output_file="scc_chatgpt.txt"

# Clear the output file if it exists
> "$output_file"

# Loop through all .c files in the target directory
for file in *.c; do
    if [ -e "$file" ]; then  # Check if the file exists
        echo "Processing $file..." >> "$output_file"
        scc "$file" >> "$output_file" 2>&1  # Run scc and redirect output and errors
        echo "Done processing $file." >> "$output_file"
        echo "----------------------------------------------------------------------------------------------------------------------------------------------------------------" >> "$output_file"
    else
        echo "No .c files found in the directory."
    fi
done

echo "All done! Output saved to $output_file."
