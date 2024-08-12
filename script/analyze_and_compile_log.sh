#!/bin/bash

# Define the compiler and flags
CC=clang
CFLAGS="-Wall -O0"
ANALYZE_FLAGS="--analyze -Xanalyzer -analyzer-checker=alpha.core -Xanalyzer -analyzer-checker=alpha.deadcode -Xanalyzer -analyzer-checker=alpha.unix -Xanalyzer -analyzer-checker=alpha.security"
LOGFILE="compile_and_analyze_log.txt"

# Iterate over all .c files in the current directory
cd ../src

# Create or clear the log file
> "$LOGFILE"

for cfile in *.c; do
    if [[ -f "$cfile" ]]; then
        # Remove the .c extension and add .o to get the object file name
        ofile="${cfile%.c}.o"
        
        echo "Analyzing and compiling $cfile to $ofile" | tee -a "$LOGFILE"
        # Compile the C file to an object file with static analysis enabled
        # Redirect both stdout and stderr to the log file
        $CC $CFLAGS $ANALYZE_FLAGS -c "$cfile" -o "$ofile" >> "$LOGFILE" 2>&1
        
        # Check if the compilation was successful
        if [[ $? -eq 0 ]]; then
            echo "Compilation and analysis of $cfile succeeded" | tee -a "$LOGFILE"
        else
            echo "Compilation and analysis of $cfile failed" | tee -a "$LOGFILE"
        fi
    fi
done

echo "Compilation and static analysis completed." | tee -a "$LOGFILE"
