import os

def process_c_files(directory):
    result = []

    # Traverse the directory
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.c'):
                file_path = os.path.join(root, file)
                count = 0

                # Open each .c file and check each line
                with open(file_path, 'r') as f:
                    for line in f:
                        if '?' in line and ':' in line:
                            count += 2
                
                # Append the result for this file
                result.append(f"{file}: {count}")

    return result

def write_results_to_file(results, output_file):
    with open(output_file, 'w') as f:
        for line in results:
            f.write(line + '\n')

if __name__ == "__main__":
    directory_to_process = "../src"
    output_file = "ternary_chatgpt.txt"

    results = process_c_files(directory_to_process)
    write_results_to_file(results, output_file)
    print(f"Results written to {output_file}")
