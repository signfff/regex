import os
import hashlib

def main():
    # Configuration
    input_file = "regular_exprs_final.txt"
    output_dir = "/home/lxy/regex_fuzzing/regex/fuzz/corpus/fuzz_diff_eqs"

    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created directory: {output_dir}")

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return

    count = 0
    for line in lines:
        # Strip newline characters but keep other whitespace
        # Note: fuzzing corpus usually contains raw bytes, so we might want to avoid stripping if trailing spaces are significant.
        # However, for text files, usually we want to strip the newline at the end.
        content = line.strip('\n')
        
        if not content:
            continue

        # Use hash of content for filename to avoid duplicates and handle special chars
        # Using sha1 for a reasonable length filename
        filename = hashlib.sha1(content.encode('utf-8')).hexdigest()
        file_path = os.path.join(output_dir, filename)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        count += 1

    print(f"Successfully created {count} corpus files in '{output_dir}'")

if __name__ == "__main__":
    main()
