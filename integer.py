import re

def detect_integer_overflow_underflow(file_path):
    with open(file_path, 'r') as file:
        solidity_code = file.read()

    patterns = (
        r'(\+|-|\*|/|%)\s*=\s*[^=]',  # Arithmetic operations
        r'(\+|-|\*|/|%)\s*[^=]',      # Arithmetic operations without assignment
    )

    vulnerable_lines = []
    for line_number, line in enumerate(solidity_code.split('\n'), start=1):
         for pattern in patterns:
            if re.search(pattern, line):
                vulnerable_lines.append(line_number)
                #break

    return vulnerable_lines



