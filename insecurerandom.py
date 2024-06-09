import re

def detect_insecure_randomness(file_path):
    regex_pattern = r'^.*blockhash.*|^.*block\.timestamp.*|^.*block\.difficulty.*'
    with open(file_path, 'r') as solidity_file:
        contract_code = solidity_file.read()
    pattern = re.compile(regex_pattern, re.IGNORECASE)
    lines = contract_code.split('\n')
    matching_lines = [(i + 1, line) for i, line in enumerate(lines) if pattern.match(line)]

    return matching_lines

def fix_insecure_randomness(file_path):
    with open(file_path, 'r') as solidity_file:
        contract_code = solidity_file.read()

    insecure_randomness_pattern = re.compile(r'^.*blockhash.*|^.*block\.timestamp.*|^.*block\.difficulty.*', re.IGNORECASE)

    vulnerable_lines = []
    lines = contract_code.split('\n')
    for line_number, line in enumerate(lines, start=1):
        if insecure_randomness_pattern.match(line):
            vulnerable_lines.append(line_number)

    fixed_code = []
    for line_number, line in enumerate(lines, start=1):
        if line_number in vulnerable_lines:
            fixed_line = re.sub(insecure_randomness_pattern,
                                'keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender))',
                                line)
            fixed_code.append(fixed_line)
        else:
            fixed_code.append(line)

    fixed_file_path = file_path.replace('.sol', '_fixed.sol')
    with open(fixed_file_path, 'w') as fixed_solidity_file:
        fixed_solidity_file.write('\n'.join(fixed_code))

    return fixed_file_path