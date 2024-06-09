import re

def parse_contract(contract):
    return contract.split('\n')

def throw_vulnerability_detection(file_path):
    with open(file_path, 'r') as file:
        contract_code = file.read()
    r = re.compile(r'^.*throw.*')
    parsed_contract_into_list = parse_contract(contract_code)
    vulnerable_lines = []

    for line_number, line in enumerate(parsed_contract_into_list, start=1):
        if r.match(line):
            vulnerable_lines.append(line_number)

    return vulnerable_lines