import re
import sys
import csv

# TODO: Step 3
def get_log_file_path_from_cmd_line(param_number):
    if len(sys.argv) <= param_number:
        print(f"Error: No parameter {param_number} provided.")
        sys.exit(1)
    log_file_path = sys.argv[param_number]
    if not os.path.isfile(log_file_path):
        print(f"Error: The file {log_file_path} does not exist.")
        sys.exit(1)
    return log_file_path

# TODO: Steps 4-7
def filter_log_by_regex(log_file_path, regex, case_sensitive=False, print_summary=False, print_records=False):
    """Gets a list of records in a log file that match a specified regex.

    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(regex, flags)
    matched_records = []
    with open(log_file_path, 'r') as file:
        for line in file:
            if pattern.search(line):
                matched_records.append(line)
                if print_records:
                    print(line.strip())
    if print_summary:
        print(f"The log file contains {len(matched_records)} records that match the regex '{regex}'.")
    return matched_records

# TODO: Step 8
def tally_port_traffic(log_file_path):
    port_tally = {}
    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.search(r'DPT=(\d+)', line)
            if match:
                port = match.group(1)
                if port in port_tally:
                    port_tally[port] += 1
                else:
                    port_tally[port] = 1
    return port_tally

# TODO: Step 9
def generate_port_traffic_report(log_file_path, port_number):
    report_filename = f"destination_port_{port_number}_report.csv"
    with open(log_file_path, 'r') as file, open(report_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Date", "Time", "Source IP", "Destination IP", "Source Port", "Destination Port"])
        for line in file:
            if f"DPT={port_number}" in line:
                match = re.search(r'(\S+ \S+) (\S+) SRC=(\S+) DST=(\S+) .*SPT=(\S+) DPT=(\S+)', line)
                if match:
                    writer.writerow(match.groups())
    return

# TODO: Step 11
def generate_invalid_user_report(log_file_path):
    report_filename = "invalid_users.csv"
    with open(log_file_path, 'r') as file, open(report_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Date", "Time", "Username", "IP Address"])
        for line in file:
            if "Invalid user" in line:
                match = re.search(r'(\S+ \S+) (\S+) Invalid user (\S+) from (\S+)', line)
                if match:
                    writer.writerow(match.groups())
                                    
# TODO: Step 12
def generate_source_ip_log(log_file_path, source_ip):
    output_filename = f"source_ip_{source_ip.replace('.', '_')}.log"
    with open(log_file_path, 'r') as file, open(output_filename, 'w') as output_file:
        for line in file:
            if f"SRC={source_ip}" in line:
                output_file.write(line)

def create_port_report(log_file_path, destination_port):
    report_filename = f"destination_port_{destination_port}_report.csv"
    with open(log_file_path, 'r') as file, open(report_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Date", "Time", "Source IP", "Destination IP", "Source Port", "Destination Port"])
        for line in file:
            if f"DPT={destination_port}" in line:
                match = re.search(r'(\S+ \S+) (\S+) SRC=(\S+) DST=(\S+) .*SPT=(\S+) DPT=(\S+)', line)
                if match:
                    writer.writerow(match.groups())

def create_invalid_user_report(log_file_path):
    report_filename = "invalid_users.csv"
    with open(log_file_path, 'r') as file, open(report_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Date", "Time", "Username", "IP Address"])
        for line in file:
            if "Invalid user" in line:
                match = re.search(r'(\S+ \S+) (\S+) Invalid user (\S+) from (\S+)', line)
                if match:
                    writer.writerow(match.groups())

def extract_source_ip_records(log_file_path, source_ip):
    output_filename = f"source_ip_{source_ip.replace('.', '_')}.log"
    with open(log_file_path, 'r') as file, open(output_filename, 'w') as output_file:
        for line in file:
            if f"SRC={source_ip}" in line:
                output_file.write(line)
from log_utils import (
    get_log_file_path_from_cmd_line,
    filter_log_by_regex,
    tally_port_traffic,
    generate_port_traffic_report,
    generate_invalid_user_report,
    generate_source_ip_log,
)

def main():
    log_file_path = get_log_file_path_from_cmd_line(1)
    
    filter_log_by_regex(log_file_path, 'sshd', case_sensitive=False, print_records=True, print_summary=True)
    filter_log_by_regex(log_file_path, 'invalid user', case_sensitive=False, print_records=True, print_summary=True)
    filter_log_by_regex(log_file_path, 'invalid user.*220.195.35.40', case_sensitive=False, print_records=True, print_summary=True)
    filter_log_by_regex(log_file_path, 'error', case_sensitive=False, print_records=True, print_summary=True)
    filter_log_by_regex(log_file_path, 'pam', case_sensitive=False, print_records=True, print_summary=True)
    
    port_tally = tally_port_traffic(log_file_path)
    for port, count in port_tally.items():
        if count >= 100:
            generate_port_traffic_report(log_file_path, port)
    
    generate_invalid_user_report(log_file_path)
    generate_source_ip_log(log_file_path, '220.195.35.40')

if __name__ == '__main__':
    main()
