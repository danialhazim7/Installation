#!/usr/bin/python3
import subprocess
import os
import csv
import socket

def run_sublist3r(domain, output_directory):
    output_file = os.path.join(output_directory, f"{domain}.txt")
    command = f"sublist3r -d {domain} -o {output_file}"
    subprocess.run(command, shell=True)

def resolve_subdomains(input_file, csv_output_file, unique_ips_file):
    subdomains = []
    with open(input_file, 'r') as file:
        subdomains = [line.strip() for line in file.readlines()]

    unique_ips = set()
    resolved_subdomains = []

    for idx, subdomain in enumerate(subdomains, start=1):
        try:
            ip_address = socket.gethostbyname(subdomain)
            resolved_subdomains.append((idx, subdomain, ip_address))
            unique_ips.add(ip_address)
        except socket.gaierror:
            print(f"Could not resolve {subdomain}")

    with open(csv_output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["No.", "Subdomain", "IP Address"])
        writer.writerows(resolved_subdomains)

    with open(unique_ips_file, 'w') as file:
        for ip in unique_ips:
            file.write(f"{ip}\n")

def run_nmap(unique_ips_file, output_directory):
    with open(unique_ips_file, 'r') as file:
        unique_ips = [line.strip() for line in file.readlines()]

    for ip in unique_ips:
        output_file = os.path.join(output_directory, f"{ip}-open-ports.txt")
        #command = f"nmap -sS -p- -Pn -T3 {ip} -oN {output_file}"
        command = f"nmap -sS {ip} -oN {output_file}"
        subprocess.run(command, shell=True)

def main():
    # Prompt user to enter the target domain

    target_domain = input("Enter the target domain: ").strip()

    


    # Specify the base output directory
    base_output_directory = "/var/log/asm/"

    # Create a directory for the target domain
    target_directory = os.path.join(base_output_directory, target_domain)
    os.makedirs(target_directory, exist_ok=True)

    # Run Sublist3r
    print("\n=====================Initializing Domain Scanning======================\n")
    run_sublist3r(target_domain, target_directory)

    # Resolve subdomains and write to CSV
    sublist3r_output = os.path.join(target_directory, f"{target_domain}.txt")
    print("\n=====================Domain Scanning Completed=======================\n")
    
    csv_output_file = os.path.join(target_directory, f"{target_domain}_resolved.csv")
    unique_ips_file = os.path.join(target_directory, f"{target_domain}_unique_ips.txt")
    resolve_subdomains(sublist3r_output, csv_output_file, unique_ips_file)
    print("\n=====================CSV file has been Saved====================\n")
    print("\nCSV File: "+csv_output_file +"\nFile for unique IPs: "+unique_ips_file "\n")


    # Run Nmap using unique IPs
    print("\n=====================Step 2: Open Ports Scanning====================\n")
    run_nmap(unique_ips_file, target_directory)
    print("\n=====================Open Ports Scanning Completed====================\n")
    print("Target File is at:"+ target_directory)

if __name__ == "__main__":
    main()
