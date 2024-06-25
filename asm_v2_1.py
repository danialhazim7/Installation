#!/usr/bin/python3
import subprocess
import os

def run_sublist3r(domain, output_directory):
    output_file = os.path.join(output_directory, f"{domain}.txt")
    command = f"sublist3r -d {domain} -o {output_file}"
    subprocess.run(command, shell=True)

#def store_csv():
   # target_domain


  #  return 1
#def remove_duplicates():

 #   return 1


def run_nmap(input_file, output_directory):
    output_file = os.path.join(output_directory, f"{os.path.splitext(os.path.basename(input_file))[0]}-open-ports.txt")
    command = f"nmap -sS {input_file} -oN {output_file}"
    subprocess.run(command, shell=True)

def main():
    # Prompt user to enter the target domain
    print=("=====================Step 1: Domain Scanning====================")
    target_domain = input("Enter the target domain: ").strip()

    # Specify the base output directory
    base_output_directory = "/var/log/asm/"

    # Create a directory for the target domain
    target_directory = os.path.join(base_output_directory, target_domain)
    os.makedirs(target_directory, exist_ok=True)

    # Run Sublist3r

    print=("=====================Initializing Domain Scanning======================")
    run_sublist3r(target_domain, target_directory)

    # Run Nmap using the output from Sublist3r
    sublist3r_output = os.path.join(target_directory, f"{target_domain}.txt")
    print=("=====================Domain Scanning Completed=======================")
    print=("=====================Step 2: Open Ports Scanning====================")
    run_nmap(sublist3r_output, target_directory)
    print=("=====================Open Ports Scanning Completed====================")
    print=("Target File is at:"+ target_directory)

if __name__ == "__main__":
    main()