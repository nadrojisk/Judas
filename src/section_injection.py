import pefile
import os
import mmap


def align(val_to_align, alignment):
    return ((val_to_align + alignment - 1) / alignment) * alignment


def add_section(info):

    exe_path, name, virtual_size, raw_size, characteristics = info
    original_size = os.path.getsize(exe_path)
    pe = pefile.PE(exe_path)

    pe.sections[-1].Misc_VirtualSize = 0x8000

    raw_offset, virtual_offset, new_section_offset = locate_offsets(pe)

    # Section name must be equal to 8 bytes
    name += '\x00' * (8 - len(name))

    # pe.sections
    # Set the name
    pe.set_bytes_at_offset(new_section_offset, name.encode())
    # Set the virtual size
    pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
    # Set the virtual offset
    pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
    # Set the raw size
    pe.set_dword_at_offset(new_section_offset + 16, raw_size)
    # Set the raw offset
    pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
    # Set the following fields to zero
    pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00').encode())
    # Set the characteristics
    pe.set_dword_at_offset(new_section_offset + 36, characteristics)

    # Edit the value in the File and Optional headers
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset
    pe.write(exe_path)

    fd = open(exe_path, 'a+b')
    map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
    map.resize(original_size + 0x2000)
    map.close()
    fd.close()


def locate_offsets(pe):
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

    # get offset for new section by looking at the last sections last byte
    raw_offset = pe.sections[last_section].PointerToRawData + \
        pe.sections[last_section].SizeOfRawData

    virtual_offset = pe.sections[last_section].VirtualAddress + \
        pe.sections[last_section].Misc_VirtualSize

    SECTION_HEADER_LENGTH = 40
    number_of_section = pe.FILE_HEADER.NumberOfSections

    new_section_offset = (
        pe.sections[number_of_section - 1].get_file_offset() + SECTION_HEADER_LENGTH)

    raw_offset = 0x10ba00
    virtual_offset = 0x111000

    return raw_offset, virtual_offset, new_section_offset


if __name__ == "__main__":
    exe_path = "./assets/bin/putty.exe"
    name = ".pwn"
    virtual_size = 0x1000
    raw_size = 0x1000
    characteristics = 0xE0000000

    info = [exe_path, name, virtual_size, raw_size, characteristics]
    add_section(info)
