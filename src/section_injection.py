import mmap
import math
import pefile
import utilities
import os


def add_section(info):
    # TODO Ensure there is enough space to add more sections

    exe_path, name, virtual_size, raw_size, characteristics = info

    pe = pefile.PE(exe_path)

    FILE_ALIGNMENT = pe.OPTIONAL_HEADER.FileAlignment

    raw_offset, virtual_offset, new_section_offset = locate_offsets(pe)

    # ensure raw size is multiple of filealignment
    if raw_size % FILE_ALIGNMENT != 0:
        raw_size = math.ceil(raw_size / FILE_ALIGNMENT) * FILE_ALIGNMENT

    # Section name must be equal to 8 bytes
    if len(name) > 8:
        print("Error: Section name must be less than or equal to 8 bytes")
        return

    name += '\x00' * (8 - len(name))

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
    # PointerToRelocations, PointerToLinenumbers, NumberOfRelocations,
    # NumberOfLinenumbers
    pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00').encode())
    # Set the characteristics
    pe.set_dword_at_offset(new_section_offset + 36, characteristics)

    # Edit the value in the File and Optional headers
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset

    # write changes
    pe.write(exe_path)

    resize(exe_path)


def resize(path):
    fd = open(path, 'a+b')
    original_size = os.path.getsize(path)
    map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
    map.resize(original_size + 0x2000)
    map.close()
    fd.close()


def locate_offsets(pe):

    SECTION_ALIGNMENT = pe.OPTIONAL_HEADER.SectionAlignment
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1

    # get offset for new section by looking at the last sections last byte
    raw_offset = pe.sections[last_section].PointerToRawData + \
        pe.sections[last_section].SizeOfRawData

    virtual_offset = pe.sections[last_section].VirtualAddress + \
        pe.sections[last_section].Misc_VirtualSize

    # ensure virtual offset is a multiple of sectionalignment
    if virtual_offset % SECTION_ALIGNMENT != 0:
        factor = math.ceil(virtual_offset / SECTION_ALIGNMENT)
        virtual_offset = factor * SECTION_ALIGNMENT

    SECTION_HEADER_LENGTH = 40
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section_offset = pe.sections[number_of_section - 1].get_file_offset()
    new_section_offset = last_section_offset + SECTION_HEADER_LENGTH

    return raw_offset, virtual_offset, new_section_offset


if __name__ == "__main__":

    path = utilities.make_duplicate("./assets/bin/putty.exe", 'injection')
    file_info = [path,
                 ".pwn",
                 0x1000,
                 0x1000,
                 0xE0000000]
    add_section(file_info)
