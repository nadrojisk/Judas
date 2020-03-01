import mmap
import math
import pefile
import utilities
import os

VERBOSE = False


def add_section(exe_path, name, virtual_size, raw_size, characteristics, verbose=False):
    global VERBOSE
    VERBOSE = verbose
    if VERBOSE:
        print(f"New Section Information:\n\
            \tName: {name}\n\
            \tVirtual Size: {virtual_size}\n\
            \tRaw Size: {raw_size}\n\
            \tCharactersitics: {hex(characteristics)}\n")

    exe_path = utilities.make_duplicate(exe_path, 'injection')

    if VERBOSE:
        print(f"Loading {exe_path} into PE File Module\n")
    pe = pefile.PE(exe_path)
    if not pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE:
        print("Error: File is not a 32-bit binary.")
        utilities.delete_file(
            exe_path, )
        exit(1)
    if no_space(pe):
        utilities.delete_file(exe_path)
        exit(1)

    last_section_offset = pe.sections[pe.FILE_HEADER.NumberOfSections -
                                      1].get_file_offset()

    FILE_ALIGNMENT = pe.OPTIONAL_HEADER.FileAlignment

    # print(f"File alignment is {FILE_ALIGNMENT}")

    raw_offset, virtual_offset, new_section_offset = locate_offsets(pe)
    if VERBOSE:
        print(f"Section Offsets:\n\
            \tRaw offset: {hex(raw_offset)}\n\
            \tVirtual offset: {hex(virtual_offset)}\n\
            \tSection table offset: {hex(new_section_offset)}\n")

    # ensure raw size is multiple of filealignment
    if raw_size % FILE_ALIGNMENT != 0:
        # print(f"Raw size is not a multiple of the file alignment: {hex(FILE_ALIGNMENT)}\n")
        raw_size = math.ceil(raw_size / FILE_ALIGNMENT) * FILE_ALIGNMENT

    # Section name must be equal to 8 bytes
    if len(name) > 8:
        print("Error: Section name must be less than or equal to 8 bytes")
        utilities.delete_file(exe_path)
        exit(1)

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

    # resize file
    resize(exe_path)

    print("[x] Section Added\n")

    return exe_path


def resize(path):
    fd = open(path, 'a+b')
    original_size = os.path.getsize(path)
    map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
    map.resize(original_size + 0x2000)  # TODO 0x2000 may not always be needed!
    map.close()
    fd.close()


def locate_offsets(pe):

    SECTION_ALIGNMENT = pe.OPTIONAL_HEADER.SectionAlignment
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1

    # get offset for new section by looking at the last sections location

    raw_offset = pe.sections[last_section].PointerToRawData + \
        pe.sections[last_section].SizeOfRawData

    virtual_offset = pe.sections[last_section].VirtualAddress + \
        pe.sections[last_section].Misc_VirtualSize

    # ensure virtual offset is a multiple of sectionalignment
    if virtual_offset % SECTION_ALIGNMENT != 0:
        # print(f"Virtual offset is not a multiple of the section alignment: {hex(SECTION_ALIGNMENT)}\n")
        factor = math.ceil(virtual_offset / SECTION_ALIGNMENT)
        virtual_offset = factor * SECTION_ALIGNMENT

    SECTION_HEADER_LENGTH = 40
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section_offset = pe.sections[number_of_section - 1].get_file_offset()
    new_section_offset = last_section_offset + SECTION_HEADER_LENGTH

    return raw_offset, virtual_offset, new_section_offset


def no_space(pe):
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section_offset = pe.sections[number_of_section - 1].get_file_offset()
    for x in pe.get_data(last_section_offset+0x40, 0x40):
        if x != 0x0:
            print('Error: Not enough space in file!')
            return 1
    return 0


if __name__ == "__main__":

    add_section("./assets/bin/sublime_text.exe",
                ".pwn",
                0x1000,
                0x1000,
                0xE0000000)
