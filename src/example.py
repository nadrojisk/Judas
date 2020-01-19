import pefile

pe = pefile.PE('./assets/bin/putty.exe')

print(pe.FILE_HEADER.NumberOfSections)

print(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

print(pe.OPTIONAL_HEADER.FileAlignment)

print(pe.OPTIONAL_HEADER.SectionAlignment)

for section in pe.sections:
    print(section)
