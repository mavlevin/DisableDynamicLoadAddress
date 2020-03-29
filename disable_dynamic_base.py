#!/usr/bin/env python3

"""
Simple program to disable the DYNAMIC_BASE* flag on Windows PE files (.exes, .dlls, etc...),
which will force the program to load to the same address each run. 
This allows for easier debugging as now breakpoing addresses don't need to change between runs.

*https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics
"""

import struct

def disable_dynamic_base(pe_path):
    # naive and simple implementation w/minimal checks. returns True on success; otherwise False

    f = open(pe_path, "rb+")
    first_chunk = f.read(0x1000)
    if not first_chunk.startswith(b"MZ"):
        print("[-] Not a PE file. Try using on a .exe file for example.")
        return False

    offset_pe_header = 0x3c
    size_pe_header = 4
    offset_dll_chars = 0x5e
    size_dll_chars = 2

    addr_dll_characteristics = struct.unpack("<I", 
        first_chunk[offset_pe_header:offset_pe_header+size_pe_header])[0] + offset_dll_chars
    dll_characteristics = struct.unpack("<H", 
        first_chunk[addr_dll_characteristics:addr_dll_characteristics+size_dll_chars])[0]

    # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag is 0x0040
    flag_dyn_base_off = 0xffbf # = binary not of 0x0040
    dll_characteristics &= flag_dyn_base_off

    f.seek(addr_dll_characteristics)
    f.write(struct.pack("<H", dll_characteristics))
    f.close()
    return True

def main():
    import sys
    if (len(sys.argv) != 2):
        print(f"[-] Usage: {sys.argv[0]} <path to target PE>")
        return

    disable_dynamic_base(sys.argv[1])
    print("[+] Done")
    return

if __name__ == '__main__':
    main()