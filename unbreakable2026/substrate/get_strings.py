#!/usr/bin/env python3
"""
Solver for Substrate CTF challenge.
Emulates the decode functions in SubstrateUM.exe using Unicorn engine,
then analyzes the kernel driver's IOCTL handler.
"""

import struct
from unicorn import *
from unicorn.x86_const import *

# Load the PE files
with open("SubstrateUM.exe", "rb") as f:
    exe_data = f.read()

with open("SubstrateKM.sys", "rb") as f:
    sys_data = f.read()

# Parse PE to find section mappings
import pefile
pe_exe = pefile.PE(data=exe_data)
pe_sys = pefile.PE(data=sys_data)

def emulate_decode_func(pe, func_rva, input_byte, index):
    """Emulate a decode function from the EXE.
    The function takes cl=input_byte, edx=index and returns al=decoded_byte.
    """
    image_base = pe.OPTIONAL_HEADER.ImageBase  # 0x140000000
    
    # Create emulator
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    
    # Map memory for the image
    # Map enough for the whole image
    image_size = 0x10000  # 64KB pages
    for section in pe.sections:
        sec_start = image_base + section.VirtualAddress
        sec_size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        # Align to page
        sec_start_aligned = sec_start & ~0xFFF
        sec_end = sec_start + sec_size
        sec_end_aligned = (sec_end + 0xFFF) & ~0xFFF
        try:
            mu.mem_map(sec_start_aligned, sec_end_aligned - sec_start_aligned)
        except:
            pass  # Already mapped
        # Write section data
        raw_data = section.get_data()
        mu.mem_write(sec_start, raw_data[:sec_size])
    
    # Set up stack
    stack_base = 0x7FFE0000
    stack_size = 0x10000
    mu.mem_map(stack_base, stack_size)
    mu.reg_write(UC_X86_REG_RSP, stack_base + stack_size - 0x100)
    
    # Write a return address on stack (we'll stop when we hit it)
    ret_addr = 0xDEAD0000
    mu.mem_map(ret_addr & ~0xFFF, 0x1000)
    mu.mem_write(ret_addr, b'\xCC')  # INT3
    
    # The function uses push r12, r13, r14, r15, so we need stack space
    # Push return address
    rsp = mu.reg_read(UC_X86_REG_RSP)
    # The function doesn't have a standard prologue with push rbp
    # It starts with saving registers to stack slots (rsp+0x28, etc)
    # and pushing r12-r15
    # We need to have the return address where ret will find it
    # After push r12, r13, r14, r15 (4 pushes = 32 bytes), RSP points to ret addr
    # Actually, the function will ret from the current RSP after pops
    # Let's just put ret_addr at current RSP
    
    # Set up registers
    mu.reg_write(UC_X86_REG_RCX, input_byte & 0xFF)
    mu.reg_write(UC_X86_REG_RDX, index)
    
    # Push return address onto stack
    rsp = mu.reg_read(UC_X86_REG_RSP)
    mu.mem_write(rsp, struct.pack('<Q', ret_addr))
    
    func_addr = image_base + func_rva
    
    try:
        mu.emu_start(func_addr, ret_addr, timeout=5000000)
    except UcError as e:
        pass
    
    # Get return value (al)
    rax = mu.reg_read(UC_X86_REG_RAX)
    return rax & 0xFF


# Get section info for exe
print("=== SubstrateUM.exe sections ===")
for section in pe_exe.sections:
    print(f"  {section.Name.decode().strip(chr(0)):10} VA=0x{section.VirtualAddress:08x} Size=0x{section.Misc_VirtualSize:08x} RawSize=0x{section.SizeOfRawData:08x}")

# Function addresses (RVA = VA - ImageBase)
# ImageBase = 0x140000000
# All decode functions and their parameters from the disassembly

# The first string built in main (success path): 23 bytes at rsp+0x50
# Using fcn.140003e40 (RVA = 0x3e40)
decode_func_1_rva = 0x3e40
params_1 = [
    (0x65, 0),   # index 0
    (0xfe, 1),   # index 1
    (0xb4, 2),   # index 2
    (0x13, 3),   # index 3
    (0xc4, 4),   # index 4
    (0x8c, 5),   # index 5
    (0x6b, 6),   # index 6
    (0x94, 7),   # index 7
    (0xf4, 8),   # index 8
    (0xe1, 9),   # index 9
    (0x04, 10),  # index 10
    (0x32, 11),  # index 11
    (0x07, 12),  # index 12
    (0xd3, 13),  # index 13
    (0x6a, 14),  # index 14
    (0xf6, 15),  # index 15
    (0xed, 16),  # index 16 (edx not explicitly set, follows from previous ba11000000)
    (0x27, 17),  # index 17 (edx=0x11=17... wait let me re-check)
    (0x2c, 18),  # index 18
    (0x65, 19),  # index 19
    (0xdb, 20),  # index 20
    (0xd0, 21),  # index 21
    (0x0d, 22),  # index 22
]

print("\n=== Decoding string 1 (main success path, fcn.140003e40) ===")
decoded_1 = []
for byte_val, idx in params_1:
    result = emulate_decode_func(pe_exe, decode_func_1_rva, byte_val, idx)
    decoded_1.append(result)
    print(f"  decode(0x{byte_val:02x}, {idx:2d}) = 0x{result:02x} '{chr(result) if 32 <= result < 127 else '.'}'")

print(f"  Full string: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded_1)}")
print(f"  Hex: {bytes(decoded_1).hex()}")

# Error path strings - let's decode them all too
# fcn.140003af0 (RVA = 0x3af0) - error when GetStdHandle(-11) fails
decode_func_2_rva = 0x3af0
params_2 = [
    (0x9e, 0), (0xa7, 1), (0x73, 2), (0x3a, 3), (0x96, 4),
    (0xf4, 5), (0x5b, 6), (0xb7, 7), (0xb1, 8), (0x97, 9),
]

print("\n=== Decoding string 2 (fcn.140003af0) ===")
decoded_2 = []
for byte_val, idx in params_2:
    result = emulate_decode_func(pe_exe, decode_func_2_rva, byte_val, idx)
    decoded_2.append(result)
    print(f"  decode(0x{byte_val:02x}, {idx:2d}) = 0x{result:02x} '{chr(result) if 32 <= result < 127 else '.'}'")
print(f"  Full string: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded_2)}")

# fcn.140003790 (RVA = 0x3790) - error when GetStdHandle(-10) fails  
decode_func_3_rva = 0x3790
params_3 = [
    (0xa6, 0), (0x76, 1), (0x76, 2), (0x60, 3), (0x34, 4),
    (0x19, 5), (0x2a, 6), (0xb4, 7), (0x96, 8), (0x0a, 9),
]

print("\n=== Decoding string 3 (fcn.140003790) ===")
decoded_3 = []
for byte_val, idx in params_3:
    result = emulate_decode_func(pe_exe, decode_func_3_rva, byte_val, idx)
    decoded_3.append(result)
    print(f"  decode(0x{byte_val:02x}, {idx:2d}) = 0x{result:02x} '{chr(result) if 32 <= result < 127 else '.'}'")
print(f"  Full string: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded_3)}")

# fcn.140003440 (RVA = 0x3440) - error when VirtualAlloc fails
decode_func_4_rva = 0x3440
params_4 = [
    (0xf0, 0), (0x31, 1), (0x46, 2), (0x6b, 3), (0xb2, 4),
    (0x03, 5), (0x6f, 6), (0x1c, 7), (0xd9, 8), (0xc9, 9),
]

print("\n=== Decoding string 4 (fcn.140003440) ===")
decoded_4 = []
for byte_val, idx in params_4:
    result = emulate_decode_func(pe_exe, decode_func_4_rva, byte_val, idx)
    decoded_4.append(result)
    print(f"  decode(0x{byte_val:02x}, {idx:2d}) = 0x{result:02x} '{chr(result) if 32 <= result < 127 else '.'}'")
print(f"  Full string: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded_4)}")

# fcn.1400030f0 (RVA = 0x30f0) - error when OpenProcess fails
decode_func_5_rva = 0x30f0
params_5 = [
    (0xc9, 0), (0xf9, 1), (0x7b, 2), (0xd7, 3), (0x63, 4),
    (0xd7, 5), (0xad, 6), (0x21, 7), (0x2a, 8), (0xbe, 9),
]

print("\n=== Decoding string 5 (fcn.1400030f0) ===")
decoded_5 = []
for byte_val, idx in params_5:
    result = emulate_decode_func(pe_exe, decode_func_5_rva, byte_val, idx)
    decoded_5.append(result)
    print(f"  decode(0x{byte_val:02x}, {idx:2d}) = 0x{result:02x} '{chr(result) if 32 <= result < 127 else '.'}'")
print(f"  Full string: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded_5)}")

# fcn.140002d90 (RVA = 0x2d90) - error when CreateFile fails
decode_func_6_rva = 0x2d90
params_6 = [
    (0xf2, 0), (0x45, 1), (0x0e, 2), (0x6d, 3), (0x09, 4),
    (0x98, 5), (0xda, 6), (0x5b, 7), (0x32, 8), (0x08, 9),
]

print("\n=== Decoding string 6 (fcn.140002d90) ===")
decoded_6 = []
for byte_val, idx in params_6:
    result = emulate_decode_func(pe_exe, decode_func_6_rva, byte_val, idx)
    decoded_6.append(result)
    print(f"  decode(0x{byte_val:02x}, {idx:2d}) = 0x{result:02x} '{chr(result) if 32 <= result < 127 else '.'}'")
print(f"  Full string: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded_6)}")

# fcn.1400026f0 (RVA = 0x26f0) - error when DeviceIoControl IOCTL 0x228128 fails
decode_func_7_rva = 0x26f0
params_7 = [
    (0x31, 0), (0xc2, 1), (0xb4, 2), (0x77, 3), (0x08, 4),
    (0x30, 5), (0x01, 6), (0x45, 7), (0x76, 8), (0x9a, 9),
]

print("\n=== Decoding string 7 (fcn.1400026f0) ===")
decoded_7 = []
for byte_val, idx in params_7:
    result = emulate_decode_func(pe_exe, decode_func_7_rva, byte_val, idx)
    decoded_7.append(result)
    print(f"  decode(0x{byte_val:02x}, {idx:2d}) = 0x{result:02x} '{chr(result) if 32 <= result < 127 else '.'}'")
print(f"  Full string: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded_7)}")

# fcn.1400023b0 (RVA = 0x23b0) - success message when [var_40h] == 0
decode_func_8_rva = 0x23b0
params_8 = [
    (0x6a, 0), (0xe0, 1), (0x69, 2), (0x4c, 3), (0xbe, 4),
    (0x3c, 5), (0xaf, 6), (0xe5, 7), (0x22, 8), (0x73, 9),
    (0x18, 10), (0x0f, 11), (0x37, 12), (0xe2, 13), (0x84, 14),
    (0x6f, 15),
]

print("\n=== Decoding string 8 (fcn.1400023b0) - 'success' path ===")
decoded_8 = []
for byte_val, idx in params_8:
    result = emulate_decode_func(pe_exe, decode_func_8_rva, byte_val, idx)
    decoded_8.append(result)
    print(f"  decode(0x{byte_val:02x}, {idx:2d}) = 0x{result:02x} '{chr(result) if 32 <= result < 127 else '.'}'")
print(f"  Full string: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded_8)}")

# fcn.140002060 (RVA = 0x2060) - error path after DeviceIoControl success check
decode_func_9_rva = 0x2060
params_9 = [
    (0x31, 0), (0x9a, 1), (0xef, 2), (0xb3, 3), (0x05, 4),
    (0x8c, 5), (0x09, 6), (0x72, 7), (0xa1, 8),
]

print("\n=== Decoding string 9 (fcn.140002060) ===")
decoded_9 = []
for byte_val, idx in params_9:
    result = emulate_decode_func(pe_exe, decode_func_9_rva, byte_val, idx)
    decoded_9.append(result)
    print(f"  decode(0x{byte_val:02x}, {idx:2d}) = 0x{result:02x} '{chr(result) if 32 <= result < 127 else '.'}'")
print(f"  Full string: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded_9)}")

# fcn.140002a40 (RVA = 0x2a40) - error when DeviceIoControl in loop fails
decode_func_10_rva = 0x2a40
params_10 = [
    (0x44, 0), (0x65, 1), (0x31, 2), (0x8d, 3), (0x5a, 4),
    (0x98, 5), (0x10, 6), (0x00, 7), (0x91, 8), (0xa1, 9),
]

print("\n=== Decoding string 10 (fcn.140002a40) ===")
decoded_10 = []
for byte_val, idx in params_10:
    result = emulate_decode_func(pe_exe, decode_func_10_rva, byte_val, idx)
    decoded_10.append(result)
    print(f"  decode(0x{byte_val:02x}, {idx:2d}) = 0x{result:02x} '{chr(result) if 32 <= result < 127 else '.'}'")
print(f"  Full string: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded_10)}")

# Now let's also decode the initial error string from fcn.140001c00
print("\n=== Analyzing fcn.140001c00 (initial check error) ===")

# And fcn.1400041a0 which is another function
print("\n=== Analyzing fcn.1400041a0 ===")
