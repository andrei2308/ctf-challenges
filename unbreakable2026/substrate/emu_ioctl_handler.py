#!/usr/bin/env python3
"""
Emulate the IOCTL 0x228128 handler from SubstrateKM.sys using Unicorn
to understand the verification logic, then solve for the correct input.
"""

import struct
from unicorn import *
from unicorn.x86_const import *
import pefile

# Load the driver binary
with open("SubstrateKM.sys", "rb") as f:
    sys_data = f.read()

pe = pefile.PE(data=sys_data)
IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase  # 0x140000000

def setup_driver_emulator():
    """Set up a Unicorn emulator with the driver image mapped."""
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    
    # Map all sections
    for section in pe.sections:
        sec_start = IMAGE_BASE + section.VirtualAddress
        sec_size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        sec_start_aligned = sec_start & ~0xFFF
        sec_end_aligned = ((sec_start + sec_size) + 0xFFF) & ~0xFFF
        size = sec_end_aligned - sec_start_aligned
        try:
            mu.mem_map(sec_start_aligned, size)
        except:
            pass
        raw_data = section.get_data()
        mu.mem_write(sec_start, raw_data[:sec_size])
    
    # Map stack
    stack_base = 0x7FFE0000
    stack_size = 0x100000
    mu.mem_map(stack_base, stack_size)
    mu.reg_write(UC_X86_REG_RSP, stack_base + stack_size - 0x1000)
    
    return mu

def test_input(user_input_bytes):
    """Test a candidate input through the driver's IOCTL 0x228128 handler.
    Returns the result byte (1 = correct, 0 = wrong).
    """
    mu = setup_driver_emulator()
    
    # Write user input to 0x14000c5d8
    input_buf = bytes(user_input_bytes[:72]).ljust(72, b'\x00')
    mu.mem_write(IMAGE_BASE + 0xc5d8, input_buf)
    
    # Set up fake IRP structure
    irp_addr = 0x50000000
    mu.mem_map(irp_addr, 0x10000)
    
    # Output buffer (where result byte will be written)
    output_buf_addr = irp_addr + 0x1000
    mu.mem_write(output_buf_addr, b'\xFF')  # Initialize to 0xFF
    
    # IRP structure: [rdx + 0x18] = SystemBuffer (output buffer for 0x228128)
    # [rdx + 0xb8] = IO_STACK_LOCATION
    io_stack_addr = irp_addr + 0x2000
    
    # IO_STACK_LOCATION: [io_stack + 0x18] = IOCTL code = 0x228128
    mu.mem_write(io_stack_addr + 0x18, struct.pack('<I', 0x228128))
    
    # IRP: [irp + 0x18] = SystemBuffer
    mu.mem_write(irp_addr + 0x18, struct.pack('<Q', output_buf_addr))
    # IRP: [irp + 0xb8] = IO_STACK_LOCATION
    mu.mem_write(irp_addr + 0xb8, struct.pack('<Q', io_stack_addr))
    # IRP: [irp + 0x38] = IoStatus.Information (output)
    mu.mem_write(irp_addr + 0x38, struct.pack('<Q', 0))
    # IRP: [irp + 0x30] = IoStatus.Status (output)
    mu.mem_write(irp_addr + 0x30, struct.pack('<I', 0))
    
    # Set up registers for calling the IOCTL handler at 0x140001730
    # rcx = first arg (unused WDFREQUEST or similar)
    # rdx = second arg (IRP-like structure)
    mu.reg_write(UC_X86_REG_RCX, 0)
    mu.reg_write(UC_X86_REG_RDX, irp_addr)
    
    # Push return address
    ret_addr = 0xDEAD0000
    mu.mem_map(ret_addr & ~0xFFF, 0x1000)
    mu.mem_write(ret_addr, b'\xCC')
    
    rsp = mu.reg_read(UC_X86_REG_RSP)
    mu.mem_write(rsp, struct.pack('<Q', ret_addr))
    
    func_addr = IMAGE_BASE + 0x1730  # IOCTL handler function
    
    try:
        mu.emu_start(func_addr, ret_addr, timeout=10000000)
    except UcError as e:
        print(f"Emulation error: {e}")
        return None
    
    # Read result byte from output buffer
    result = mu.mem_read(output_buf_addr, 1)[0]
    return result

# First, test with all zeros (should return 0 = wrong)
print("Testing with all zeros...")
result = test_input(b'\x00' * 72)
print(f"Result: {result} (expected 0 = wrong)")

# Now let's understand the expected data at 0xc000
expected_data = sys_data[0xa800:0xa800+72]
print(f"\nExpected data at 0xc000 (72 bytes):")
for i in range(0, 72, 9):
    chunk = expected_data[i:i+9]
    print(f"  Block {i//9}: {' '.join(f'{b:02x}' for b in chunk)}")

# Now let me dump what the code uses as key
# The "key" matrix comes from entry0 area (0x140009a60 in the code section)
# Let's extract it
entry0_offset = 0x9a60  # RVA of entry0
entry0_file = None
for s in pe.sections:
    if s.VirtualAddress <= entry0_offset < s.VirtualAddress + s.Misc_VirtualSize:
        entry0_file = s.PointerToRawData + (entry0_offset - s.VirtualAddress)
        break

if entry0_file:
    entry0_data = sys_data[entry0_file:entry0_file+72]
    print(f"\nCode bytes at entry0 (0x{entry0_offset:x}):")
    for i in range(0, 72, 9):
        chunk = entry0_data[i:i+9]
        print(f"  Block {i//9}: {' '.join(f'{b:02x}' for b in chunk)}")

# Let me also look at what's at c5d8 + nearby in the data section
# The reference matrix for the multiply might be at a different offset
# Let me check: 0x14000c5d8 in rdata 
c5d8_file = 0xadd8  # File offset for RVA 0xc5d8
print(f"\nData at 0xc5d8 (should be zero-initialized user input area):")
for i in range(0, 72, 16):
    chunk = sys_data[c5d8_file+i:c5d8_file+i+16]
    print(f"  {' '.join(f'{b:02x}' for b in chunk)}")

# Now let me try to emulate with a known string like "CTF{test}" to see what happens
print("\nTesting with 'CTF{test}'...")
test_bytes = b'CTF{test}' + b'\x00' * (72 - 9)
result = test_input(test_bytes)
print(f"Result: {result}")

# Try to figure out the algorithm by testing individual bytes
print("\n=== Probing the algorithm ===")

# Test with a single byte at position 0
for val in [0x41, 0x42, 0x43]:
    inp = bytes([val] + [0]*71)
    result = test_input(inp)
    print(f"Input[0]={chr(val)}, result={result}")

# Test with identity-like inputs for the first 3x3 block
# If it's matrix multiply, inputs arranged as 3x3:
# [[a,b,c],[d,e,f],[g,h,i]] * key = expected[0:9]
# Let's try setting first 9 bytes to identity matrix (1,0,0,0,1,0,0,0,1)
identity = bytes([1,0,0,0,1,0,0,0,1] + [0]*63)
result = test_input(identity)
print(f"Identity matrix first block, result={result}")

# Let me now read the actual computed value in the local buffer
# by instrumenting the emulation
print("\n=== Deep analysis: watching computation ===")

def trace_computation(user_input_bytes):
    """Trace the computation to understand the matrix operation."""
    mu = setup_driver_emulator()
    input_buf = bytes(user_input_bytes[:72]).ljust(72, b'\x00')
    mu.mem_write(IMAGE_BASE + 0xc5d8, input_buf)
    
    irp_addr = 0x50000000
    mu.mem_map(irp_addr, 0x10000)
    output_buf_addr = irp_addr + 0x1000
    mu.mem_write(output_buf_addr, b'\xFF')
    io_stack_addr = irp_addr + 0x2000
    mu.mem_write(io_stack_addr + 0x18, struct.pack('<I', 0x228128))
    mu.mem_write(irp_addr + 0x18, struct.pack('<Q', output_buf_addr))
    mu.mem_write(irp_addr + 0xb8, struct.pack('<Q', io_stack_addr))
    mu.mem_write(irp_addr + 0x38, struct.pack('<Q', 0))
    mu.mem_write(irp_addr + 0x30, struct.pack('<I', 0))
    
    mu.reg_write(UC_X86_REG_RCX, 0)
    mu.reg_write(UC_X86_REG_RDX, irp_addr)
    
    ret_addr = 0xDEAD0000
    try:
        mu.mem_map(ret_addr & ~0xFFF, 0x1000)
    except:
        pass
    mu.mem_write(ret_addr, b'\xCC')
    
    rsp = mu.reg_read(UC_X86_REG_RSP)
    mu.mem_write(rsp, struct.pack('<Q', ret_addr))
    
    # Hook specific addresses to trace the computation
    trace_data = {'computed': [], 'expected': [], 'cmp_count': 0}
    
    def hook_cmp(mu, address, size, user_data):
        """Hook the comparison instruction at 0x1400018aa."""
        if address == IMAGE_BASE + 0x18aa:
            rdi_val = mu.reg_read(UC_X86_REG_RDI)
            rcx_val = mu.reg_read(UC_X86_REG_RCX)
            # Read the compared bytes
            computed = mu.mem_read(rcx_val, 1)[0]
            expected = mu.mem_read(rdi_val + rcx_val, 1)[0]
            trace_data['computed'].append(computed)
            trace_data['expected'].append(expected)
            trace_data['cmp_count'] += 1
    
    mu.hook_add(UC_HOOK_CODE, hook_cmp)
    
    func_addr = IMAGE_BASE + 0x1730
    try:
        mu.emu_start(func_addr, ret_addr, timeout=30000000)
    except UcError as e:
        print(f"Trace error: {e}")
    
    result = mu.mem_read(output_buf_addr, 1)[0]
    return result, trace_data

# Test with identity first block
identity = bytes([1,0,0,0,1,0,0,0,1] + [0]*63)
result, trace = trace_computation(identity)
print(f"\nIdentity block test: result={result}, comparisons={trace['cmp_count']}")
if trace['computed']:
    print(f"Computed values ({len(trace['computed'])}): {[f'{b:02x}' for b in trace['computed']]}")
if trace['expected']:
    print(f"Expected values ({len(trace['expected'])}): {[f'{b:02x}' for b in trace['expected']]}")

# Test with all 0x01
ones = bytes([1]*72)
result, trace = trace_computation(ones)
print(f"\nAll 1s test: result={result}, comparisons={trace['cmp_count']}")
if trace['computed']:
    print(f"Computed values ({len(trace['computed'])}): {[f'{b:02x}' for b in trace['computed']]}")
if trace['expected']:
    print(f"Expected values ({len(trace['expected'])}): {[f'{b:02x}' for b in trace['expected']]}")
