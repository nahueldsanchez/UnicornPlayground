#!/usr/bin/env python
'''
Script to solve the assembly-0 challenge
of picoCTF 2018.

Assembly code given:

.intel_syntax noprefix
.bits 32
	
.global asm0
asm0:
        push    ebp
        mov     ebp,esp
        mov     eax,DWORD PTR [ebp+0x8]
        mov     ebx,DWORD PTR [ebp+0xc]
        mov     eax,ebx
        mov     esp,ebp
        pop     ebp	
        ret

code is invoked with the following args
asm0(0xd8,0x7a). We'll modify the code
pushing the parameters to the stack.

To solve the challenge you have to determine
the value of EAX at the end of the execution.
'''
from keystone import *
from capstone import *
from unicorn import *
from unicorn.x86_const import *

md = Cs(CS_ARCH_X86, CS_MODE_32)

# callback for tracing instructions
# we read every instruction and print it
def hook_code32(uc, address, size, user_data):
    
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    # Code from: http://www.capstone-engine.org/lang_python.html
    for i in md.disasm(uc.mem_read(address, size), address):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    pass

def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_READ_UNMAPPED:
        print(">>> Missing memory is being READ at 0x%x, data size = %u, data value = 0x%x" \
                %(address, size, value))
        return True

CODE = 	b"""
        push    0x7a
        push    0xd8
        push    0x00
        push    ebp
        mov     ebp,esp
        mov     eax,DWORD PTR [ebp+0x8]
        mov     ebx,DWORD PTR [ebp+0xc]
        mov     eax,ebx
        mov     esp,ebp
        pop     ebp	
        """

try:
    # Initialize engine in X86-32bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    X86_CODE32, count = ks.asm(CODE)
    print("%s = %s (number of statements: %u)" % (CODE, X86_CODE32, count))
    X86_CODE32 = "".join(map(chr,X86_CODE32))

except KsError as e:
    print("ERROR: %s" %e)

try:
    #Now we'll try to emulate the previously obtained opcodes
    #Code based on the sample_x86.py from unicorn/bindings/python
    #Directory.
    ADDRESS = 0x1000000
    print("Emulate i386 code")
    
    # Initialize emulator in X86-32bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    
    # map 2MB memory for this emulation
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)
    
    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, X86_CODE32)
    
    # setup stack
    STACK_ADDR = 0x0
    STACK_SIZE = 0x1000
    print("Stack will be at: 0x%x" % (STACK_ADDR + STACK_SIZE - 8))
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE - 8)

    # tracing all instructions in range [ADDRESS, ADDRESS+20]
    mu.hook_add(UC_HOOK_CODE, hook_code32)

    # intercept invalid memory events
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)

    # emulate machine code in infinite time
    mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))

    # now print out some registers
    print(">>> Emulation done. Below is the CPU context")
    eax = mu.reg_read(UC_X86_REG_EAX)
    print(">>> EAX = 0x%x" %eax)

except UcError as e:
    print("ERROR: %s" % e)