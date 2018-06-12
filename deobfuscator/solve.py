from triton import *
import sys
import lief
import string
import struct
import pdb
import os

from arybo.tools.triton_ import tritonexprs2arybo, tritonast2arybo
from arybo.lib.exprs_asm import to_llvm_function

from recompiler import Recompiler

DEBUG = True

CALL_VFUNC = 0x4006BD

BASE_PLT   = 0x7f0000000000
BASE_ARGV  = 0x20000000
BASE_STACK = 0x9fffffff

TOTAL_INST = 0
TOTAL_UNIQUE_INST = {}
TOTAL_FUNCTIONS = 0

# Multiple_paths
CONDITION = list()
PATHS = list()

VM_INPUT = []


def recompile(M):
    filename = sys.argv[1].split('/')[-1]
    funcname = "secret"
    ll_name = "{}.ll".format(filename)

    with open(ll_name, 'w') as f:
        M = str(M).replace("__arybo", funcname)
        M = str(M).replace("unknown-unknown-unknown", "x86_64-pc-linux-gnu")
        f.write(M)
        debug("[+] LLVM module wrote in {}".format(ll_name))

    debug("[+] Compiling deobfuscated function...")
    os.system("clang -c {} -O2 -o {}.o".format(ll_name, funcname))
    debug("[+] Deobfuscated function compiled: {}.o".format(funcname))

    debug("[+] Inject deobfuscated function into binary...")
    os.system("objcopy --add-section .dcode={}.o --set-section-flags .dcode=code {} {}.deobfuscated".format(funcname, filename, filename))
    debug("[+] Deobfuscated function injected")
    return


def generateLLVMExpressions(ctx):
    global PATHS

    exprs = PATHS[0]

    debug("[+] Converting Symbolic Expressions to an LLVM module...")
    e = tritonexprs2arybo(exprs)
    arybo_vars = []
    sym_vars = ctx.getSymbolicVariables()
    for var_id in sym_vars:
        arybo_vars.append(tritonast2arybo(ctx.getAstContext().variable(sym_vars[var_id])).v)
    M = to_llvm_function(e, arybo_vars)

    return M

def get_memory_string(ctx, addr):
    s = str()
    index = 0

    while ctx.getConcreteMemoryValue(addr + index):
        c = chr(ctx.getConcreteMemoryValue(addr + index))
        if c not in string.printable:
            c = ''
        s += c
        index += 1

    return s

def __libc_start_main(ctx):
    debug("[+] __libc_start_main hooked")

    # Get arguments
    main = ctx.getConcreteRegisterValue(ctx.registers.rdi)

    # Push the return value to jump into the main() function
    ctx.concretizeRegister(ctx.registers.rsp)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(ctx.registers.rsp)-CPUSIZE.QWORD)
    
    ret2main = MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD)
    ctx.concretizeMemory(ret2main)
    ctx.setConcreteMemoryValue(ret2main, main)

    # Setup argc/argv
    ctx.concretizeRegister(ctx.registers.rdi)
    ctx.concretizeRegister(ctx.registers.rsi)

    argvs = [
        sys.argv[1],  # argv[0]
    ]

    base = BASE_ARGV
    addrs = list()

    index = 0
    for argv in argvs:
        addrs.append(base)
        ctx.setConcreteMemoryAreaValue(base, argv+'\x00')
        base += len(argv) + 1
        debug("[+] argv[{}] = {}".format(index, argv))
        index += 1

    argc = len(argvs)
    argv = base
    for addr in addrs:
        ctx.setConcreteMemoryValue(MemoryAccess(base, CPUSIZE.QWORD), addr)
        base += CPUSIZE.QWORD

    ctx.setConcreteRegisterValue(ctx.registers.rdi, argc)
    ctx.setConcreteRegisterValue(ctx.registers.rsi, argv)

    return 0


def getFormatString(ctx, addr):
    return get_memory_string(ctx, addr)                                               \
           .replace("%s", "{}").replace("%d", "{:d}").replace("%#02x", "{:#02x}")   \
           .replace("%#x", "{:#x}").replace("%x", "{:x}").replace("%02X", "{:02x}") \
           .replace("%c", "{:c}").replace("%02x", "{:02x}").replace("%ld", "{:d}")  \
           .replace("%*s", "").replace("%lX", "{:x}").replace("%08x", "{:08x}")     \
           .replace("%u", "{:d}").replace("%lu", "{:d}")                            \


def __printf(ctx):
    debug("[+] printf hooked")

    # Get arguments
    arg1   = getFormatString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
    arg2   = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    arg3   = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    arg4   = ctx.getConcreteRegisterValue(ctx.registers.rcx)
    arg5   = ctx.getConcreteRegisterValue(ctx.registers.r8)
    arg6   = ctx.getConcreteRegisterValue(ctx.registers.r9)
    nbArgs = arg1.count("{")
    args   = [arg2, arg3, arg4, arg5, arg6][:nbArgs]
    s      = arg1.format(*args)

    print (s)

    return len(s)


def __scanf(ctx):
    debug("[*] scanf hooked")

    fmt = get_memory_string(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
    buf = ctx.getConcreteRegisterValue(ctx.registers.rsi)

    if fmt == "%d":
        ctx.convertMemoryToSymbolicVariable(MemoryAccess(buf, CPUSIZE.DWORD))
    else:
        debug("[-] scanf: unsupported format string: {}".format(fmt))
        exit()

    #ctx.setConcreteMemoryValue(MemoryAccess(buf, CPUSIZE.DWORD), 4)
    """
    for i in range(n):
        VM_INPUT.append(ord('x'))
        mem = MemoryAccess(buf + i, CPUSIZE.BYTE)
        ctx.setConcreteMemoryValue(mem, VM_INPUT[-1])
        var1 = ctx.convertMemoryToSymbolicVariable(mem)
    """
    
    return 1


HOOKING_TABLE = [
    ("__libc_start_main", __libc_start_main, BASE_PLT + 0),
    ("printf",            __printf,          BASE_PLT + 1),
    ("__isoc99_scanf",    __scanf,           BASE_PLT + 2),
]

def debug(s):
    if DEBUG: print s


def make_relocation(ctx, binary):
    for rel in binary.pltgot_relocations:
        symbol_name = rel.symbol.name
        symbol_relo = rel.address
        for h_info in HOOKING_TABLE:
            if symbol_name == h_info[0]:
                debug("[+] Hooking {} at {}".format(symbol_name, hex(symbol_relo)))
                ctx.setConcreteMemoryValue(MemoryAccess(symbol_relo, CPUSIZE.QWORD), h_info[2])
    return


def load_binary(ctx, binary):
    # Map the binary into the memory
    phdrs = binary.segments
    for phdr in phdrs:
        size  = phdr.physical_size
        vaddr = phdr.virtual_address
        debug("[+] Loading 0x{0:06x} - 0x{1:06x}".format(vaddr, vaddr+size))
        ctx.setConcreteMemoryAreaValue(vaddr, phdr.content)
    return


def hooking_handler(ctx):
    global CONDITION
    global PATHS
    global TOTAL_FUNCTIONS  # used for metric

    pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
    for h_info in HOOKING_TABLE:
        if h_info[2] == pc:
            ret_value = h_info[1](ctx)
            if ret_value is not None:
                ctx.concretizeRegister(ctx.registers.rax)
                ctx.setConcreteRegisterValue(ctx.registers.rax, ret_value)

            TOTAL_FUNCTIONS += 1
            
            # Get the return address
            ret_addr = ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD))

            # Hijack RIP to skip the call
            ctx.concretizeRegister(ctx.registers.rip)
            ctx.setConcreteRegisterValue(ctx.registers.rip, ret_addr)

            # Restore RSP (simulate the ret)
            ctx.concretizeRegister(ctx.registers.rsp)
            ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(ctx.registers.rsp)+CPUSIZE.QWORD)
    return


def emulate(ctx, pc):
    global CONDITION

    while pc:
        opcodes = ctx.getConcreteMemoryAreaValue(pc, 16)

        # Create the Triton instruction
        instruction = Instruction()
        instruction.setOpcode(opcodes)
        instruction.setAddress(pc)

        # Process
        if ctx.processing(instruction) == False:
            debug("[-] Instruction not supported: {}".format(str(instruction)))
            break

        #debug("[*] {}".format(instruction))

        if instruction.getType() == OPCODE.HLT:
            break

        if pc == CALL_VFUNC + 5:
            exprs = ctx.sliceExpressions(ctx.getSymbolicExpressionFromId(ctx.getSymbolicRegisterId(ctx.registers.rax)))
            PATHS.append(exprs)
            break

        # Simulate routines
        hooking_handler(ctx)

        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)


def run(ctx, binary):
    # Concretize previous context
    ctx.concretizeAllMemory()
    ctx.concretizeAllRegister()

    # Define a fake stack
    ctx.setConcreteRegisterValue(ctx.registers.rbp, BASE_STACK)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, BASE_STACK)

    debug("[+] Starting emulation.")
    emulate(ctx, binary.entrypoint)
    debug("[+] Emulation done.")
    return


def main():
    global VM_INPUT
    global CONDITION
    global PATHS
    
    # Get a Triton context
    ctx = TritonContext()

    # Set the architecture
    ctx.setArchitecture(ARCH.X86_64)

    # Set optimization
    ctx.enableMode(MODE.ALIGNED_MEMORY, True)  # TODO
    ctx.enableMode(MODE.ONLY_ON_SYMBOLIZED, True)  # TODO`

    # AST representation as Python syntax
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

    if len(sys.argv) != 2:
        sys.argv.append("virtualife")
        #return -1

    # Parse the binary
    binary = lief.parse(sys.argv[1])

    # Load the binary
    load_binary(ctx, binary)

    # Perform our own relocations
    make_relocation(ctx, binary)

    # Init and emulate
    run(ctx, binary)

    if len(CONDITION) == 0:
        # Generate llvm of the first path
        M = generateLLVMExpressions(ctx)

        # Recompile the LLVM-IL
        recompiler = Recompiler(M, sys.argv[1].split('/')[-1], "deobfuscated")
        recompiler.compile_ll()
        recompiler.extract_bytecodes()
        recompiler.inject_bytecodes(CALL_VFUNC)

    else:
        print("[-] There is Multiple conditions.")


if __name__ == "__main__":
    main()
