import subprocess
import lief
import struct

class Recompiler(object):
    def __init__(self, _llvm_exprs, _filename, _funcname):
        self.llvm_exprs = _llvm_exprs
        self.filename = _filename
        self.funcname = _funcname
        self.l_file   = "{}.ll".format(self.funcname)
        self.b_file   = "{}.b".format(self.funcname)
        self.o_file   = "{}.o".format(self.funcname)

    def compile_ll(self):
        result = True

        with open(self.l_file, 'w') as f:
            m = str(self.llvm_exprs).replace("__arybo", self.funcname)
            m = m.replace("unknown-unknown-unknown", "x86-64-pc-linux-gnu")
            f.write(m)

        clang = subprocess.Popen(["clang",
                                  self.l_file,
                                  "-o", "{}.o".format(self.funcname),
                                  "-c",
                                  "-O2",
                                  "-fno-stack-protector"
        ])
        if clang.wait():
            print("clang error")
            result = False

        return result

    def extract_bytecodes(self):
        result = True
        o_elf = lief.parse(self.o_file)
        bytecodes = o_elf.get_section(".text").content
    
        if bytecodes is None:
            result = Faile

        with open(self.b_file, "wb") as f:
            f.write(''.join([chr(d) for d in bytecodes]))

        return result

    def inject_bytecodes(self, call_vfunc):
        result = True

        objcopy = subprocess.Popen(["objcopy",
                                    self.filename,
                                    self.filename + ".devirtualized",
                                    "--add-section", ".{}={}".format(self.funcname, self.b_file),
                                    "--set-section-flags", ".{}=code".format(self.funcname)
        ])
        if objcopy.wait():
            print("objcopy injection error")
            result = False

        d_elf  = lief.parse(self.filename + ".devirtualized")
        section = d_elf.get_section(".{}".format(self.funcname))
        vma = section.file_offset + d_elf.imagebase
        end = section.file_offset + section.size

        objcopy = subprocess.Popen(["objcopy",
                                    self.filename + ".devirtualized",
                                    "--change-section-vma", ".{}={}".format(self.funcname, vma)
        ])
        if objcopy.wait():
            print("objcopy change section vma error")
            result = False
        
        ph3_offset = d_elf.header.program_header_offset + 2 * 0x38
        hook_pnt = call_vfunc - d_elf.imagebase
        new_code = "\xE8" + struct.pack("<I", vma - call_vfunc - 5)

        with open("{}.devirtualized".format(self.filename), "rb") as f:
            filedata = f.read()
        with open("{}.devirtualized".format(self.filename), "wb") as f:
            f.write(filedata[ : ph3_offset + 0x20])
            # Edit PHT
            f.write(struct.pack("<Q", end))  # Elf64_Xword p_filesz_SEGMENT_FILE_LENGTH
            f.write(struct.pack("<Q", end))  # Elf64_Xword p_memsz_SEGMENT_RAM_LENGTH
            # Hooking
            f.write(filedata[ph3_offset + 0x30 : hook_pnt])
            f.write(new_code)  # call v_func -> call devirtualized
            f.write(filedata[hook_pnt + 5 : ])
            
        return result
