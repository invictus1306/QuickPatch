from capstone import *
from keystone import *

import sys
import os
import stat
import gdb
import binascii


archs_32_gdb = ["i386:x64-32", "i386:x64-32:nacl", "i386:x64-32:intel"]
archs_64_gdb = ["i386:x86-64:intel", "i386:x86-64", "i386:x86-64:nacl"]


class Arch(object):
    def __init__(self):
        self.cs = ""
        self.ks = ""

    def arch(self, arch_type):
        if arch_type == "x86-32":
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        elif arch_type == "x86-64":
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        else:
            return 1

        return 0


class FilesOp:
    def __init__(self, binary):
        self.binary = binary
        self.fd = ""
        self.data = ""

    def read_file(self):
        try:
            self.fd = open(self.binary, 'rb')
            self.data = self.fd.read()
            self.size = self.get_file_size(self.binary)
        except Exception as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            sys.exit()

    def disas_from_offset(self, offset):
         try:
             with open(self.binary, 'rb') as fd:
                 self.fd.seek(offset, 0)
                 data_from_offset = self.fd.read()
                 self.fd.close()
                 return data_from_offset
         except Exception as e:
             print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
             sys.exit()

    def patch_file(self, filename, offset, patch):
        try:
            with open(filename, 'wb') as fd:
                fd.write(self.data)
                fd.seek(offset)
                fd.write(patch)
                fd.close()
                self.fd.close()

            new_size = self.get_file_size(filename)
            if new_size != self.size:
                print("The size of the new file {} is different than the one of original file {}".format(new_size, self.size))
            statinfo = os.stat(filename)
            os.chmod(filename, statinfo.st_mode | stat.S_IEXEC)
        except Exception as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            sys.exit()

        print("[*] File {} with patch is created".format(filename))

    def check_file(self):
        try:
            if not os.path.exists(self.binary):
                print("file not found {}".format(self.binary))
                sys.exit()
        except Exception as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            sys.exit()

    def get_file_size(self, binary):
        try:
            statinfo = os.stat(binary)
            return statinfo.st_size
        except Exception as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            sys.exit()

class Core(Arch):
    def __init__(self):
        super(Arch, self).__init__()

    def disassemble(self, code, disassembly_len, mode=False):
        ''' currently no command uses the disassemble method '''
        try:
            if mode == False:
                code = self.get_bytes(code)
            for i in self.cs.disasm(code, 0x00, disassembly_len):
                print("{0:}: {1:16} {2:5} {3:16}".format(i.address, ''.join(format(x, '02x') for x in i.bytes), i.mnemonic, i.op_str))
        except (CsError, ValueError, Exception) as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            sys.exit()

    def assemble(self, code, mode=False):
        try:
            encoding, count = self.ks.asm(code)
            if count > 0:
                if mode:
                    print("[*] Instructions: {} (len: {})\n[*] Encoding: {} (len: {})".format(code.split(";"), count, ' '.join(hex(x) for x in encoding), len(encoding)))
                else:
                    print("[*] %s = %s (number of statements: %u)" %(code, encoding, count))
                return encoding
        except (KsError, ValueError, Exception) as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            sys.exit()

    def get_bytes(self, code):
        try:
            code_bytes = b''
            code = code.replace(" ", "").replace("0x", "")
            code = code.split(",")
            for i in code:
                code_bytes += binascii.unhexlify(i)
            return code_bytes
        except Exception as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            sys.exit()

class Patch(gdb.Command):
    """ Patch instructions -> program_patch <instructions|bytes> <address> <file> e.g.
    gdb> program_patch "xor rax,rax;nop" 0x400123 out_bin
    gdb> program_patch "0x90,0x90" 0x400123 out_bin"""

    def __init__(self):
        super(Patch, self).__init__("program_patch", gdb.COMMAND_SUPPORT)

    def invoke(self, args, from_tty):
        print("[*] program_patch command is called")
        print("-----------------------------------------------------")
        argv = gdb.string_to_argv (args)
        if len (argv) != 3:
            raise gdb.GdbError ("Error! Please enter the instructions that you want to patch (e.g (gdb) program_patch \"push rbp; mov rax, 0x10\" 0x400123 out_bin_file)")

        arch_keystone = get_arch()

        instructions = argv[0]
        address = argv[1]
        out_file = argv[2]

        patch(instructions, address, out_file, arch_keystone)

        return


class GetBytes(gdb.Command):
    """ Get the instruction opcodes -> e.g. get_bytes "xor rax,rax;nop" """

    def __init__(self):
        super(GetBytes, self).__init__("get_bytes", gdb.COMMAND_SUPPORT)

    def invoke(self, args, from_tty):
        print("[*] get_bytes command is called")
        print("-----------------------------------------------------")
        argv = gdb.string_to_argv (args)
        if len (argv) != 1:
            raise gdb.GdbError ("Error! Please enter the instructions (e.g get_bytes \'push rbp;nop\')")

        arch_keystone = get_arch()

        instructions = argv[0]
        get_bytes(instructions, arch_keystone)

        return


class MemoryGdbPatch(gdb.Command):
    """ Memory patch instruction -> memory_patch <instructions|bytes> <address> e.g.
    gdb> memory_patch "xor rax,rax;nop" 0x400123
    gdb> memory_patch "0x90,0x90" 0x400123"""

    def __init__(self):
        super(MemoryGdbPatch, self).__init__("memory_patch", gdb.COMMAND_SUPPORT)

    def invoke(self, args, from_tty):
        print("[*] memory_patch command is called")
        print("-----------------------------------------------------")
        argv = gdb.string_to_argv (args)
        if len (argv) != 2:
            raise gdb.GdbError ("Error! Please enter the instructions that you want to patch in gdb (e.g memory_patch \"push rbp; mov rax, 0x10\") 0x400123")

        arch_keystone = get_arch()

        instructions = argv[0]
        address = argv[1]

        memory_patch(instructions, address, arch_keystone)
        print("[*] Memory is successfully patched at address {}".format(address))

        return

Patch()
GetBytes()
MemoryGdbPatch()


def runnning_gdb():
    return gdb.selected_inferior().pid


def get_core_obj(arch):
    core_obj = Core()

    if core_obj.arch(arch):
        print("Architecture not supported!")
        sys.exit()

    return core_obj


def get_arch():
    try:
        if runnning_gdb():
            arch_str = gdb.selected_frame().architecture()
            arch_str = arch_str.name()
        else:
            arch = gdb.execute("show architecture", to_string=True).rstrip()
            arch_str = arch.split()[-1].replace(")", "")

        arch_keystone = ""
        print("[*] Arch is " + arch_str)

        for arch_gdb in archs_32_gdb:
            if arch_str == arch_gdb:
                arch_keystone = "x86-32"

        for arch_gdb in archs_64_gdb:
            if arch_str == arch_gdb:
                arch_keystone = "x86-64"

        if arch_keystone == "":
            print("Architecture not supported!")
            sys.exit()

        return arch_keystone
    except Exception as e:
        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
        sys.exit()


def patch(instructions, address, out_file, arch):
    try:
        if not runnning_gdb():
            print("In order to patch the binary, you need to run GDB")
            return

        #file to patch
        proc = gdb.execute("info proc", to_string=True)
        file_to_patch = proc.split()[4].replace("'", "")

        #calc offset
        #pc = gdb.selected_frame().read_register("pc")
        #pc_str = str(pc).split()[0]
        proc_map = gdb.execute("info proc mapping", to_string=True)
        index = proc_map.find("\n\n")
        proc_map = proc_map[index+1:]
        proc_map = proc_map.split()
        address_base = proc_map[7]
        module_name = proc_map[11]
        print("[*] Address " + address_base + " module name " + module_name + " address is " + address)
        offset = int(address, 16) - int(address_base, 16)
        print("[*] Offset is {}".format((hex(offset))))

        core_obj = get_core_obj(arch)

        if file_to_patch and offset:
            file_obj = FilesOp(file_to_patch)
            file_obj.check_file()
            file_obj.read_file()
            #patch binary
            start_check = instructions.replace("0x", "")[0:2]
            if start_check.isdigit():
                patch = core_obj.get_bytes(instructions)
                file_obj.patch_file(out_file, offset, patch)
            else:
                patch = core_obj.assemble(instructions, True)
                patch = bytearray(patch)
                file_obj.patch_file(out_file, offset, patch)
    except Exception as e:
        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
        sys.exit()


def get_bytes(instructions, arch):
    try:
        core_obj = get_core_obj(arch)
        core_obj.assemble(instructions, True)
    except Exception as e:
        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
        sys.exit()


def memory_patch(instructions, address, arch):
    try:
        if not runnning_gdb():
            print("In order to patch the binary, you need to run GDB")
            return

        address = int(address, 16)
        core_obj = get_core_obj(arch)
        #get pc
        #pc = gdb.selected_frame().read_register("pc")
        #pc_str = str(pc).split()[0]
        start_check = instructions.replace("0x", "")[0:2]
        if start_check.isdigit():
            patch = core_obj.get_bytes(instructions)
            print("[*] Bytes: {} (len: {})".format(instructions, len(patch)))
        else:
            patch = core_obj.assemble(instructions, True)

        for i in range(0, len(patch)):
            gdb.execute("set *(char*)({}+{}) = {}".format(hex(address), i, patch[i]))
    except Exception as e:
        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
        sys.exit()
