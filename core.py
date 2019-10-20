from capstone import *
from keystone import *

import sys
import os
import stat
import binascii
import datetime


class Arch:
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
        elif arch_type == "arm":
            self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            self.ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        elif arch_type == "arm64":
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self.ks = Ks(KS_ARCH_ARM64, KS_MODE_ARM)
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
                    print("[*] The size of the new file {} is different than the one of original file {}".format(new_size, self.size))
                statinfo = os.stat(filename)
                os.chmod(filename, statinfo.st_mode | stat.S_IEXEC)
        except Exception as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            sys.exit()

        print("[*] File {} with patch is created".format(filename))

    def get_file_size(self, binary):
        try:
            statinfo = os.stat(binary)
            return statinfo.st_size
        except Exception as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            sys.exit()

    def check_file(self):
        try:
            if not os.path.exists(self.binary):
                print("file not found {}".format(self.binary))
                sys.exit()
        except Exception as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            sys.exit()

    def generate_random(self):
        try:
            unique_filename = "out" + str(datetime.datetime.now().date()) + '_' + str(datetime.datetime.now().time()).replace(':', '.')
            out_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), unique_filename)
            return out_file
        except Exception as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            sys.exit()


class Core(Arch):
    def __init__(self):
        Arch.__init__(self)

    def disassemble(self, code, disassembly_len, offset, mode=False):
        try:
            if mode == False:
                code = self.get_bytes(code)
            for i in self.cs.disasm(code, offset, disassembly_len):
                print("{0:}: {1:16} {2:5} {3:16}".format(hex(i.address), ''.join(format(x, '02x') for x in i.bytes), i.mnemonic, i.op_str))
        except (CsError, ValueError, Exception) as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)

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
