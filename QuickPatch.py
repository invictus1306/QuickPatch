from argparse import ArgumentParser
from argparse import RawTextHelpFormatter
from core import Core
from core import FilesOp

import sys
import os


def main():
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter, description="""QuickPatch - a simple patching tool""", epilog="""examples:
   python3 QuickPatch.py -A x86-64 -a 'mov rax,0x10; add rax, 0x69' -o 0x3b2 -b binary -of out_binary
   python3 QuickPatch.py -A x86-64 -o 0x3b2 -b binary
   python3 QuickPatch.py -A x86-64 -a 'mov rax,0x10; add rax, 0x69'
   python3 QuickPatch.py -A x86-64 -d '0x55,0x48,0x8b,0x05,0xb8,0x13,0x00,0x00'
   python3 QuickPatch.py -A x86-64 -o 0x40b -b binary -p "0x90,0x90" -of out_binary
  """)

    parser.add_argument('-b', '--binary', dest='binary', help='binary to disassemble/patch')
    parser.add_argument('-A', '--arch', dest='architecture', required=True, help='supported architecture values [x86-32, x86-64, arm, arm64]')
    parser.add_argument('-a', '--assembly', dest='assembly', help='assemble/patch the instructions')
    parser.add_argument('-d', '--disassembly', dest='disassembly', help='disassemble the bytes')
    parser.add_argument('-p', '--patch_bytes', dest='patch_bytes', help='patch the bytes')
    parser.add_argument('-dl', '--disas_len', dest='disas_len', help='number of the instructions to disassemble, default value is 16')
    parser.add_argument('-o', '--offset', dest='offset', help='position in the binary of the bytes to disassemble/patch')
    parser.add_argument('-of', '--out_file', dest='out_file', help='output file, by defaut a file with a random name will be created')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0 - 20/10/2019', help='display the version')

    options = parser.parse_args()

    binary = options.binary
    arch = options.architecture
    disassembly = options.disassembly
    disassembly_len = options.disas_len
    assembly = options.assembly
    patch_bytes = options.patch_bytes
    offset = options.offset
    out_file = options.out_file

    try:
        core_obj = Core()

        if core_obj.arch(arch):
            print("Architecture not supported! Supported architectures are: [x86-32, x86-64, arm, arm64]")
            return

        if not disassembly_len:
            disassembly_len = 0x10
        else:
            disassembly_len = int(disassembly_len, 16)

        if binary and offset:
            offset = int(offset, 16)
            file_obj = FilesOp(binary)
            file_obj.check_file()
            file_obj.read_file()
            if assembly or patch_bytes: #patch binary
                if not out_file:
                    out_file = file_obj.generate_random()
                if patch_bytes:
                    patch = core_obj.get_bytes(patch_bytes)
                    file_obj.patch_file(out_file, offset, patch)
                    print("[*] Bytes: {} (len: {})".format(patch_bytes, len(patch_bytes)))
                else:
                    patch = core_obj.assemble(assembly, True)
                    patch = bytearray(patch)
                    file_obj.patch_file(out_file, offset, patch)
            else: #disassembly binary
                data = file_obj.disas_from_offset(offset)
                core_obj.disassemble(data, disassembly_len, offset, True)
        elif assembly:
            core_obj.assemble(assembly, True)
        elif disassembly:
            core_obj.disassemble(disassembly, disassembly_len, 0, False)
        else:
            print("In order to patch or disassembly a binary file, the options --binary --offset and --assembly are required")
    except Exception as e:
        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
        sys.exit()

if __name__ == "__main__":
    main()
