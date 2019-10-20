# QuickPatch

## Tool description
[QuickPatch](https://github.com/invictus1306/QuickPatch) is mainly a GDB plug-in giving users the ability to patch an ELF file quickly, just by write the instructions to patch.

With *QuickPatch* is also possible to patch/disassemble a binary file for the architectures x86-32 x86-64 arm and arm64.   

It is based on [Capstone](https://www.capstone-engine.org/) and [Keystone](http://www.keystone-engine.org/).

## Features
These are the features implemented so far:
* `program_patch` -- patch a program --> *GDB command*
* `memory_patch` -- patch a program in memory (not persistent) --> *GDB command*
* `get_bytes` -- get opcode of instructions --> *GDB command*
* Disassemble from file
* Patch a file
* Disassemble from user inputs
* Assemble from user inputs

## Requirements
* [Capstone](https://www.capstone-engine.org/)
* [Keystone](http://www.keystone-engine.org/)
* GDB 7.x+ (python 2.7.x)
* Python 3.x

## Usage
It is possible to use the program:
* From GDB
* From command line

### From GDB
```
$ wget https://github.com/invictus1306/QuickPatch/raw/master/gdbQuickPatch.py -O ~/gdbQuickPatch.py
$ echo "source ~/gdbQuickPatch.py" >> ~/.gdbinit
```

List of available commands:
* program_patch
* memory_patch
* get_bytes

Get usage for a specific command:
```
gdb>  help program_patch
 Patch instructions -> program_patch <instructions|bytes> <address> <file> e.g.
    gdb> program_patch "xor rax,rax;nop" 0x400123 out_bin
    gdb> program_patch "0x90,0x90" 0x400123 out_bin
gdb>  help memory_patch
 Memory patch instruction -> memory_patch <instructions|bytes> <address> e.g.
    gdb> memory_patch "xor rax,rax;nop" 0x400123
    gdb> memory_patch "0x90,0x90" 0x400123
gdb> help get_bytes
 Get the instruction opcodes -> get_bytes <instructions> e.g.
    gdb> get_bytes "xor rax,rax;nop"
```

### From command line
```
$ git clone https://github.com/invictus1306/QuickPatch.git
$ cd QuickPatch
$ python3 QuickPatch.py --help
usage: QuickPatch.py [-h] [-b BINARY] -A ARCHITECTURE [-a ASSEMBLY]
                     [-d DISASSEMBLY] [-p PATCH_BYTES] [-dl DISAS_LEN]
                     [-o OFFSET] [-of OUT_FILE] [-v]

QuickPatch - a simple patching tool

optional arguments:
  -h, --help            show this help message and exit
  -b BINARY, --binary BINARY
                        binary to disassemble/patch
  -A ARCHITECTURE, --arch ARCHITECTURE
                        supported architecture values [x86-32, x86-64, arm, arm64]
  -a ASSEMBLY, --assembly ASSEMBLY
                        assemble/patch the instructions
  -d DISASSEMBLY, --disassembly DISASSEMBLY
                        disassemble the bytes
  -p PATCH_BYTES, --patch_bytes PATCH_BYTES
                        patch the bytes
  -dl DISAS_LEN, --disas_len DISAS_LEN
                        number of the instructions to disassemble, default value is 16
  -o OFFSET, --offset OFFSET
                        position in the binary of the bytes to disassemble/patch
  -of OUT_FILE, --out_file OUT_FILE
                        output file, by defaut a file with a random name will be created
  -v, --version         display the version

examples:
   python3 QuickPatch.py -A x86-64 -a 'mov rax,0x10; add rax, 0x69' -o 0x3b2 -b binary -of out_binary
   python3 QuickPatch.py -A x86-64 -o 0x3b2 -b binary
   python3 QuickPatch.py -A x86-64 -a 'mov rax,0x10; add rax, 0x69'
   python3 QuickPatch.py -A x86-64 -d '0x55,0x48,0x8b,0x05,0xb8,0x13,0x00,0x00'
   python3 QuickPatch.py -A x86-64 -o 0x40b -b binary -p "0x90,0x90" -of out_binary

```

### GDB: patch a program
With the `program_patch` GDB command we can patch a program in a persistent way.

We have to specify:
* instructions or bytes to patch
* the address of in the binary at run-time
* the name of the output file

```
gdb> program_patch <INSTRUCTIONS|BYTES> <ADDRESS> <NEW_ELF_NAME>
```
For example (instructions to patch)
```
gdb> program_patch "xor rax,rax;xor rbx,rbx" 0x400123 out_bin
```
For example (bytes to patch)
```
gdb> program_patch "0x48,0x31,0xc0,0x48,0x31,0xdb" 0x400123 out_bin
```

### GDB: patch a program in memory (not persistent)
With the `memory_patch` GDB command we can patch a program not in a persistent way, but only in memory.

We have to specify:
* instructions or bytes to patch
* the address of in the binary at run-time

For example (instructions to patch)
```
gdb> program_patch "xor rax,rax;xor rbx,rbx" 0x400123
```
For example (bytes to patch)
```
gdb> program_patch "0x48,0x31,0xc0,0x48,0x31,0xdb" 0x400123
```

### GDB: get opcode of instructions
With the `get_bytes` GDB command we can get the opcodes of instructions.

We have to specify:
* instructions

```
gdb> get_bytes <INSTRUCTIONS>

gdb> get_bytes "xor rax,rax;xor rbx,rbx"

```

### Disassemble from file
```
$ python3 QuickPatch.py -A x86-64 -o 0x98f -b ./tests/patch_me_pie -dl 5
0x98f: 85c0             test  eax, eax        
0x991: 7513             jne   0x9a6           
0x993: 488d3dce000000   lea   rdi, [rip + 0xce]
0x99a: e8e1fdffff       call  0x780           
0x99f: b800000000       mov   eax, 0
```

### Patch a file
#### patch with instructions
```
$ python3 QuickPatch.py -A x86-64 -a 'nop;nop;nop;nop' -o 0x98f -b ./tests/patch_me_pie -of patched_1
[*] Instructions: ['nop', 'nop', 'nop', 'nop'] (len: 4)
[*] Encoding: 0x90 0x90 0x90 0x90 (len: 4)
[*] File patched_1 with patch is created
```
#### patch with bytes

```
python3 QuickPatch.py -A x86-64 -p '0x90,0x90,0x90,0x90' -o 0x98f -b ./tests/patch_me_pie -of patched
[*] File patched with patch is created
[*] Bytes: 0x90,0x90,0x90,0x90 (len: 19)
```

### Disassemble from user inputs
```
$ python3 QuickPatch.py -A x86-64 -d '0x55,0x48,0x8b,0x05,0xb8,0x13,0x00,0x00'
0x0: 55               push  rbp             
0x1: 488b05b8130000   mov   rax, qword ptr [rip + 0x13b8]
```

### Assemble from user inputs
```
$ python3 QuickPatch.py -A x86-32 -a 'mov eax,0x10; add eax, 0x69'
[*] Instructions: ['mov eax,0x10', ' add eax, 0x69'] (len: 2)
[*] Encoding: 0xb8 0x10 0x0 0x0 0x0 0x83 0xc0 0x69 (len: 8)
```

## Article
A small article that describe how to use it:
* QuickPatch [article](https://invictus1306.github.io/vulnerabilities/2019/10/20/quickpatch.html)

