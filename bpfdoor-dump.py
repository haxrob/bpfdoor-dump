#!/usr/bin/python3
# @haxrob - 2025-05-30

# deps: pip install pyelftools capstone

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import sys
import re
import hashlib

KNOWN_SALT = "I5*AYbs@LdaWbsO"
HASHCAT_CMD = "hashcat -a 3 -m 20 ?1?1?1?1?1?1?1?1?1?1?1?1?1?1?1?1 -i -1 ?ld"
def print_err(string) :
   print(string, file=sys.stderr)

def get_sha256(filename):
   sha256_hash = hashlib.sha256()
   with open(filename, "rb") as f:
      # Read and update hash string value in blocks of 4K
      for byte_block in iter(lambda: f.read(4096), b""):
         sha256_hash.update(byte_block)
   return sha256_hash.hexdigest()

def find_hidden(filename, action):
    file_hash = get_sha256(filename)
    print(f"Sample SHA256: {file_hash}")
    with open(filename, 'rb') as f:
        try :
           elf = ELFFile(f)
        except :
         print_err("Not a valid ELF")
         return

        text_section = elf.get_section_by_name('.text')
        if not text_section:
            print_err("No .text section found")
            return

        md = Cs(CS_ARCH_X86, CS_MODE_64)

        code = text_section.data()
        instructions = list(md.disasm(code, text_section['sh_addr']))

        current_string = ""
        count = 1
        found_known_salt = False
        found_hash = False
        for insn in instructions:
            if insn.mnemonic == 'mov':
                parts = insn.op_str.split(', ')
                if len(parts) == 2 and parts[1].startswith('0x'):
                    try:
                        value = int(parts[1], 16)
                        if 32 <= value <= 126:
                            current_string += chr(value)
                        else:
                            if current_string:
                                current_string = ""
                    except ValueError:
                        pass
                elif parts[1] == '0' and len(current_string) > 3  :
                   if action == "dump":
                      print("\t%s" % current_string)
                      current_string = ""
                      continue
                   if action == "check" and current_string == KNOWN_SALT :
                      found_known_salt = True
                      print("\tsalt  : %s" % KNOWN_SALT)
                   pattern = r'\b[a-f0-9]{32}\b'
                   if re.match(pattern, current_string) :
                      if action == "check" :
                         print("\thash %d: %s" % (count, current_string))
                         found_hash = True
                         count = count + 1
                      if action == "hashcat" :
                         print("\t%s %s:%s" % (HASHCAT_CMD, current_string, KNOWN_SALT))
                      current_string = ""
                      continue

            else:
                if current_string:
                    current_string = ""
        if action == "check" :
           if found_hash == True :
              if found_known_salt == False :
                 print("! found hash but no salt")
           else :
              print("\t! no hashes found. Are keys in plain text?")

if len(sys.argv) != 3 :
   print("usage: ./%s <check|hashcat|dump> <bpfdoor_sample>" % sys.argv[0])
   sys.exit(1)

find_hidden(sys.argv[2], sys.argv[1])
