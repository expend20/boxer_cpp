# Original idea is taken from here:
# https://github.com/gamozolabs/mesos/blob/master/mesogen_scripts/ida.py


import idautils
import ida_bytes
from idaapi import *
from ida_nalt import *
from idc import *
import struct

# Wait for auto analysis to complete
idaapi.auto_wait()

print("Analysis done, generating bbs")

image_base = idaapi.get_imagebase()

input_name = ida_nalt.get_root_filename()
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    input_name = ARGV[3]

filename = "%s\\%s.bbs" % (
        os.path.dirname(os.path.abspath(__file__)), input_name)
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    filename = ARGV[2]

with open(filename, "wb") as fd:

    for funcea in idautils.Functions():
        funcname = get_func_off_str(funcea)

        blockoffs = bytearray()
        for block in idaapi.FlowChart(idaapi.get_func(funcea)):
            if is_code(ida_bytes.get_full_flags(block.start_ea)):
                # Write signed 32-bit offset from base of function
                blockoffs += struct.pack("<i", block.start_ea - image_base)
        
        fd.write(blockoffs)

print("Generated bbs: %s" % filename[:-4])

# Exit only if we were invoked from the command line
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    idc.Exit(0)
