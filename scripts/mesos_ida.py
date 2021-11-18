# Originally taken from here:
# https://github.com/gamozolabs/mesos/blob/master/mesogen_scripts/ida.py


import idautils
import ida_bytes
from idaapi import *
from ida_nalt import *
from idc import *
import struct

# Wait for auto analysis to complete
idaapi.auto_wait()

print("Analysis done, generating meso")

image_base = idaapi.get_imagebase()

input_name = ida_nalt.get_root_filename()
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    input_name = ARGV[3]

filename = "%s/%s.bbs" % (
        os.path.dirname(os.path.abspath(__file__)), input_name)
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    filename = ARGV[2]
filename += ".tmp"

with open(filename, "wb") as fd:
    # Write record type 0 (module)
    # unsigned 16-bit module name
    # And module name
    # fd.write(struct.pack("<BH", 101, 
    #     len(input_name)) + input_name.encode("utf-8"))

    for funcea in idautils.Functions():
        funcname = get_func_off_str(funcea)

        # Write record type 1 (function)
        # Write unsigned 16-bit function name length and function name
        # fd.write(struct.pack("<BH", 1, 
        #     len(funcname)) + funcname.encode("utf-8"))

        # Write unsigned 64-bit offset of the function WRT the module base
        # fd.write(struct.pack("<Q", funcea - image_base))

        blockoffs = bytearray()
        for block in idaapi.FlowChart(idaapi.get_func(funcea)):
            if is_code(ida_bytes.get_full_flags(block.start_ea)):
                # Write signed 32-bit offset from base of function
                blockoffs += struct.pack("<i", block.start_ea - image_base)
        
        # Unsigned 32-bit number of blocks
        # fd.write(struct.pack("<I", int(len(blockoffs) / 4)))
        fd.write(blockoffs)

# Rename .tmp file to actual name
os.rename(filename, filename[:-4])

print("Generated meso: %s" % filename[:-4])

# Exit only if we were invoked from the command line
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    idc.Exit(0)
