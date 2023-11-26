import argparse

from binaryninja import *

parser = argparse.ArgumentParser(
    prog="Binja DataVar Read/Write checker",
    description="This program finds all reads/writes for the specified data vars",
    epilog="Author: Scott Lagler (SmoothHacker)")

parser.add_argument("bndb")
parser.add_argument("--vars", dest="target_addrs", metavar="N", type=str, nargs='*', help='Target addresses')

args = parser.parse_args()
print(args)

target_data_var: DataVariable

def find_var(_a: str, inst: MediumLevelILOperandType, _c: str, parent: Optional['MediumLevelILInstruction']) -> bool:
    global target_data_var
    if isinstance(inst, MediumLevelILConstPtr) or isinstance(inst, MediumLevelILImport):
        if inst.value.value == target_data_var.address:
            return False
    return True

def is_in_listed_segments(rw_segments: List[Segment], dv: DataVariable):
    for seg in rw_segments:
        if seg.start <= dv.address and dv.address <= seg.end:
            return True
    return False

bv: BinaryView = load(args.bndb)

rw_segments = [x for x in bv.segments if x.readable and x.writable]
total_xrefs = 0

if args.target_addrs is None:
    target_vars = bv.data_vars.items()
else:
    target_vars = []
    for x in args.target_addrs:
        addr = int(x, 16)
        target_vars.append((addr, bv.data_vars[addr]))

for addr, dv in target_vars:
    # check if data var resides in R/W memory
    if not is_in_listed_segments(rw_segments, dv):
        continue

    # Iterate through data var xrefs
    for dv_xref in bv.get_code_refs(addr):
        #print(f"Searching for {dv.address:#x} @ {dv_xref.address:#x}")
        total_xrefs += 1
        if dv_xref.mlil is None:
            continue
        target_data_var = dv
        if isinstance(dv_xref.mlil, MediumLevelILSetVar) or isinstance(dv_xref.mlil, MediumLevelILCall) or isinstance(dv_xref.mlil, MediumLevelILTailcall) or isinstance(dv_xref.mlil, MediumLevelILRet) or isinstance(dv_xref.mlil, MediumLevelILJump):
            print(f"Found read for {dv.address:#x} @ {dv_xref.mlil.address:#x}")
        elif isinstance(dv_xref.mlil, MediumLevelILStore):
            print(f"Found write for {dv.address:#x} @ {dv_xref.mlil.address:#x}")
        elif isinstance(dv_xref.mlil, MediumLevelILIf):
            # dv can be found in condition or missing due to x86 LLIL lifting
            if not dv_xref.mlil.condition.visit(find_var):
                print(f"Found read for {dv.address:#x} @ {dv_xref.mlil.address:#x}")
        else:
            print(f"Found unhandled operation {dv_xref.mlil.operation.name} @ {dv_xref.mlil.address:#x}")


print(f"Searched though {total_xrefs} xrefs")
