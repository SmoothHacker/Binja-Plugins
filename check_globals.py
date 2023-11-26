from binaryninja import *

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

bv: BinaryView = load(sys.argv[1])

rw_segments = [x for x in bv.segments if x.readable and x.writable]
total_xrefs = 0

for addr, dv in bv.data_vars.items():
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
