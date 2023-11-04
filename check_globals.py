from binaryninja import *

num_reads = 0
num_writes = 0

operations_found = set()

def visitor(_a: str, inst: MediumLevelILOperandType, _c: str, parent: Optional[MediumLevelILInstruction]) -> bool:
    global num_reads
    global num_writes
    global operations_found
    if isinstance(inst, MediumLevelILLoad):
        if isinstance(inst.operands[0], MediumLevelILConstPtr):
            # Sort RW based on parent mlil instr
            operations_found.add(parent.operation)

            if parent.operation == MediumLevelILOperation.MLIL_SET_VAR:
                # use dest and src
                pass
            elif parent.operation == MediumLevelILOperation.MLIL_JUMP:
                num_reads += 1
            else:
                print(f"parent op: {parent.operation.name} | {hex(parent.address)}")

            return False

def is_rw(rw_segments: List[Segment], dv: DataVariable):
    for seg in rw_segments:
        if seg.start <= dv.address and dv.address <= seg.end:
            return True
    return False

bv: BinaryView = load(sys.argv[1])

rw_segments = list(x for x in bv.segments if x.readable and x.writable)

for addr, dv in bv.data_vars.items():
    # check if data var resides in R/W memory
    if not is_rw(rw_segments, dv):
        continue

    # Iterate through data var xrefs
    for dv_xref in bv.get_code_refs(addr):
        if dv_xref.mlil is None:
            continue
        dv_xref.mlil.visit(visitor)

print(f"count {num_reads}")
