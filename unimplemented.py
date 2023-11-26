# checks all LLIL operations to find any unlimiplemented lifting
# 
# Especially useful when building a new architecture and wanting to see what disassembly you're running into with real binaries to prioritize 

import sys
from binaryninja import open_view
from binaryninja.lowlevelil import LowLevelILInstruction
from binaryninja import *

def visit(unimp, expr):
    for field in LowLevelILInstruction.ILOperations[expr.operation]:
        if field[1] == "expr":
            visit(unimp, getattr(expr, field[0]))
    if expr.operation in [LowLevelILOperation.LLIL_UNIMPL, LowLevelILOperation.LLIL_UNIMPL_MEM]:
        if hasattr(expr, "expr_index"):
            index = expr.expr_index
        else:
            index = 0
        dis = bv.get_disassembly(expr.address)
        mnemonic = dis.split(" ")[0]
        if mnemonic in unimp.keys():
            unimp[mnemonic].append([expr.address, index])
        else:
            unimp[mnemonic] = [[expr.address, index]]


bv = open_view(f"{sys.argv[1]}")
unimp = {}

for llili in bv.llil_instructions:
    visit(unimp, llili)

print(f"Found {len(unimp)} total unimplemented mnemonics")
for k, v in sorted(unimp.items(), key=len):
    print(f"Unimplemented mnemonic: {k}:")
    for x in v:
        print(f"  {hex(x[0])} / {x[1]}")
