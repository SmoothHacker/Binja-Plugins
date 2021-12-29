from binaryninja import *

# This plugin finds printf functions and marks the format string as a const char array instead of the default void type

def fixPrintf(bv):
  printfSymbol = bv.get_symbol_by_raw_name("printf")

  printfRefList= bv.get_code_refs(printfSymbol.address)
  t = bv.parse_type_string("const char [0x3]")

  for printfRef in printfRefList:
    LLIL_instr = printfRef.function.get_low_level_il_at(printfRef.address)
    fmtStringAddr = LLIL_instr.high_level_il.operands[1][0].operands[0]
    bv.define_data_var(fmtStringAddr, t[0])

PluginCommand.register("Format String Fixer", "Fixes data type for format strings", fixPrintf)

