from binaryninja import *

def undefine_funcs(bv: BinaryView):
    for sym in bv.symbols:
        if ".cold" in bv.symbols[sym].name:
            bv.undefine_auto_symbol(sym)
    return

def is_valid(bv: BinaryView):
    for sym in bv.symbols:
        if ".cold" in bv.symbols[sym].name:
            return True
    return False


PluginCommand.register("Undefine Cold Functions", "Undefines functions with a .cold suffix so that BN can inline them", undefine_funcs, is_valid)
