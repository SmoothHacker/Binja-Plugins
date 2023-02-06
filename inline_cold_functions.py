from binaryninja import *

def undefine_funcs(bv: BinaryView):
    for func in bv:
        if ".cold" in func.name:
            bv.undefine_auto_symbol(func.symbol)
    return

def is_valid(bv: BinaryView):
    for func in bv:
        if ".cold" in func.name:
            return True
    return False


PluginCommand.register("Undefine Cold Functions", "Undefines functions with a .cold suffix so that BN can inline them", undefine_funcs, is_valid)