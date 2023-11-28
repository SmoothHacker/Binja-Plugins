from .lib import lib_main

from binaryninja import *

def action(bv: BinaryView, addr: int) -> None:
    lib_main(bv, [bv.data_vars[addr]])
    return

def is_valid(bv: BinaryView, addr: int) -> bool:
    return addr in bv.data_vars

PluginCommand.register_for_address("Print Var Read/Writes", "Creates a report of data var read/writes", action, is_valid)
