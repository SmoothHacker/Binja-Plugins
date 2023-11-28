from .lib import *

import argparse

from binaryninja import *

parser = argparse.ArgumentParser(
    prog="Binja DataVar Read/Write checker",
    description="This program finds all reads/writes for the specified data vars",
    epilog="Author: Scott Lagler (SmoothHacker)")

parser.add_argument("bndb")
parser.add_argument("--vars", dest="target_addrs", metavar="N", type=str, nargs='*', help='Target addresses')

args = parser.parse_args()

bv: BinaryView = load(args.bndb)

if args.target_addrs is None:
    target_vars = bv.data_vars.items()
else:
    target_vars = []
    for x in args.target_addrs:
        addr = int(x, 16)
        target_vars.append(bv.data_vars[addr])
