import sys
from binaryninja import *

bv = BinaryViewType.get_view_of_file(sys.argv[1])
bv.update_analysis_and_wait()

print(f"[*] Saving {bv.file.filename}.bndb . . .")
bv.create_database(f"{os.path.basename(sys.argv[1])}.bndb", None, None)
