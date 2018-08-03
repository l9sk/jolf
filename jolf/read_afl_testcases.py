import sys, os
import glob
from os import stat_result
import struct
from stat_vars import *

def get_argtype(parent_dir):
    fuzzer_stats = open(os.path.join(parent_dir, "fuzzer_stats"), "r")
    for line in fuzzer_stats:
        if "command_line" in line.split(":")[0]:
            if "@@" in line.strip().split(":")[1]:
                return "file"

    return "stdin"

def get_executable(parent_dir):
    pass

def write_testcases(out_dir, all_blocks):
    pass

def main(parent_dir, out_dir):
    afl_list = glob.glob(os.path.join(parent_dir, "crashes/" + "id*")) + \
            glob.glob(os.path.join(parent_dir, "hangs/" + "id*")) + \
            glob.glob(os.path.join(parent_dir, "queue/" + "id*"))

    if not afl_list:
        print("No testcases found in %s.\nExiting..."%(parent_dir))
        sys.exit(1)

    argtype = get_argtype(parent_dir)
    executable = get_executable(parent_dir)
    
if __name__=="__main__":
    if len(sys.argv) == 3:
        afl_out = sys.argv[1]
        out_folder = sys.argv[2]
    elif len(sys.argv) == 2:
        afl_out = sys.argv[1]
        if not os.path.isdir("/tmp/testcases"):
            os.system("mkdir /tmp/testcases")
        out_folder = "/tmp/testcases"
    else:
        print("Only %d arguments given." % (len(sys.argv)))
        print(sys.argv)
        print("Correct usage: read_afl_testcases.py <afl-resafl-resultsder> [testcase output folder]")
        sys.exit(-1)

    main(afl_out, out_folder)

