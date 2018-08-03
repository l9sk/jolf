import sys, os
import glob
from os import stat_result
import struct
from stat_vars import *

def was_file_input_given(parent_dir):
    fuzzer_stats = open(os.path.join(parent_dir, "fuzzer_stats"), "r")
    for line in fuzzer_stats:
        if "command_line" in line.split(":")[0]:
            if "@@" in line.strip().split(":")[1]:
                return True

    return False

def get_data(filename):
    with open(filename, "rb") as f:
        ret = f.read()
        return ret

def get_stat(filename):
    """
    stat = os.stat(filename)
    stat_bytes = [bytes(stat.st_dev),
            bytes(stat.st_ino), 
            bytes(stat.st_mode), 
            bytes(stat.st_nlink), 
            bytes(stat.st_uid), 
            bytes(stat.st_gid),
            bytes(stat.st_rdev), 
            bytes(stat.st_size), 
            bytes(stat.st_blksize), 
            bytes(stat.st_blocks), 
            b"".join([b"0x%02x" % b for b in bytearray(struct.pack("f", stat.st_atime))]),
            b"".join([b"0x%02x" % b for b in bytearray(struct.pack("f", stat.st_mtime))]),
            b"".join([b"0x%02x" % b for b in bytearray(struct.pack("f", stat.st_ctime))])]

    ret = b"".join(stat_bytes)
    return ret
    """

    # A goddamn hack
    return STAT_DATA

def read_files(afl_list):
    files_datas = []
    files_stats = []
    for filename in afl_list:
        files_datas.append(get_data(filename))
        files_stats.append(get_stat(filename))

    return files_datas, files_stats

def generate_data_block(data, datatype):
    obj_string = "object    0: name: '%s'\n"%(datatype)
    obj_string += "object    0: size: '%d'\n"%(len(data))
    obj_string += "object    0: data: '%s'\n"%(data)

    return obj_string

def generate_stat_block(data, datatype):
    obj_string = "object    1: name: '%s-stat'\n"%(datatype)
    obj_string += "object    1: size: '%d'\n"%(144)
    obj_string += "object    1: data: '%s'\n"%(STAT_DATA)

    return obj_string

def generate_object_blocks(datas, stats, datatype):
    object_blocks = []

    for i, d in enumerate(datas):
        data_block = generate_data_block(datas[i], datatype)
        stat_block = generate_stat_block(stats[i], datatype)

        object_blocks.append([data_block, stat_block, MODEL_BLOCK])

def generate_start_blocks(parent_dir, file_input):
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

    file_input = was_file_input_given(parent_dir)
    afl_datas, afl_stats = read_files(afl_list)
    
    if file_input:
        print("AFL was run with file input")
        object_blockss = generate_object_blocks(afl_datas, afl_stats, "A-data")
    else:
        print("AFL was run with STDIN")
        object_blockss = generate_object_blocks(afl_datas, afl_stats, "stdin")

    start_blocksss = generate_start_blocks(afl_datas, file_input)

    write_testcases(out_dir, start_blocks, data_blocks, final_blocks)

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

