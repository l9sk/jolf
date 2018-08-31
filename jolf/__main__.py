from read_klee_testcases import main as rkt_main
from read_klee_testcases import process_klee_out
#from read_afl_testcases import main as rat_main
import argparse
import os, sys, time, glob
from config import AFL_FUZZ, KLEE
import subprocess

def call_afl(max_time, seed_inputs_dir, output_dir, afl_object, argv):
    timeout = ["timeout", "--preserve-status", str(max_time)+"s"]
    afl_command = [AFL_FUZZ, "-i", seed_inputs_dir, "-o", output_dir, afl_object, argv, "@@"]
    try:
        ret = subprocess.check_call(timeout + afl_command)
    except subprocess.CalledProcessError:
        print("Exiting Jolf...")
        sys.exit(-1)

def call_klee(output_dir, max_time, klee_object, afl_seed_out_dirs):
    klee_command = [KLEE]
    
    # Seeding related arguments
    seeding_from_afl = []
    for d in afl_seed_out_dirs:
        seeding_from_afl += ["-afl-seed-out-dir="+d]
    if len(afl_seed_out_dirs)>0:
        seeding_from_afl += ["-named-seed-matching", "-allow-seed-extension", "-zero-seed-extension"]

    libc = ["-posix-runtime", "-libc=uclibc"]
    output = ["-output-dir="+output_dir]
    timeout = ["-max-time="+max_time, "-watchdog"]
    other_args = ["-only-output-states-covering-new", "-max-instruction-time=10", "-optimize", "-suppress-external-warnings", "-write-cov"]
    sym_args = ["A", "--sym-args", "1", "2", "3", "--sym-files", "1", "100"]

    try:
        ret = subprocess.check_call(klee_command + seeding_from_afl + libc + output + timeout + other_args + [klee_object] + sym_args)
    except subprocess.CalledProcessError:
        print("Something wrong with the KLEE run...")
        #sys.exit(-1)

def clean_argv(argv):
    clean = []
# 
    for a in argv:
        stripped = a.strip("\x00\x01 ")
        
        if (stripped=="") or (stripped in clean):
            continue

        clean.append(stripped)

    return clean

def main():
    parser = argparse.ArgumentParser(description="AFL+KLEE flipper")
    parser.add_argument("-t", "--max-time-each", help="Max time(sec) allowed for each round of KLEE or AFL")
    parser.add_argument("-i", "--seed-inputs-dir", help="Seed inputs for AFL")
    parser.add_argument("-o", "--all-output-dir", help="Folder to run experiments in")
    parser.add_argument("-k", "--klee-object", help="Bitcode for KLEE")
    parser.add_argument("-b", "--afl-object", help="Binary or LLVM IR for AFL")
    
    args = parser.parse_args()
    seed_inputs_dir = os.path.join(args.all_output_dir, "all_seeds/")
    
    # Prepare directory
    if not os.path.isdir(args.all_output_dir):
        ret = subprocess.check_call(["mkdir", args.all_output_dir])
        ret = subprocess.check_call(["mkdir", seed_inputs_dir])
        os.system("cp " + os.path.join(args.seed_inputs_dir, "* ") + seed_inputs_dir)

    # First fuzz
    if not os.path.isdir(os.path.join(args.all_output_dir, "init-fuzzing")):
        call_afl(args.max_time_each, seed_inputs_dir, os.path.join(args.all_output_dir, "init-fuzzing"), args.afl_object, "")

    # Concolic execution with AFL seeds
    if not os.path.isdir(os.path.join(args.all_output_dir, "klee0")):
        call_klee(os.path.join(args.all_output_dir, "klee0"), args.max_time_each, args.klee_object, [os.path.join(args.all_output_dir, "init-fuzzing")])

    # Read KLEE testcases and populate new seed-inputs folder
    argv = process_klee_out(args.all_output_dir+"/klee0/", seed_inputs_dir)
    
    argv = clean_argv(argv)
    print(argv)
    time.sleep(3)
    
    #sys.exit(-1)

    # How many sets of command line arguments were found by KLEE?
    if len(argv)>0:
        if (int(args.max_time_each)/len(argv))<30:
            max_time_fuzzing_instance = 30 
        else:
            max_time_fuzzing_instance = int(args.max_time_each)/len(argv)
    else:
        argv = [" "]
        max_time_fuzzing_instance = args.max_time_each
    
    # Second fuzzing round
    second_round_fuzzed_list = glob.glob(args.all_output_dir+"/fuzzing-*")
    if len(second_round_fuzzed_list)==0:
        for i, arg in enumerate(argv):
            call_afl(max_time_fuzzing_instance, seed_inputs_dir, os.path.join(args.all_output_dir, "fuzzing-"+str(i)), args.afl_object, arg)
    
    # Concolic execution again
    afl_seed_out_dirs = glob.glob(args.all_output_dir+"/fuzzing-*")
    call_klee(os.path.join(args.all_output_dir, "klee1"), args.max_time_each, args.klee_object, afl_seed_out_dirs)

if __name__=="__main__":
    main()

