from Jolf import Jolf
import argparse

def main():
    parser = argparse.ArgumentParser(description="AFL+KLEE flipper")
    parser.add_argument("-t", "--max-time-each", help="Max time(sec) allowed for each round of KLEE or AFL")
    parser.add_argument("-i", "--seed-inputs-dir", help="Seed inputs for AFL")
    parser.add_argument("-o", "--all-output-dir", help="Folder to run experiments in")
    parser.add_argument("-k", "--klee-object", help="Bitcode for KLEE")
    parser.add_argument("-b", "--afl-object", help="Binary or LLVM IR for AFL")
    parser.add_argument("-c", "--coverage-mode", help="Run Jolf in coverage mode (results existing)")
    parser.add_argument("-g", "--coverage-source", help="Location of project compiled with gcov")
    parser.add_argument("-e", "--coverage-executable", help="Name of executable compiled with Gcov")
    
    args = parser.parse_args()
    
    if args.coverage_mode=="True":
        mode = "coverage"
    else:
        mode = "timed"

    jolf = Jolf(mode, args.max_time_each, args.seed_inputs_dir, args.all_output_dir, args.klee_object, args.afl_object, args.coverage_source, args.coverage_executable)
    jolf.dispatch()
    
if __name__=="__main__":
    main()

