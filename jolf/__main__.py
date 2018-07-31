from read_klee_testcases import main as rkt_main 
import argparse
import os, sys

def main():
    parser = argparse.ArgumentParser(description="Convert between KLEE and AFL testcases")
    parser.add_argument("-i", "--input-dir", required=True, help="Directory containing inputs")
    parser.add_argument("-t", "--target", required=True, help="Conversion target, i.e. klee or afl")
    parser.add_argument("-o", "--output-dir", help="Output dir")
    
    args = parser.parse_args()

    if args.target=="afl":
        rkt_main(args.input_dir, args.output_dir)
    elif args.target=="klee":
        pass
    else:
        print("Target can be klee or afl only.")
        sys.exit(-1)

if __name__=="__main__":
    main()

