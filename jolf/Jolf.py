from read_klee_testcases import main as rkt_main
from read_klee_testcases import process_klee_out
#from read_afl_testcases import main as rat_main
import os, sys, time, glob, signal, json
from os import kill
from config import AFL_FUZZ, KLEE
import subprocess
from collections import OrderedDict

class Jolf:
    def LOG(self, line):
        log_file = open(os.path.join(self.all_output_dir, "jolf.log"), "a+")
        log_file.write("%s: %s\n"%(time.ctime(None), line))
        log_file.close()
        
    def call_afl(self, max_time, seed_inputs_dir, output_dir, afl_object, argv):
        self.LOG("Calling AFL")
        self.LOG("\tMax-time: %d, output-dir: %s, argv: %s"%(max_time, output_dir, argv))

        if max_time>0:
            timeout = ["timeout", "--preserve-status", str(max_time)+"s"]
        else:
            timeout = []
        afl_command = [AFL_FUZZ, "-i", seed_inputs_dir, "-o", output_dir, afl_object, argv, "@@"]
        try:
            return subprocess.Popen(timeout + afl_command)
        except subprocess.CalledProcessError:
            self.LOG("Encountered error in call_afl (subprocess.Popen).\n\tExiting now.")
            print("Exiting Jolf...")
            sys.exit(-1)

    def get_max_size_in_queue(self, afl_seed_out_dirs):
        max_size = 0
        for d in afl_seed_out_dirs:
            for f in glob.glob(os.path.join(d, "queue") + "/id*"):
                if os.path.getsize(f)>max_size:
                    max_size = os.path.getsize(f)
        return max_size

    def call_klee(self, output_dir, max_time, klee_object, afl_seed_out_dirs):
        self.LOG("Calling KLEE")
        self.LOG("\tMax-time: %d, output-dir: %s"%(max_time, output_dir))

        klee_command = [KLEE]
        
        # Seeding related arguments
        seeding_from_afl = []
        for d in afl_seed_out_dirs:
            seeding_from_afl += ["-afl-seed-out-dir="+d]
        if len(afl_seed_out_dirs)>0:
            seeding_from_afl += ["-named-seed-matching", "-allow-seed-extension", "-zero-seed-extension"]

        sym_file_size = self.get_max_size_in_queue(afl_seed_out_dirs)

        libc = ["-posix-runtime", "-libc=uclibc"]
        output = ["-output-dir="+output_dir]
        if max_time>0:
            timeout = ["-max-time="+str(max_time), "-watchdog"]
        else:
            timeout = []

        other_args = ["-only-output-states-covering-new", "-max-instruction-time=10", "-optimize", "-suppress-external-warnings", "-write-cov", "-istats-write-interval=1"]
        sym_args = ["A", "--sym-args", "1", "2", "3", "--sym-files", "1", str(sym_file_size)]

        try:
            ret = subprocess.Popen(klee_command + seeding_from_afl + libc + output + timeout + other_args + [klee_object] + sym_args)
            return ret
        except subprocess.CalledProcessError:
            self.LOG("Encountered error in call_klee (subprocess.Popen).\n\tExiting now.")
            print("Something wrong with the KLEE run...")
            #sys.exit(-1)
            return None

    def clean_argv(self, argv):
        clean = []
        
        for a in argv:
            stripped = a.strip("\x00\x01 ")
            
            if (stripped=="") or (stripped in clean):
                continue

            clean.append(stripped)

        return clean

    def get_afl_command_args(self, d):
        fuzzer_stats = open(os.path.join(d, "fuzzer_stats"), "r")
        
        command_args = ""

        command_line = ""
        for l in fuzzer_stats:
            if l.startswith("command_line"):
                command_line = l

        toks = command_line.strip().split()
        
        i = len(toks)-1

        if not toks[i]=="@@":
            return command_args

        i -= 1

        while i>=0 and toks[i].startswith("-"):
           command_args += " " + toks[i]
           i -= 1

        return command_args

    def get_afl_coverage(self, coverage_list, afl_out_dir):
        coverage_file = open(os.path.join(afl_out_dir, "cov/id-delta-cov"), "r")
        
        for line in coverage_file:
            if line.startswith("#"):
                continue
            fields = line.strip().split(", ")
            if not fields[2].startswith(self.PREFIXES[1]):
                continue
            if not fields[3]=="line":
                continue
            file_name = fields[2].split(self.PREFIXES[1])[-1]
            line_no = int(fields[4])

            if (file_name, line_no) not in coverage_list:
                coverage_list.append((file_name, line_no))

        return coverage_list

    def get_klee_coverage(self, coverage_list, klee_out_dir):
        for f in glob.glob(klee_out_dir+"/*.cov"):
            cov_file = open(f, "r")
            for line in cov_file:
                if not line.startswith(self.PREFIXES[0]):
                    continue
                file_name = line.strip().split(":")[0].split(self.PREFIXES[0])[-1]
                line_no = int(line.strip().split(":")[-1])
                if (file_name, line_no) not in coverage_list:
                    coverage_list.append((file_name, line_no))

        return coverage_list

    def sort_inputs_by_size(self, input_dirs):
        size_dict = {}
        
        for dir in input_dirs:
            for f in glob.glob(dir+"/id:*"):
                if not self.size_batch:
                    if 0 not in size_dict.keys():
                        size_dict[0] = []
                    size_dict[0].append(f)
                else:
                    size = os.path.getsize(f)
                    if size not in size_dict.keys():
                        size_dict[size] = []
                    size_dict[size].append(f)

        return size_dict

    def check_klee(self):
        self.call_klee("/tmp/klee-out", 5, self.klee_object, [])
        print("Checking if KLEE works with the object")
        print("You have 5 seconds to hit Ctrl+C")
        time.sleep(5)

    def check_afl(self):
        self.call_afl(5, self.afl_seed_inputs_dir, "/tmp/afl-out", self.afl_object, "")
        print("Checking if AFL works with the object")
        print("You have 5 seconds to hit Ctrl+C")
        time.sleep(5)
        os.system("rm -rf /tmp/afl-out")

    def dispatch(self):
        seed_inputs_dir = self.prepare_directory()
        if self.mode != "coverage":
            self.check_klee()
            self.check_afl()
        
        log_line = "Jolf dispatching\n"
        log_line += "\tMax time: %s\n"%(self.max_time_each)
        log_line += "\tKLEE Object: %s\n"%(self.klee_object)
        log_line += "\tAFL Object: %s\n"%(self.afl_object)
        if self.size_batch:
            log_line += "\tUsing size-wise file batching for KLEE runs"
        else:
            log_line += "\tNOT grouping files by size. Feeding everything to KLEE at once"

        self.LOG(log_line)
        
        self.LOG("Dispatch method: %s"%(self.dispatch_method.__name__))

        self.dispatch_method(seed_inputs_dir)

        self.LOG("Dispatch method returned")
        self.LOG("Exiting Jolf..")

    def call_afl_cov(self, afl_output_dir, coverage_executable, afl_command_args, coverage_source, live=False):
        if live:
            live_arg = "--live --background --sleep 2"
        else:
            live_arg = ""
        os.system("afl-cov -d %s %s --coverage-cmd \"%s %s AFL_FILE\" --code-dir %s --coverage-include-lines"%(afl_output_dir, live_arg, coverage_executable, afl_command_args, coverage_source))

    def _dispatch_coverage(self, seed_inputs_dir):
        print("Calculating coverage...")
        # fuzzing_dirs = glob.glob(self.all_output_dir+"/fuzzing-*")
        
        coverage_list = []
        for d in glob.glob(self.all_output_dir+"/fuzzing-*"):
            print("Processing AFL output dir: %s"%(d))
            if not os.path.isdir(d+"/cov"):
                afl_command_args = self.get_afl_command_args(d)
                self.call_afl_cov(d, self.coverage_executable, afl_command_args, self.coverage_source)
            coverage_list = self.get_afl_coverage(coverage_list, d)

        for d in glob.glob(self.all_output_dir + "/klee-*"):
            print("Processing KLEE output dir: %s"%(d))
            coverage_list = self.get_klee_coverage(coverage_list, d)

        print("Covered lines: %d"%(len(coverage_list)))

        return 0

    def prepare_directory(self):
        seed_inputs_dir = os.path.join(self.all_output_dir, "all_seeds/")

        # Prepare directory
        if not os.path.isdir(self.all_output_dir):
            ret = subprocess.check_call(["mkdir", self.all_output_dir])
            ret = subprocess.check_call(["mkdir", seed_inputs_dir])
            os.system("cp " + os.path.join(self.afl_seed_inputs_dir, "* ") + seed_inputs_dir)

        return seed_inputs_dir

    def _dispatch_timed(self, seed_inputs_dir):
        # First fuzz
        if not os.path.isdir(os.path.join(self.all_output_dir, "init-fuzzing")):
            self.call_afl(self.max_time_each, seed_inputs_dir, os.path.join(self.all_output_dir, "init-fuzzing"), self.afl_object, "")

        # Sort fuzzing test-cases by size
        file_size_dict = self.sort_inputs_by_size([os.path.join(os.path.join(self.all_output_dir, "init-fuzzing"), "queue")])

        # Concolic execution with AFL seeds - grouped by seed-input size
        if (int(self.max_time_each)/len(file_size_dict.keys()))<30:
            max_time_klee_instance = 30 
        else:
            max_time_klee_instance = int(self.max_time_each)/len(file_size_dict.keys())
        
        print("AFL inputs grouped into %d groups"%(len(file_size_dict.keys())))
        print("Allocating %f seconds for each KLEE instance"%(max_time_klee_instance))
        time.sleep(2)
        
        for i, s in enumerate(file_size_dict.keys()):
            if not os.path.isdir(os.path.join(self.all_output_dir, "klee"+str(i))):
                if os.path.isdir("/tmp/afl-seed-group"):
                    os.system("rm -rf /tmp/afl-seed-group")
                os.system("mkdir /tmp/afl-seed-group")
                os.system("mkdir /tmp/afl-seed-group/queue")
                for f in file_size_dict[s]:
                    os.system("cp %s /tmp/afl-seed-group/queue/"%(f))
                
                self.call_klee(os.path.join(self.all_output_dir, "klee"+str(i)), max_time_klee_instance, self.klee_object, ["/tmp/afl-seed-group"])

        # Read KLEE testcases and populate new seed-inputs folder
        argv = []
        for k in glob.glob(self.all_output_dir+"/klee*"):
            argv.extend(process_klee_out(k, seed_inputs_dir))
        
        argv = self.clean_argv(argv)
        print(argv)
        time.sleep(3)
        
        #sys.exit(-1)

        # How many sets of command line arguments were found by KLEE?
        if len(argv)>0:
            if (int(self.max_time_each)/len(argv))<30:
                max_time_fuzzing_instance = 30 
            else:
                max_time_fuzzing_instance = int(self.max_time_each)/len(argv)
        else:
            argv = [" "]
            max_time_fuzzing_instance = self.max_time_each
        
        # Second fuzzing round
        second_round_fuzzed_list = glob.glob(self.all_output_dir+"/fuzzing-*")
        if len(second_round_fuzzed_list)==0:
            for i, arg in enumerate(argv):
                self.call_afl(max_time_fuzzing_instance, seed_inputs_dir, os.path.join(self.all_output_dir, "fuzzing-"+str(i)), self.afl_object, arg)
        
        # Sort fuzzing test-cases by size
        file_size_dict = self.sort_inputs_by_size(glob.glob(self.all_output_dir+"/fuzzing-*/queue"))

        # Concolic execution with AFL seeds - grouped by seed-input size
        if (int(self.max_time_each)/len(file_size_dict.keys()))<30:
            max_time_klee_instance = 30 
        else:
            max_time_klee_instance = int(self.max_time_each)/len(file_size_dict.keys())
        
        print("AFL inputs grouped into %d groups"%(len(file_size_dict.keys())))
        print("Allocating %f seconds for each KLEE instance"%(max_time_klee_instance))
        time.sleep(2)
        
        # Concolic execution again
        for i, s in enumerate(file_size_dict.keys()):
            if not os.path.isdir(os.path.join(self.all_output_dir, "klee-2-"+str(i))):
                if os.path.isdir("/tmp/afl-seed-group"):
                    os.system("rm -rf /tmp/afl-seed-group")
                os.system("mkdir /tmp/afl-seed-group")
                os.system("mkdir /tmp/afl-seed-group/queue")
                for f in file_size_dict[s]:
                    os.system("cp %s /tmp/afl-seed-group/queue/"%(f))
                
                afl_seed_out_dirs = "/tmp/afl-seed-group/"
                self.call_klee(os.path.join(self.all_output_dir, "klee-2-"+str(i)), self.max_time_klee_instance, self.klee_object, [afl_seed_out_dirs])

    def parse_plot_data_line(self, line):
        if line.startswith("#"):
            return None
        tokens = line.strip().split(",")

        if len(tokens)==11:
            for i, t in enumerate(tokens):
                try:
                    tokens[i] = int(tokens[i])
                except Exception:
                    pass
            return tokens

        return None

    def afl_saturated(self, i):
        if (time.time() - self.start_time) > int(self.max_time_each):
            self.LOG("AFL saturated because of timeout.")
            return True

        while (not os.path.exists(os.path.join(os.path.join(self.all_output_dir, "fuzzing-"+str(i), "plot_data")))):
            continue
        
        plot_data = open(os.path.join(os.path.join(self.all_output_dir, "fuzzing-"+str(i), "plot_data")))
        
        lines = reversed(plot_data.readlines())
        
        for line in lines:
            progress = self.parse_plot_data_line(line)
            if not progress: # Maybe start of the file
                continue
            if progress[0] in self.afl_progress.keys(): # We have already read this timestamp
                break
            self.afl_progress[progress[0]] = progress[1:]

        zero_since = 0
        for timestamp in reversed(sorted(self.afl_progress.keys())):
            if self.afl_progress[timestamp][3]==0 and self.afl_progress[timestamp][4]==0: # pending_total and pending_favs
                if self.afl_progress[timestamp][0]>0: # If more than one cycle is done then converge to an end faster
                    zero_since += 2
                else:
                    zero_since += 1
            else:
                break
        if zero_since>2: # If no new paths have been seen in the last 3 log items 
            self.LOG("AFL saturated because zero_since=%d."%(zero_since))
            return True
        
        self.LOG("Continuing AFL. zero_since=%d"%(zero_since))
        return False
    
    def parse_klee_cov(self, f):
        content = open(f)
        
        covered_lines = []

        for line in content:
            covered_lines.append(line.strip())

        if not covered_lines==[]:
            return covered_lines
        
        return None

    def parse_run_istats(self, istats_file):
        istats = open(istats_file)
        found_new = False
        
        for line in istats:
            tokens = line.split()
            if len(tokens)!=15:
                continue
            llvm, src, cov = int(tokens[0]), int(tokens[1]), int(tokens[2]) # Read source-level coverage rather than LLVM level
            
            if (cov>0):
                if src not in self.klee_progress.keys(): # Definitely new source-level coverage
                    self.klee_progress[src] = {}
                    self.klee_progress[src][llvm] = cov # The same line number could have been from any source file. Use LLVM instruction number to differentiate
                    found_new = True
                elif llvm not in self.klee_progress[src].keys(): # The covered LLVM instruction is newly covered, but source line was seen before
                    self.klee_progress[src][llvm] = cov # The source line corresponds to a different file number from the one seen before
                    found_new = True
                else:
                    found_new = False # The pair (llvm, src) has been seen before. No new coverage

        return found_new

    def klee_saturated(self, i):
        if (time.time() - self.start_time) > int(self.max_time_each):
            self.LOG("KLEE saturated because of timeout.")
            return True
        
        while (not os.path.exists(os.path.join(os.path.join(self.all_output_dir, "klee-"+str(i)), "run.istats"))): # Klee should have at least done something 
            continue
        len_old_covered = len([len(self.klee_progress[k].keys()) for k in self.klee_progress.keys()])
        new_covered = {}

        os.system("cp " + os.path.join(os.path.join(self.all_output_dir, "klee-"+str(i)), "run.istats") + " /tmp/run.istats")
        new_covered = self.parse_run_istats("/tmp/run.istats")
        if new_covered:
            len_new_covered = len([len(self.klee_progress[k].keys()) for k in self.klee_progress.keys()])
            self.LOG("Continuing KLEE. Line coverage increased from %d to %d"%(len_old_covered, len_new_covered))
            return False

        self.LOG("KLEE saturated. No new line-coverage found")
        return True

    def _dispatch_saturation(self, seed_inputs_dir):
        self.start_time = time.time()
        fuzzing_i = 1
        klee_i = 1
        
        while(time.time()-self.start_time < int(self.max_time_each)):
            fuzzing_i = len(glob.glob(self.all_output_dir+"/fuzzing-*")) + 1
            # Read KLEE testcases and populate new seed-inputs folder
            argv = []
            for k in glob.glob(self.all_output_dir+"/klee-*"):
                argv.extend(process_klee_out(k, seed_inputs_dir))
            
            argv = self.clean_argv(argv)
            print(argv)
            time.sleep(2)
            
            # How many sets of command line arguments were found by KLEE?
            if len(argv)==0:
                argv = [" "]
            
            for i, arg in enumerate(argv):
                if not os.path.isdir(os.path.join(self.all_output_dir, "fuzzing-"+str(fuzzing_i))):
                    proc = self.call_afl(0, seed_inputs_dir, os.path.join(self.all_output_dir, "fuzzing-"+str(fuzzing_i)), self.afl_object, arg)
                    afl_saturate = False
                    while (not afl_saturate):
                        time.sleep(6) # 1 second more than how often plot_data is updated 
                        afl_saturate = self.afl_saturated(fuzzing_i)

                    kill(proc.pid, signal.SIGINT)
                    time.sleep(3) # Wait for AFL to exit
                    fuzzing_i += 1
            
            # Sort afl test-cases by size
            file_size_dict = self.sort_inputs_by_size(glob.glob(self.all_output_dir+"/fuzzing-*/queue"))
            self.LOG("AFL inputs grouped into %d groups"%(len(file_size_dict.keys())))
            
            klee_i = len(glob.glob(self.all_output_dir+"/klee-*")) + 1
            for i, s in enumerate(file_size_dict.keys()):
                if not os.path.isdir(os.path.join(self.all_output_dir, "klee-"+str(klee_i))):
                    if os.path.isdir("/tmp/afl-seed-group"):
                        os.system("rm -rf /tmp/afl-seed-group")
                    os.system("mkdir /tmp/afl-seed-group")
                    os.system("mkdir /tmp/afl-seed-group/queue")
                    for f in file_size_dict[s]:
                        os.system("cp %s /tmp/afl-seed-group/queue/"%(f))
                    
                    proc = self.call_klee(os.path.join(self.all_output_dir, "klee-"+str(klee_i)), 0, self.klee_object, ["/tmp/afl-seed-group"])
                    seed_inputs = len(os.listdir("/tmp/afl-seed-group/queue/"))
                    self.LOG("Giving %d seconds to KLEE for seeding"%(5*seed_inputs))
                    time.sleep(5*seed_inputs) # Give KLEE some seeding time 

                    klee_saturate = False
                    while (not klee_saturate):
                        seed_inputs = len(os.listdir("/tmp/afl-seed-group/"))
                        time.sleep(5) # Takes a lot of time for KLEE to generate anything meaningful
                        klee_saturate = self.klee_saturated(klee_i)
                    
                    kill(proc.pid, signal.SIGINT)
                    time.sleep(10) # Might take a long time for KLEE to be killed properly
                    klee_i += 1

    def __init__(self, 
            mode, 
            max_time_each, 
            afl_seed_inputs_dir, 
            all_output_dir, 
            klee_object, 
            afl_object, 
            coverage_source, 
            coverage_executable,
            size_batch):
        
        self.mode = mode 
        self.max_time_each = max_time_each
        self.afl_seed_inputs_dir = afl_seed_inputs_dir
        self.all_output_dir = all_output_dir
        self.klee_object = klee_object
        self.afl_object = afl_object
        self.coverage_source = coverage_source
        self.coverage_executable = coverage_executable
        self.size_batch = size_batch


        self.afl_progress = {}
        self.klee_progress = {}
        self.start_time = 0
        os.system("rm -rf /tmp/klee-out")
        os.system("rm -rf /tmp/afl-out")
        
        if self.mode=="timed":
            self.dispatch_method = self._dispatch_timed
        elif self.mode=="coverage":
            self.dispatch_method = self._dispatch_coverage
        elif self.mode=="saturation":
            self.dispatch_method = self._dispatch_saturation
        
        self.PREFIXES = ["/home/ognawala/coreutils-8.30/", "/home/ognawala/coreutils-8.30-gcov/"]

