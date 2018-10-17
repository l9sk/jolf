from read_klee_testcases import main as rkt_main
from read_klee_testcases import process_klee_out
#from read_afl_testcases import main as rat_main
import os, sys, time, glob, signal, json
from os import kill
from config import AFL_FUZZ, KLEE, PREFIXES
import subprocess
from collections import OrderedDict
import tempfile, shutil

class Jolf:
    def LOG(self, line):
        log_file = open(os.path.join(self.all_output_dir, "jolf.log"), "a+")
        log_file.write("%s: %s\n"%(time.ctime(None), line))
        log_file.close()
        
    def write_coverage(self):
        sorted_keys = sorted(self.coverage_list.keys())
        coverage_file = open(os.path.join(self.all_output_dir, "coverage.log"), "a+")
        for s in sorted_keys:
            if s in self.written_coverage:
                continue
            for tup in self.coverage_list[s]:
                coverage_file.write("%s: %s: %s %d\n"%(time.ctime(s), tup[0], tup[1], tup[2]))
            self.written_coverage.append(s)
        coverage_file.close()

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
        if max_size==0:
            return 10 # Default non-zero size file
        else:
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

        other_args = ["-only-output-states-covering-new", "-max-instruction-time=10", "-suppress-external-warnings", "-write-cov", "-istats-write-interval=1"]
        sym_args = ["--sym-args", "1", "3", "3", "--sym-files", "1", str(sym_file_size)]

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

    def get_afl_coverage(self, afl_out_dir):
        if not os.path.exists(os.path.join(afl_out_dir, "cov/id-delta-cov")):
            return []

        coverage_file = open(os.path.join(afl_out_dir, "cov/id-delta-cov"), "r")
        new_covered = []

        for line in coverage_file:
            if line.startswith("#"):
                continue
            fields = line.strip().split(", ")
            """
            if not fields[2].startswith(self.PREFIXES[1]):
                continue
            """
            if not fields[3]=="line":
                continue
            #file_name = fields[2].split(self.PREFIXES[1])[-1]
            file_name = fields[2].strip()
            line_no = int(fields[4])

            if not(any([ (("AFL", os.path.basename(file_name), line_no) in v or ("KLEE", os.path.basename(file_name), line_no) in v) for v in self.coverage_list.values() ])):
                new_covered.append(("AFL", os.path.basename(file_name), line_no)) 

        return new_covered

    def get_klee_coverage(self, klee_out_dir):
        new_covered = []

        for f in glob.glob(klee_out_dir+"/*.cov"):
            cov_file = open(f, "r")
            for line in cov_file:
                """
                if not line.startswith(self.PREFIXES[0]):
                    continue
                """ 
                #file_name = line.strip().split(":")[0].split(self.PREFIXES[0])[-1]
                file_name = line.strip().split(":")[0].strip()
                line_no = int(line.strip().split(":")[-1])
                if not(any([ (("AFL", os.path.basename(file_name), line_no) in v or ("KLEE", os.path.basename(file_name), line_no) in v) for v in self.coverage_list.values() ])):
                    new_covered.append(("KLEE", os.path.basename(file_name), line_no)) 

        return new_covered

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
        while True:
            tmp_klee_dir_name = os.path.join("/tmp/", "klee-out-"+next(tempfile._get_candidate_names()))
            if not os.path.isdir(tmp_klee_dir_name):
                break

        self.call_klee(tmp_klee_dir_name, 5, self.klee_object, [])
        print("Checking if KLEE works with the object")
        print("You have 5 seconds to hit Ctrl+C")
        time.sleep(5)
        shutil.rmtree(tmp_klee_dir_name)

    def check_afl(self):
        tmp_afl_dir = tempfile.mkdtemp(prefix="afl-out-")
        self.call_afl(5, self.afl_seed_inputs_dir, tmp_afl_dir, self.afl_object, "")
        print("Checking if AFL works with the object")
        print("You have 5 seconds to hit Ctrl+C")
        time.sleep(5)
        shutil.rmtree(tmp_afl_dir)

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
        self.LOG("Attempting to call afl-cov: %s %s %s"%(afl_output_dir, coverage_executable, coverage_source))
        if live:
            live_arg = "--live --background --quiet --sleep 2"
        else:
            live_arg = ""
        ret = os.system("afl-cov -d %s %s --coverage-cmd \"%s %s AFL_FILE\" --code-dir %s --coverage-include-lines >> %s 2>&1"%(afl_output_dir, live_arg, coverage_executable, afl_command_args, coverage_source, os.path.join(self.all_output_dir, "afl-cov.out")))

        if ret==0:
            self.LOG("Dispatching afl-cov was successful\n\t%s"%(afl_output_dir))
        else:
            self.LOG("FAILED to dispatch afl-cov\n\treturn value: %d"%(ret))
        
        return ret

    def _dispatch_coverage(self, seed_inputs_dir):
        print("Calculating coverage...")
        # fuzzing_dirs = glob.glob(self.all_output_dir+"/fuzzing-*")
        
        for d in glob.glob(self.all_output_dir+"/fuzzing-*"):
            print("Processing AFL output dir: %s"%(d))
            if not os.path.isdir(d+"/cov"):
                afl_command_args = self.get_afl_command_args(d)
                self.call_afl_cov(d, self.coverage_executable, afl_command_args, self.coverage_source)
            new_covered = self.get_afl_coverage(d)
            if new_covered:
                key = time.time()
                print(key)
                self.coverage_list[key] = new_covered

        for d in glob.glob(self.all_output_dir + "/klee-*"):
            print("Processing KLEE output dir: %s"%(d))
            new_covered = self.get_klee_coverage(d)
            if new_covered:
                key = time.time()
                print(key)
                self.coverage_list[key] = new_covered

        #print("Covered lines: %d"%(len(covered)))
        print(self.coverage_list)

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
        self.start_time = time.time()
        
        time_each_round = int(self.max_time_each)/4

        if time_each_round<30:
            time_each_round = 30

        while time.time()-self.start_time<int(self.max_time_each):
            # Read KLEE testcases and populate new seed-inputs folder
            argv = []
            for k in glob.glob(self.all_output_dir+"/klee-*"):
                argv.extend(process_klee_out(k, seed_inputs_dir))
            
            argv = self.clean_argv(argv)
            
            # How many sets of command line arguments were found by KLEE?
            if len(argv)==0:
                argv = [" "]
            
            afl_time_each_round = time_each_round/len(argv)
            if afl_time_each_round<30:
                afl_time_each_round = 30
            
            # First fuzz
            for i, arg in enumerate(argv):
                fuzzing_i = len(glob.glob(self.all_output_dir+"/fuzzing-*")) + 1
                current_round_start = time.time()
                if not (os.path.isdir(os.path.join(self.all_output_dir, "fuzzing-"+str(fuzzing_i))) or time.time()-self.start_time>int(self.max_time_each)):
                    proc = self.call_afl(0, seed_inputs_dir, os.path.join(self.all_output_dir, "fuzzing-"+str(fuzzing_i)), self.afl_object, arg)
                    self.call_afl_cov(os.path.join(self.all_output_dir, "fuzzing-"+str(fuzzing_i)), self.coverage_executable, arg, self.coverage_source, True)
                    
                    # Keep writing coverage every five seconds
                    while time.time()-current_round_start<afl_time_each_round:
                        new_covered = self.get_afl_coverage(os.path.join(self.all_output_dir, "fuzzing-"+str(fuzzing_i)))
                        self.coverage_list[time.time()] = new_covered
                        self.write_coverage()
                        time.sleep(5) # 1 second more than how often plot_data is updated 
                    
                    kill(proc.pid, signal.SIGINT)
                    time.sleep(3) # Wait for AFL to exit
                    new_covered = self.get_afl_coverage(os.path.join(self.all_output_dir, "fuzzing-"+str(fuzzing_i)))
                    self.coverage_list[time.time()] = new_covered
                    self.write_coverage()
                    
            # Sort fuzzing test-cases by size
            file_size_dict = self.sort_inputs_by_size(glob.glob(self.all_output_dir+"/fuzzing-*/queue"))
            self.LOG("AFL inputs grouped into %d groups"%(len(file_size_dict.keys())))

            klee_time_each_round = time_each_round/len(file_size_dict.keys())
            if klee_time_each_round<30:
                klee_time_each_round = 30

            # Concolic execution with AFL seeds - grouped by seed-input size
            for i, s in enumerate(file_size_dict.keys()):
                klee_i = len(glob.glob(self.all_output_dir+"/klee-*")) + 1
                current_round_start = time.time()
                if not (os.path.isdir(os.path.join(self.all_output_dir, "klee-"+str(klee_i))) or time.time()-self.start_time>int(self.max_time_each)):
                    tmp_afl_seed_group_dir = tempfile.mkdtemp(prefix="afl-seed-group-")
                    os.system("mkdir %s/queue"%(tmp_afl_seed_group_dir))
                    for f in file_size_dict[s]:
                        os.system("cp %s %s/queue/"%(f, tmp_afl_seed_group_dir))
                    
                    proc = self.call_klee(os.path.join(self.all_output_dir, "klee-"+str(klee_i)), 0, self.klee_object, [tmp_afl_seed_group_dir])
                    seed_inputs = len(os.listdir("%s/queue/"%(tmp_afl_seed_group_dir)))
                    self.LOG("Giving %d seconds to KLEE for seeding"%(5*seed_inputs))
                    time.sleep(5*seed_inputs) # Give KLEE some seeding time 

                    while time.time()-current_round_start<klee_time_each_round:
                        new_covered = self.get_klee_coverage(os.path.join(self.all_output_dir, "klee-"+str(klee_i)))
                        self.coverage_list[time.time()] = new_covered
                        self.write_coverage()
                        time.sleep(5) # Takes a lot of time for KLEE to generate anything meaningful
                    
                    kill(proc.pid, signal.SIGINT)
                    time.sleep(10) # Might take a long time for KLEE to be killed properly
                    shutil.rmtree(tmp_afl_seed_group_dir)
                    new_covered = self.get_klee_coverage(os.path.join(self.all_output_dir, "klee-"+str(klee_i)))
                    self.coverage_list[time.time()] = new_covered
                    self.write_coverage()
        
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

        tmp_istats_dir = tempfile.mkdtemp()
        os.system("cp " + os.path.join(os.path.join(self.all_output_dir, "klee-"+str(i)), "run.istats") + " " + tmp_istats_dir)
        new_covered = self.parse_run_istats(os.path.join(tmp_istats_dir, "run.istats"))
        if new_covered:
            len_new_covered = len([len(self.klee_progress[k].keys()) for k in self.klee_progress.keys()])
            self.LOG("Continuing KLEE. Line coverage increased from %d to %d"%(len_old_covered, len_new_covered))
            return False

        self.LOG("KLEE saturated. No new line-coverage found")
        shutil.rmtree(tmp_istats_dir)
        return True

    def _dispatch_saturation(self, seed_inputs_dir):
        self.start_time = time.time()
        
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
                if not (os.path.isdir(os.path.join(self.all_output_dir, "fuzzing-"+str(fuzzing_i))) or time.time()-self.start_time>int(self.max_time_each)):
                    # Call AFL
                    proc = self.call_afl(0, seed_inputs_dir, os.path.join(self.all_output_dir, "fuzzing-"+str(fuzzing_i)), self.afl_object, arg)
                    # Call afl-cov on the side
                    self.call_afl_cov(os.path.join(self.all_output_dir, "fuzzing-"+str(fuzzing_i)), self.coverage_executable, arg, self.coverage_source, True)
                    
                    afl_saturate = False
                    while not afl_saturate:
                        afl_saturate = self.afl_saturated(fuzzing_i)
                        new_covered = self.get_afl_coverage(os.path.join(self.all_output_dir, "fuzzing-"+str(fuzzing_i)))
                        self.coverage_list[time.time()] = new_covered
                        self.write_coverage()
                        time.sleep(5) # 1 second more than how often plot_data is updated 

                    kill(proc.pid, signal.SIGINT)
                    time.sleep(3) # Wait for AFL to exit
                    new_covered = self.get_afl_coverage(os.path.join(self.all_output_dir, "fuzzing-"+str(fuzzing_i)))
                    self.coverage_list[time.time()] = new_covered
                    self.write_coverage()
            
            # Sort afl test-cases by size
            file_size_dict = self.sort_inputs_by_size(glob.glob(self.all_output_dir+"/fuzzing-*/queue"))
            self.LOG("AFL inputs grouped into %d groups"%(len(file_size_dict.keys())))
            
            for i, s in enumerate(file_size_dict.keys()):
                klee_i = len(glob.glob(self.all_output_dir+"/klee-*")) + 1
                if not (os.path.isdir(os.path.join(self.all_output_dir, "klee-"+str(klee_i))) or time.time()-self.start_time>int(self.max_time_each)):
                    tmp_afl_seed_group_dir = tempfile.mkdtemp(prefix="afl-seed-group-")
                    """
                    if os.path.isdir("/tmp/afl-seed-group"):
                        os.system("rm -rf /tmp/afl-seed-group")
                    os.system("mkdir /tmp/afl-seed-group")
                    """
                    os.system("mkdir %s/queue"%(tmp_afl_seed_group_dir))
                    for f in file_size_dict[s]:
                        os.system("cp %s %s/queue/"%(f, tmp_afl_seed_group_dir))
                    
                    proc = self.call_klee(os.path.join(self.all_output_dir, "klee-"+str(klee_i)), 0, self.klee_object, [tmp_afl_seed_group_dir])
                    seed_inputs = len(os.listdir("%s/queue/"%(tmp_afl_seed_group_dir)))
                    self.LOG("Giving %d seconds to KLEE for seeding"%(5*seed_inputs))
                    time.sleep(5*seed_inputs) # Give KLEE some seeding time 

                    klee_saturate = False
                    while not klee_saturate:
                        new_covered = self.get_klee_coverage(os.path.join(self.all_output_dir, "klee-"+str(klee_i)))
                        self.coverage_list[time.time()] = new_covered
                        self.write_coverage()
                        time.sleep(5) # Takes a lot of time for KLEE to generate anything meaningful
                        klee_saturate = self.klee_saturated(klee_i)
                    
                    kill(proc.pid, signal.SIGINT)
                    time.sleep(10) # Might take a long time for KLEE to be killed properly
                    shutil.rmtree(tmp_afl_seed_group_dir)
                    new_covered = self.get_klee_coverage(os.path.join(self.all_output_dir, "klee-"+str(klee_i)))
                    self.coverage_list[time.time()] = new_covered
                    self.write_coverage()

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


        self.afl_progress = {} # Used to store values from plot_data and to determine if AFL has saturated
        self.klee_progress = {} # Used to store values from run.istats and to determine if KLEE has saturated
        self.coverage_list = {}
        self.written_coverage = []

        self.start_time = 0
        """
        os.system("rm -rf /tmp/klee-out")
        os.system("rm -rf /tmp/afl-out")
        """
        
        if self.mode=="timed":
            self.dispatch_method = self._dispatch_timed
        elif self.mode=="coverage":
            self.dispatch_method = self._dispatch_coverage
        elif self.mode=="saturation":
            self.dispatch_method = self._dispatch_saturation
        
        self.PREFIXES = PREFIXES
