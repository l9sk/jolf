#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/Pass.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>

#include <fstream>
#include <sstream>

#include <klee/Internal/ADT/KTest.h>

//#include "Compat.h"
//#include "TypeHelper.h"

#define MIN(a,b)   (((a) < (b)) ? (a) : (b))

/**
 * Helper pass to extract a ktest file from an inputfile and the functionname
 */
using namespace std;
using namespace llvm;
	/*
    static llvm::cl::opt<std::string> KTestFunction(
		"ktestfunction",
		llvm::cl::desc("Name of the function the ktest should be generated for"));
    */
	
    /*
    static llvm::cl::opt<std::string> AFLInputFile(
		"aflinputfile",
		llvm::cl::desc("Path to the fuzzer-input file containing the data"));

	static llvm::cl::opt<std::string> KTestOut(
		"ktestout",
		llvm::cl::desc("Where to save the ktest file"));

	static llvm::cl::opt<std::string> ArgType(
		"argtype",
		llvm::cl::desc("Type or mode of input: file or stdin"));
	
	static llvm::cl::opt<std::string> AFLObject(
		"aflobject",
		llvm::cl::desc("Object (binary or bitcode) used for fuzzing"));
    */
    /*
    static llvm::cl::list<std::string> KleeArgs(
		"kleeargs",
		llvm::cl::desc("KleeArgs that should be saved in the ktest file"));
    */

	
    /*
    struct KTestGenerator : public llvm::ModulePass
	{
		static char ID; 

		KTestGenerator() : llvm::ModulePass(ID) { };

        //llvm::outs() << "Creating file...";
		bool runOnModule(llvm::Module &M) override;
	};
    */


//bool KTestGenerator::runOnModule(llvm::Module &M)
int main(int argc, char* argv[])
{
    if (argc!=5)
    {
        llvm::errs() << "Usage: generator.o aflinputfile ktestout argtype aflobject\n";
        exit(-1);
    }
    assert(kTest_getCurrentVersion() == 3);

    std::string AFLInputFile = argv[1];
    
    std::string KTestOut = argv[2];

    std::string ArgType = argv[3];

    std::string AFLObject = argv[4];
    
    /* Check all the command line arguments */
    if(AFLInputFile.empty())
    {
        llvm::errs() << "Error: -aflinputfile parameter is needed!\n";
        return -1;
    }
    if(KTestOut.empty())
    {
        llvm::errs() << "Error: -ktestout parameter is needed!\n";
        return -1;
    }
    if(ArgType.empty() || (ArgType!="file" && ArgType!="stdin"))
    {
        llvm::errs() << "Error: -argtype cannot be empty and needs to  be file or stdin\n";
        return -1;
    }
    if(AFLObject.empty())
    {
        llvm::errs() << "Error: -aflobject cannot be empty!\n";
        return -1;
    }

    /* Create and initialize the ktest object */
    KTest* newKTest = (KTest*)malloc(sizeof(KTest));

    /* These are zero because the input is either stdin or file */
    newKTest->symArgvs = 0;
    newKTest->symArgvLen = 0;
    
    newKTest->version = kTest_getCurrentVersion();

    /* Read the input file into buffer */
    std::string inputBuffer;
    {
        std::ifstream instream_input(AFLInputFile);
        std::stringstream input_stream;
        input_stream << instream_input.rdbuf();
        inputBuffer = input_stream.str();
    }
    
    size_t inputSize = inputBuffer.size();
    std::stringstream ss;
    ss << inputSize;
    
    //std::string inputStat = "abs";
    std::string inputStat = "\xff\xff\xff\xff\xff\xff\xff\xff\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    size_t inputStatSize = strlen(inputStat.c_str());
    
    llvm::outs() << "Status: Read input data\n\tData: " << inputSize << "\n\tStat: " << inputStatSize << "\n"; 
    
    /* Now say what the arguments to KLEE should be */
    if(ArgType=="stdin")
    {
        newKTest->numArgs = 3;
    }
    else
    {
        newKTest->numArgs =5;
    }

    newKTest->args = (char**)malloc(sizeof(char*) * newKTest->numArgs);
    newKTest->args[0] = (char*)malloc(AFLObject.size());
    strcpy(newKTest->args[0], AFLObject.c_str());
    newKTest->args[0][AFLObject.size()] = 0;
    
    if(ArgType=="stdin")
    {    
        newKTest->args[1] = (char*)malloc(strlen("--sym-stdin"));
        strcpy(newKTest->args[1], "--sym-stdin");
    }
    else
    {
        /* It will always only be one file, called "A" */
        newKTest->args[1] = (char*)malloc(strlen("A"));
        strcpy(newKTest->args[1], "A");
        /* Then fill the file A */
        newKTest->args[2] = (char*)malloc(strlen("--sym-files"));
        strcpy(newKTest->args[2], "--sym-files");
        newKTest->args[3] = (char*)malloc(strlen("1"));
        strcpy(newKTest->args[3], "1");
    }

    newKTest->args[newKTest->numArgs-1] = (char*)malloc(ss.str().size());
    strcpy(newKTest->args[newKTest->numArgs-1], ss.str().c_str());
    
    llvm::outs() << "Status: Set argv\n"; 

    /* Allocate array for KTestObjects */
    newKTest->numObjects = 3; // data, stat and model_version
    newKTest->objects = (KTestObject*)malloc(sizeof(KTestObject) * newKTest->numObjects);
    
    KTestObject* obj = newKTest->objects;

    if(ArgType=="stdin")
    {
        obj->name = (char*)malloc(5+1);
        strcpy(obj->name, "stdin");
        //obj->name[5]=0;
    }
    else if(ArgType=="file")
    {
        obj->name = (char*)malloc(6+1);
        strcpy(obj->name, "A-data");
        //obj->name[6]=0;
    }
    obj->numBytes = inputSize;
    
    obj->bytes = (unsigned char*)malloc(obj->numBytes);
    memcpy(obj->bytes, const_cast<char*>(inputBuffer.c_str()), obj->numBytes);
    llvm::outs() << "Status: Set data object\n"; 
    
    obj++;

    if(ArgType=="stdin")
    {
        obj->name = (char*)malloc(10+1);
        strcpy(obj->name, "stdin-stat");
        obj->name[10]=0;
    }
    else if(ArgType=="file")
    {
        obj->name = (char*)malloc(11+1);
        strcpy(obj->name, "A-data-stat");
        obj->name[11]=0;
    }
    obj->numBytes = 144;
    
    obj->bytes = (unsigned char*)malloc(obj->numBytes);
    memcpy(obj->bytes, const_cast<char*>(inputStat.c_str()), obj->numBytes);
    llvm::outs() << "Status: Set stat object\n";

    obj++;

    obj->name = (char*)malloc(strlen("model_version")+1);
    strcpy(obj->name, "model_version");
    obj->numBytes = 4;
    obj->bytes = (unsigned char*)malloc(sizeof(int));
    int *dum = (int*)malloc(sizeof(int));
    *dum = 1;
    memcpy(obj->bytes, dum, obj->numBytes);
    llvm::outs() << "Status: Set model_version\n";
    
    /* Output the KTest to file */
    if(!kTest_toFile(newKTest, KTestOut.c_str()))
        llvm::errs() << "Unspecified error in kTest_toFile!\n";

    llvm::outs() << "Freeing newKTest\n";
    kTest_free(newKTest);
    llvm::outs() << "Status: Generated KTest file\n"; 

    return 0;
}

//char KTestGenerator::ID = 0; /* Value is ignored */

//static llvm::RegisterPass<KTestGenerator> X(
//	"generate-ktest", "Create a ktest file from an AFL input",
//	false, /* Does not only look at CFG */
//	true   /* Is only analysis */
//	);

