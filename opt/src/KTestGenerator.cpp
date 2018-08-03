#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/Pass.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>

#include <fstream>
#include <sstream>
#include <list>

#include <klee/Internal/ADT/KTest.h>


#define MIN(a,b)   (((a) < (b)) ? (a) : (b))

using namespace std;
using namespace llvm;
int main(int argc, char* argv[])
{
    if (argc<5)
    {
        llvm::errs() << "Usage: generator.o aflinputfile ktestout argtype aflobject concrete-args\n";
        exit(-1);
    }
    assert(kTest_getCurrentVersion() == 3);

    std::string AFLInputFile = argv[1];
    
    std::string KTestOut = argv[2];

    std::string ArgType = argv[3];

    std::string AFLObject = argv[4];

    std::vector<std::string> ConcreteArgs = {};
    
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
    
    /* Did we pass any (command-line) arguments? */
    if(argc>5)
    {
        for(int i=5; i<argc; i++)
        {
            ConcreteArgs.push_back(argv[i]);
        }
    }
    
    /* Create and initialize the ktest object */
    KTest* newKTest = (KTest*)malloc(sizeof(KTest));

    /* These are zero because the input is either stdin or file */
    /* No, actually they are zero because I don't know what the heck they do*/
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
    
    /* Now say what the arguments to KLEE should be */
    if(ArgType=="stdin")
    {
        newKTest->numArgs = 3;
    }
    else
    {
        newKTest->numArgs =5;
    }

    if(ConcreteArgs.size()>0)
    {
        /* "--sym-args 0 <max-args> <max-arg-len>" */
        newKTest->numArgs += 4;
    }

    int argInd = 0;

    newKTest->args = (char**)malloc(sizeof(char*) * newKTest->numArgs);
    newKTest->args[argInd] = (char*)malloc(AFLObject.size());
    strcpy(newKTest->args[argInd], AFLObject.c_str());
    newKTest->args[argInd][AFLObject.size()] = 0;
    
    argInd++;

    /* Now again the concrete arguments */
    if(ConcreteArgs.size()>0)
    {
        newKTest->args[argInd] = (char*)malloc(strlen("--sym-args"));
        strcpy(newKTest->args[argInd], "--sym-args");
        argInd++;
        newKTest->args[argInd] = (char*)malloc(strlen("0"));
        strcpy(newKTest->args[argInd], "0");
        argInd++;
        newKTest->args[argInd] = (char*)malloc(to_string(ConcreteArgs.size()).size());
        strcpy(newKTest->args[argInd], to_string(ConcreteArgs.size()).c_str());
        argInd++;
        /* How long can each argument be? This long */
        newKTest->args[argInd] = (char*)malloc(strlen("5"));
        strcpy(newKTest->args[argInd], "5");
        argInd++;
    }

    if(ArgType=="stdin")
    {    
        newKTest->args[argInd] = (char*)malloc(strlen("--sym-stdin"));
        strcpy(newKTest->args[argInd], "--sym-stdin");
        argInd++;
    }
    else
    {
        /* It will always only be one file, called "A" */
        newKTest->args[argInd] = (char*)malloc(strlen("A"));
        strcpy(newKTest->args[argInd], "A");
        argInd++;
        /* Then fill the file A */
        newKTest->args[argInd] = (char*)malloc(strlen("--sym-files"));
        strcpy(newKTest->args[argInd], "--sym-files");
        argInd++;
        newKTest->args[argInd] = (char*)malloc(strlen("1"));
        strcpy(newKTest->args[argInd], "1");
        argInd++;
    }

    newKTest->args[argInd] = (char*)malloc(ss.str().size()); // ss is the size, not the string
    strcpy(newKTest->args[argInd], ss.str().c_str());
    argInd++;
    
    /* Allocate array for KTestObjects */
    newKTest->numObjects = argInd; // command-line args, data, stat and model_version
    if(ConcreteArgs.size()>0)
    {
        /* Need to add an "n_args" field */
        newKTest->numObjects++;
    }

    newKTest->objects = (KTestObject*)malloc(sizeof(KTestObject) * newKTest->numObjects);
    
    KTestObject* obj = newKTest->objects;

    if(ConcreteArgs.size()>0)
    {
        obj->name = (char*)malloc(strlen("n_args")+1);
        strcpy(obj->name, "n_args");
        obj->numBytes = 4;
        obj->bytes = (unsigned char*)malloc(sizeof(int));
        int *d;
        *d = ConcreteArgs.size();
        memcpy(obj->bytes, d, obj->numBytes);

        obj++;
        for(int i=0; i<int(ConcreteArgs.size()); i++)
        {
            obj->name = (char*)malloc(strlen("arg0")+1);
            char *argname = (char*)malloc(strlen("arg")+1);
            strcpy(argname, "arg");
            strcpy(obj->name, strcat(argname, to_string(i).c_str()));
            obj->numBytes = strlen(ConcreteArgs.at(i).c_str());
            obj->bytes = (unsigned char*)malloc(strlen(ConcreteArgs.at(i).c_str()));
            memcpy(obj->bytes, ConcreteArgs.at(i).c_str(), obj->numBytes);
            obj++;
        }
    }

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

    obj++;

    obj->name = (char*)malloc(strlen("model_version")+1);
    strcpy(obj->name, "model_version");
    obj->numBytes = 4;
    obj->bytes = (unsigned char*)malloc(sizeof(int));
    int *dum = (int*)malloc(sizeof(int));
    *dum = 1;
    memcpy(obj->bytes, dum, obj->numBytes);
    
    /* Output the KTest to file */
    if(!kTest_toFile(newKTest, KTestOut.c_str()))
        llvm::errs() << "Unspecified error in kTest_toFile!\n";

    kTest_free(newKTest);
    llvm::outs() << "Status: Generated KTest file: " << KTestOut << "\n"; 

    return 0;
}

