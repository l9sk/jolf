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
    if (argc<3)
    {
        llvm::errs() << "Usage: KTestGenerator aflinputfile ktestout\n";
        exit(-1);
    }
    assert(kTest_getCurrentVersion() == 3);

    std::string AFLInputFile = argv[1];
    
    std::string KTestOut = argv[2];

    std::string ArgType = "file";

    std::string AFLObject = "dummy.bc";


    size_t inputSize;
    int argInd;
    KTestObject* obj;
    int *dum;
    
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
    KTest* newKTest = (KTest*)calloc(1, sizeof(KTest));
    if(!newKTest) {
        llvm::errs() << "Can't allocate memory";
        return -1;
    }

    newKTest->version = kTest_getCurrentVersion();

    /* Read the input file into buffer */
    std::string inputBuffer;
    {
        std::ifstream instream_input(AFLInputFile);
        std::stringstream input_stream;
        input_stream << instream_input.rdbuf();
        inputBuffer = input_stream.str();
    }
    
    inputSize = inputBuffer.size();
    
    //std::string inputStat = "abs";
    std::string inputStat = "\xff\xff\xff\xff\xff\xff\xff\xff\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    
    /* Now say what the arguments to KLEE should be */
    /* dummy.bc A --sym-files 1 1 <file_size> --sym-stdin <stdin_size>  */
    newKTest->numArgs = 8;

    newKTest->args = (char**)calloc(newKTest->numArgs, sizeof(char*));
    if(!newKTest->args)
        goto error;
    
    argInd = 0;

    newKTest->args[argInd] = (char*)calloc(1, AFLObject.size()+1); // args[0]
    if(!newKTest->args[argInd])
        goto error;

    strcpy(newKTest->args[argInd], AFLObject.c_str());
    llvm::outs() << newKTest->args[argInd] << " ";
    argInd++;

    newKTest->args[argInd] = (char*)calloc(1, strlen("A")+1); // args[1]
    if(!newKTest->args[argInd])
        goto error;

    strcpy(newKTest->args[argInd], "A");
    llvm::outs() << newKTest->args[argInd] << " ";
    argInd++;
    
    newKTest->args[argInd] = (char*)calloc(1, strlen("--sym-files")+1); // args[2]
    if(!newKTest->args[argInd])
        goto error;

    strcpy(newKTest->args[argInd], "--sym-files");
    llvm::outs() << newKTest->args[argInd] << " ";
    argInd++;
    
    newKTest->args[argInd] = (char*)calloc(1, strlen("1")+1); // args[3]
    if(!newKTest->args[argInd])
        goto error;

    strcpy(newKTest->args[argInd], "1");
    llvm::outs() << newKTest->args[argInd] << " ";
    argInd++;
    
    newKTest->args[argInd] = (char*)calloc(1, strlen("1")+1); // args[4]
    if(!newKTest->args[argInd])
        goto error;

    strcpy(newKTest->args[argInd], "1");
    llvm::outs() << newKTest->args[argInd] << " ";
    argInd++;
   
    newKTest->args[argInd] = (char*)calloc(1, std::to_string(inputSize).size()+1); // args[5]
    if(!newKTest->args[argInd])
        goto error;

    strcpy(newKTest->args[argInd], std::to_string(inputSize).c_str());
    llvm::outs() << newKTest->args[argInd] << " ";
    argInd++;

    newKTest->args[argInd] = (char*)calloc(1, strlen("--sym-stdin")+1); // args[6]
    if(!newKTest->args[argInd])
        goto error;

    strcpy(newKTest->args[argInd], "--sym-stdin");
    llvm::outs() << newKTest->args[argInd] << " ";
    argInd++;
    
    newKTest->args[argInd] = (char*)calloc(1, std::to_string(inputSize).size()+1); // args[7]
    if(!newKTest->args[argInd])
        goto error;

    strcpy(newKTest->args[argInd], std::to_string(inputSize).c_str());
    llvm::outs() << newKTest->args[argInd] << "\n";
    argInd++;
    
    llvm::outs() << argInd << " arguments written\n";
   
    /* These are zero because the input is either stdin or file */
    /* No, actually they are zero because I don't know what the heck they do*/
    newKTest->symArgvs = 0;
    newKTest->symArgvLen = 0;
    
    /* Allocate array for KTestObjects */
    /* Objects: A-data, A-data-stat, stdin, stdin-stat, model_version */
    newKTest->numObjects = 5; 

    newKTest->objects = (KTestObject*)calloc(5, sizeof(*newKTest->objects));
    if(!newKTest->objects)
        goto error;

    obj = newKTest->objects;
    llvm::outs() << "\nWriting objects\n";

    /* Finally add the data from AFL testcases */
    llvm::outs() << "object 0: \n";
    obj->name = (char*)calloc(1, strlen("A-data")+1);
    if(!obj->name)
        goto error;
    strcpy(obj->name, "A-data");
    llvm::outs() << "\tname: " << obj->name << "\n";
    obj->numBytes = inputSize;
    llvm::outs() << "\tnumBytes: " << obj->numBytes << "\n";
    obj->bytes = (unsigned char*)calloc(1, obj->numBytes+1);
    if(!obj->bytes)
        goto error;
    memcpy(obj->bytes, const_cast<char*>(inputBuffer.c_str()), obj->numBytes);
    obj->bytes[obj->numBytes] = 0;
    llvm::outs() << "\tbytes: " << obj->bytes << "\n";
    obj++;

    obj->name = (char*)calloc(1, strlen("A-data-stat")+1);
    llvm::outs() << "object 1: \n";
    if(!obj->name)
        goto error;
    strcpy(obj->name, "A-data-stat");
    llvm::outs() << "\tname: " << obj->name << "\n";
    obj->numBytes = 144;
    llvm::outs() << "\tnumBytes: " << obj->numBytes << "\n";
    obj->bytes = (unsigned char*)calloc(1, 144);
    if(!obj->bytes)
        goto error;
    memcpy(obj->bytes, inputStat.c_str(), inputStat.size());
    // obj->bytes[obj->numBytes] = 0;
    llvm::outs() << "\tbytes: " << obj->bytes << "\n";
    obj++;
    
    llvm::outs() << "object 2: \n";
    obj->name = (char*)calloc(1, strlen("stdin")+1);
    if(!obj->name)
        goto error;
    strcpy(obj->name, "stdin");
    llvm::outs() << "\tname: " << obj->name << "\n";
    obj->numBytes = inputSize;
    llvm::outs() << "\tnumBytes: " << obj->numBytes << "\n";
    obj->bytes = (unsigned char*)calloc(1, obj->numBytes+1);
    if(!obj->bytes)
        goto error;
    memcpy(obj->bytes, const_cast<char*>(inputBuffer.c_str()), obj->numBytes);
    obj->bytes[obj->numBytes] = 0;
    llvm::outs() << "\tbytes: " << obj->bytes << "\n";
    obj++;

    obj->name = (char*)calloc(1, strlen("stdin-stat")+1);
    llvm::outs() << "object 3: \n";
    if(!obj->name)
        goto error;
    strcpy(obj->name, "stdin-stat");
    llvm::outs() << "\tname: " << obj->name << "\n";
    obj->numBytes = 144;
    llvm::outs() << "\tnumBytes: " << obj->numBytes << "\n";
    obj->bytes = (unsigned char*)calloc(1, 144);
    if(!obj->bytes)
        goto error;
    memcpy(obj->bytes, inputStat.c_str(), inputStat.size());
    // obj->bytes[obj->numBytes] = 0;
    llvm::outs() << "\tbytes: " << obj->bytes << "\n";
    obj++;
    
    obj->name = (char*)calloc(1, strlen("model_version")+1);
    llvm::outs() << "object 4: \n";
    if(!obj->name)
        goto error;
    strcpy(obj->name, "model_version");
    llvm::outs() << "\tname: " << obj->name << "\n";
    obj->numBytes = 4;
    llvm::outs() << "\tnumBytes: " << obj->numBytes << "\n";
    obj->bytes = (unsigned char*)calloc(1, sizeof(int));
    if(!obj->bytes)
        goto error;
    dum = (int*)malloc(sizeof(int));
    *dum = 1;
    memcpy(obj->bytes, dum, obj->numBytes);
    free(dum);
    llvm::outs() << "\tbytes: " << obj->bytes << "\n";
    
    if(!kTest_toFile(newKTest, const_cast<char*>(KTestOut.c_str())))
        goto error;
    kTest_free(newKTest);
    llvm::outs() << "Status: Generated KTest file: " << KTestOut << "\n"; 

    return 0;
  error:
    llvm::outs() << "Encountered some error. Exiting without writing to file";
    kTest_free(newKTest);
    return -1;
}

