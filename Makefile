MAKEFLAGS       += -swr

# Klee variables
KLEE_BUILDDIR   ?= $$HOME/build/klee/Release+Asserts
KLEE_INCLUDES   ?= $$HOME/build/klee/include/
KLEE_LIB_PATH = $(KLEE_BUILDDIR)/lib

# Set some variables to llvm dirs for compilation
CXX				:= clang++-6.0
LLVM_CONFIG     ?= /usr/bin/llvm-config

TARGET          := KTestGenerator  # Name of the target
TARGET          := opt/$(TARGET)         # Put the target in bin/ directory

SOURCES         := $(shell find opt/src -name '*.cpp')
HEADERS         := $(shell find opt/src -name '*.h')

#HELPER_SOURCES  := opt/helper_funcs/buffer_extract.c

# Specific flags needed for compilation
CXXFLAGS		+= -g -fsanitize=address -fno-omit-frame-pointer 
CXXFLAGS        += $(shell $(LLVM_CONFIG) --cxxflags) 
LDFLAGS         := $(shell $(LLVM_CONFIG) --ldflags)
#LDFLAGS         := $(shell $(LLVM_CONFIG) --ldflags)
LDLIBS          := $(shell $(LLVM_CONFIG) --libs)
DEL             := rm -rfv



###################################################################################################################################################
# collection of files

OBJS            := $(SOURCES)
#HELPEROBJS      := $(patsubst %.c,build/%.o, $(HELPER_SOURCES))

###################################################################################################################################################
# end of definitions - start of rules

all: $(TARGET)


ifneq "$(MAKECMDGOALS)" "clean"
ifneq "$(MAKECMDGOALS)" "distclean"
ifneq "$(MAKECMDGOALS)" "edit"
ifneq "$(MAKECMDGOALS)" "test"
#DUMMY           := $(shell mkdir -p build/helper_funcs)
endif
endif
endif
endif


#Delete implicit rules
%: %.c # delete impicit rule
%: %.cpp # delete impicit rule
%.o: %.c # delete impicit rule
%.o: %.cpp # delete impicit rule
%.o: %.asm # delete impicit rule
%.o: %.S # delete impicit rule


$(TARGET): #$(HELPEROBJS)
	@echo "Compiling ..."
	@mkdir -p $$(dirname $(TARGET))
	#$(CXX) $(LDLIBS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(HELPEROBJS) -L$(KLEE_LIB_PATH) -lkleeBasic 
	$(CXX) $(CXXFLAGS) -I$(KLEE_INCLUDES) $(LDLIBS) $(LDFLAGS) -o $(TARGET) $(OBJS) -L$(KLEE_LIB_PATH) -lkleeBasic 


#build/helper_funcs/%.o: helper_funcs/%.c
#	@echo "compiling $< ..."
#	$(CC) $(CFLAGS) -c -o $@ $<

distclean:
	@$(DEL) opt/bin


clean: distclean
	@$(DEL) opt/KTestGenerator

edit:
	$(EDITOR) $(SOURCES)


test:
	@echo "-------------------------------------------------------------------------------"
	@echo "SOURCES=$(SOURCES)"
	@echo "-------------------------------------------------------------------------------"
	@echo "OBJS=$(OBJS)"
	@echo "-------------------------------------------------------------------------------"
	@echo "CXXFLAGS=$(CXXFLAGS)"
	@echo "-------------------------------------------------------------------------------"
	@echo "LDFLAGS=$(LDFLAGS)"
	@echo "-------------------------------------------------------------------------------"

