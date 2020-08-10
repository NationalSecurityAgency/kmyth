# Makefile for kmyth logging utility

# Specify source code path
PREFIX = .#                              Makefile @ src root directory

# Specify fundamental compiler parameters
CC = gcc#                                invoke gcc compiler
CC += -std=c11#                          use C11 standard

# Specify debugging information options
DEBUG = -g#                              produce debugging information

# Specify gcc flags for object compilation step
CFLAGS_OBJ = -Wall#                      enable all warnings
CFLAGS_OBJ += -c#                        compile, but do not link
CFLAGS_OBJ += $(DEBUG)#                  debugging options (above)
CFLAGS_OBJ += -D_GNU_SOURCE#             GNU/LINUX platform
CFLAGS_OBJ += -fPIC#                     generate position independent code

# Specify gcc flags for shared library compilation step
CFLAGS_LIB = -shared#                    compile/link shared library

# Specify top-level source and target directories for build process
INCLUDE_DIR = include
OBJ_DIR = obj
LIB_DIR = lib
SRC_DIR = src
DOC_DIR = doc

# Specify source/header files
KMYTH_LOG_SOURCE = $(SRC_DIR)/kmyth_log.c
KMYTH_LOG_HEADER = $(INCLUDE_DIR)/kmyth_log.h
KMYTH_LOG_OBJECT = $(OBJ_DIR)/kmyth_log.o

# Specify path for output (shared library) 
LIB_NAME = "kmythlogger"
LIB_SONAME = lib$(LIB_NAME).so
LIB_LOCAL_DEST = $(LIB_DIR)/$(LIB_SONAME)
LIB_INSTALL_DIR = $(MY_KMYTH_LOG_DIR)

all: pre libkmythlogger

libkmythlogger: $(KMYTH_LOG_OBJECT)
	$(CC) $(CFLAGS_LIB) $(KMYTH_LOG_OBJECT) -o $(LIB_LOCAL_DEST)

pre:
	indent -bli0 -bap -bad -sob -cli0 -npcs -nbc -bls -blf -lp -ip0 -ts2 -nut -npsl -bbo -l80 src/*.c
	indent -bli0 -bap -bad -sob -cli0 -npcs -nbc -bls -blf -lp -ip0 -ts2 -nut -npsl -bbo -l80 include/*.h
	rm -f src/*.c~
	rm -f include/*.h~
	mkdir -p $(LIB_DIR)
	mkdir -p $(OBJ_DIR)
	mkdir -p $(DOC_DIR)

doc: $(KMYTH_LOG_HEADER) $(KMYTH_LOG_SOURCE) Doxyfile
	doxygen Doxyfile

$(KMYTH_LOG_OBJECT): $(KMYTH_LOG_SOURCE) $(KMYTH_LOG_HEADER)
	$(CC) $(CFLAGS_OBJ) -I$(INCLUDE_DIR) $< -o $@

install:
	mkdir -p $(LIB_INSTALL_DIR)/include
	mkdir -p $(LIB_INSTALL_DIR)/lib
	cp $(KMYTH_LOG_HEADER) $(LIB_INSTALL_DIR)/include
	cp $(LIB_LOCAL_DEST) $(LIB_INSTALL_DIR)/lib
	ldconfig -n $(LIB_INSTALL_DIR)/lib

.PHONY: clean
clean:
	rm -rf $(PREFIX)/$(LIB_DIR)
	rm -rf $(PREFIX)/$(OBJ_DIR)
	rm -rf $(PREFIX)/$(DOC_DIR)
