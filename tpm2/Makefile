# Makefile for KMYTH using TPM 2.0

#====================== BUILD ENVIRONMENT DEFINITION ==========================

# Specify top-level directories for build process
SRC_DIR ?= src
INC_DIR ?= include
OBJ_DIR ?= obj
BIN_DIR ?= bin
DOC_DIR ?= doc
LIB_DIR ?= lib
LOGGER_DIR ?= logger

# Specify kmyth applications (main) directories/files
MAIN_SRC_DIR = $(SRC_DIR)/main
MAIN_SOURCES = $(wildcard $(MAIN_SRC_DIR)/*.c)
MAIN_OBJ_DIR = $(OBJ_DIR)/main
MAIN_OBJECTS = $(subst $(MAIN_SRC_DIR), \
							         $(MAIN_OBJ_DIR), \
											 $(MAIN_SOURCES:%.c=%.o))

# Specify Kmyth general utility directories/files
UTIL_SRC_DIR = $(SRC_DIR)/util
UTIL_SOURCES = $(wildcard $(UTIL_SRC_DIR)/*.c)
UTIL_INC_DIR = $(INC_DIR)/util
UTIL_OBJ_DIR = $(OBJ_DIR)/util
UTIL_OBJECTS = $(subst $(UTIL_SRC_DIR), \
							         $(UTIL_OBJ_DIR), \
											 $(UTIL_SOURCES:%.c=%.o))

# Specify Kmyth cipher utility directories/files
CIPHER_SRC_DIR = $(SRC_DIR)/cipher
CIPHER_SOURCES = $(wildcard $(CIPHER_SRC_DIR)/*.c)
CIPHER_INC_DIR = $(INC_DIR)/cipher
CIPHER_OBJ_DIR = $(OBJ_DIR)/cipher
CIPHER_OBJECTS = $(subst $(CIPHER_SRC_DIR), \
								         $(CIPHER_OBJ_DIR), \
												 $(CIPHER_SOURCES:%.c=%.o))

# Specify Kmyth TPM 2.0 utility directories/files
TPM_SRC_DIR = $(SRC_DIR)/tpm
TPM_SOURCES = $(wildcard $(TPM_SRC_DIR)/*.c)
TPM_INC_DIR = $(INC_DIR)/tpm
TPM_OBJ_DIR = $(OBJ_DIR)/tpm
TPM_OBJECTS = $(subst $(TPM_SRC_DIR), \
							        $(TPM_OBJ_DIR), \
											$(TPM_SOURCES:%.c=%.o))

# Specify Kmyth header files
HEADER_FILES = $(wildcard $(INC_DIR)/*.h)
HEADER_FILES += $(wildcard $(CIPHER_INC_DIR)/*.h)
HEADER_FILES += $(wildcard $(TPM_INC_DIR)/*.h)

# Consolidate created directories to simplify mkdir call for 'pre' target
OBJECT_DIRS = $(MAIN_OBJ_DIR)
OBJECT_DIRS += $(UTIL_OBJ_DIR)
OBJECT_DIRS += $(CIPHER_OBJ_DIR)
OBJECT_DIRS += $(TPM_OBJ_DIR)
OBJECT_DIRS += $(LOGGER_OBJ_DIR)

# Specify Kmyth logger shared library directories/files
LOGGER_SRC_DIR = $(LOGGER_DIR)/src
LOGGER_SOURCES = $(wildcard $(LOGGER_SRC_DIR)/*.c)
LOGGER_INC_DIR = $(LOGGER_DIR)/include
LOGGER_OBJ_DIR = $(LOGGER_DIR)/obj
LOGGER_OBJECTS = $(subst $(LOGGER_SRC_DIR), \
								         $(LOGGER_OBJ_DIR), \
												 $(LOGGER_SOURCES:%.c=%.o))
LOGGER_HEADER_FILES = $(wildcard $(LOGGER_INC_DIR)/*.h)

# Specify path for logger output of shared library
KMYTH_LIB_NAME = kmyth
KMYTH_LIB_SONAME = lib$(KMYTH_LIB_NAME).so
KMYTH_LIB_LOCAL_DEST = $(LIB_DIR)/$(KMYTH_LIB_SONAME)

#================== END BUILD ENVIRONMENT DEFINITION =========================

#==================== TEST ENVIRONMENT DEFINITION ============================

# Specify top-level unit testing directory structure
TEST_DIR ?= test
TEST_SRC_DIR ?= $(TEST_DIR)/src
TEST_INC_DIR ?= $(TEST_DIR)/include
TEST_OBJ_DIR ?= $(TEST_DIR)/obj

# Specify 'testrunner' (kmyth-test) files
TESTRUNNER_SOURCES = $(TEST_DIR)/kmyth-test.c
TESTRUNNER_OBJECTS = $(TEST_OBJ_DIR)/kmyth-test.o

# Specify directories/files supporting kmyth application (main) testing
TEST_MAIN_SRC_DIR = $(TEST_SRC_DIR)/main
TEST_MAIN_SOURCES = $(wildcard $(TEST_MAIN_SRC_DIR)/*.c)
TEST_MAIN_OBJ_DIR = $(TEST_OBJ_DIR)/main
TEST_MAIN_OBJECTS = $(subst $(TEST_MAIN_SRC_DIR), \
										        $(TEST_MAIN_OBJ_DIR), \
														$(TEST_MAIN_SOURCES:%.c=%.o))

# Specify directories/files supporting kmyth general utility (util) testing
TEST_UTIL_SRC_DIR = $(TEST_SRC_DIR)/util
TEST_UTIL_SOURCES = $(wildcard $(TEST_UTIL_SRC_DIR)/*.c)
TEST_UTIL_INC_DIR = $(TEST_INC_DIR)/util
TEST_UTIL_OBJ_DIR = $(TEST_OBJ_DIR)/util
TEST_UTIL_OBJECTS = $(subst $(TEST_UTIL_SRC_DIR), \
										        $(TEST_UTIL_OBJ_DIR), \
														$(TEST_UTIL_SOURCES:%.c=%.o))

# Specify directories/files supporting kmyth TPM utility testing
TEST_TPM_SRC_DIR = $(TEST_SRC_DIR)/tpm
TEST_TPM_SOURCES = $(wildcard $(TEST_TPM_SRC_DIR)/*.c)
TEST_TPM_INC_DIR = $(TEST_INC_DIR)/tpm
TEST_TPM_OBJ_DIR = $(TEST_OBJ_DIR)/tpm
TEST_TPM_OBJECTS = $(subst $(TEST_TPM_SRC_DIR), \
									         $(TEST_TPM_OBJ_DIR), \
													 $(TEST_TPM_SOURCES:%.c=%.o))

# Specify directories/files supporting kmyth cipher utility testing
TEST_CIPHER_SRC_DIR  = $(TEST_SRC_DIR)/cipher
TEST_CIPHER_SOURCES  = $(wildcard $(TEST_CIPHER_SRC_DIR)/*.c)
TEST_CIPHER_INC_DIR = $(TEST_INC_DIR)/cipher
TEST_CIPHER_OBJ_DIR  = $(TEST_OBJ_DIR)/cipher
TEST_CIPHER_OBJECTS  = $(subst $(TEST_CIPHER_SRC_DIR), \
											         $(TEST_CIPHER_OBJ_DIR), \
															 $(TEST_CIPHER_SOURCES:%.c=%.o))

# Create consolidated list of test source files
TEST_SOURCES = $(TESTRUNNER_SOURCES)
TEST_SOURCES += $(TEST_MAIN_SOURCES)
TEST_SOURCES += $(TEST_UTIL_SOURCES)
TEST_SOURCES += $(TEST_TPM_SOURCES)
TEST_SOURCES += $(TEST_CIPHER_SOURCES)

# Create consolidated list of test object files
TEST_OBJECTS = $(TESTRUNNER_OBJECTS)
TEST_OBJECTS += $(TEST_MAIN_OBJECTS)
TEST_OBJECTS += $(TEST_UTIL_OBJECTS)
TEST_OBJECTS += $(TEST_TPM_OBJECTS)
TEST_OBJECTS += $(TEST_CIPHER_OBJECTS)

# Consolidate created directories to simplify mkdir call for 'pretest' target
TEST_OBJECT_DIRS = $(TEST_MAIN_OBJ_DIR)
TEST_OBJECT_DIRS += $(TEST_UTIL_OBJ_DIR)
TEST_OBJECT_DIRS += $(TEST_TPM_OBJ_DIR)
TEST_OBJECT_DIRS += $(TEST_CIPHER_OBJ_DIR)

#===================== END TEST ENVIRONMENT DEFINITION =======================

#========================== TOOL CONFIGURATION ===============================

# Specify fundamental compiler parameters
CC = gcc#                                invoke gcc compiler
CC += -std=c11#                          use C11 standard
DEBUG = -g#                              produce debugging information
PREFIX ?= /usr/local#                    set source installation path 

# Specify Kmyth 'include directory' compiler option flags
KMYTH_INCLUDE_FLAGS = -I$(INC_DIR)
KMYTH_INCLUDE_FLAGS += -I$(UTIL_INC_DIR)
KMYTH_INCLUDE_FLAGS += -I$(CIPHER_INC_DIR)
KMYTH_INCLUDE_FLAGS += -I$(TPM_INC_DIR)
KMYTH_INCLUDE_FLAGS += -I$(LOGGER_INC_DIR)

# Specify Kmyth unit test 'include directory' compiler option flags
TEST_INCLUDE_FLAGS = -I$(TEST_INC_DIR)
TEST_INCLUDE_FLAGS += -I$(TEST_UTIL_INC_DIR)
TEST_INCLUDE_FLAGS += -I$(TEST_CIPHER_INC_DIR)
TEST_INCLUDE_FLAGS += -I$(TEST_TPM_INC_DIR)

# Specify shared library dependencies
LDLIBS = -ltss2-tcti-device#             TCTI for hardware TPM 2.0
LDLIBS += -ltss2-tcti-mssim#             TCTI for TPM 2.0 simulator
LDLIBS += -ltss2-tcti-tabrmd#            TPM 2.0 Access Broker/Resource Mgr.
LDLIBS += -ltss2-mu#                     TPM 2.0 marshal/unmarshal
LDLIBS += -ltss2-sys#                    TPM 2.0 SAPI
LDLIBS += -ltss2-rc#                     TPM 2.0 Return Code Utilities
LDLIBS += -lssl#                         OpenSSL
LDLIBS += -lcrypto#                      libcrypto
LDLIBS += -lkmip#                        libkmip

# Specify basic set of required compiler flags
CFLAGS = -Wall#                          enable all warnings
CFLAGS += -c#                            compile, but do not link
CFLAGS += $(DEBUG)#                      debugging options (above)
CFLAGS += -D_GNU_SOURCE#                 GNU/LINUX platform
CFLAGS += -fPIC#                         Generate position independent code

# Specify compiler flags for building kmyth applications that use logger library
KMYTH_CFLAGS = $(CFLAGS)
KMYTH_CFLAGS += -I$(LOGGER_DIR)/include# kmyth logging utility header files

# Specify flags for the SO build of the logger
LOGGER_CFLAGS = $(CFLAGS)

SOFLAGS = -shared#                       compile/link shared library
SOFLAGS += -fPIC#

# Specify linker flags
LDFLAGS += -Llib#                        libkmyth
LDFLAGS += -Wl,-rpath=lib#               runtime path for libkmyth.soa

# Specify indentation options
INDENT_OPTS = -bli0#                     indent braces zero spaces
INDENT_OPTS += -bap#                     blank lines after procedure bodies
INDENT_OPTS += -bad#                     blank lines after declarations
INDENT_OPTS += -sob#                     swallow optional blank lines
INDENT_OPTS += -cli0#                    case label indent of zero spaces
INDENT_OPTS += -npcs#                    no space after function in calls
INDENT_OPTS += -nbc#                     don't force newlines after commas
INDENT_OPTS += -bls#                     put braces on line after struct decl
INDENT_OPTS += -blf#                     put braces on line after func def
INDENT_OPTS += -lp#                      align continued lines at parentheses
INDENT_OPTS += -ip0#                     indent parameter types zero spaces
INDENT_OPTS += -ts2#                     set tab size to two spaces
INDENT_OPTS += -nut#                     use spaces instead of tabs
INDENT_OPTS += -npsl#                    type of proc on same line as name
INDENT_OPTS += -bbo#                     prefer break before boolean operator
INDENT_OPTS += -l80#                     max non-comment line length is 80

#====================== END TOOL CONFIGURATION ===============================

#======================= TARGET CONFIGURATION ================================

.PHONY: all
all: pre kmyth-lib kmyth-seal kmyth-unseal kmyth-getkey

kmyth-lib: $(LOGGER_OBJECTS) $(UTIL_OBJECTS) $(CIPHER_OBJECTS) $(TPM_OBJECTS)
	$(CC) $(SOFLAGS) $(LOGGER_OBJECTS) $(UTIL_OBJECTS) $(CIPHER_OBJECTS) \
	$(TPM_OBJECTS) -o $(KMYTH_LIB_LOCAL_DEST) $(LDLIBS)

kmyth-seal: $(MAIN_OBJ_DIR)/seal.o
	$(CC) $(MAIN_OBJ_DIR)/seal.o -o $(BIN_DIR)/kmyth-seal $(LDFLAGS) $(LDLIBS) \
	-lkmyth

kmyth-unseal: $(MAIN_OBJ_DIR)/unseal.o
	$(CC) $(MAIN_OBJ_DIR)/unseal.o -o $(BIN_DIR)/kmyth-unseal $(LDFLAGS) \
	$(LDLIBS) -lkmyth

kmyth-getkey: $(MAIN_OBJ_DIR)/getkey.o
	$(CC) $(MAIN_OBJ_DIR)/getkey.o -o $(BIN_DIR)/kmyth-getkey $(LDFLAGS) \
	$(LDLIBS) -lkmyth

$(LOGGER_OBJECTS): $(LOGGER_SOURCES) $(LOGGER_HEADER_FILES)
	$(CC) $(LOGGER_CFLAGS) -I$(LOGGER_INC_DIR) $< -o $@

$(MAIN_OBJ_DIR)/%.o: $(MAIN_SRC_DIR)/%.c | $(MAIN_OBJ_DIR) 
	$(CC) $(KMYTH_CFLAGS) $(KMYTH_INCLUDE_FLAGS) $< -o $@

$(UTIL_OBJ_DIR)/%.o: $(UTIL_SRC_DIR)/%.c \
	                   $(UTIL_INC_DIR)/%.h \
                     | $(UTIL_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) $(KMYTH_INCLUDE_FLAGS) $< -o $@

$(TPM_OBJ_DIR)/%.o: $(TPM_SRC_DIR)/%.c $(TPM_INC_DIR)/%.h | $(TPM_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) $(KMYTH_INCLUDE_FLAGS) $< -o $@

$(CIPHER_OBJ_DIR)/%.o: $(CIPHER_SRC_DIR)/%.c \
	                     $(CIPHER_INC_DIR)/%.h \
                       | $(CIPHER_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) $(KMYTH_INCLUDE_FLAGS) $< -o $@

.PHONY: pre
pre:
	indent $(INDENT_OPTS) src/*/*.c
	indent $(INDENT_OPTS) include/*.h
	rm -f src/*/*.c~
	rm -f include/*.h~
	mkdir -p $(BIN_DIR)
	mkdir -p $(OBJECT_DIRS)
	mkdir -p $(LIB_DIR)

.PHONY: doc
doc: $(HEADER_FILES) \
	   $(UTIL_SOURCES) \
		 $(TOOL_SOURCES) \
		 $(MAIN_SOURCES) \
		 $(LOGGER_HEADERS) \
		 $(LOGGER_SOURCES) \
		 Doxyfile
	mkdir -p $(DOC_DIR)
	doxygen Doxyfile

.PHONY: test
test: pretest kmyth-test
	./bin/kmyth-test 2>/dev/null

.PHONY: pretest
pretest:
	mkdir -p $(TEST_OBJECT_DIRS)

kmyth-test: $(TEST_OBJECTS)
	$(CC) $(TEST_OBJECTS) -o $(BIN_DIR)/kmyth-test $(LDFLAGS) $(LDLIBS) \
	-lcunit -lkmyth

$(TEST_OBJ_DIR)/kmyth-test.o: $(TEST_SRC_DIR)/kmyth-test.c | $(TEST_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) $(KMYTH_INCLUDE_FLAGS) $(TEST_INCLUDE_FLAGS) $< -o $@

$(TEST_UTIL_OBJ_DIR)/%.o: $(TEST_UTIL_SRC_DIR)/%.c \
	                        $(TEST_UTIL_INC_DIR)/%.h \
                          | $(TEST_UTIL_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) $(KMYTH_INCLUDE_FLAGS) $(TEST_INCLUDE_FLAGS) $< -o $@

$(TEST_TPM_OBJ_DIR)/%.o: $(TEST_TPM_SRC_DIR)/%.c \
	                       $(TEST_TPM_INC_DIR)/%.h \
                         | $(TEST_TPM_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) $(KMYTH_INCLUDE_FLAGS) $(TEST_INCLUDE_FLAGS) $< -o $@

$(TEST_CIPHER_OBJ_DIR)/%.o: $(TEST_CIPHER_SRC_DIR)/%.c \
	                          $(TEST_CIPHER_INC_DIR)/%.h \
                            | $(TEST_CIPHER_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) $(KMYTH_INCLUDE_FLAGS) $(TEST_INCLUDE_FLAGS) $< -o $@

.PHONY: install
install:
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 755 $(LIB_DIR)/libkmyth.so $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/kmyth/
	install -m 644 $(LOGGER_INC_DIR)/kmyth_log.h \
		             $(DESTDIR)$(PREFIX)/include/kmyth/
	install -m 644 $(INC_DIR)/kmyth.h $(DESTDIR)$(PREFIX)/include/kmyth/
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BIN_DIR)/kmyth-seal $(DESTDIR)$(PREFIX)/bin/
	install -m 755 $(BIN_DIR)/kmyth-unseal $(DESTDIR)$(PREFIX)/bin/
	ldconfig

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/libkmyth.so	
	rm -rf $(DESTDIR)$(PREFIX)/include/kmyth
	rm -f $(DESTDIR)$(PREFIX)/bin/kmyth-seal
	rm -f $(DESTDIR)$(PREFIX)/bin/kmyth-unseal

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
	rm -rf $(OBJ_DIR)
	rm -rf $(DOC_DIR)
	rm -rf $(LIB_DIR)
	rm -rf $(TEST_OBJ_DIR)

#============================ END TARGET CONFIGURATION =======================

