#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Makefile for KMYTH using TPM 2.0                                           |
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#====================== START: BUILD ENVIRONMENT DEFINITION ==================

# Specify top-level directories for build process
SRC_DIR ?= src
INC_DIR ?= include
OBJ_DIR ?= obj
BIN_DIR ?= bin
DOC_DIR ?= doc
LIB_DIR ?= lib
LOGGER_DIR ?= logger
UTILS_DIR ?= utils

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
UTIL_HEADERS = $(wildcard $(UTIL_INC)DIR/*.h)
UTIL_OBJ_DIR = $(OBJ_DIR)/util
UTIL_OBJECTS = $(subst $(UTIL_SRC_DIR), \
                       $(UTIL_OBJ_DIR), \
                       $(UTIL_SOURCES:%.c=%.o))

# Specify Kmyth cipher utility directories/files
CIPHER_SRC_DIR = $(SRC_DIR)/cipher
CIPHER_SOURCES = $(wildcard $(CIPHER_SRC_DIR)/*.c)
CIPHER_INC_DIR = $(INC_DIR)/cipher
CIPHER_HEADERS = $(wildcard $(CIPHER_INC_DIR)/*.h)
CIPHER_OBJ_DIR = $(OBJ_DIR)/cipher
CIPHER_OBJECTS = $(subst $(CIPHER_SRC_DIR), \
                         $(CIPHER_OBJ_DIR), \
                         $(CIPHER_SOURCES:%.c=%.o))

# Specify Kmyth TPM 2.0 utility directories/files
TPM_SRC_DIR = $(SRC_DIR)/tpm
TPM_SOURCES = $(wildcard $(TPM_SRC_DIR)/*.c)
TPM_INC_DIR = $(INC_DIR)/tpm
TPM_HEADERS = $(wildcard $(TPM_INC_DIR)/*.h)
TPM_OBJ_DIR = $(OBJ_DIR)/tpm
TPM_OBJECTS = $(subst $(TPM_SRC_DIR), \
                      $(TPM_OBJ_DIR), \
                      $(TPM_SOURCES:%.c=%.o))

# Specify Kmyth source files
SOURCE_FILES = $(wildcard $(SRC_DIR)/*.c)
SOURCE_FILES += $(MAIN_SOURCES)
SOURCE_FILES += $(UTIL_SOURCES)
SOURCE_FILES += $(CIPHER_SOURCES)
SOURCE_FILES += $(TPM_SOURCES)

# Specify Kmyth header files
HEADER_FILES = $(wildcard $(INC_DIR)/*.h)
HEADER_FILES += $(UTIL_HEADERS)
HEADER_FILES += $(CIPHER_HEADERS)
HEADER_FILES += $(TPM_HEADERS)

# Specify Kmyth Utilities shared library directories/files
UTILS_SRC_DIR = $(UTILS_DIR)/src
UTILS_SOURCES = $(wildcard $(UTILS_SRC_DIR)/*.c)
UTILS_INC_DIR = $(UTILS_DIR)/include
UTILS_OBJ_DIR = $(UTILS_DIR)/obj
UTILS_OBJECTS = $(subst $(UTILS_SRC_DIR), \
                         $(UTILS_OBJ_DIR), \
                         $(UTILS_SOURCES:%.c=%.o))
UTILS_HEADER_FILES = $(wildcard $(UTILS_INC_DIR)/*.h)

# Specify Kmyth logger shared library directories/files
LOGGER_SRC_DIR = $(LOGGER_DIR)/src
LOGGER_SOURCES = $(wildcard $(LOGGER_SRC_DIR)/*.c)
LOGGER_INC_DIR = $(LOGGER_DIR)/include
LOGGER_OBJ_DIR = $(LOGGER_DIR)/obj
LOGGER_OBJECTS = $(subst $(LOGGER_SRC_DIR), \
                         $(LOGGER_OBJ_DIR), \
                         $(LOGGER_SOURCES:%.c=%.o))
LOGGER_HEADER_FILES = $(wildcard $(LOGGER_INC_DIR)/*.h)

# Specify details for kmyth TPM utilities shared (.so) library
TPM_UTIL_LIB_NAME = kmyth-tpm
TPM_UTIL_LIB_SONAME = lib$(TPM_UTIL_LIB_NAME).so
TPM_UTIL_LIB_LOCAL_DEST = $(LIB_DIR)/$(TPM_UTIL_LIB_SONAME)

# Specify details for kmyth utilities shared (.so) library
UTILS_LIB_NAME = kmyth-utils
UTILS_LIB_SONAME = lib$(UTILS_LIB_NAME).so
UTILS_LIB_LOCAL_DEST = $(LIB_DIR)/$(UTILS_LIB_SONAME)

# Specify details for kmyth logger shared (.so) library
LOGGER_LIB_NAME = kmyth-logger
LOGGER_LIB_SONAME = lib$(LOGGER_LIB_NAME).so
LOGGER_LIB_LOCAL_DEST = $(LIB_DIR)/$(LOGGER_LIB_SONAME)

# Specify backup files to be cleaned up
BACKUP_FILES = $(shell find -name "*~" -print)

#====================== END: BUILD ENVIRONMENT DEFINITION ====================

#====================== START: TEST ENVIRONMENT DEFINITION ===================

# Specify top-level unit testing directory structure
TEST_DIR ?= test
TEST_SRC_DIR ?= $(TEST_DIR)/src
TEST_INC_DIR ?= $(TEST_DIR)/include
TEST_OBJ_DIR ?= $(TEST_DIR)/obj
TEST_DATA_DIR ?= $(TEST_DIR)/data

# Specify 'testrunner' (kmyth-test) files
TESTRUNNER_SOURCES = $(wildcard $(TEST_SRC_DIR)/*.c)
TESTRUNNER_HEADERS = $(wildcard $(TEST_INC_DIR)/*.h)
TESTRUNNER_OBJECTS = $(subst $(TEST_SRC_DIR), \
                             $(TEST_OBJ_DIR), \
														 $(TESTRUNNER_SOURCES:%.c=%.o))

# Specify directories/files supporting kmyth application (main) testing
TEST_MAIN_SRC_DIR = $(TEST_SRC_DIR)/main
TEST_MAIN_SOURCES = $(wildcard $(TEST_MAIN_SRC_DIR)/*.c)
TEST_MAIN_INC_DIR = $(TEST_INC_DIR)/main
TEST_MAIN_HEADERS = $(wildcard $(TEST_MAIN_INC_DIR)/*.h)
TEST_MAIN_OBJ_DIR = $(TEST_OBJ_DIR)/main
TEST_MAIN_OBJECTS = $(subst $(TEST_MAIN_SRC_DIR), \
                            $(TEST_MAIN_OBJ_DIR), \
                            $(TEST_MAIN_SOURCES:%.c=%.o))

# Specify directories/files supporting kmyth general utility (util) testing
TEST_UTIL_SRC_DIR = $(TEST_SRC_DIR)/util
TEST_UTIL_SOURCES = $(wildcard $(TEST_UTIL_SRC_DIR)/*.c)
TEST_UTIL_INC_DIR = $(TEST_INC_DIR)/util
TEST_UTIL_HEADERS = $(wildcard $(TEST_UTIL_INC_DIR)/*.h)
TEST_UTIL_OBJ_DIR = $(TEST_OBJ_DIR)/util
TEST_UTIL_OBJECTS = $(subst $(TEST_UTIL_SRC_DIR), \
                            $(TEST_UTIL_OBJ_DIR), \
                            $(TEST_UTIL_SOURCES:%.c=%.o))

# Specify directories/files supporting kmyth TPM utility testing
TEST_TPM_SRC_DIR = $(TEST_SRC_DIR)/tpm
TEST_TPM_SOURCES = $(wildcard $(TEST_TPM_SRC_DIR)/*.c)
TEST_TPM_INC_DIR = $(TEST_INC_DIR)/tpm
TEST_TPM_HEADERS = $(wildcard $(TEST_TPM_INC_DIR)/*.h)
TEST_TPM_OBJ_DIR = $(TEST_OBJ_DIR)/tpm
TEST_TPM_OBJECTS = $(subst $(TEST_TPM_SRC_DIR), \
                           $(TEST_TPM_OBJ_DIR), \
                           $(TEST_TPM_SOURCES:%.c=%.o))

# Specify directories/files supporting kmyth cipher utility testing
TEST_CIPHER_SRC_DIR = $(TEST_SRC_DIR)/cipher
TEST_CIPHER_SOURCES = $(wildcard $(TEST_CIPHER_SRC_DIR)/*.c)
TEST_CIPHER_INC_DIR = $(TEST_INC_DIR)/cipher
TEST_CIPHER_HEADERS = $(wildcard $(TEST_CIPHER_INC_DIR)/*.h)
TEST_CIPHER_OBJ_DIR = $(TEST_OBJ_DIR)/cipher
TEST_CIPHER_OBJECTS = $(subst $(TEST_CIPHER_SRC_DIR), \
                              $(TEST_CIPHER_OBJ_DIR), \
                              $(TEST_CIPHER_SOURCES:%.c=%.o))

# Create consolidated list of test source files
TEST_SOURCES = $(TESTRUNNER_SOURCES)
TEST_SOURCES += $(TEST_MAIN_SOURCES)
TEST_SOURCES += $(TEST_UTIL_SOURCES)
TEST_SOURCES += $(TEST_TPM_SOURCES)
TEST_SOURCES += $(TEST_CIPHER_SOURCES)

# Create consolidated list of test header files
TEST_HEADERS = $(TESTRUNNER_HEADERS)
TEST_HEADERS += $(TEST_MAIN_HEADERS)
TEST_HEADERS += $(TEST_UTIL_HEADERS)
TEST_HEADERS += $(TEST_TPM_HEADERS)
TEST_HEADERS += $(TEST_CIPHER_HEADERS)

# Create consolidated list of test object files
TEST_OBJECTS = $(TESTRUNNER_OBJECTS)
TEST_OBJECTS += $(TEST_MAIN_OBJECTS)
TEST_OBJECTS += $(TEST_UTIL_OBJECTS)
TEST_OBJECTS += $(TEST_TPM_OBJECTS)
TEST_OBJECTS += $(TEST_CIPHER_OBJECTS)

# Create consolidated list of test object directories
TEST_OBJECT_DIRS = $(TEST_MAIN_OBJ_DIR)
TEST_OBJECT_DIRS += $(TEST_UTIL_OBJ_DIR)
TEST_OBJECT_DIRS += $(TEST_TPM_OBJ_DIR)
TEST_OBJECT_DIRS += $(TEST_CIPHER_OBJ_DIR)

# Create consolidated list of test vector directories
TEST_VEC_DIRS = $(TEST_DATA_DIR)/kwtestvectors
TEST_VEC_DIRS += $(TEST_DATA_DIR)/gcmtestvectors

# 
#====================== END: TEST ENVIRONMENT DEFINITION =====================

#====================== START: TOOL CONFIGURATION ============================

# Specify fundamental compiler parameters
CC = gcc#                                invoke gcc compiler
CC += -std=c11#                          use C11 standard
CC += -Wall#                             enable all warnings
DEBUG = -g#                              produce debugging information
PREFIX ?= /usr/local#                    set source installation path 

# Specify Kmyth 'include directory' compiler option flags
KMYTH_INCLUDE_FLAGS = -I$(INC_DIR)
KMYTH_INCLUDE_FLAGS += -I$(UTIL_INC_DIR)
KMYTH_INCLUDE_FLAGS += -I$(CIPHER_INC_DIR)
KMYTH_INCLUDE_FLAGS += -I$(TPM_INC_DIR)
KMYTH_INCLUDE_FLAGS += -I$(UTILS_INC_DIR)
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
CFLAGS += -c#                            compile, but do not link
CFLAGS += $(DEBUG)#                      debugging options (above)
CFLAGS += -D_GNU_SOURCE#                 GNU/LINUX platform
CFLAGS += -fPIC#                         Generate position independent code

# Specify compiler flags for building kmyth applications that use logger library
KMYTH_CFLAGS = $(CFLAGS)
KMYTH_CFLAGS += -I$(UTILS_INC_DIR)#      kmyth utilities header files
KMYTH_CFLAGS += -I$(LOGGER_INC_DIR)#     kmyth logging utility header files

# Specify flags for the SO build of the logger
LOGGER_CFLAGS = $(CFLAGS)

SOFLAGS = -shared#                       compile/link shared library
SOFLAGS += -fPIC#

# Specify linker flags
LDFLAGS += -Llib#                        libkmyth
LDFLAGS += -Wl,-rpath=lib#               runtime path for libkmyth.so

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

#====================== END: TOOL CONFIGURATION ==============================

#====================== START: RULES =========================================

.PHONY: all
all: pre clean-backups \
     $(BIN_DIR)/kmyth-seal \
     $(BIN_DIR)/kmyth-unseal \
     $(BIN_DIR)/kmyth-getkey \
     $(BIN_DIR)/nsl-client \
     $(BIN_DIR)/nsl-server \
		 $(LIB_DIR)/libkmyth-utils.so \
     $(LIB_DIR)/libkmyth-logger.so \
     $(LIB_DIR)/libkmyth-tpm.so

.PHONY: pre
pre:
	indent $(INDENT_OPTS) $(SOURCE_FILES)
	indent $(INDENT_OPTS) $(HEADER_FILES)

.PHONY: libs
libs: pre clean-backups \
      $(LIB_DIR)/libkmyth-utils.so \
      $(LIB_DIR)/libkmyth-logger.so \
      $(LIB_DIR)/libkmyth-tpm.so

.PHONY: utils-lib
logger-lib: pre clean-backups $(LIB_DIR)/libkmyth-utils.so

.PHONY: logger-lib
logger-lib: pre clean-backups $(LIB_DIR)/libkmyth-logger.so

$(LIB_DIR)/libkmyth-utils.so: $(UTILS_OBJECTS) | $(LIB_DIR)
	$(CC) $(SOFLAGS) \
	      $(UTILS_OBJECTS) \
	      -o $(UTILS_LIB_LOCAL_DEST)

$(LIB_DIR)/libkmyth-logger.so: $(LOGGER_OBJECTS) | $(LIB_DIR)
	$(CC) $(SOFLAGS) \
	      $(LOGGER_OBJECTS) \
	      -o $(LOGGER_LIB_LOCAL_DEST)

$(LIB_DIR)/libkmyth-tpm.so: $(UTIL_OBJECTS) \
                            $(CIPHER_OBJECTS) \
                            $(TPM_OBJECTS) \
                            $(LIB_DIR)/libkmyth-utils.so \
                            $(LIB_DIR)/libkmyth-logger.so | \
                            $(LIB_DIR)
	$(CC) $(SOFLAGS) \
	      $(UTIL_OBJECTS) \
	      $(CIPHER_OBJECTS) \
	      $(TPM_OBJECTS) \
	      -o $(TPM_UTIL_LIB_LOCAL_DEST) \
	      $(LDFLAGS) \
	      $(LDLIBS) \
				-lkmyth-utils \
	      -lkmyth-logger


$(BIN_DIR)/kmyth-seal: $(MAIN_OBJ_DIR)/seal.o \
                       $(LIB_DIR)/libkmyth-tpm.so | \
                       $(BIN_DIR)
	$(CC) $(MAIN_OBJ_DIR)/seal.o \
	      -o $(BIN_DIR)/kmyth-seal \
	      $(LDFLAGS) \
	      $(LDLIBS) \
				-lkmyth-utils \
	      -lkmyth-logger \
	      -lkmyth-tpm

$(BIN_DIR)/kmyth-unseal: $(MAIN_OBJ_DIR)/unseal.o \
                         $(LIB_DIR)/libkmyth-tpm.so | \
												 $(BIN_DIR)
	$(CC) $(MAIN_OBJ_DIR)/unseal.o \
	      -o $(BIN_DIR)/kmyth-unseal \
	      $(LDFLAGS) \
	      $(LDLIBS) \
				-lkmyth-utils \
	      -lkmyth-logger \
	      -lkmyth-tpm

$(BIN_DIR)/kmyth-getkey: $(MAIN_OBJ_DIR)/getkey.o \
                         $(LIB_DIR)/libkmyth-tpm.so | \
                         $(BIN_DIR)
	$(CC) $(MAIN_OBJ_DIR)/getkey.o \
	      -o $(BIN_DIR)/kmyth-getkey \
	      $(LDFLAGS) \
	      $(LDLIBS) \
				-lkmyth-utils \
	      -lkmyth-logger \
	      -lkmyth-tpm


$(BIN_DIR)/nsl-client: $(MAIN_OBJ_DIR)/nsl_client.o \
                       $(LIB_DIR)/libkmyth-tpm.so | \
                       $(BIN_DIR)
	$(CC) $(MAIN_OBJ_DIR)/nsl_client.o \
	      -o $(BIN_DIR)/nsl-client \
	      $(LDFLAGS) \
	      $(LDLIBS) \
				-lkmyth-utils \
	      -lkmyth-logger \
	      -lkmyth-tpm

$(BIN_DIR)/nsl-server: $(MAIN_OBJ_DIR)/nsl_server.o \
                       $(LIB_DIR)/libkmyth-tpm.so | \
                       $(BIN_DIR)
	$(CC) $(MAIN_OBJ_DIR)/nsl_server.o \
	      -o $(BIN_DIR)/nsl-server \
	      $(LDFLAGS) \
	      $(LDLIBS) \
				-lkmyth-utils \
	      -lkmyth-logger \
	      -lkmyth-tpm

$(UTILS_OBJ_DIR)/%.o: $(UTILS_SRC_DIR)/%.c \
                      $(UTILS_INC_DIR)/%.h | \
                      $(UTILS_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) \
	      $(KMYTH_INCLUDE_FLAGS) \
				-I$(UTILS_INC_DIR) \
	      $< \
	      -o $@

$(LOGGER_OBJECTS): $(LOGGER_SOURCES) \
                   $(LOGGER_HEADER_FILES) | \
                   $(LOGGER_OBJ_DIR)
	$(CC) $(LOGGER_CFLAGS) \
	      -I$(LOGGER_INC_DIR) \
	      $< \
	      -o $@

$(MAIN_OBJ_DIR)/%.o: $(MAIN_SRC_DIR)/%.c | \
                     $(MAIN_OBJ_DIR) 
	$(CC) $(KMYTH_CFLAGS) \
	      $(KMYTH_INCLUDE_FLAGS) \
	      $< \
	      -o $@

$(UTIL_OBJ_DIR)/%.o: $(UTIL_SRC_DIR)/%.c \
                     $(UTIL_INC_DIR)/%.h | \
                     $(UTIL_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) \
	      $(KMYTH_INCLUDE_FLAGS) \
	      $< \
	      -o $@

$(TPM_OBJ_DIR)/%.o: $(TPM_SRC_DIR)/%.c \
                    $(TPM_INC_DIR)/%.h | \
                    $(TPM_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) \
	      $(KMYTH_INCLUDE_FLAGS) \
	      $< \
	      -o $@

$(CIPHER_OBJ_DIR)/%.o: $(CIPHER_SRC_DIR)/%.c \
                       $(CIPHER_INC_DIR)/%.h | \
                       $(CIPHER_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) \
	      $(KMYTH_INCLUDE_FLAGS) \
	      $< \
	      -o $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

$(MAIN_OBJ_DIR):
	mkdir -p $(MAIN_OBJ_DIR)

$(UTIL_OBJ_DIR):
	mkdir -p $(UTIL_OBJ_DIR)

$(CIPHER_OBJ_DIR):
	mkdir -p $(CIPHER_OBJ_DIR)

$(TPM_OBJ_DIR):
	mkdir -p $(TPM_OBJ_DIR)

$(UTILS_OBJ_DIR):
	mkdir -p $(UTILS_OBJ_DIR)

$(LOGGER_OBJ_DIR):
	mkdir -p $(LOGGER_OBJ_DIR)

$(DOC_DIR):
	mkdir -p $(DOC_DIR)

.PHONY: docs
docs: $(HEADER_FILES) \
     $(UTIL_SOURCES) \
     $(TOOL_SOURCES) \
     $(MAIN_SOURCES) \
     $(LOGGER_HEADERS) \
     $(LOGGER_SOURCES) \
     Doxyfile | \
		 $(DOC_DIR)
	doxygen Doxyfile

.PHONY: test
test: pretest clean-backups $(BIN_DIR)/kmyth-test
	./bin/kmyth-test 2>/dev/null

.PHONY: pretest
pretest:
	indent $(INDENT_OPTS) $(TEST_SOURCES)
	indent $(INDENT_OPTS) $(TEST_HEADERS)


$(BIN_DIR)/kmyth-test: $(TEST_OBJECTS) \
                       $(LIB_DIR)/libkmyth-tpm.so | \
                       $(BIN_DIR)
	$(CC) $(TEST_OBJECTS) \
	      -o $(BIN_DIR)/kmyth-test \
	      $(LDFLAGS) \
	      $(LDLIBS) \
	      -lcunit \
	      -lkmyth-tpm

$(TEST_OBJ_DIR)/kmyth-test.o: $(TEST_SRC_DIR)/kmyth-test.c | $(TEST_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) $(KMYTH_INCLUDE_FLAGS) $(TEST_INCLUDE_FLAGS) $< -o $@

$(TEST_UTIL_OBJ_DIR)/%.o: $(TEST_UTIL_SRC_DIR)/%.c \
                          $(TEST_UTIL_INC_DIR)/%.h | \
                          $(TEST_UTIL_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) \
	      $(KMYTH_INCLUDE_FLAGS) \
	      $(TEST_INCLUDE_FLAGS) \
	      $< \
	      -o $@

$(TEST_TPM_OBJ_DIR)/%.o: $(TEST_TPM_SRC_DIR)/%.c \
                         $(TEST_TPM_INC_DIR)/%.h | \
                         $(TEST_TPM_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) \
	      $(KMYTH_INCLUDE_FLAGS) \
	      $(TEST_INCLUDE_FLAGS) \
	      $< -o \
	      $@

$(TEST_CIPHER_OBJ_DIR)/%.o: $(TEST_CIPHER_SRC_DIR)/%.c \
                            $(TEST_CIPHER_INC_DIR)/%.h | \
                            $(TEST_CIPHER_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) \
	      $(KMYTH_INCLUDE_FLAGS) \
	      $(TEST_INCLUDE_FLAGS) \
	      $< \
	      -o $@

$(TEST_OBJ_DIR):
	mkdir -p $(TEST_OBJ_DIR)

$(TEST_MAIN_OBJ_DIR):
	mkdir -p $(TEST_MAIN_OBJ_DIR)

$(TEST_UTIL_OBJ_DIR):
	mkdir -p $(TEST_UTIL_OBJ_DIR)

$(TEST_TPM_OBJ_DIR):
	mkdir -p $(TEST_TPM_OBJ_DIR)

$(TEST_CIPHER_OBJ_DIR):
	mkdir -p $(TEST_CIPHER_OBJ_DIR)

.PHONY: install
install:
ifeq ($(wildcard $(UTILS_LIB_LOCAL_DEST)), $(UTILS_LIB_LOCAL_DEST))
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 755 $(UTILS_LIB_LOCAL_DEST) $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/kmyth
	install -m 644 $(UTILS_HEADER_FILES) \
	               $(DESTDIR)$(PREFIX)/include/kmyth/
	ldconfig
endif
ifeq ($(wildcard $(LOGGER_LIB_LOCAL_DEST)), $(LOGGER_LIB_LOCAL_DEST))
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 755 $(LOGGER_LIB_LOCAL_DEST) $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/kmyth
	install -m 644 $(LOGGER_INC_DIR)/kmyth_log.h \
	               $(DESTDIR)$(PREFIX)/include/kmyth/
	ldconfig
endif
ifeq ($(wildcard $(TPM_UTIL_LIB_LOCAL_DEST)), $(TPM_UTIL_LIB_LOCAL_DEST))
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 755 $(TPM_UTIL_LIB_LOCAL_DEST) $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/kmyth
	install -m 644 $(INC_DIR)/kmyth.h $(DESTDIR)$(PREFIX)/include/kmyth/
	ldconfig
endif
ifeq ($(wildcard $(BIN_DIR)/kmyth-seal), $(BIN_DIR)/kmyth-seal)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BIN_DIR)/kmyth-seal $(DESTDIR)$(PREFIX)/bin/
endif
ifeq ($(wildcard $(BIN_DIR)/kmyth-unseal), $(BIN_DIR)/kmyth-unseal)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BIN_DIR)/kmyth-unseal $(DESTDIR)$(PREFIX)/bin/
endif

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/$(TPM_UTIL_LIB_SONAME)
	rm -f $(DESTDIR)$(PREFIX)/lib/$(LOGGER_LIB_SONAME)
	rm -f $(DESTDIR)$(PREFIX)/include/kmyth/kmyth.h
	rm -f $(DESTDIR)$(PREFIX)/include/kmyth/kmyth_log.h
ifeq ($(wildcard $(DESTDIR)$(PREFIX)/include/kmyth/*.h),)
	rm -rf $(DESTDIR)$(PREFIX)/include/kmyth
endif
	rm -f $(DESTDIR)$(PREFIX)/bin/kmyth-seal
	rm -f $(DESTDIR)$(PREFIX)/bin/kmyth-unseal

.PHONY: install-test-vectors
install-test-vectors: uninstall-test-vectors
	mkdir -p $(TEST_VEC_DIRS)
	wget https://csrc.nist.gov/groups/STM/cavp/documents/mac/kwtestvectors.zip
	unzip kwtestvectors.zip -d $(TEST_DATA_DIR)
	rm kwtestvectors.zip
	wget https://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
	unzip gcmtestvectors.zip -d $(TEST_DATA_DIR)/gcmtestvectors/
	rm gcmtestvectors.zip

.PHONY: uninstall-test-vectors
uninstall-test-vectors:
	rm -rf $(TEST_VEC_DIRS)

.PHONY: clean
clean: clean-backups
	rm -rf $(BIN_DIR)
	rm -rf $(OBJ_DIR)
	rm -rf $(DOC_DIR)
	rm -rf $(LIB_DIR)
	rm -rf $(TEST_OBJ_DIR)
	rm -rf $(UTILS_OBJ_DIR)
	rm -rf $(LOGGER_OBJ_DIR)

.PHONY: clean-backups
clean-backups:
ifneq ($(BACKUP_FILES),)
	rm -f $(BACKUP_FILES)
endif

#====================== END: RULES =========================================
