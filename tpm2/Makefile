# Makefile for KMYTH using TPM 2.0

# Specify the 'libkmythlogger' library path
LOGGER_DIR ?= logger#                    Set a default path to the logger

# Specify source code path
PREFIX ?= /usr/local#                    Set a default install location 

# Specify fundamental compiler parameters
CC = gcc#                                invoke gcc compiler
CC += -std=c11#                          use C11 standard

# Specify debugging information options
DEBUG = -g#                              produce debugging information

# Specify shared library information
LDLIBS = -ltss2-tcti-device#              TCTI for hardware TPM 2.0
LDLIBS += -ltss2-tcti-mssim#              TCTI for TPM 2.0 simulator
LDLIBS += -ltss2-tcti-tabrmd#             TPM 2.0 Access Broker/Resource Mgr.
LDLIBS += -ltss2-mu#                      TPM 2.0 marshal/unmarshal
LDLIBS += -ltss2-sys#                     TPM 2.0 SAPI
LDLIBS += -ltss2-rc#                      TPM 2.0 Return Code Utilities
LDLIBS += -lssl#                          OpenSSL
LDLIBS += -lcrypto#                       libcrypto
LDLIBS += -lkmip#                         libkmip

# Specify compiler flags
CFLAGS = -Wall#                          enable all warnings
CFLAGS += -c#                            compile, but do not link
CFLAGS += $(DEBUG)#                      debugging options (above)
CFLAGS += -D_GNU_SOURCE#                 GNU/LINUX platform
CFLAGS += -fPIC#                         Generate position independent code

KMYTH_CFLAGS = $(CFLAGS)
KMYTH_CFLAGS += -I$(LOGGER_DIR)/include#    kmyth logging utility header files

# Specify flags for the SO build of the logger
LOGGER_CFLAGS = $(CFLAGS)

SOFLAGS = -shared#                          compile/link shared library
SOFLAGS += -fPIC#

# Specify linker flags
LDFLAGS += -Llib#                            libkmyth
LDFLAGS += -Wl,-rpath=lib#                   runtime path for libkmyth.so

# Specify top-level source and target directories for build process
INCLUDE_DIR = include
CIPHER_INCLUDE_DIR = include/cipher
TPM_INCLUDE_DIR = include/tpm
OBJ_DIR = obj
SRC_DIR = src
BIN_DIR = bin
DOC_DIR = doc
LIB_DIR = lib
TEST_DIR = test
TEST_INC_DIR = $(TEST_DIR)/include
TEST_OBJ_DIR = $(TEST_DIR)/obj
LOGGER_INC_DIR = $(LOGGER_DIR)/include
LOGGER_OBJ_DIR = $(LOGGER_DIR)/obj
LOGGER_SRC_DIR = $(LOGGER_DIR)/src

# Specify kmyth-seal main() source/object path/files
MAIN_SRC_DIR = $(SRC_DIR)/main
MAIN_SOURCES = $(wildcard $(MAIN_SRC_DIR)/*.c)
MAIN_OBJ_DIR = $(OBJ_DIR)/main
MAIN_OBJECTS = $(subst $(MAIN_SRC_DIR), $(MAIN_OBJ_DIR), $(MAIN_SOURCES:%.c=%.o))

# Specify Kmyth 'utility function' source/object path/files
UTIL_SRC_DIR = $(SRC_DIR)/util
UTIL_SOURCES = $(wildcard $(UTIL_SRC_DIR)/*.c)
UTIL_OBJ_DIR = $(OBJ_DIR)/util
UTIL_OBJECTS = $(subst $(UTIL_SRC_DIR), $(UTIL_OBJ_DIR), $(UTIL_SOURCES:%.c=%.o))

# Specify kmyth cipher source/object path/files
CIPHER_SRC_DIR = $(SRC_DIR)/cipher
CIPHER_SOURCES = $(wildcard $(CIPHER_SRC_DIR)/*.c)
CIPHER_OBJ_DIR = $(OBJ_DIR)/cipher
CIPHER_OBJECTS = $(subst $(CIPHER_SRC_DIR), $(CIPHER_OBJ_DIR), $(CIPHER_SOURCES:%.c=%.o))

# Specify kmyth tpm source/object path/files
TPM_SRC_DIR = $(SRC_DIR)/tpm
TPM_SOURCES = $(wildcard $(TPM_SRC_DIR)/*.c)
TPM_OBJ_DIR = $(OBJ_DIR)/tpm
TPM_OBJECTS = $(subst $(TPM_SRC_DIR), $(TPM_OBJ_DIR), $(TPM_SOURCES:%.c=%.o))

# Specify logger source/object/header files
LOGGER_SOURCES = $(wildcard $(LOGGER_SRC_DIR)/*.c)
LOGGER_OBJECTS = $(subst $(LOGGER_SRC_DIR), $(LOGGER_OBJ_DIR), $(LOGGER_SOURCES:%.c=%.o))

# Specify, then consolidate kmyth-test source/object path/files
TEST_MAIN_SOURCES = $(TEST_DIR)/kmyth-test.c
TEST_MAIN_OBJECTS = $(TEST_OBJ_DIR)/kmyth-test.o

TEST_UTIL_SRC_DIR = $(TEST_DIR)/util
TEST_UTIL_SOURCES = $(wildcard $(TEST_UTIL_SRC_DIR)/*.c)
TEST_UTIL_OBJ_DIR = $(TEST_OBJ_DIR)/util
TEST_UTIL_OBJECTS = $(subst $(TEST_UTIL_SRC_DIR), $(TEST_UTIL_OBJ_DIR), $(TEST_UTIL_SOURCES:%.c=%.o))

TEST_SOURCES = $(TEST_MAIN_SOURCES)
TEST_SOURCES += $(TEST_UTIL_SOURCES)

TEST_OBJECTS = $(TEST_UTIL_OBJECTS)
TEST_OBJECTS += $(TEST_MAIN_OBJECTS)

# Specify Kmyth header files
HEADER_FILES = $(wildcard $(INCLUDE_DIR)/*.h)
HEADER_FILES += $(wildcard $(CIPHER_INCLUDE_DIR)/*.h)
HEADER_FILES += $(wildcard $(TPM_INCLUDE_DIR)/*.h)
LOGGER_HEADER_FILES = $(wildcard $(LOGGER_INC_DIR)/*.h)

#Specify path for logger output of shared library
KMYTH_LIB_NAME = kmyth
KMYTH_LIB_SONAME = lib$(KMYTH_LIB_NAME).so
KMYTH_LIB_LOCAL_DEST = $(LIB_DIR)/$(KMYTH_LIB_SONAME)

# Consolidate created directories to simplify mkdir call for 'pre' target below
OBJECT_DIRS = $(MAIN_OBJ_DIR)
OBJECT_DIRS += $(UTIL_OBJ_DIR)
OBJECT_DIRS += $(CIPHER_OBJ_DIR)
OBJECT_DIRS += $(TPM_OBJ_DIR)
OBJECT_DIRS += $(LOGGER_OBJ_DIR)
TEST_OBJECT_DIRS = $(TEST_UTIL_OBJ_DIR)

.PHONY: all
all: pre kmyth-lib kmyth-seal kmyth-unseal kmyth-getkey

kmyth-lib: $(LOGGER_OBJECTS) $(UTIL_OBJECTS) $(CIPHER_OBJECTS) $(TPM_OBJECTS)
	$(CC) $(SOFLAGS) $(LOGGER_OBJECTS) $(UTIL_OBJECTS) $(CIPHER_OBJECTS) $(TPM_OBJECTS) -o $(KMYTH_LIB_LOCAL_DEST) $(LDLIBS)

kmyth-seal: $(MAIN_OBJ_DIR)/seal.o
	$(CC) $(MAIN_OBJ_DIR)/seal.o -o $(BIN_DIR)/kmyth-seal $(LDFLAGS) $(LDLIBS) -lkmyth

kmyth-unseal: $(MAIN_OBJ_DIR)/unseal.o
	$(CC) $(MAIN_OBJ_DIR)/unseal.o -o $(BIN_DIR)/kmyth-unseal $(LDFLAGS) $(LDLIBS) -lkmyth

kmyth-getkey: $(MAIN_OBJ_DIR)/getkey.o
	$(CC) $(MAIN_OBJ_DIR)/getkey.o -o $(BIN_DIR)/kmyth-getkey $(LDFLAGS) $(LDLIBS) -lkmyth

$(LOGGER_OBJECTS): $(LOGGER_SOURCES) $(LOGGER_HEADER_FILES)
	$(CC) $(LOGGER_CFLAGS) -I$(LOGGER_INC_DIR) $< -o $@

$(MAIN_OBJ_DIR)/%.o: $(MAIN_SRC_DIR)/%.c | $(MAIN_OBJ_DIR) 
	$(CC) $(KMYTH_CFLAGS) -I$(INCLUDE_DIR) -I$(CIPHER_INCLUDE_DIR) -I$(TPM_INCLUDE_DIR) -I$(LOGGER_INC_DIR) $< -o $@

$(UTIL_OBJ_DIR)/%.o: $(UTIL_SRC_DIR)/%.c $(INCLUDE_DIR)/%.h | $(UTIL_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) -I$(INCLUDE_DIR) -I$(CIPHER_INCLUDE_DIR) -I$(TPM_INCLUDE_DIR) -I$(LOGGER_INC_DIR) $< -o $@

$(TPM_OBJ_DIR)/%.o: $(TPM_SRC_DIR)/%.c $(TPM_INCLUDE_DIR)/%.h | $(TPM_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) -I$(INCLUDE_DIR) -I$(CIPHER_INCLUDE_DIR) -I$(TPM_INCLUDE_DIR) -I$(LOGGER_INC_DIR) $< -o $@

$(CIPHER_OBJ_DIR)/%.o: $(CIPHER_SRC_DIR)/%.c $(CIPHER_INCLUDE_DIR)/%.h | $(CIPHER_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) -I$(INCLUDE_DIR) -I$(CIPHER_INCLUDE_DIR) -I$(TPM_INCLUDE_DIR) -I$(LOGGER_INC_DIR) $< -o $@

.PHONY: pre
pre:
	indent -bli0 -bap -bad -sob -cli0 -npcs -nbc -bls -blf -lp -ip0 -ts2 -nut -npsl -bbo -l80 src/*/*.c
	indent -bli0 -bap -bad -sob -cli0 -npcs -nbc -bls -blf -lp -ip0 -ts2 -nut -npsl -bbo -l80 include/*.h
	rm -f src/*/*.c~
	rm -f include/*.h~
	mkdir -p $(BIN_DIR)
	mkdir -p $(OBJECT_DIRS)
	mkdir -p $(LIB_DIR)

.PHONY: doc
doc: $(HEADER_FILES) $(UTIL_SOURCES) $(TOOL_SOURCES) $(MAIN_SOURCES) $(LOGGER_HEADERS) $(LOGGER_SOURCES) Doxyfile
	mkdir -p $(DOC_DIR)
	doxygen Doxyfile

.PHONY: test
test: pretest kmyth-test
	./bin/kmyth-test 2>/dev/null

.PHONY: pretest
pretest:
	mkdir -p $(TEST_OBJECT_DIRS)

$(TEST_OBJ_DIR)/kmyth-test.o: $(TEST_DIR)/kmyth-test.c | $(TEST_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) -I$(TEST_INC_DIR) $< -o $@

$(TEST_UTIL_OBJ_DIR)/%.o: $(TEST_UTIL_SRC_DIR)/%.c $(TEST_INC_DIR)/%.h | $(TEST_UTIL_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) -I$(TEST_INC_DIR) -I$(INCLUDE_DIR) -I$(CIPHER_INCLUDE_DIR) -I$(TPM_INCLUDE_DIR) $< -o $@

kmyth-test: $(TEST_OBJECTS)
	$(CC) $(TEST_OBJECTS) -o $(BIN_DIR)/kmyth-test $(LDFLAGS) $(LDLIBS) -lcunit -lkmyth

.PHONY: install
install:
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 755 $(LIB_DIR)/libkmyth.so $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/kmyth/
	install -m 644 $(LOGGER_INC_DIR)/kmyth_log.h $(DESTDIR)$(PREFIX)/include/kmyth/
	install -m 644 $(INCLUDE_DIR)/kmyth.h $(DESTDIR)$(PREFIX)/include/kmyth/
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
