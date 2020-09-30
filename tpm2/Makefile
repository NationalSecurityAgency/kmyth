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
CFLAGS += ${DEBUG}#                      debugging options (above)
CFLAGS += -D_GNU_SOURCE#                 GNU/LINUX platform
CFLAGS += -fPIC#                         Generate position independent code

KMYTH_CFLAGS = $(CFLAGS)
KMYTH_CFLAGS += -I${LOGGER_DIR}/include#    kmyth logging utility header files

# Specify flags for the SO build of the logger
LOGGER_CFLAGS = $(CFLAGS)

SOFLAGS = -shared#                          compile/link shared library
SOFLAGS += -fPIC#

# Specify linker flags
LDFLAGS += -Llib#                            libkmyth
LDFLAGS += -Wl,-rpath=lib#                   runtime path for libkmyth.so

# Specify top-level source and target directories for build process
INCLUDE_DIR = include
OBJ_DIR = obj
SRC_DIR = src
BIN_DIR = bin
DOC_DIR = doc
LIB_DIR = lib
LOGGER_INC_DIR = $(LOGGER_DIR)/include
LOGGER_OBJ_DIR = $(LOGGER_DIR)/obj
LOGGER_SRC_DIR = $(LOGGER_DIR)/src
LOGGER_DOC_DIR = $(LOGGER_DIR)/doc

# Specify kmyth-seal main() source/object path/files
SEAL_SRC_DIR = $(SRC_DIR)/seal
SEAL_SOURCES = $(wildcard $(SEAL_SRC_DIR)/*.c)
SEAL_OBJ_DIR = $(OBJ_DIR)/seal
SEAL_OBJECTS = $(subst $(SEAL_SRC_DIR), $(SEAL_OBJ_DIR), $(SEAL_SOURCES:%.c=%.o))

# Specify kmyth-unseal main() source/object path/files
UNSEAL_SRC_DIR = $(SRC_DIR)/unseal
UNSEAL_SOURCES = $(wildcard $(UNSEAL_SRC_DIR)/*.c)
UNSEAL_OBJ_DIR = $(OBJ_DIR)/unseal
UNSEAL_OBJECTS = $(subst $(UNSEAL_SRC_DIR), $(UNSEAL_OBJ_DIR), $(UNSEAL_SOURCES:%.c=%.o))

# Specify kmyth-getkey main() source/object path/files
GETKEY_SRC_DIR = $(SRC_DIR)/getkey
GETKEY_SOURCES = $(wildcard $(GETKEY_SRC_DIR)/*.c)
GETKEY_OBJ_DIR = $(OBJ_DIR)/getkey
GETKEY_OBJECTS = $(subst $(GETKEY_SRC_DIR), $(GETKEY_OBJ_DIR), $(GETKEY_SOURCES:%.c=%.o))

# Specify Kmyth 'utility function' source/object path/files
UTIL_SRC_DIR = $(SRC_DIR)/util
UTIL_SOURCES = $(wildcard $(UTIL_SRC_DIR)/*c)
UTIL_OBJ_DIR = $(OBJ_DIR)/util
UTIL_OBJECTS = $(subst $(UTIL_SRC_DIR), $(UTIL_OBJ_DIR), $(UTIL_SOURCES:%.c=%.o))

# Specify logger source/object/header files
LOGGER_SOURCES = $(wildcard $(LOGGER_SRC_DIR)/*c)
LOGGER_OBJECTS = $(subst $(LOGGER_SRC_DIR), $(LOGGER_OBJ_DIR), $(LOGGER_SOURCES:%.c=%.o))

# Specify Kmyth header files
HEADER_FILES = $(wildcard $(INCLUDE_DIR)/*h)
LOGGER_HEADER_FILES = $(wildcard $(LOGGER_INC_DIR)/*h)

#Specify path for logger output of shared library
KMYTH_LIB_NAME = kmyth
KMYTH_LIB_SONAME = lib$(KMYTH_LIB_NAME).so
KMYTH_LIB_LOCAL_DEST = $(LIB_DIR)/$(KMYTH_LIB_SONAME)

# Consolidate created directories to simplify mkdir call for 'pre' target below
OBJECT_DIRS = $(SEAL_OBJ_DIR)
OBJECT_DIRS += $(UNSEAL_OBJ_DIR)
OBJECT_DIRS += $(GETKEY_OBJ_DIR)
OBJECT_DIRS += $(UTIL_OBJ_DIR)
OBJECT_DIRS += $(LOGGER_OBJ_DIR)
DOC_DIRS = $(DOC_DIR)
DOC_DIRS += $(LOGGER_DOC_DIR)

.PHONY: all
all: pre kmyth-lib kmyth-seal kmyth-unseal kmyth-getkey

kmyth-lib: $(LOGGER_OBJECTS) $(UTIL_OBJECTS)
	$(CC) $(SOFLAGS) $(LOGGER_OBJECTS) $(UTIL_OBJECTS) -o $(KMYTH_LIB_LOCAL_DEST) $(LDLIBS)

kmyth-seal: $(SEAL_OBJECTS)
	$(CC) $(SEAL_OBJECTS) $(UTIL_OBJECTS) -o $(BIN_DIR)/kmyth-seal $(LDFLAGS) $(LDLIBS) -lkmyth

kmyth-unseal: $(UNSEAL_OBJECTS)
	$(CC) $(UNSEAL_OBJECTS) $(UTIL_OBJECTS) -o $(BIN_DIR)/kmyth-unseal $(LDFLAGS) $(LDLIBS) -lkmyth

kmyth-getkey: $(GETKEY_OBJECTS)
	$(CC) $(GETKEY_OBJECTS) $(UTIL_OBJECTS) -o $(BIN_DIR)/kmyth-getkey $(LDFLAGS) $(LDLIBS) -lkmyth

$(LOGGER_OBJECTS): $(LOGGER_SOURCES) $(LOGER_HEADERS)
	$(CC) $(LOGGER_CFLAGS) -I$(LOGGER_INC_DIR) $< -o $@

$(SEAL_OBJ_DIR)/%.o: $(SEAL_SRC_DIR)/%.c | $(SEAL_OBJ_DIR) 
	$(CC) $(KMYTH_CFLAGS) -I$(INCLUDE_DIR) -I$(LOGGER_INC_DIR) $< -o $@

$(UNSEAL_OBJ_DIR)/%.o: $(UNSEAL_SRC_DIR)/%.c | $(UNSEAL_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) -I$(INCLUDE_DIR) -I$(LOGGER_INC_DIR) $< -o $@

$(UTIL_OBJ_DIR)/%.o: $(UTIL_SRC_DIR)/%.c | $(UTIL_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) -I$(INCLUDE_DIR) -I$(LOGGER_INC_DIR) $< -o $@

$(GETKEY_OBJ_DIR)/%.o: $(GETKEY_SRC_DIR)/%.c | $(GETKEY_OBJ_DIR)
	$(CC) $(KMYTH_CFLAGS) -I$(INCLUDE_DIR) -I$(LOGGER_INC_DIR) $< -o $@

.PHONY: pre
pre:
	indent -bli0 -bap -bad -sob -cli0 -npcs -nbc -bls -blf -lp -ip0 -ts2 -nut -npsl -bbo -l80 src/*/*.c
	indent -bli0 -bap -bad -sob -cli0 -npcs -nbc -bls -blf -lp -ip0 -ts2 -nut -npsl -bbo -l80 include/*.h
	rm -f src/*/*.c~
	rm -f include/*.h~
	mkdir -p $(BIN_DIR)
	mkdir -p $(OBJECT_DIRS)
	mkdir -p $(DOC_DIRS)
	mkdir -p $(LIB_DIR)

.PHONY: doc
doc: $(HEADER_FILES) $(UTIL_SOURCES) $(TOOL_SOURCES) $(SEAL_SOURCES) $(UNSEAL_SOURCES) $(GETKEY_SOURCES) $(LOGGER_HEADERS) $(LOGGER_SOURCES) Doxyfile
	doxygen Doxyfile

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
	rm -rf $(OBJECT_DIRS)
	rm -rf $(DOC_DIRS)
	rm -rf $(LIB_DIR)
