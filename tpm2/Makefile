# Makefile for KMYTH using TPM 2.0

# Specify the 'libkmythlogger' library path
LOGGER_DIR ?= logger#       		       Set a default path to the logger

# Specify source code path
PREFIX ?= /usr/local#                    Set a default install location 

# Specify fundamental compiler parameters
CC = gcc#                                invoke gcc compiler
CC += -std=c11#                          use C11 standard

# Specify debugging information options
DEBUG = -g#                              produce debugging information

# Specify shared library information
LLIBS = -ltss2-tcti-device#              TCTI for hardware TPM 2.0
LLIBS += -ltss2-tcti-mssim#              TCTI for TPM 2.0 simulator
LLIBS += -ltss2-tcti-tabrmd#             TPM 2.0 Access Broker/Resource Mgr.
LLIBS += -ltss2-mu#                      TPM 2.0 marshal/unmarshal
LLIBS += -ltss2-sys#                     TPM 2.0 SAPI
LLIBS += -ltss2-rc#                      TPM 2.0 Return Code Utilities
LLIBS += -lssl#                          OpenSSL
LLIBS += -lcrypto#                       libcrypto
LLIBS += -lkmip#                         libkmip
LLIBS += -lkmythlogger#                  kmyth logging utility shared library

# Specify compiler flags
CFLAGS = -Wall#                          enable all warnings
CFLAGS += -c#                            compile, but do not link
CFLAGS += ${DEBUG}#                      debugging options (above)
CFLAGS += -D_GNU_SOURCE#                 GNU/LINUX platform

KMYTH_CFLAGS = $(CFLAGS)
KMYTH_CFLAGS += -I${LOGGER_DIR}/include#    kmyth logging utility header files

# Specify flags for the SO build of the logger
LOGGER_CFLAGS = $(CFLAGS)
LOGGER_CFLAGS += -fPIC#                     Generate position independent code

SOFLAGS = -shared#                          compile/link shared library

# Specify linker flags
LFLAGS += -L${LOGGER_DIR}/lib#          libkmythlogger
LFLAGS += -Wl,-rpath=${LOGGER_DIR}/lib# runtime path for libkmythlogger.so

# Specify top-level source and target directories for build process
INCLUDE_DIR = include
OBJ_DIR = obj
SRC_DIR = src
BIN_DIR = bin
DOC_DIR = doc
LOGGER_INC_DIR = $(LOGGER_DIR)/include
LOGGER_OBJ_DIR = $(LOGGER_DIR)/obj
LOGGER_LIB_DIR = $(LOGGER_DIR)/lib
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
LOGGER_LIB_NAME = kmythlogger
LOGGER_LIB_SONAME = lib$(LOGGER_LIB_NAME).so
LOGGER_LIB_LOCAL_DEST = $(LOGGER_LIB_DIR)/$(LOGGER_LIB_SONAME)

# Consolidate created directories to simplify mkdir call for 'pre' target below
OBJECT_DIRS = $(SEAL_OBJ_DIR)
OBJECT_DIRS += $(UNSEAL_OBJ_DIR)
OBJECT_DIRS += $(GETKEY_OBJ_DIR)
OBJECT_DIRS += $(UTIL_OBJ_DIR)
OBJECT_DIRS += $(LOGGER_OBJ_DIR)
DOC_DIRS = $(DOC_DIR)
DOC_DIRS += $(LOGGER_DOC_DIR)

.PHONY: all
all: pre logger kmyth-seal kmyth-unseal kmyth-getkey

logger: $(LOGGER_OBJECTS)
	$(CC) $(SOFLAGS) $(LOGGER_OBJECTS) -o $(LOGGER_LIB_LOCAL_DEST)

kmyth-seal: $(SEAL_OBJECTS) $(UTIL_OBJECTS)
	$(CC) $(SEAL_OBJECTS) $(UTIL_OBJECTS) -o $(BIN_DIR)/kmyth-seal $(LLIBS) $(LFLAGS)

kmyth-unseal: $(UNSEAL_OBJECTS) $(UTIL_OBJECTS)
	$(CC) $(UNSEAL_OBJECTS) $(UTIL_OBJECTS) -o $(BIN_DIR)/kmyth-unseal $(LLIBS) $(LFLAGS)

kmyth-getkey: $(GETKEY_OBJECTS) $(UTIL_OBJECTS)
	$(CC) $(GETKEY_OBJECTS) $(UTIL_OBJECTS) -o $(BIN_DIR)/kmyth-getkey $(LLIBS) $(LFLAGS)

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
	mkdir -p $(LOGGER_LIB_DIR)

.PHONY: doc
doc: $(HEADER_FILES) $(UTIL_SOURCES) $(TOOL_SOURCES) $(SEAL_SOURCES) $(UNSEAL_SOURCES) $(GETKEY_SOURCES) $(LOGGER_HEADERS) $(LOGGER_SOURCES) Doxyfile
	doxygen Doxyfile

.PHONY: install
install:
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 755 $(LOGGER_LIB_DIR)/libkmythlogger.so $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/kmyth/logger
	install -m 644 $(LOGGER_INC_DIR)/*.h $(DESTDIR)$(PREFIX)/include/kmyth/logger
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BIN_DIR)/kmyth-seal $(DESTDIR)$(PREFIX)/bin/
	install -m 755 $(BIN_DIR)/kmyth-unseal $(DESTDIR)$(PREFIX)/bin/
	ldconfig

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/libkmythlogger.so	
	rm -rf $(DESTDIR)$(PREFIX)/include/kmyth
	rm -f $(DESTDIR)$(PREFIX)/bin/kmyth-seal
	rm -f $(DESTDIR)$(PREFIX)/bin/kmyth-unseal

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
	rm -rf $(OBJECT_DIRS)
	rm -rf $(DOC_DIRS)
	rm -rf $(LOGGER_LIB_DIR)
