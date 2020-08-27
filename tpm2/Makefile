# Makefile for KMYTH using TPM 2.0

# Choose OpenSSL 'base' path (header file and library path prefix)
OPENSSL_DIR = $(MY_OPENSSL_DIR)#         custom shell environment variable

# Specify the 'libkmythlogger' library path
KMYTH_LOG_DIR = $(MY_KMYTH_LOG_DIR)#       custom shell environment variable

# Specify source code path
PREFIX = .#                              Makefile @ src root directory

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
CFLAGS += -I${OPENSSL_DIR}/include#      OpenSSL header files
CFLAGS += -I${KMYTH_LOG_DIR}/include#    kmyth logging utility header files

# Specify linker flags
LFLAGS = -L${OPENSSL_DIR}/lib#             OpenSSL shared library
LFLAGS += -L${KMYTH_LOG_DIR}/lib#          libkmythlogger
LFLAGS += -Wl,-rpath=${OPENSSL_DIR}/lib#   runtime path for OpenSSL library
LFLAGS += -Wl,-rpath=${KMYTH_LOG_DIR}/lib# runtime path for libkmythlogger.so

# Specify top-level source and target directories for build process
INCLUDE_DIR = include
OBJ_DIR = obj
SRC_DIR = src
BIN_DIR = bin
DOC_DIR = doc

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

# Specify Kmyth header files
HEADER_FILES = $(wildcard $(INCLUDE_DIR)/*h)

# Consolidate object directories to simplify mkdir call for 'pre' target below
OBJECT_DIRS = $(SEAL_OBJ_DIR)
OBJECT_DIRS += $(UNSEAL_OBJ_DIR)
OBJECT_DIRS += $(GETKEY_OBJ_DIR)
OBJECT_DIRS += $(UTIL_OBJ_DIR)

all: pre kmyth-seal kmyth-unseal kmyth-getkey

kmyth-seal: $(SEAL_OBJECTS) $(UTIL_OBJECTS)
	$(CC) $(SEAL_OBJECTS) $(UTIL_OBJECTS) -o $(BIN_DIR)/kmyth-seal $(LLIBS) $(LFLAGS)

kmyth-unseal: $(UNSEAL_OBJECTS) $(UTIL_OBJECTS)
	$(CC) $(UNSEAL_OBJECTS) $(UTIL_OBJECTS) -o $(BIN_DIR)/kmyth-unseal $(LLIBS) $(LFLAGS)

kmyth-getkey: $(GETKEY_OBJECTS) $(UTIL_OBJECTS)
	$(CC) $(GETKEY_OBJECTS) $(UTIL_OBJECTS) -o $(BIN_DIR)/kmyth-getkey $(LLIBS) $(LFLAGS)

pre:
	indent -bli0 -bap -bad -sob -cli0 -npcs -nbc -bls -blf -lp -ip0 -ts2 -nut -npsl -bbo -l80 src/*/*.c
	indent -bli0 -bap -bad -sob -cli0 -npcs -nbc -bls -blf -lp -ip0 -ts2 -nut -npsl -bbo -l80 include/*.h
	rm -f src/*/*.c~
	rm -f include/*.h~
	mkdir -p $(BIN_DIR)
	mkdir -p $(OBJECT_DIRS)
	mkdir -p $(DOC_DIR)

doc: $(HEADER_FILES) $(UTIL_SOURCES) $(TOOL_SOURCES) $(SEAL_SOURCES) $(UNSEAL_SOURCES) $(GETKEY_SOURCES) Doxyfile
	doxygen Doxyfile

$(SEAL_OBJ_DIR)/%.o: $(SEAL_SRC_DIR)/%.c | $(SEAL_OBJ_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $< -o $@

$(UNSEAL_OBJ_DIR)/%.o: $(UNSEAL_SRC_DIR)/%.c | $(UNSEAL_OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $< -o $@

$(UTIL_OBJ_DIR)/%.o: $(UTIL_SRC_DIR)/%.c | $(UTIL_OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $< -o $@

$(GETKEY_OBJ_DIR)/%.o: $(GETKEY_SRC_DIR)/%.c | $(GETKEY_OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $< -o $@

.PHONY: clean
clean:
	rm -rf $(PREFIX)/$(BIN_DIR)
	rm -rf $(PREFIX)/$(OBJ_DIR)
	rm -rf $(PREFIX)/$(DOC_DIR)
